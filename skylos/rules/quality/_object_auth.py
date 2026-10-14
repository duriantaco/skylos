"""Review defeated ownership checks in direct route-local object flows.

This is deliberately narrower than a general permission analysis. A route
must contain an explicit ownership comparison; fetching an object alone does
not establish that it is private. Unsupported control flow is left for review
outside this rule rather than being treated as a safety proof.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace


_OWNER_FIELDS = {"owner", "owner_id", "user_id", "tenant", "tenant_id", "account_id"}
_IDENTITY_FIELDS = {"id", "user_id", "tenant_id", "account_id", "subject", "sub"}
_READ_METHODS = {"get", "get_by_id", "fetch", "find", "find_one", "load", "read"}
_WRITE_METHODS = {"update", "delete", "remove", "save"}


class _Unsupported(Exception):
    pass


@dataclass(frozen=True)
class _Value:
    objects: frozenset[int] = frozenset()
    identifiers: frozenset[str] = frozenset()
    principals: frozenset[str] = frozenset()
    identities: frozenset[tuple[str, str]] = frozenset()
    owners: frozenset[int] = frozenset()
    owner_field: str = ""
    closure: tuple | None = None
    mappings: frozenset[int] = frozenset()
    selector: tuple | None = None


def _combine(values):
    values = list(values)
    return _Value(
        objects=frozenset().union(*(v.objects for v in values)),
        identifiers=frozenset().union(*(v.identifiers for v in values)),
    )


@dataclass
class _State:
    values: dict[str, _Value] = field(default_factory=dict)
    trusted: set[str] = field(default_factory=set)
    authorized: set[int] = field(default_factory=set)
    changed_fields: dict[str, set[str]] = field(default_factory=dict)
    mapping_versions: dict[int, int] = field(default_factory=dict)

    def copy(self):
        return _State(
            dict(self.values),
            set(self.trusted),
            set(self.authorized),
            {name: set(fields) for name, fields in self.changed_fields.items()},
            dict(self.mapping_versions),
        )


@dataclass
class _Exit:
    state: _State
    kind: str = "live"
    value: _Value = _Value()
    exception: str = ""


class _Flow:
    def __init__(self, *, shadowed_builtins=()):
        self.saw_owner_check = False
        self.unsafe = False
        self.steps = 0
        self.shadowed_builtins = set(shadowed_builtins)
        self.next_identity = 0
        self.lookup_objects = {}
        self.exception_outcomes = None
        self.call_frames = []
        self.try_depth = 0

    def _fresh_identity(self):
        self.next_identity += 1
        return self.next_identity

    def _selected_object(self, base, selected, state):
        if len(base.mappings) == 1 and selected.selector is not None:
            mapping = next(iter(base.mappings))
            key = (mapping, state.mapping_versions.get(mapping, 0), selected.selector)
            if key not in self.lookup_objects:
                self.lookup_objects[key] = self._fresh_identity()
            return _Value(objects=frozenset({self.lookup_objects[key]}))
        return _Value(objects=frozenset({self._fresh_identity()}))

    def _change_mapping(self, mappings, state):
        for mapping in mappings:
            state.mapping_versions[mapping] = self._fresh_identity()

    def _may_raise(self, state, exceptions):
        if self.exception_outcomes is not None:
            for exception in exceptions:
                snapshot = state.copy()
                if self.call_frames:
                    snapshot.values = dict(self.call_frames[0].values)
                self.exception_outcomes.append(
                    _Exit(snapshot, "raise", exception=exception)
                )

    def _value(self, node, state, depth=0):
        if node is None:
            return _Value()
        if depth > 8:
            raise _Unsupported
        if isinstance(node, ast.Name):
            return state.values.get(node.id, _Value())
        if isinstance(node, ast.Constant):
            return _Value(selector=("literal", type(node.value).__name__, node.value))
        if isinstance(node, ast.Await):
            return self._value(node.value, state, depth + 1)
        if isinstance(node, ast.Lambda):
            defaults = self._defaults(node.args, state)
            return _Value(closure=(node.args, node.body, defaults))
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = self._value(node.value, state, depth + 1)
            if isinstance(node, ast.Subscript) and base.mappings:
                selected = self._value(node.slice, state, depth + 1)
                self._may_raise(state, {"KeyError", "TypeError"})
                return self._selected_object(base, selected, state)
            name = (
                node.attr
                if isinstance(node, ast.Attribute)
                else (
                    node.slice.value if isinstance(node.slice, ast.Constant) else None
                )
            )
            if name in _IDENTITY_FIELDS:
                self._may_raise(
                    state,
                    {"AttributeError"}
                    if isinstance(node, ast.Attribute)
                    else {"KeyError", "TypeError"},
                )
                identities = frozenset(
                    (principal, name)
                    for principal in base.principals
                    if principal in state.trusted
                    and name not in state.changed_fields.get(principal, set())
                )
                if name in _OWNER_FIELDS and base.objects:
                    return replace(base, owners=base.objects, owner_field=name)
                return _Value(objects=base.objects, identities=identities)
            if name in _OWNER_FIELDS:
                self._may_raise(
                    state,
                    {"AttributeError"}
                    if isinstance(node, ast.Attribute)
                    else {"KeyError", "TypeError"},
                )
                return replace(base, owners=base.objects, owner_field=name)
            if isinstance(node, ast.Subscript):
                selected = self._value(node.slice, state, depth + 1)
                self._may_raise(
                    state, {"KeyError", "TypeError"} if base.mappings else {"*"}
                )
                if base.mappings:
                    return self._selected_object(base, selected, state)
                if selected.identifiers and not base.identifiers:
                    return self._selected_object(base, selected, state)
            else:
                self._may_raise(state, {"AttributeError"})
                if base.mappings:
                    return replace(base, selector=None)
            return _Value(objects=base.objects, identifiers=base.identifiers)
        if isinstance(node, ast.Call):
            function = self._value(node.func, state, depth + 1)
            arguments = [self._value(arg, state, depth + 1) for arg in node.args]
            keywords = {
                kw.arg: self._value(kw.value, state, depth + 1) for kw in node.keywords
            }
            if function.closure is not None:
                if None in keywords or any(
                    isinstance(arg, ast.Starred) for arg in node.args
                ):
                    raise _Unsupported
                params, body, defaults = function.closure
                if params.vararg is not None or params.kwarg is not None:
                    raise _Unsupported
                child = state.copy()
                positional = [*params.posonlyargs, *params.args]
                names = {param.arg for param in [*positional, *params.kwonlyargs]}
                if set(keywords) - names:
                    raise _Unsupported
                if {param.arg for param in positional[: len(arguments)]} & set(
                    keywords
                ):
                    raise _Unsupported
                for name in names:
                    child.values.pop(name, None)
                child.values.update(defaults)
                child.values.update(
                    {param.arg: value for param, value in zip(positional, arguments)}
                )
                child.values.update(keywords)
                if len(arguments) > len(positional) or any(
                    param.arg not in child.values
                    for param in [*positional, *params.kwonlyargs]
                ):
                    raise _Unsupported
                self.call_frames.append(state)
                try:
                    value = self._value(body, child, depth + 1)
                finally:
                    self.call_frames.pop()
                state.changed_fields = child.changed_fields
                state.mapping_versions = child.mapping_versions
                return value
            name = (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else (node.func.id if isinstance(node.func, ast.Name) else "")
            )
            combined = _combine([function, *arguments, *keywords.values()])
            if name == "setattr" and isinstance(node.func, ast.Name):
                if (
                    name in self.shadowed_builtins
                    or len(node.args) != 3
                    or node.keywords
                ):
                    raise _Unsupported
                attribute = (
                    node.args[1].value
                    if isinstance(node.args[1], ast.Constant)
                    else None
                )
                self._may_raise(state, {"AttributeError", "TypeError"})
                self._change_identity(
                    arguments[0], attribute, state, value=arguments[2]
                )
                return _Value()
            if (
                name == "get"
                and function.mappings
                and len(arguments) == 1
                and not keywords
            ):
                self._may_raise(state, {"TypeError"})
                return self._selected_object(function, arguments[0], state)
            exceptions = self._call_exceptions(node, name)
            self._may_raise(state, exceptions)
            # An opaque call can change a module dictionary. Its next lookup
            # cannot inherit a previous object's proof merely from its key.
            if not self._literal_conversion(node, name):
                self._change_mapping(state.mapping_versions, state)
            if name in _READ_METHODS | _WRITE_METHODS and combined.identifiers:
                if function.identifiers:
                    return combined
                result = _Value(objects=frozenset({self._fresh_identity()}))
                if name in _WRITE_METHODS:
                    self._expose(result, state)
                return result
            return combined
        if isinstance(node, (ast.NamedExpr, ast.Yield, ast.YieldFrom)):
            raise _Unsupported
        return _combine(
            self._value(child, state, depth + 1) for child in ast.iter_child_nodes(node)
        )

    def _literal_conversion(self, node, name):
        return (
            isinstance(node.func, ast.Name)
            and name not in self.shadowed_builtins
            and name in {"int", "float", "complex", "str", "bool"}
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and not node.keywords
        )

    def _call_exceptions(self, node, name):
        conversions = {
            "int": int,
            "float": float,
            "complex": complex,
            "str": str,
            "bool": bool,
        }
        if (
            not isinstance(node.func, ast.Name)
            or name in self.shadowed_builtins
            or name not in conversions
        ):
            return {"*"}
        if self._literal_conversion(node, name):
            value = node.args[0].value
            if isinstance(value, (str, bytes)) and len(value) > 256:
                return {"ValueError", "TypeError", "OverflowError"}
            try:
                conversions[name](value)
            except (ValueError, TypeError, OverflowError) as exc:
                return {type(exc).__name__}
            return set()
        return {"ValueError", "TypeError", "OverflowError"}

    def _defaults(self, args, state):
        positional = [*args.posonlyargs, *args.args]
        return {
            param.arg: self._value(default, state)
            for param, default in [
                *zip(
                    positional[-len(args.defaults) :] if args.defaults else [],
                    args.defaults,
                ),
                *zip(args.kwonlyargs, args.kw_defaults),
            ]
            if default is not None
        }

    def _facts(self, test, state, truth):
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._facts(test.operand, state, not truth)
        if isinstance(test, ast.BoolOp):
            parts = [self._facts(value, state, truth) for value in test.values]
            if truth == isinstance(test.op, ast.And):
                return set().union(*parts)
            return set.intersection(*parts)
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            self._value(test, state)
            return set()
        if not isinstance(test.ops[0], (ast.Eq, ast.NotEq)):
            self._value(test, state)
            return set()
        left, right = (
            self._value(test.left, state),
            self._value(test.comparators[0], state),
        )
        owner, principal = (left, right) if left.owner_field else (right, left)
        if not owner.owner_field or not owner.owners:
            return set()
        self.saw_owner_check = True
        if truth != isinstance(test.ops[0], ast.Eq):
            return set()
        identities = {
            name for ref, name in principal.identities if ref in state.trusted
        }
        if any(
            ref in state.trusted and not state.changed_fields.get(ref)
            for ref in principal.principals
        ):
            identities.add("value")
        accepted = {
            "tenant": {"tenant_id", "value"},
            "tenant_id": {"tenant_id"},
            "account_id": {"account_id"},
        }.get(owner.owner_field, {"id", "user_id", "subject", "sub", "value"})
        return set(owner.owners) if identities & accepted else set()

    def _expose(self, value, state):
        if value.objects - state.authorized:
            self.unsafe = True

    def _assign(self, target, value, state, *, augmented=False):
        if isinstance(target, ast.Name):
            state.values[target.id] = (
                _combine([state.values.get(target.id, _Value()), value])
                if augmented
                else value
            )
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            raise _Unsupported
        if not isinstance(target, (ast.Attribute, ast.Subscript)):
            raise _Unsupported
        base = self._value(target.value, state)
        self._expose(base, state)
        name = (
            target.attr
            if isinstance(target, ast.Attribute)
            else (
                target.slice.value if isinstance(target.slice, ast.Constant) else None
            )
        )
        if isinstance(target, ast.Subscript):
            self._change_mapping(base.mappings, state)
        self._change_identity(
            base, name, state, value=value if not augmented else _Value()
        )

    def _change_identity(self, base, name, state, *, value=_Value()):
        if name in _IDENTITY_FIELDS or name is None:
            for principal in base.principals:
                if name is not None and value.identities == frozenset(
                    {(principal, name)}
                ):
                    state.changed_fields.setdefault(principal, set()).discard(name)
                    continue
                state.changed_fields.setdefault(principal, set()).update(
                    _IDENTITY_FIELDS if name is None else {name}
                )

    def _catches(self, exception_type, exception):
        if exception_type is None:
            return True
        if isinstance(exception_type, ast.Tuple):
            return any(self._catches(item, exception) for item in exception_type.elts)
        if not isinstance(exception_type, ast.Name):
            return False
        if exception == "*" or exception_type.id in {exception, "BaseException"}:
            return True
        return exception_type.id == "Exception" and exception not in {
            "KeyboardInterrupt",
            "SystemExit",
            "GeneratorExit",
            "BaseException",
        }

    def _block(self, statements, state):
        outcomes = [_Exit(state)]
        for statement in statements:
            following = []
            for outcome in outcomes:
                if outcome.kind != "live":
                    following.append(outcome)
                    continue
                self.steps += 1
                if self.steps > 256:
                    raise _Unsupported
                following.extend(self._statement(statement, outcome.state))
            outcomes = following
        return outcomes

    def _statement(self, stmt, state):
        previous = self.exception_outcomes
        self.exception_outcomes = [] if self.try_depth else None
        try:
            outcomes = self._execute_statement(stmt, state)
            return [*(self.exception_outcomes or []), *outcomes]
        finally:
            self.exception_outcomes = previous

    def _execute_statement(self, stmt, state):
        if isinstance(stmt, ast.If):
            outcomes = []
            for truth, branch in [(True, stmt.body), (False, stmt.orelse)]:
                child = state.copy()
                child.authorized.update(self._facts(stmt.test, child, truth))
                outcomes.extend(self._block(branch, child))
            return outcomes
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            value = self._value(stmt.value, state)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                self._assign(
                    target, value, state, augmented=isinstance(stmt, ast.AugAssign)
                )
        elif isinstance(stmt, ast.Return):
            return [_Exit(state, "return", self._value(stmt.value, state))]
        elif isinstance(stmt, ast.Raise):
            exception = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
            name = exception.id if isinstance(exception, ast.Name) else ""
            return [_Exit(state, "raise", exception=name)]
        elif isinstance(stmt, ast.Try):
            outcomes = []
            self.try_depth += 1
            try:
                body_outcomes = self._block(stmt.body, state.copy())
            finally:
                self.try_depth -= 1
            for outcome in body_outcomes:
                if outcome.kind == "live":
                    outcomes.extend(self._block(stmt.orelse, outcome.state))
                elif outcome.kind == "raise":
                    handlers = []
                    for handler in stmt.handlers:
                        if self._catches(handler.type, outcome.exception):
                            handlers.append(handler)
                        if outcome.exception != "*" and handlers:
                            break
                        if outcome.exception == "*" and (
                            handler.type is None
                            or any(
                                isinstance(node, ast.Name)
                                and node.id in {"Exception", "BaseException"}
                                for node in ast.walk(handler.type)
                            )
                        ):
                            break
                    if not handlers:
                        outcomes.append(outcome)
                    else:
                        for handler in (
                            handlers if outcome.exception == "*" else handlers[:1]
                        ):
                            child = outcome.state.copy()
                            if handler.name:
                                child.values[handler.name] = _Value()
                            outcomes.extend(self._block(handler.body, child))
                else:
                    outcomes.append(outcome)
            finalized = []
            for outcome in outcomes:
                for final in self._block(stmt.finalbody, outcome.state):
                    finalized.append(
                        replace(outcome, state=final.state)
                        if final.kind == "live"
                        else final
                    )
            return finalized
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = (
                stmt.body[1:]
                if stmt.body
                and isinstance(stmt.body[0], ast.Expr)
                and isinstance(stmt.body[0].value, ast.Constant)
                else stmt.body
            )
            if (
                stmt.decorator_list
                or len(body) != 1
                or not isinstance(body[0], ast.Return)
            ):
                raise _Unsupported
            state.values[stmt.name] = _Value(
                closure=(stmt.args, body[0].value, self._defaults(stmt.args, state))
            )
        elif isinstance(stmt, ast.Expr):
            value = self._value(stmt.value, state)
            if (
                isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Attribute)
                and stmt.value.func.attr in _WRITE_METHODS
            ):
                self._expose(value, state)
        elif not isinstance(stmt, (ast.Pass, ast.Import, ast.ImportFrom)):
            raise _Unsupported
        return [_Exit(state)]


def defeated_owner_guard(module, function, identifiers, principals):
    """Return whether a supported route exposes an object despite its guard."""
    if not identifiers or not principals:
        return False
    if not isinstance(principals, dict):
        principals = {name: name for name in principals}
    state = _State(
        values={
            name: _Value(identifiers=frozenset({name}), selector=("argument", name))
            for name in identifiers
        },
        trusted=set(principals.values()),
    )
    state.values.update(
        {
            name: _Value(principals=frozenset({token}))
            for name, token in principals.items()
        }
    )
    bindings = {}
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bindings.setdefault(node.id, []).append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings.setdefault(node.name, []).append(node)
        elif isinstance(node, ast.arg):
            bindings.setdefault(node.arg, []).append(node)
        elif isinstance(node, ast.alias):
            bindings.setdefault(node.asname or node.name.split(".")[0], []).append(node)
    flow = _Flow(shadowed_builtins=bindings)
    for statement in module.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = statement.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
            ):
                body = body[1:]
            defaults = [*statement.args.defaults, *statement.args.kw_defaults]
            if (
                len(bindings.get(statement.name, [])) == 1
                and not statement.decorator_list
                and len(body) == 1
                and isinstance(body[0], ast.Return)
                and isinstance(body[0].value, ast.Constant)
                and statement.args.vararg is None
                and statement.args.kwarg is None
                and all(
                    value is None or isinstance(value, ast.Constant)
                    for value in defaults
                )
            ):
                state.values.setdefault(
                    statement.name,
                    _Value(
                        closure=(
                            statement.args,
                            body[0].value,
                            flow._defaults(statement.args, state),
                        )
                    ),
                )
            continue
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.value, ast.Dict)
        ):
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or len(bindings.get(target.id, [])) != 1:
            continue
        mapping = id(statement)
        state.values.setdefault(target.id, _Value(mappings=frozenset({mapping})))
        state.mapping_versions[mapping] = 0
    try:
        for outcome in flow._block(function.body, state):
            if outcome.kind == "return":
                flow._expose(outcome.value, outcome.state)
    except _Unsupported:
        return False
    return flow.saw_owner_check and flow.unsafe
