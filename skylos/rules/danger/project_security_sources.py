"""Positive source evidence shared by the dynamic-import/argv checks only.

This reuses the bounded project graph without granting path sanitizers the
ability to sanitize import names or command options.
"""

from __future__ import annotations

import ast
from pathlib import Path

from .danger_fs.path_provenance import (
    UNTRUSTED,
    _Facts,
    _Project,
    _Tracer,
    _V,
    _Site,
    PARAMETER,
    _step,
)

_MODEL_BASES = frozenset(
    {
        "pydantic.BaseModel",
        "pydantic.main.BaseModel",
        "pydantic_settings.BaseSettings",
        "pydantic_settings.main.BaseSettings",
    }
)


class SecurityProject(_Project):
    """Preserve model receiver identities at documented validation APIs."""

    def _values(self, unit, scope, expr, depth):
        if isinstance(expr, ast.Constant) and expr.value is None:
            return frozenset()
        return super()._values(unit, scope, expr, depth)

    def _param_values(self, unit, owner, bind, depth):
        values = super()._param_values(unit, owner, bind, depth)
        if (
            values is not None
            or depth > 24
            or id(owner.node) in self._param_value_active
            or id(owner.node) in self._sites_active
        ):
            return values
        self._param_value_active.add(id(owner.node))
        try:
            sites = self.call_sites(unit, owner.node)
            resolved = set()
            for site in sites.resolved[:64]:
                for expression, source_unit, source_scope in self.bind_argument(
                    owner.node, site, bind.node.arg
                ):
                    supplied = self.values(
                        source_unit, source_scope, expression, depth + 4
                    )
                    if supplied:
                        resolved |= supplied
            return frozenset(resolved) if resolved else None
        finally:
            self._param_value_active.discard(id(owner.node))

    def _name_values(self, unit, scope, expr, depth):
        found = unit.lookup(scope, expr.id)
        if found is None or not any(bind.kind == "unpack" for bind in found[1]):
            return super()._name_values(unit, scope, expr, depth)
        result = set()
        for bind in found[1]:
            values = None
            handled = False
            if (
                bind.kind == "unpack"
                and isinstance(bind.node, ast.Assign)
                and isinstance(bind.value, ast.Call)
            ):
                targets = [
                    target
                    for target in bind.node.targets
                    if isinstance(target, (ast.Tuple, ast.List))
                ]
                if len(targets) == 1 and not any(
                    isinstance(target, ast.Starred) for target in targets[0].elts
                ):
                    position = next(
                        (
                            index
                            for index, target in enumerate(targets[0].elts)
                            if isinstance(target, ast.Name) and target.id == expr.id
                        ),
                        None,
                    )
                    callees = self.values(unit, bind.scope, bind.value.func, depth + 1)
                    if (
                        position is not None
                        and callees
                        and all(value.kind == "fn" for value in callees)
                    ):
                        selected = set()
                        handled = True
                        for callee in callees:
                            returned = self.returned_values(callee.node)
                            if not returned or not all(
                                isinstance(item, (ast.Tuple, ast.List))
                                and len(item.elts) == len(targets[0].elts)
                                for item in returned
                            ):
                                handled = False
                                break
                            for item in returned:
                                part = item.elts[position]
                                resolved = self.values(
                                    callee.unit,
                                    callee.unit.scope_of(part),
                                    part,
                                    depth + 1,
                                )
                                if resolved is None:
                                    return None
                                selected |= resolved
                        values = frozenset(selected)
            if not handled:
                values = self.bind_values(unit, found[0], bind, depth + 1)
            if values is None:
                return None
            result |= values
        return frozenset(result)

    def _call_values(self, unit, scope, call, depth):
        if isinstance(call.func, ast.Attribute) and call.func.attr in {
            "model_validate",
            "parse_obj",
        }:
            owners = self.values(unit, scope, call.func.value, depth + 1)
            methods = self.values(unit, scope, call.func, depth + 1)
            if (
                owners
                and (
                    not methods
                    or all(value.kind in {"ext", "extattr"} for value in methods)
                )
                and all(
                    value.kind == "cls"
                    and self._class_extends(value.node, _MODEL_BASES)
                    for value in owners
                )
            ):
                return frozenset(_V("inst", value.unit, value.node) for value in owners)
        return super()._call_values(unit, scope, call, depth)

    def _external_call_values(self, unit, scope, call, name, depth):
        if name in {"typing.cast", "typing_extensions.cast"} and len(call.args) == 2:
            if not SourceTracer(self, "SKY-D212")._external_rebound(name):
                return self.values(unit, scope, call.args[1], depth + 1)
        return super()._external_call_values(unit, scope, call, name, depth)

    def _defined_member(self, unit, cls, attr, instance, depth):
        if instance and self._class_extends(cls, _MODEL_BASES):
            for field in cls.body:
                if (
                    not isinstance(field, ast.AnnAssign)
                    or not isinstance(field.target, ast.Name)
                    or field.target.id != attr
                ):
                    continue
                annotation = field.annotation
                if isinstance(annotation, ast.Subscript):
                    annotation = annotation.slice
                values = self.values(
                    unit, unit.class_scopes[id(cls)], annotation, depth + 1
                )
                if values and all(
                    value.kind == "cls"
                    and self._class_extends(value.node, _MODEL_BASES)
                    for value in values
                ):
                    return frozenset(
                        _V("inst", value.unit, value.node) for value in values
                    )
        return super()._defined_member(unit, cls, attr, instance, depth)


class SourceTracer(_Tracer):
    def __init__(self, project, rule):
        super().__init__(project, rule)
        self._registered_sources = {}

    def _param(self, unit, owner, param, env):
        if env is None:
            key = (id(owner.node), param.arg)
            if key not in self._registered_sources:
                self._registered_sources[key] = None
                from .registered_callback_sources import registered_thread_argument

                self._registered_sources[key] = registered_thread_argument(
                    self, unit, owner, param
                )
            registered = self._registered_sources[key]
            if registered is not None:
                return registered
        return super()._param(unit, owner, param, env)

    def _guarded(self, site, expr):
        return None

    def _model(self, cls):
        return self.project._class_extends(cls, _MODEL_BASES)

    def _bind_facts(self, unit, owner, bind, name, env):
        if (
            bind.kind == "unpack"
            and isinstance(bind.node, ast.Assign)
            and isinstance(bind.value, ast.Call)
        ):
            targets = [
                target
                for target in bind.node.targets
                if isinstance(target, (ast.Tuple, ast.List))
            ]
            if len(targets) == 1 and all(
                isinstance(target, ast.Name) for target in targets[0].elts
            ):
                position = next(
                    (
                        index
                        for index, target in enumerate(targets[0].elts)
                        if target.id == name
                    ),
                    None,
                )
                callees = self.project.values(unit, bind.scope, bind.value.func)
                if (
                    position is not None
                    and callees
                    and all(value.kind == "fn" for value in callees)
                ):
                    facts = _Facts()
                    for value in callees:
                        returned = self.project.returned_values(value.node)
                        if not returned or not all(
                            isinstance(expr, (ast.Tuple, ast.List))
                            and len(expr.elts) == len(targets[0].elts)
                            for expr in returned
                        ):
                            return super()._bind_facts(unit, owner, bind, name, env)
                        site = _Site(
                            unit,
                            bind.scope,
                            bind.value,
                            list(bind.value.args),
                            list(bind.value.keywords),
                            value.bound,
                            "call",
                        )

                        def summarize():
                            result = _Facts()
                            for expression in returned:
                                part = expression.elts[position]
                                result.add(
                                    self.trace(
                                        value.unit,
                                        value.unit.scope_of(part),
                                        part,
                                        (id(value.node), None, None),
                                    )
                                )
                            return result

                        summary = self._memoized(
                            self.summary_memo,
                            ("tuple-summary", id(value.node), position),
                            summarize,
                        )
                        resolved = _Facts()
                        for kind in _Facts.KINDS:
                            if kind != PARAMETER:
                                resolved.chains[kind] = list(summary.chains[kind])
                        for chain in summary.chains[PARAMETER]:
                            passed = _Facts()
                            for (
                                expression,
                                source_unit,
                                source_scope,
                            ) in self.project.bind_argument(value.node, site, chain[0]):
                                passed.add(
                                    self.trace(
                                        source_unit, source_scope, expression, env
                                    )
                                )
                            for step in chain[1:]:
                                passed = passed.then(step)
                            resolved.add(passed)
                        facts.add(resolved)
                    return facts.then(
                        _step(
                            unit,
                            bind.node,
                            f"`{name}` receives returned tuple item {position}",
                        )
                    )
        return super()._bind_facts(unit, owner, bind, name, env)

    def _model_method_is_external(self, cls, method):
        hierarchy, _ = self.project.mro(cls)
        ids = {id(owner) for _, owner in hierarchy}
        for _, owner in hierarchy:
            for statement in owner.body:
                if (
                    isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and statement.name == method
                ):
                    return False
                if isinstance(statement, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == method
                    for target in statement.targets
                ):
                    return False
        for unit, target, _, _, scope in self.project.attr_stores.get(method, ()):
            owners = self.project.values(unit, scope, target.value)
            if owners is None or any(
                value.kind in {"cls", "inst"} and id(value.node) in ids
                for value in owners
            ):
                return False
        return not any(
            self._external_rebound(base + "." + method) for base in _MODEL_BASES
        )

    def _visible_binds(self, unit, owner, binds, use):
        candidates = super()._visible_binds(unit, owner, binds, use)

        def branches(node):
            found = {}
            current = node
            while id(current) in unit.parents:
                parent = unit.parents[id(current)]
                if isinstance(parent, ast.If):
                    if current in parent.body:
                        found[id(parent)] = True
                    elif current in parent.orelse:
                        found[id(parent)] = False
                current = parent
            return found

        used = branches(use)
        return [
            bind
            for bind in candidates
            if all(
                used.get(key, side) == side for key, side in branches(bind.node).items()
            )
        ]

    def _call(self, unit, scope, node, env):
        if self._external_call(unit, scope, node, {"shlex.split"}) and node.args:
            argument = node.args[0]
            if (
                not node.keywords
                and len(node.args) == 1
                and isinstance(argument, ast.Call)
                and len(argument.args) == 1
                and not argument.keywords
                and self._external_call(unit, scope, argument, {"shlex.quote"})
            ):
                return self.trace(unit, scope, argument.args[0], env)
            return self.trace(unit, scope, node.args[0], env).then(
                _step(
                    unit,
                    node,
                    "shlex.split expands text into separate command arguments",
                )
            )
        if (
            self._external_call(
                unit, scope, node, {"typing.cast", "typing_extensions.cast"}
            )
            and len(node.args) == 2
        ):
            return self.trace(unit, scope, node.args[1], env).then(
                _step(unit, node, "typing.cast preserves its data argument")
            )
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"model_validate", "parse_obj"}
            and node.args
        ):
            owners = self.project.values(unit, scope, node.func.value)
            methods = self.project.values(unit, scope, node.func)
            if (
                owners
                and (
                    not methods
                    or all(
                        value.kind in {"ext", "extattr"}
                        and value.name.split(".")[0]
                        in {"pydantic", "pydantic_settings"}
                        for value in methods
                    )
                )
                and all(
                    value.kind == "cls"
                    and self._model(value.node)
                    and self._model_method_is_external(value.node, node.func.attr)
                    for value in owners
                )
            ):
                return self.trace(unit, scope, node.args[0], env).then(
                    _step(unit, node, "Pydantic validates the supplied model data")
                )
        return super()._call(unit, scope, node, env)

    def _attribute(self, unit, scope, node, env):
        facts = super()._attribute(unit, scope, node, env)
        owners = self.project.values(unit, scope, node.value)
        if owners and all(
            value.kind in {"inst", "cls"} and self._model(value.node)
            for value in owners
        ):
            if all(self._data_field(value.node, node.attr) for value in owners):
                facts.add(
                    self.trace(unit, scope, node.value, env).then(
                        _step(
                            unit,
                            node,
                            f"validated model data supplies field `.{node.attr}`",
                        )
                    )
                )
        return facts

    def _attribute_container_writes(self, cls_node, attr, targets):
        facts = super()._attribute_container_writes(cls_node, attr, targets)
        if not self._mutable_attribute(cls_node, attr):
            return facts
        hierarchy, _ = self.project.mro(cls_node)
        for unit, owner in hierarchy:

            def aliases(expression, scope, depth=0):
                if depth > 6:
                    return False
                if isinstance(expression, ast.Attribute) and expression.attr == attr:
                    cls = self._self_class(unit, scope, expression.value)
                    return cls is not None and id(cls) in targets
                if isinstance(expression, ast.IfExp):
                    return aliases(expression.body, scope, depth + 1) or aliases(
                        expression.orelse, scope, depth + 1
                    )
                if isinstance(expression, ast.Name):
                    found = unit.lookup(scope, expression.id)
                    if found:
                        return any(
                            bind.kind == "assign"
                            and aliases(bind.value, bind.scope, depth + 1)
                            for bind in self._visible_binds(
                                unit, found[0], found[1], expression
                            )
                        )
                return False

            for mutations in unit.name_mutations.values():
                for call, scope in mutations:
                    if not isinstance(
                        call.func, ast.Attribute
                    ) or call.func.attr not in {
                        "append",
                        "extend",
                        "insert",
                        "add",
                        "update",
                    }:
                        continue
                    if aliases(call.func.value, scope):
                        supplied = self._union(
                            unit,
                            scope,
                            [*call.args, *[keyword.value for keyword in call.keywords]],
                            None,
                        )
                        facts.add(
                            supplied.then(
                                _step(
                                    unit,
                                    call,
                                    f"local alias `.{call.func.attr}()` adds to `.{attr}`",
                                )
                            )
                        )
        return facts

    def _data_field(self, cls, name):
        """Keep field literals/enums and relevant custom validators unknown."""
        hierarchy, _ = self.project.mro(cls)
        field = None
        field_context = None
        for field_unit, owner in hierarchy:
            for statement in owner.body:
                if (
                    isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                    and statement.target.id == name
                ):
                    if field is None:
                        field = statement
                        field_context = (field_unit, owner)
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for decorator in statement.decorator_list:
                    if not isinstance(decorator, ast.Call):
                        continue
                    target = decorator.func
                    label = (
                        target.attr
                        if isinstance(target, ast.Attribute)
                        else target.id
                        if isinstance(target, ast.Name)
                        else ""
                    )
                    if label in {"model_validator", "root_validator"}:
                        return False
                    if label in {"field_validator", "validator"} and any(
                        not isinstance(arg, ast.Constant) or arg.value in {name, "*"}
                        for arg in decorator.args
                    ):
                        return False
        if field is None:
            return False
        annotation = field.annotation
        field_unit, field_owner = field_context
        resolved = self.project.values(
            field_unit, field_unit.class_scopes[id(field_owner)], annotation
        )
        if resolved and all(
            value.kind == "cls" and self._finite_enum(value.node) for value in resolved
        ):
            return False
        for part in ast.walk(annotation):
            if isinstance(part, ast.Name) and part.id in {"Literal", "Enum"}:
                return False
            if isinstance(part, ast.Attribute) and part.attr in {"Literal", "Enum"}:
                return False
        return True

    def _finite_enum(self, cls):
        info = self.project.class_info.get(id(cls))
        if info is None:
            return False
        enum_names = {"enum.Enum", "enum.StrEnum", "enum.IntEnum"}
        found_enum = False
        for base in cls.bases:
            values = self.project.values(info[0], info[1], base)
            if not values or any(
                value.kind != "ext"
                or value.name
                not in enum_names | {"builtins.str", "builtins.int", "builtins.object"}
                for value in values
            ):
                return False
            found_enum |= any(value.name in enum_names for value in values)
        if not found_enum or any(self._external_rebound(name) for name in enum_names):
            return False
        hierarchy, _ = self.project.mro(cls)
        members = False
        for _, owner in hierarchy:
            for statement in owner.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return False
                if isinstance(statement, ast.Assign):
                    names = [
                        target.id
                        for target in statement.targets
                        if isinstance(target, ast.Name)
                    ]
                    if any(not name.startswith("_") for name in names):
                        if not isinstance(
                            statement.value, ast.Constant
                        ) or not isinstance(statement.value.value, (str, int)):
                            return False
                        members = True
        for unit, target, _, _, scope in self.project.attr_stores.get(
            "_member_map_", ()
        ):
            owners = self.project.values(unit, scope, target.value)
            if owners is None or any(
                value.kind == "cls" and value.node is cls for value in owners
            ):
                return False
        return members


class ProjectSources:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.project = SecurityProject.load(self.root)
        self.tracer = SourceTracer(self.project, "SKY-D357")
        self.command_tracer = SourceTracer(self.project, "SKY-D212")

    def _production_chain(self, chain):
        return not any(
            unit.is_test and any(step.startswith(unit.rel + ":") for step in chain)
            for unit in self.project.units
        )

    def locate_call(self, file_path, call):
        unit = self.project.by_path.get(Path(file_path).resolve())
        if unit is None:
            return None, None
        for candidate, _ in unit.calls:
            if (
                candidate.lineno == call.lineno
                and candidate.col_offset == call.col_offset
                and ast.dump(candidate, include_attributes=False)
                == ast.dump(call, include_attributes=False)
            ):
                return unit, candidate
        return None, None

    def import_evidence(self, file_path, call):
        unit, target = self.locate_call(file_path, call)
        if target is None:
            return None
        argument = (
            target.args[0]
            if target.args
            else next(
                (keyword.value for keyword in target.keywords if keyword.arg == "name"),
                None,
            )
        )
        if argument is None:
            return None
        facts = self.tracer.trace(unit, unit.scope_of(argument), argument)
        chains = [
            chain for chain in facts.chains[UNTRUSTED] if self._production_chain(chain)
        ]
        if not chains:
            return None
        chain = list(chains[0])
        return {
            "evidence_kind": "python_dynamic_import_taint",
            "source": chain[0],
            "sources": [chain[0]],
            "sink": "dynamic Python import",
            "path": chain,
            "guards_missing": ["select a module from a fixed allowlist"],
            "analysis_complete": False,
        }

    def command_evidence(self, file_path, call):
        unit, target = self.locate_call(file_path, call)
        if target is None or not self.command_tracer._external_call(
            unit,
            unit.scope_of(target),
            target,
            {
                "subprocess.Popen",
                "subprocess.run",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
            },
        ):
            return None
        argument = (
            target.args[0]
            if target.args
            else next((kw.value for kw in target.keywords if kw.arg == "args"), None)
        )
        if argument is None:
            return None
        facts = self.command_tracer.trace(unit, unit.scope_of(argument), argument)
        for chain in facts.chains[UNTRUSTED]:
            if not self._production_chain(chain):
                continue
            if not any(
                "shlex.split expands text into separate command arguments" in step
                for step in chain
            ):
                continue
            expansions = []
            for source_unit in self.project.units:
                for mutation, scope in source_unit.calls:
                    if (
                        not isinstance(mutation.func, ast.Attribute)
                        or mutation.func.attr != "extend"
                        or not isinstance(mutation.func.value, ast.Name)
                    ):
                        continue
                    prefix = f"{source_unit.rel}:{mutation.lineno} "
                    if any(
                        step.startswith(prefix)
                        and f"`{mutation.func.value.id}.extend(...)`" in step
                        for step in chain
                    ):
                        expansions.append((source_unit, scope, mutation))
            if not expansions or all(
                self._option_boundary(source_unit, scope, mutation)
                for source_unit, scope, mutation in expansions
            ):
                continue
            return {
                "evidence_kind": "python_argument_vector_injection",
                "source": chain[0],
                "sources": [chain[0]],
                "sink": "subprocess argument vector",
                "path": [
                    *chain,
                    _step(
                        unit,
                        target,
                        "untrusted expanded arguments reach the subprocess",
                    ),
                ],
                "guards_missing": [
                    "an option boundary before expanded input or a fixed argument allowlist"
                ],
                "analysis_complete": False,
            }
        return None

    def _option_boundary(self, unit, scope, mutation):
        receiver = mutation.func.value
        found = unit.lookup(scope, receiver.id)
        if found is None:
            return False
        owner, bindings = found
        bindings = self.command_tracer._visible_binds(unit, owner, bindings, mutation)
        if (
            len(bindings) != 1
            or bindings[0].kind != "assign"
            or not isinstance(bindings[0].value, (ast.List, ast.Tuple))
        ):
            return False
        elements = bindings[0].value.elts
        if (
            len(elements) != 2
            or not isinstance(elements[0], ast.Constant)
            or not isinstance(elements[0].value, str)
            or not elements[0].value
            or not isinstance(elements[1], ast.Constant)
            or elements[1].value != "--"
        ):
            return False
        aliases = self.command_tracer._local_aliases(owner, receiver.id)
        for node in ast.walk(owner.node):
            if getattr(node, "lineno", mutation.lineno) > mutation.lineno:
                continue
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in aliases
                    and node.func.attr not in {"append", "extend"}
                ):
                    return False
                if any(
                    isinstance(value, ast.Name) and value.id in aliases
                    for value in node.args
                ) and not self.command_tracer._external_call(
                    unit,
                    unit.scope_of(node),
                    node,
                    {"builtins.len", "builtins.tuple", "builtins.list"},
                ):
                    return False
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and isinstance(node.value, ast.Name)
                and node.value.id in aliases
            ):
                return False
        return True
