"""Native JSON numbers validated before filename formatting.

An ``int`` annotation or isinstance check alone is insufficient: an int subclass
can override formatting. Default native JSON decoding and nonescaping storage
provide the additional value-domain proof. Decoder hooks and mutations fail closed.
"""

from __future__ import annotations

import ast

from skylos.rules.danger.import_proof import provider_binding_is_stable


class JSONScalarProof:
    MAX_WORK = 256
    MAX_DEPTH = 24

    def __init__(self, tracer):
        self.tracer = tracer
        self.project = tracer.project
        self.work = 0
        self.tuple_returns = set()

    def external(self, unit, scope, call, names):
        values = self.project.values(unit, scope, call.func)
        return (
            self.tracer._external_call(unit, scope, call, names)
            and bool(values)
            and (
                not names & {"json.loads", "json.load"}
                or all(
                    provider_binding_is_stable(
                        dependency, unit.tree, unit.path, self.project.root
                    )
                    for dependency in (
                        "json.loads",
                        "json._default_decoder",
                        "json.JSONDecoder",
                        "json.decoder.JSONDecoder",
                        "json.JSONDecoder.decode",
                        "json.JSONDecoder.raw_decode",
                        "json.JSONDecoder.__init__",
                        "json.scanner.make_scanner",
                        "json.decoder.JSONObject",
                        "json.decoder.JSONArray",
                        "json.decoder.scanstring",
                    )
                )
            )
            and all(
                provider_binding_is_stable(
                    value.name, unit.tree, unit.path, self.project.root
                )
                for value in values
            )
        )

    def instance_check(self, unit, scope, call):
        if not self.external(unit, scope, call, {"builtins.isinstance"}):
            return False
        if len(call.args) != 2 or call.keywords:
            return False
        types = (
            call.args[1].elts if isinstance(call.args[1], ast.Tuple) else [call.args[1]]
        )
        for item in types:
            values = self.project.values(unit, scope, item)
            if not values or any(
                value.kind != "ext"
                or value.name
                not in {
                    "builtins.int",
                    "builtins.bool",
                    "builtins.str",
                    "builtins.float",
                    "builtins.dict",
                    "builtins.list",
                    "builtins.type",
                }
                or self.tracer._external_rebound(value.name)
                or not provider_binding_is_stable(
                    value.name, unit.tree, unit.path, self.project.root
                )
                for value in values
            ):
                return False
        return bool(types)

    @staticmethod
    def parameter_get(function, call):
        parameters = {
            arg.arg for arg in [*function.args.posonlyargs, *function.args.args]
        }
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "get"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in parameters
            and not call.keywords
            and 1 <= len(call.args) <= 2
            and all(isinstance(arg, (ast.Name, ast.Constant)) for arg in call.args)
        )

    def guarded_integer_name(self, unit, scope, node, env):
        if scope.kind != "function" or not isinstance(node, ast.Name):
            return False
        found = unit.lookup(scope, node.id)
        if found is None or found[0] is not scope:
            return False
        binds = self.tracer._visible_binds(unit, scope, found[1], node)
        if len(binds) != 1 or binds[0].kind != "assign" or not binds[0].top_level:
            return False
        binding = binds[0]
        for statement in scope.node.body:
            if statement.lineno >= node.lineno:
                break
            if (
                not isinstance(statement, ast.If)
                or binding.node.end_lineno >= statement.lineno
            ):
                continue
            if not self.tracer._guard_terminates(unit, scope, statement.body):
                continue
            terms = (
                statement.test.values
                if isinstance(statement.test, ast.BoolOp)
                and isinstance(statement.test.op, ast.Or)
                else [statement.test]
            )
            rejected = False
            for term in terms:
                if (
                    not isinstance(term, ast.UnaryOp)
                    or not isinstance(term.op, ast.Not)
                    or not isinstance(term.operand, ast.Call)
                ):
                    continue
                call = term.operand
                if (
                    not self.instance_check(unit, scope, call)
                    or not isinstance(call.args[0], ast.Name)
                    or call.args[0].id != node.id
                ):
                    continue
                types = self.project.values(unit, scope, call.args[1])
                rejected |= bool(types) and all(
                    value.kind == "ext" and value.name == "builtins.int"
                    for value in types
                )
            if not rejected:
                continue
            for call in ast.walk(statement.test):
                if not isinstance(call, ast.Call) or self.instance_check(
                    unit, scope, call
                ):
                    continue
                if not (
                    isinstance(call.func, ast.Attribute)
                    and call.func.attr == "get"
                    and self.native(unit, scope, call, env)
                ):
                    return False
            if self.native(unit, binding.scope, binding.value, env):
                return True
        return False

    def _non_alias_item(self, unit, scope, node, active=frozenset()):
        if node in active or len(active) >= self.MAX_DEPTH:
            return False
        active = active | {node}
        if isinstance(node, ast.Constant):
            return type(node.value) in {str, int, float, bool, type(None)}
        if isinstance(node, ast.Call):
            return self.external(unit, scope, node, {"os.stat", "os.fstat", "os.lstat"})
        if not isinstance(node, ast.Name):
            return False
        found = unit.lookup(scope, node.id)
        if found is None or found[0].kind != "function" or len(found[1]) != 1:
            return False
        binding = found[1][0]
        return (
            binding.kind == "assign"
            and binding.top_level
            and self._non_alias_item(unit, binding.scope, binding.value, active)
        )

    def _unpacked_native(self, unit, owner, binding, env, active):
        from .path_provenance import _Site

        call = binding.value
        if (
            not isinstance(call, ast.Call)
            or binding.index is None
            or binding.arity is None
        ):
            return False
        targets = self.project.values(unit, binding.scope, call.func)
        if not targets or any(target.kind != "fn" for target in targets):
            return False
        for target in targets:
            function = target.node
            if function.decorator_list:
                return False
            source = self.project.function_info[id(function)][0]
            returned = self.project.returned_values(function)
            if not returned:
                return False
            site = _Site(
                unit,
                binding.scope,
                call,
                list(call.args),
                list(call.keywords),
                target.bound,
                "call",
            )
            context = (id(function), site, env)
            for result in returned:
                if (
                    not isinstance(result, ast.Tuple)
                    or len(result.elts) != binding.arity
                ):
                    return False
                if any(
                    not self._non_alias_item(source, source.scope_of(item), item)
                    for index, item in enumerate(result.elts)
                    if index != binding.index
                ):
                    return False
                self.tuple_returns.add(id(result))
                try:
                    if not self.native(
                        source,
                        source.scope_of(result),
                        result.elts[binding.index],
                        context,
                        active,
                    ):
                        return False
                finally:
                    self.tuple_returns.discard(id(result))
        return True

    def validated_integer(self, unit, scope, call, value, site, env):
        fn = value.node
        source = self.project.function_info[id(fn)][0]
        if fn.decorator_list or fn.args.vararg or fn.args.kwarg:
            return False
        returned = self.project.returned_values(fn)
        nonempty = [
            node
            for node in returned
            if not isinstance(node, ast.Constant) or node.value is not None
        ]
        if not nonempty or not all(isinstance(node, ast.Name) for node in nonempty):
            return False
        name = nonempty[0].id
        if any(node.id != name for node in nonempty):
            return False
        owner = source.function_scopes[id(fn)]
        found = source.lookup(owner, name)
        if found is None or found[0] is not owner:
            return False
        binds = found[1]
        if len(binds) != 1 or binds[0].kind != "assign":
            return False
        binding = binds[0]
        if not binding.top_level:
            return False
        guarded = False
        for statement in fn.body:
            if not isinstance(statement, ast.If):
                continue
            if statement.lineno <= binding.node.lineno or any(
                statement.end_lineno >= node.lineno for node in nonempty
            ):
                continue
            if not statement.body or not all(
                isinstance(item, ast.Return)
                and isinstance(item.value, ast.Constant)
                and item.value.value is None
                for item in statement.body
            ):
                continue
            terms = (
                statement.test.values
                if isinstance(statement.test, ast.BoolOp)
                and isinstance(statement.test.op, ast.Or)
                else [statement.test]
            )
            for term in terms:
                if not isinstance(term, ast.UnaryOp) or not isinstance(
                    term.op, ast.Not
                ):
                    continue
                check = term.operand
                if (
                    not isinstance(check, ast.Call)
                    or len(check.args) != 2
                    or check.keywords
                ):
                    continue
                if not isinstance(check.args[0], ast.Name) or check.args[0].id != name:
                    continue
                if not self.instance_check(source, owner, check):
                    continue
                kinds = self.project.values(source, owner, check.args[1])
                if kinds and all(
                    kind.kind == "ext"
                    and kind.name == "builtins.int"
                    and not self.tracer._external_rebound(kind.name)
                    for kind in kinds
                ):
                    guarded = True
        if not guarded:
            return False
        # Side-effecting checks/body code could invalidate the earlier value.
        for node in ast.walk(fn):
            if node is not fn and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                return False
            if isinstance(node, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom)):
                return False
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                return False
            if isinstance(node, ast.Call):
                if self.instance_check(source, owner, node):
                    continue
                if self.parameter_get(fn, node):
                    continue
                return False
        context = (id(fn), site, env)
        return self.native(source, owner, binding.value, context)

    def _stable_storage(self, unit, scope, name, origin):
        """Reject mutation/escape of a locally decoded JSON container."""
        if scope.globals or scope.nonlocals:
            return False
        aliases = {name}
        changed = True
        while changed:
            changed = False
            for other, binds in scope.binds.items():
                if (
                    any(
                        bind.kind == "assign"
                        and isinstance(bind.value, ast.Name)
                        and bind.value.id in aliases
                        for bind in binds
                    )
                    and other not in aliases
                ):
                    aliases.add(other)
                    changed = True
        for node, source_scope in unit.loads:
            if not isinstance(node, ast.Name) or node.id not in aliases:
                continue
            found = unit.lookup(source_scope, node.id)
            if found is None or found[0] is not scope:
                continue
            if source_scope is not scope:
                return False
            parent = unit.parents.get(id(node))
            if isinstance(parent, (ast.List, ast.Tuple, ast.Set, ast.Dict)) and (
                not isinstance(parent, ast.Tuple)
                or id(parent) not in self.tuple_returns
            ):
                return False
            if isinstance(parent, (ast.Assign, ast.AnnAssign)):
                targets = (
                    parent.targets
                    if isinstance(parent, ast.Assign)
                    else [parent.target]
                )
                if any(not isinstance(target, ast.Name) for target in targets):
                    return False
            if isinstance(parent, ast.Attribute):
                operation = unit.parents.get(id(parent))
                if (
                    not isinstance(operation, ast.Call)
                    or operation.func is not parent
                    or parent.attr != "get"
                ):
                    return False
        for alias in aliases:
            if unit.name_mutations.get(alias):
                return False
            for target, _, _, target_scope in unit.subscript_stores:
                if (
                    target_scope is scope
                    and isinstance(target.value, ast.Name)
                    and target.value.id == alias
                ):
                    return False
            for call, caller in unit.name_escapes.get(alias, ()):
                if caller is not scope:
                    continue
                if self.instance_check(unit, scope, call):
                    continue
                targets = self.project.values(unit, scope, call.func)
                if targets and all(
                    target.kind == "fn" and self._readonly(target) for target in targets
                ):
                    continue
                return False
        return True

    def _readonly(self, value):
        """Only a finite local scalar-reading helper can receive the container."""
        fn = value.node
        source = self.project.function_info[id(fn)][0]
        owner = source.function_scopes[id(fn)]
        if fn.decorator_list or fn.args.vararg or fn.args.kwarg:
            return False
        for node in ast.walk(fn):
            if node is not fn and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                return False
            if isinstance(node, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom)):
                return False
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                return False
            if not isinstance(node, ast.Call):
                continue
            if self.instance_check(source, owner, node):
                continue
            if self.parameter_get(fn, node):
                continue
            return False
        return True

    def native(self, unit, scope, node, env=None, active=frozenset()):
        from .path_provenance import _env_lookup, _Site

        self.work += 1
        key = (id(node), id(scope))
        if (
            node is None
            or key in active
            or len(active) >= self.MAX_DEPTH
            or self.work > self.MAX_WORK
        ):
            return False
        active = active | {key}
        if isinstance(node, ast.Constant):
            return type(node.value) in {str, int, float, bool, type(None)}
        if isinstance(node, ast.Subscript):
            return self.native(unit, scope, node.value, env, active) and self.native(
                unit, scope, node.slice, env, active
            )
        if isinstance(node, ast.Call):
            if self.external(unit, scope, node, {"json.loads", "json.load"}):
                return (
                    len(node.args) == 1
                    and not node.keywords
                    and not isinstance(node.args[0], ast.Starred)
                )
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                return (
                    1 <= len(node.args) <= 2
                    and not node.keywords
                    and self.native(unit, scope, node.func.value, env, active)
                    and all(
                        self.native(unit, scope, arg, env, active) for arg in node.args
                    )
                )
            targets = self.project.values(unit, scope, node.func)
            if not targets or any(target.kind != "fn" for target in targets):
                return False
            for target in targets:
                fn = target.node
                source = self.project.function_info[id(fn)][0]
                returned = self.project.returned_values(fn)
                if not returned or fn.decorator_list:
                    return False
                site = _Site(
                    unit,
                    scope,
                    node,
                    list(node.args),
                    list(node.keywords),
                    target.bound,
                    "call",
                )
                context = (id(fn), site, env)
                if not all(
                    self.native(source, source.scope_of(item), item, context, active)
                    for item in returned
                ):
                    return False
            return True
        if not isinstance(node, ast.Name):
            return False
        found = unit.lookup(scope, node.id)
        if found is None:
            return False
        owner, binds = found
        binds = self.tracer._visible_binds(unit, owner, binds, node)
        if len(binds) != 1:
            return False
        binding = binds[0]
        if binding.kind == "param" and owner.kind == "function":
            context = _env_lookup(env, id(owner.node))
            if context is None or context[0] is None:
                return False
            site, parent = context
            values = list(
                self.project.bind_argument(owner.node, site, binding.node.arg)
            )
            immutable_arguments = bool(values) and all(
                isinstance(argument, ast.Constant)
                and type(argument.value) in {str, int, float, bool, type(None)}
                for argument, _source, _caller in values
            )
            if not immutable_arguments and not self._stable_storage(
                unit, owner, node.id, None
            ):
                return False
            return bool(values) and all(
                self.native(source, caller, argument, parent, active)
                for argument, source, caller in values
            )
        if binding.kind == "unpack" and owner.kind == "function":
            return self._stable_storage(
                unit, owner, node.id, binding.value
            ) and self._unpacked_native(unit, owner, binding, env, active)
        if binding.kind != "assign" or owner.kind not in {"function", "lambda"}:
            return False
        if not binding.top_level or binding.node.end_lineno >= node.lineno:
            return False
        return self._stable_storage(
            unit, owner, node.id, binding.value
        ) and self.native(unit, binding.scope, binding.value, env, active)
