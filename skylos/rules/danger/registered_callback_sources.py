"""Bridge a source-proven request thread to a registered plugin dispatcher.

The bridge requires the actual registry class, matching engine-type marker,
dispatcher call, Flask context wrapper and threading.Thread target/arguments.
An arbitrary function named search is not an input source.
"""

from __future__ import annotations

import ast

from .danger_fs.path_provenance import UNTRUSTED, _Facts, _step


def marker(statements):
    for statement in statements:
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
            if isinstance(statement, ast.AnnAssign)
            else []
        )
        if any(
            isinstance(target, ast.Name) and target.id == "engine_type"
            for target in targets
        ):
            value = statement.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
    return None


def registered_thread_argument(tracer, unit, owner, parameter):
    project = tracer.project
    if owner.parent is not unit.module:
        return None
    kind = marker(unit.tree.body)
    if kind is None:
        return None
    fn = owner.node
    parameters = [*fn.args.posonlyargs, *fn.args.args]
    if parameter not in parameters:
        return None
    position = parameters.index(parameter)
    facts = _Facts()
    for class_unit, _, class_scope in project.class_info.values():
        cls = class_scope.node
        if marker(cls.body) != kind:
            continue
        dispatchers = [
            method
            for method in cls.body
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
            and method.name == fn.name
        ]
        for method in dispatchers:
            forwarded = []
            for call in ast.walk(method):
                if (
                    not isinstance(call, ast.Call)
                    or not isinstance(call.func, ast.Attribute)
                    or call.func.attr != fn.name
                    or len(call.args) <= position
                ):
                    continue
                receiver = call.func.value
                if (
                    not isinstance(receiver, ast.Attribute)
                    or receiver.attr != "engine"
                    or not isinstance(receiver.value, ast.Name)
                    or receiver.value.id != "self"
                ):
                    continue
                argument = call.args[position]
                if not isinstance(argument, ast.Name):
                    continue
                method_params = [*method.args.posonlyargs, *method.args.args]
                index = next(
                    (
                        i - 1
                        for i, param in enumerate(method_params)
                        if param.arg == argument.id and i > 0
                    ),
                    None,
                )
                if index is not None:
                    forwarded.append((index, call))
            if not forwarded:
                continue
            for caller_unit in project.units:
                if caller_unit.is_test:
                    continue
                for thread, scope in caller_unit.calls:
                    if not tracer._external_call(
                        caller_unit, scope, thread, {"threading.Thread"}
                    ):
                        continue
                    keywords = {
                        keyword.arg: keyword.value for keyword in thread.keywords
                    }
                    target = keywords.get("target")
                    args = keywords.get("args")
                    if not isinstance(target, ast.Name) or not isinstance(
                        args, (ast.Tuple, ast.List)
                    ):
                        continue
                    found = caller_unit.lookup(scope, target.id)
                    if found is None:
                        continue
                    bindings = tracer._visible_binds(
                        caller_unit, found[0], found[1], thread
                    )
                    if len(bindings) != 1 or bindings[0].kind != "assign":
                        continue
                    wrapper = bindings[0].value
                    if (
                        not isinstance(wrapper, ast.Call)
                        or not wrapper.args
                        or not tracer._external_call(
                            caller_unit,
                            bindings[0].scope,
                            wrapper,
                            {
                                "flask.copy_current_request_context",
                                "flask.ctx.copy_current_request_context",
                            },
                        )
                    ):
                        continue
                    reference = wrapper.args[0]
                    if (
                        not isinstance(reference, ast.Attribute)
                        or reference.attr != method.name
                        or not isinstance(reference.value, ast.Subscript)
                    ):
                        continue
                    registries = project.values(
                        caller_unit, scope, reference.value.value
                    )
                    if not registries or not all(
                        value.kind == "inst" for value in registries
                    ):
                        continue
                    if not any(
                        _contains_dispatcher(project, value.unit, value.node, cls)
                        for value in registries
                    ):
                        continue
                    for index, call in forwarded:
                        if len(args.elts) <= index:
                            continue
                        supplied = tracer.trace(caller_unit, scope, args.elts[index])
                        if not supplied.chains[UNTRUSTED]:
                            continue
                        supplied = supplied.then(
                            _step(
                                caller_unit,
                                thread,
                                f"request thread invokes registered `{cls.name}.{method.name}`",
                            )
                        )
                        supplied = supplied.then(
                            _step(
                                class_unit,
                                call,
                                f"engine_type={kind!r} dispatcher supplies callback `{fn.name}.{parameter.arg}`",
                            )
                        )
                        facts.add(supplied)
    return facts if facts.chains[UNTRUSTED] else None


def _contains_dispatcher(project, unit, registry, dispatcher):
    """Require a populated registry, rather than an inert table of classes.

    The supported contract is deliberately structural: a literal type table
    supplies the factory, its instance invokes an initializer with a bound
    registration callback, and that callback stores the same instance in the
    registry.  Every step must be present in production source.
    """
    cache = getattr(project, "_callback_registry_proofs", None)
    if cache is None:
        cache = project._callback_registry_proofs = {}
    key = (id(registry), id(dispatcher))
    if key not in cache:
        cache[key] = False
        cache[key] = _registry_effect(project, unit, registry, dispatcher)
    return cache[key]


def _name(node, name):
    return isinstance(node, ast.Name) and node.id == name


def _attribute(node, owner, name):
    return (
        isinstance(node, ast.Attribute)
        and node.attr == name
        and _name(node.value, owner)
    )


def _method(project, cls, name):
    order, external = project.mro(cls)
    if external:
        return None
    for unit, ancestor in order:
        scope = unit.class_scopes[id(ancestor)]
        binds = scope.binds.get(name, [])
        if not binds:
            continue
        if len(binds) != 1 or binds[0].kind != "def":
            return None
        method = binds[0].node
        if method.decorator_list:
            return None
        return unit, method
    return None


def _single_binding(unit, method, name, kind):
    binds = unit.function_scopes[id(method)].binds.get(name, [])
    return binds[0] if len(binds) == 1 and binds[0].kind == kind else None


def _callback_stores(project, registry, name):
    resolved = _method(project, registry, name)
    if resolved is None:
        return False
    unit, method = resolved
    params = [*method.args.posonlyargs, *method.args.args]
    if len(params) != 3 or not all(
        _single_binding(unit, method, param.arg, "param") for param in params
    ):
        return False
    receiver, processor = params[0].arg, params[1].arg
    return any(
        isinstance(target, ast.Subscript)
        and _name(target.value, receiver)
        and _name(value, processor)
        and scope is unit.function_scopes[id(method)]
        for target, value, _, scope in unit.subscript_stores
    )


def _initializer_calls_back(project, dispatcher, name):
    resolved = _method(project, dispatcher, name)
    if resolved is None:
        return False
    unit, method = resolved
    params = [*method.args.posonlyargs, *method.args.args]
    if len(params) != 2 or not all(
        _single_binding(unit, method, param.arg, "param") for param in params
    ):
        return False
    receiver, callback = params[0].arg, params[1].arg
    return any(
        _name(call.func, callback)
        and len(call.args) == 2
        and not call.keywords
        and _name(call.args[0], receiver)
        and isinstance(call.args[1], ast.Constant)
        and call.args[1].value is True
        and scope is unit.function_scopes[id(method)]
        for call, scope in unit.calls
    )


def _populator_called(project, registry, method):
    for unit, call, scope in project.calls_by_name.get(method.name, []):
        if unit.is_test or not isinstance(call.func, ast.Attribute):
            continue
        values = project.values(unit, scope, call.func.value)
        if values and all(
            value.kind == "inst" and value.node is registry for value in values
        ):
            return True
    return False


def _registry_effect(project, unit, registry, dispatcher):
    if registry.decorator_list or registry.keywords:
        return False
    order, external = project.mro(registry)
    if external or any(
        any(
            getattr(item, "name", None)
            in {"__getitem__", "__setitem__", "__getattribute__", "__getattr__"}
            for item in cls.body
        )
        for _, cls in order
    ):
        return False
    native_dict = False
    for ancestor_unit, ancestor in order:
        definer = ancestor_unit.class_scopes[id(ancestor)].parent
        for base in ancestor.bases:
            values = project.values(
                ancestor_unit,
                definer,
                base.value if isinstance(base, ast.Subscript) else base,
            )
            native_dict |= bool(values) and all(
                value.kind == "ext" and value.name == "builtins.dict"
                for value in values
            )
    if not native_dict:
        return False
    scope = unit.class_scopes[id(registry)]
    for statement in registry.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)) or not isinstance(
            statement.value, ast.Dict
        ):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            continue
        table = targets[0].id
        if len(scope.binds.get(table, [])) != 1:
            continue
        contains = False
        for table_key, value in zip(statement.value.keys, statement.value.values):
            resolved = project.values(unit, scope, value)
            if not resolved or not all(item.kind == "cls" for item in resolved):
                continue
            if not any(item.node is dispatcher for item in resolved):
                continue
            kind = marker(dispatcher.body)
            contains |= (
                isinstance(table_key, ast.Constant) and table_key.value == kind
            ) or (
                isinstance(table_key, ast.Attribute)
                and table_key.attr == "engine_type"
                and bool(key_values := project.values(unit, scope, table_key.value))
                and all(
                    item.kind == "cls" and item.node is dispatcher
                    for item in key_values
                )
            )
        if not contains or _table_replaced(project, table):
            continue
        for method in registry.body:
            if not isinstance(method, ast.FunctionDef) or method.decorator_list:
                continue
            for call in ast.walk(method):
                if not isinstance(call, ast.Call) or not isinstance(
                    call.func, ast.Attribute
                ):
                    continue
                if (
                    not isinstance(call.func.value, ast.Name)
                    or len(call.args) != 1
                    or call.keywords
                ):
                    continue
                callback = call.args[0]
                if not isinstance(callback, ast.Attribute) or not _name(
                    callback.value, "self"
                ):
                    continue
                instance = _single_binding(unit, method, call.func.value.id, "assign")
                if instance is None or not isinstance(instance.value, ast.Call):
                    continue
                if unit.scope_of(call) is not unit.function_scopes[id(method)]:
                    continue
                factory_name = instance.value.func
                if not isinstance(factory_name, ast.Name):
                    continue
                factory = _single_binding(unit, method, factory_name.id, "assign")
                if factory is None or not isinstance(factory.value, ast.Call):
                    continue
                if not factory.node.lineno < instance.node.lineno <= call.lineno:
                    continue
                lookup = factory.value
                if (
                    not isinstance(lookup.func, ast.Attribute)
                    or lookup.func.attr != "get"
                    or not _attribute(lookup.func.value, "self", table)
                ):
                    continue
                if (
                    _callback_stores(project, registry, callback.attr)
                    and _initializer_calls_back(project, dispatcher, call.func.attr)
                    and _populator_called(project, registry, method)
                ):
                    return True
    return False


def _table_replaced(project, table):
    if project.attr_stores.get(table) or project.subscript_stores_by_name.get(table):
        return True
    for unit in project.units:
        if unit.is_test:
            continue
        if unit.attr_mutations.get(table) or unit.attr_escapes.get(table):
            return True
        for node, _ in unit.loads:
            if not isinstance(node, ast.Attribute) or node.attr != table:
                continue
            parent = unit.parents.get(id(node))
            if not isinstance(parent, ast.Attribute) or parent.attr != "get":
                return True
    return False
