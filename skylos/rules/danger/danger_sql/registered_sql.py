"""Bind registered SQL methods to a source-owned deferred worker."""

import ast
import threading

from .deferred_sql import _reflected_write, deferred_entry, row_argument
from .sql_syntax import _first, _load, _one, _own_nodes
from .sqlite_workers import native_worker_cursor


def _body(node):
    return (
        node.body[1:] if ast.get_docstring(node, clean=False) is not None else node.body
    )


def _method(project, cls, name):
    members = project.class_statements(cls).get(name, ())
    method = _one(members)
    if not isinstance(method, ast.FunctionDef):
        return None
    _, _, scope = project.class_info[id(cls)]
    return method if len(scope.binds.get(name, ())) == 1 else None


def _members_replaced(tracer, cls, names, *, initializers=()):
    project = tracer.project
    return _reflected_write(tracer, cls, names) or any(
        not unit.is_test
        and target not in initializers
        and any(
            value.kind in {"cls", "inst"} and value.node is cls
            for value in project.values(unit, scope, target.value) or ()
        )
        for name in names
        for unit, target, _, _, scope in project.attr_stores.get(name, ())
    )


def _attribute(node, owner, field=None):
    return (
        isinstance(node, ast.Attribute)
        and _load(node.value, owner)
        and (field is None or node.attr == field)
    )


def _parameters(method, count, *, forwarded=False):
    args = method.args
    positional = [*args.posonlyargs, *args.args]
    if (
        len(positional) != count
        or args.defaults
        or args.kwonlyargs
        or bool(args.vararg) != forwarded
        or bool(args.kwarg) != forwarded
    ):
        return None
    return tuple(arg.arg for arg in positional)


def _returned_registry(tracer, unit, worker):
    method = _method(tracer.project, worker, "__getattr__")
    if method is None or method.decorator_list:
        return None
    names = _parameters(method, 2)
    body = _body(method)
    if (
        not names
        or len(body) != 2
        or not isinstance(body[0], ast.For)
        or not isinstance(body[1], ast.Raise)
    ):
        return None
    loop = body[0]
    if (
        not isinstance(loop.target, ast.Name)
        or not _attribute(loop.iter, worker.name)
        or loop.orelse
        or len(loop.body) != 1
        or not isinstance(check := loop.body[0], ast.If)
        or check.orelse
        or len(check.body) != 1
        or not isinstance(result := check.body[0], ast.Return)
    ):
        return None
    scope = unit.function_scopes[id(method)]
    registry_owner = _one(tracer.project.values(unit, scope, loop.iter.value))
    if (
        registry_owner is None
        or registry_owner.kind != "cls"
        or registry_owner.node is not worker
    ):
        return None
    for call, builtin in ((check.test, "hasattr"), (result.value, "getattr")):
        if not (
            isinstance(call, ast.Call)
            and len(call.args) == 2
            and not call.keywords
            and _load(call.args[0], loop.target.id)
            and _load(call.args[1], names[1])
            and tracer._external_call(unit, scope, call, {f"builtins.{builtin}"})
        ):
            return None
    return loop.iter


def _registry_writer(tracer, unit, worker, method, field):
    if len(method.decorator_list) != 1 or not _parameters(method, 2):
        return None
    scope = unit.function_scopes[id(method)]
    decorator = _one(
        tracer.project.values(unit, scope.parent, method.decorator_list[0])
    )
    if (
        decorator is None
        or decorator.kind != "ext"
        or decorator.name != "builtins.classmethod"
    ):
        return None
    body = _body(method)
    if len(body) != 1 or not isinstance(body[0], ast.Expr):
        return None
    call = body[0].value
    arg = _parameters(method, 2)[1]
    if (
        isinstance(call, ast.Call)
        and len(call.args) == 1
        and _load(call.args[0], arg)
        and not call.keywords
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in {"append", "remove"}
        and _attribute(call.func.value, _first(method), field)
    ):
        return call
    return None


def _is_registered(tracer, unit, worker, operation_owner, operation):
    project = tracer.project
    if project.class_statements(worker).get(operation.name) or hasattr(
        threading.Thread, operation.name
    ):
        return False
    registry = _returned_registry(tracer, unit, worker)
    if registry is None or tracer._external_rebound("builtins.classmethod"):
        return False
    declaration = _one(project.class_statements(worker).get(registry.attr, ()))
    if (
        not isinstance(declaration, ast.Assign)
        or len(declaration.targets) != 1
        or not _load(declaration.targets[0], registry.attr)
        or not isinstance(declaration.value, ast.List)
        or declaration.value.elts
    ):
        return False
    writers = {}
    permitted = {registry}
    for member in worker.body:
        if isinstance(member, ast.FunctionDef) and (
            write := _registry_writer(tracer, unit, worker, member, registry.attr)
        ):
            writers[member.name] = (member, write.func.attr)
            permitted.add(write.func.value)
    if _reflected_write(tracer, worker, {registry.attr, *writers, operation.name}):
        return False
    registered = []
    registrations = set()
    for name, (method, action) in writers.items():
        calls = project.calls_by_name.get(name, ())
        for caller, call, scope in calls:
            target = _one(project.values(caller, scope, call.func))
            if target is None or target.node is not method:
                continue
            statement = caller.parents.get(id(call))
            if (
                action != "append"
                or caller is not unit
                or scope.kind != "module"
                or statement not in unit.tree.body
                or not isinstance(statement, ast.Expr)
                or len(call.args) != 1
                or call.keywords
            ):
                return False
            provider = _one(project.values(unit, scope, call.args[0]))
            if provider is None or provider.kind != "cls":
                return False
            argument = call.args[0]
            while isinstance(argument, ast.Attribute):
                argument = argument.value
            binding = (
                _one(scope.binds.get(argument.id, ()))
                if isinstance(argument, ast.Name)
                else None
            )
            if (
                binding is None
                or binding.node not in unit.tree.body
                or (binding.node.lineno, binding.node.col_offset)
                >= (call.lineno, call.col_offset)
            ):
                return False
            registrations.add(call.func)
            registered.append(((call.lineno, call.col_offset), provider.node))
    if (
        not registered
        or min(registered, key=lambda item: item[0])[1] is not operation_owner
    ):
        return False
    # References other than the exact lookup and writers can mutate the list.
    # Writer aliases could add or remove providers after a callback is selected.
    names = {registry.attr, operation.name, *writers}
    for member_unit in project.units:
        if member_unit.is_test:
            continue
        for ref in ast.walk(member_unit.tree):
            if (
                isinstance(ref, ast.Call)
                and len(ref.args) in (2, 3)
                and isinstance(ref.args[1], ast.Constant)
                and ref.args[1].value in names
            ):
                owner_scope = member_unit.scope_of(ref)
                if tracer._external_call(
                    member_unit, owner_scope, ref, {"builtins.getattr"}
                ) and any(
                    value.kind in {"cls", "inst"} and value.node is worker
                    for value in project.values(member_unit, owner_scope, ref.args[0])
                    or ()
                ):
                    return False
            if not isinstance(ref, ast.Attribute) or ref.attr not in names:
                continue
            if member_unit is unit and (ref in permitted or ref in registrations):
                continue
            values = project.values(member_unit, member_unit.scope_of(ref), ref.value)
            if (
                ref.attr != operation.name or not isinstance(ref.ctx, ast.Load)
            ) and any(
                value.kind in {"cls", "inst"} and value.node is worker
                for value in values or ()
            ):
                return False
    return True


def _job_fields(tracer, unit, job_class):
    init = _method(tracer.project, job_class, "__init__")
    special = {
        "__new__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__slots__",
        "__eq__",
        "__ne__",
    }
    if (
        init is None
        or init.decorator_list
        or job_class.decorator_list
        or job_class.bases
        or job_class.keywords
        or tracer.project.class_statements(job_class).keys() & special
        or _members_replaced(tracer, job_class, special | {"__init__"})
    ):
        return None
    names = _parameters(init, 2, forwarded=True)
    if not names:
        return None
    parameter_fields = {names[1], init.args.vararg.arg, init.args.kwarg.arg}
    fields = {}
    targets = {}
    scope = unit.function_scopes[id(init)]
    for stmt in _body(init):
        if not (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and _attribute(target := stmt.targets[0], names[0])
            and target.attr not in targets
        ):
            return None
        if tracer.project.class_statements(job_class).get(target.attr):
            return None
        targets[target.attr] = (target, stmt.value)
        if isinstance(stmt.value, ast.Name) and stmt.value.id in parameter_fields:
            if stmt.value.id in fields:
                return None
            fields[stmt.value.id] = target.attr
        elif isinstance(stmt.value, ast.Call):
            if (
                stmt.value.args
                or stmt.value.keywords
                or not tracer._external_call(
                    unit, scope, stmt.value, {"threading.Event", "inspect.currentframe"}
                )
            ):
                return None
        elif not isinstance(stmt.value, ast.Constant):
            return None
    if fields.keys() != parameter_fields:
        return None
    return (
        tuple(
            fields[name]
            for name in (names[1], init.args.vararg.arg, init.args.kwarg.arg)
        ),
        targets,
        scope,
    )


def _job_operation(tracer, unit, job_class, name, fields, initializers):
    method = _method(tracer.project, job_class, name)
    if (
        method is None
        or method.decorator_list
        or not _parameters(method, 1)
        or any(
            isinstance(node, (ast.Yield, ast.YieldFrom))
            for node in _own_nodes(method.body)
        )
        or name in initializers
        or _members_replaced(
            tracer,
            job_class,
            {name, *fields},
            initializers={assignment for assignment, _ in initializers.values()},
        )
    ):
        return False
    body = _body(method)
    if body and isinstance(body[0], ast.Try):
        body = body[0].body
    if not body:
        return False
    statement = body[0]
    self_name = _first(method)
    if isinstance(statement, ast.Assign):
        if (
            len(statement.targets) != 1
            or not _attribute(statement.targets[0], self_name)
            or statement.targets[0].attr in fields
        ):
            return False
    elif not isinstance(statement, (ast.Return, ast.Expr)):
        return False
    call = statement.value
    callback, args, kwargs = fields
    return (
        isinstance(call, ast.Call)
        and _attribute(call.func, self_name, callback)
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Starred)
        and _attribute(call.args[0].value, self_name, args)
        and len(call.keywords) == 1
        and call.keywords[0].arg is None
        and _attribute(call.keywords[0].value, self_name, kwargs)
    )


def _scheduler(tracer, entry):
    unit, worker = entry.worker_unit, entry.worker_class
    project = tracer.project
    method = _method(project, worker, entry.scheduler_name)
    if (
        method is None
        or method.decorator_list
        or _members_replaced(tracer, worker, {method.name})
        or tracer._external_rebound("queue.Queue.put")
    ):
        return None
    names = _parameters(method, 2, forwarded=True)
    body = _body(method)
    if not names or len(body) < 3:
        return None
    worker_arg, callback_arg = names
    args_arg, kwargs_arg = method.args.vararg.arg, method.args.kwarg.arg
    prepend, build, send, *tail = body
    if not (
        isinstance(prepend, ast.Assign)
        and len(prepend.targets) == 1
        and _load(prepend.targets[0], args_arg)
        and isinstance(prepend.value, ast.BinOp)
        and isinstance(prepend.value.op, ast.Add)
        and isinstance(prepend.value.left, ast.Tuple)
        and len(prepend.value.left.elts) == 1
        and _load(prepend.value.left.elts[0], worker_arg)
        and _load(prepend.value.right, args_arg)
        and isinstance(build, ast.Assign)
        and len(build.targets) == 1
        and isinstance(job := build.targets[0], ast.Name)
        and isinstance(construct := build.value, ast.Call)
        and len(construct.args) == 2
        and _load(construct.args[0], callback_arg)
        and isinstance(construct.args[1], ast.Starred)
        and _load(construct.args[1].value, args_arg)
        and len(construct.keywords) == 1
        and construct.keywords[0].arg is None
        and _load(construct.keywords[0].value, kwargs_arg)
        and isinstance(send, ast.Expr)
        and isinstance(put := send.value, ast.Call)
        and isinstance(put.func, ast.Attribute)
        and put.func.attr == "put"
        and _attribute(put.func.value, worker_arg)
        and len(put.args) == 1
        and _load(put.args[0], job.id)
        and not put.keywords
    ):
        return None
    scope = unit.function_scopes[id(method)]
    provider = _one(project.values(unit, scope, construct.func))
    if provider is None or provider.kind != "cls":
        return None
    job_fields = _job_fields(tracer, provider.unit, provider.node)
    if job_fields is None:
        return None
    fields, initializers, init_scope = job_fields
    if tail and isinstance(tail[-1], ast.Return):
        if not _attribute(tail[-1].value, job.id) or tail[-1].value.attr in fields:
            return None
        tail = tail[:-1]
    if tail:
        if (
            len(tail) != 1
            or not isinstance(tail[0], ast.Expr)
            or not isinstance(wait := tail[0].value, ast.Call)
            or not _attribute(wait.func, job.id)
            or wait.args
            or wait.keywords
        ):
            return None
        wait_method = _method(project, provider.node, wait.func.attr)
        if (
            wait_method is None
            or wait_method.decorator_list
            or not _parameters(wait_method, 1)
            or wait_method.name in initializers
            or _members_replaced(tracer, provider.node, {wait_method.name})
        ):
            return None
        statements = _body(wait_method)
        if (
            len(statements) != 1
            or not isinstance(statements[0], ast.Expr)
            or not isinstance(await_event := statements[0].value, ast.Call)
            or not isinstance(await_event.func, ast.Attribute)
            or await_event.func.attr != "wait"
            or await_event.args
            or await_event.keywords
            or not _attribute(await_event.func.value, _first(wait_method))
            or not isinstance(
                initial := initializers.get(await_event.func.value.attr, (None, None))[
                    1
                ],
                ast.Call,
            )
            or not tracer._external_call(
                provider.unit, init_scope, initial, {"threading.Event"}
            )
        ):
            return None
    return put.func.value.attr, provider, fields, initializers


def _dispatches(unit, method, queue):
    worker_arg = _first(method)
    scope = unit.function_scopes[id(method)]
    for call, caller in unit.calls:
        if (
            caller is not scope
            or not isinstance(call.func, ast.Attribute)
            or not isinstance(item := call.func.value, ast.Name)
            or call.args
            or call.keywords
        ):
            continue
        binding = _one(scope.binds.get(item.id, ()))
        read = binding.value if binding and binding.kind == "assign" else None
        if (
            isinstance(read, ast.Call)
            and isinstance(read.func, ast.Attribute)
            and read.func.attr == "get"
            and _attribute(read.func.value, worker_arg, queue)
        ):
            yield call


def registered_sql_structure(tracer, unit, scope, sink, operand):
    """Return caller control evidence for an exact registered SQLite operation."""
    if scope.parent is None or scope.parent.kind != "class":
        return None
    operation, owner = scope.node, scope.parent.node
    if (
        owner.bases
        or owner.decorator_list
        or owner.keywords
        or _method(tracer.project, owner, operation.name) is not operation
        or _members_replaced(tracer, owner, {operation.name})
    ):
        return None
    if not isinstance(sink, ast.Call) or not isinstance(sink.func, ast.Attribute):
        return None
    if not _attribute(sink.func.value, _first(operation)):
        return None
    if (path := row_argument(tracer, unit, scope, operand, sink)) is None:
        return None
    entry = deferred_entry(tracer, unit, scope)
    if entry is None or not _is_registered(
        tracer, entry.worker_unit, entry.worker_class, owner, operation
    ):
        return None
    scheduler = _scheduler(tracer, entry)
    run = _method(tracer.project, entry.worker_class, "run")
    if scheduler is None or run is None:
        return None
    queue, provider, fields, initializers = scheduler
    dispatch = _one(tuple(_dispatches(entry.worker_unit, run, queue)))
    if dispatch is None or not _job_operation(
        tracer, provider.unit, provider.node, dispatch.func.attr, fields, initializers
    ):
        return None
    if not native_worker_cursor(
        tracer, entry.worker_unit, run, dispatch, unit, operation, sink
    ):
        return None
    return path
