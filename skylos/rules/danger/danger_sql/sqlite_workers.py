"""Prove SQLite fields initialized in a source-owned queue worker's run loop."""

import ast

from ..import_proof import provider_is_unshadowed
from ..module_namespace import has_mock_api_patching
from .sql_syntax import (
    _first,
    _load,
    _native_connect_arguments,
    _one,
    _own_nodes,
    _prior,
    _reachable,
)

_NATIVE_APIS = {
    "threading.Thread.__init__",
    "threading.Thread.start",
    "queue.Queue.get",
    "queue.Queue.put",
    "sqlite3.connect",
    "sqlite3.Connection.cursor",
    "sqlite3.Cursor.execute",
}
_ATTRIBUTE_WRITERS = {"builtins.setattr", "builtins.delattr"}
_MEMBER_WRITERS = _ATTRIBUTE_WRITERS | {
    "builtins.object.__setattr__",
    "builtins.object.__delattr__",
}


def _member(expr, receiver, name=None):
    return (
        isinstance(expr, ast.Attribute)
        and (name is None or expr.attr == name)
        and _load(expr.value, receiver)
    )


def _empty_call(expr):
    return isinstance(expr, ast.Call) and not (expr.args or expr.keywords)


def _expression(call, statements):
    return next(
        (
            stmt
            for stmt in statements
            if isinstance(stmt, ast.Expr) and stmt.value is call
        ),
        None,
    )


def _reachable_prefix(unit, expression, function):
    return _reachable(unit, expression, function) and not any(
        isinstance(statement, ast.While)
        and isinstance(statement.test, ast.Constant)
        and statement.test.value is True
        and not any(isinstance(node, ast.Break) for node in ast.walk(statement))
        for statement in _prior(unit, expression, function)
    )


def _synchronous(function):
    return not any(
        isinstance(node, (ast.Yield, ast.YieldFrom))
        for node in _own_nodes(function.body)
    )


def _field_store(unit, method, receiver, field):
    scope = unit.function_scopes[id(method)]
    result = [
        (target, value, statement)
        for target, value, statement, owner in unit.attribute_stores
        if owner is scope and _member(target, receiver, field)
    ]
    if len(result) != 1:
        return None
    target, value, statement = result[0]
    if (
        not isinstance(statement, ast.Assign)
        or statement.targets != [target]
        or statement not in method.body
        or not _reachable_prefix(unit, statement, method)
    ):
        return None
    return target, value, statement


def _method(cls, name):
    members = [part for part in cls.body if getattr(part, "name", None) == name]
    if len(members) != 1 or not isinstance(members[0], ast.FunctionDef):
        return None
    function = members[0]
    return (
        function
        if not function.decorator_list and _first(function) and _synchronous(function)
        else None
    )


def _start_site(unit, cls):
    for part in cls.body:
        if (
            not isinstance(part, ast.FunctionDef)
            or part.decorator_list
            or not _synchronous(part)
        ):
            continue
        for statement in part.body:
            if (
                isinstance(statement, ast.Expr)
                and _empty_call(statement.value)
                and _member(statement.value.func, _first(part), "start")
                and _reachable_prefix(unit, statement, part)
            ):
                return True
    return False


def _native_rebound(tracer):
    if any(tracer._external_rebound(name) for name in _NATIVE_APIS):
        return True
    project = tracer.project
    for name in ("setattr", "delattr"):
        for unit, call, scope in project.calls_by_name.get(name, ()):
            if (
                unit.is_test
                or len(call.args) != (3 if name == "setattr" else 2)
                or call.keywords
                or not tracer._external_call(unit, scope, call, _ATTRIBUTE_WRITERS)
            ):
                continue
            receiver, key = call.args[:2]
            field = (
                key.value
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
                else None
            )
            for value in project.values(unit, scope, receiver) or ():
                if value.kind not in {"ext", "extinst", "extattr"}:
                    continue
                prefix = f"{value.name}.{field}." if field else f"{value.name}."
                if any(f"{api}.".startswith(prefix) for api in _NATIVE_APIS):
                    return True
    return False


def _sentinel_branch(stmt, task):
    if not isinstance(stmt, ast.If) or stmt.orelse:
        return False
    test = stmt.test
    return (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and _load(test.left, task)
        and isinstance(test.comparators[0], ast.Constant)
        and isinstance(test.comparators[0].value, str)
        and isinstance(stmt.body[-1], ast.Break)
    )


def _queue_dispatch(tracer, unit, cls, run, dispatch):
    """Return the queue fields and shutdown subtree at a direct dispatch point."""
    if not _empty_call(dispatch) or not isinstance(dispatch.func, ast.Attribute):
        return None
    task = dispatch.func.value
    if not isinstance(task, ast.Name):
        return None
    loop = next(
        (
            stmt
            for stmt in run.body
            if isinstance(stmt, ast.While) and _expression(dispatch, stmt.body)
        ),
        None,
    )
    if (
        loop is None
        or not isinstance(loop.test, ast.Constant)
        or loop.test.value is not True
    ):
        return None
    preceding = loop.body[: loop.body.index(unit.parents[id(dispatch)])]
    if not preceding:
        return None
    read, *between = preceding
    if (
        not isinstance(read, ast.Assign)
        or len(read.targets) != 1
        or not _load(read.targets[0], task.id)
        or not _empty_call(read.value)
        or not isinstance(read.value.func, ast.Attribute)
        or read.value.func.attr != "get"
        or not _member(queue := read.value.func.value, _first(run))
        or not all(_sentinel_branch(stmt, task.id) for stmt in between)
        or not _reachable_prefix(unit, dispatch, run)
    ):
        return None
    scope = unit.function_scopes[id(run)]
    if len(scope.binds.get(task.id, ())) != 1:
        return None
    init = _method(cls, "__init__")
    store = init and _field_store(unit, init, _first(init), queue.attr)
    if not store:
        return None
    target, value, statement = store
    init_scope = unit.function_scopes[id(init)]
    if not (
        _empty_call(value)
        and tracer._external_call(unit, init_scope, value, {"queue.Queue"})
    ):
        return None
    for prefix in init.body[: init.body.index(statement)]:
        call = prefix.value if isinstance(prefix, ast.Expr) else None
        if (
            _empty_call(call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "__init__"
            and _empty_call(call.func.value)
            and tracer._external_call(
                unit, init_scope, call.func.value, {"builtins.super"}
            )
            and _reachable_prefix(unit, call, init)
        ):
            return queue.attr, target, loop, between
    return None


def _rebound(tracer, worker_unit, cls, fields, expected):
    project = tracer.project
    guarded = fields | {
        "__class__",
        "__dict__",
        "__getattribute__",
        "__setattr__",
        "__delattr__",
    }
    for field in guarded:
        for unit, target, _, _, scope in project.attr_stores.get(field, ()):
            if unit.is_test or target in expected:
                continue
            owners = project.values(unit, scope, target.value)
            if any(
                owner.kind in {"cls", "inst"} and owner.node is cls
                for owner in owners or ()
            ):
                return True
    frame = worker_unit.class_scopes[id(cls)]
    return bool((guarded - {"run", "__getattr__"}) & frame.binds.keys())


def _has_unsafe_use(tracer, unit, method, fields, expected_stores, allowed_close):
    scope = unit.function_scopes[id(method)]
    receiver = _first(method)
    if receiver is None:
        return False
    if len(scope.binds.get(receiver, ())) != 1:
        return True
    if any(
        node is not method
        and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        )
        and any(_load(nested, receiver) for nested in ast.walk(node))
        for node in ast.walk(method)
    ):
        return True
    aliases = {receiver}
    members = set()
    for node in _own_nodes(method.body):
        if isinstance(node, ast.Assign):
            expr = node.value
            names = {
                target.id for target in node.targets if isinstance(target, ast.Name)
            }
            if isinstance(expr, ast.Name) and expr.id in aliases:
                aliases.update(names)
            elif any(_member(expr, alias) for alias in aliases) and expr.attr in fields:
                members.update(names)
        if isinstance(node, ast.Attribute) and node not in expected_stores:
            if (
                node.attr == "__dict__"
                or isinstance(node.ctx, (ast.Store, ast.Del))
                and node.attr in fields
            ) and any(_member(node, alias) for alias in aliases):
                return True
            owner = node.value
            if isinstance(owner, ast.Attribute) and owner.attr == "connection":
                owner = owner.value
            if (
                node.attr == "close"
                and unit.parents.get(id(node)) not in allowed_close
                and (
                    any(_member(owner, alias) for alias in aliases)
                    and owner.attr in fields
                    or isinstance(owner, ast.Name)
                    and owner.id in members
                )
            ):
                return True
        if not isinstance(node, ast.Call):
            continue
        if any(
            any(_member(arg, alias) for alias in aliases)
            and arg.attr in fields
            or isinstance(arg, ast.Name)
            and arg.id in members
            for arg in (*node.args, *(keyword.value for keyword in node.keywords))
        ):
            return True
        if (
            node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in aliases
            and tracer._external_call(unit, scope, node, _MEMBER_WRITERS)
        ):
            key = node.args[1] if len(node.args) >= 2 else None
            if not isinstance(key, ast.Constant) or key.value in fields:
                return True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"__setattr__", "__delattr__"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in aliases
            and node.args
        ):
            key = node.args[0]
            if not isinstance(key, ast.Constant) or key.value in fields:
                return True
    return False


def native_worker_cursor(
    tracer, worker_unit, worker_run, dispatch, operation_unit, operation, sink
):
    """Check the receiver after a separate proof binds the registered callback.

    The caller supplies the exact dequeued invocation and the operation whose
    first argument receives that worker. The queue and its worker start must
    refer to standard-library objects, and field creation precedes dispatch.
    """
    if (
        not isinstance(worker_run, ast.FunctionDef)
        or not isinstance(operation, ast.FunctionDef)
        or not _synchronous(operation)
        or not isinstance(sink.func, ast.Attribute)
        or sink.func.attr != "execute"
        or not _member(cursor := sink.func.value, _first(operation))
        or not _reachable_prefix(operation_unit, sink, operation)
    ):
        return False
    project = tracer.project
    run_scope = worker_unit.function_scopes[id(worker_run)]
    owner_scope = run_scope.parent
    if owner_scope.kind != "class":
        return False
    cls = owner_scope.node
    if (
        cls.decorator_list
        or cls.keywords
        or len(cls.bases) != 1
        or _method(cls, "run") is not worker_run
        or not _start_site(worker_unit, cls)
        or not all(
            provider_is_unshadowed(name, worker_unit.path, project.root)
            for name in ("sqlite3", "queue", "threading")
        )
        or any(
            has_mock_api_patching(unit.tree) for unit in (worker_unit, operation_unit)
        )
    ):
        return False
    base = _one(project.values(worker_unit, owner_scope.parent, cls.bases[0]))
    if base is None or base.kind != "ext" or base.name != "threading.Thread":
        return False
    if _native_rebound(tracer):
        return False
    job = _queue_dispatch(tracer, worker_unit, cls, worker_run, dispatch)
    if not job:
        return False
    queue, queue_target, loop, shutdown = job
    worker = _first(worker_run)
    cursor_store = _field_store(worker_unit, worker_run, worker, cursor.attr)
    if not cursor_store:
        return False
    cursor_target, value, cursor_statement = cursor_store
    if (
        not _empty_call(value)
        or not isinstance(value.func, ast.Attribute)
        or value.func.attr != "cursor"
        or not _member(connection := value.func.value, worker)
    ):
        return False
    store = _field_store(worker_unit, worker_run, worker, connection.attr)
    if not store:
        return False
    connection_target, connect, connection_statement = store
    if not (
        worker_run.body.index(connection_statement)
        < worker_run.body.index(cursor_statement)
        < worker_run.body.index(loop)
        and isinstance(connect, ast.Call)
        and tracer._external_call(worker_unit, run_scope, connect, {"sqlite3.connect"})
        and _native_connect_arguments(connect)
    ):
        return False
    fields = {cursor.attr, connection.attr, queue, "run", "start", "__getattr__"}
    expected_stores = {cursor_target, connection_target, queue_target}
    if len(fields) != 6 or _rebound(
        tracer,
        worker_unit,
        cls,
        fields,
        expected_stores,
    ):
        return False
    allowed_close = {
        stmt.value
        for branch in shutdown
        for stmt in branch.body[:-1]
        if isinstance(stmt, ast.Expr)
        and _empty_call(stmt.value)
        and isinstance(stmt.value.func, ast.Attribute)
        and stmt.value.func.attr == "close"
        and _member(stmt.value.func.value, worker)
    }
    return not any(
        _has_unsafe_use(
            tracer, worker_unit, method, fields, expected_stores, allowed_close
        )
        for method in cls.body
        if isinstance(method, ast.FunctionDef)
    ) and not _has_unsafe_use(tracer, operation_unit, operation, fields, set(), set())
