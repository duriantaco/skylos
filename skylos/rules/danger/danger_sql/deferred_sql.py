"""Source proofs for argument-preserving deferred SQL method decorators."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ..danger_fs.path_provenance import PARAMETER, _Unit
from ..module_namespace import attribute_write_names, has_mock_api_patching
from .sql_syntax import _prior, _reachable


@dataclass(frozen=True)
class DeferredEntry:
    worker_unit: _Unit
    worker_class: ast.ClassDef
    scheduler_name: str
    decorator: ast.expr
    initializer_call: ast.Call


def _one(values):
    return next(iter(values)) if values and len(values) == 1 else None


def _name(node, value):
    return isinstance(node, ast.Name) and node.id == value


def _body(node):
    body = node.body
    if ast.get_docstring(node, clean=False) is not None:
        return body[1:]
    return body


def _parameter_names(fn, count):
    args = fn.args
    if args.vararg or args.kwarg or args.kwonlyargs or args.defaults:
        return None
    formals = [*args.posonlyargs, *args.args]
    return [arg.arg for arg in formals] if len(formals) == count else None


def _native_decorator(tracer, unit, fn, expected):
    if len(fn.decorator_list) != 1:
        return False
    scope = unit.function_scopes[id(fn)].parent
    provider = _one(tracer.project.values(unit, scope, fn.decorator_list[0]))
    return (
        provider is not None
        and provider.kind == "ext"
        and provider.name == expected
        and not tracer._external_rebound(expected)
    )


def _forwarded_call(tracer, unit, decorator):
    names = _parameter_names(decorator, 2)
    body = _body(decorator)
    if (
        not names
        or len(body) != 2
        or not isinstance(body[0], ast.FunctionDef)
        or not isinstance(body[1], ast.Return)
        or not _name(body[1].value, body[0].name)
    ):
        return None
    wrapper = body[0]
    args = wrapper.args
    if (
        args.posonlyargs
        or args.args
        or args.kwonlyargs
        or not args.vararg
        or not args.kwarg
    ):
        return None
    if not _native_decorator(tracer, unit, wrapper, "builtins.staticmethod"):
        return None
    statements = _body(wrapper)
    if len(statements) != 1 or not isinstance(statements[0], ast.Return):
        return None
    call = statements[0].value
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Attribute)
        and _name(call.func.value.value, names[0])
        and len(call.args) == 2
        and _name(call.args[0], names[1])
        and isinstance(call.args[1], ast.Starred)
        and _name(call.args[1].value, args.vararg.arg)
        and len(call.keywords) == 1
        and call.keywords[0].arg is None
        and _name(call.keywords[0].value, args.kwarg.arg)
    ):
        return None
    return call.func.value.attr, call.func.attr


def _slot_setter(tracer, cls, slot, decorator_name):
    project = tracer.project
    stores = []
    for unit, target, value, statement, scope in project.attr_stores.get(slot, ()):
        owners = project.values(unit, scope, target.value)
        if any(owner.kind == "cls" and owner.node is cls for owner in owners or ()):
            stores.append((unit, target, value, statement, scope))
    if len(stores) != 1:
        return None
    unit, target, value, stmt, scope = stores[0]
    fn = scope.node
    if (
        not isinstance(fn, ast.FunctionDef)
        or scope.parent.node is not cls
        or _body(fn) != [stmt]
    ):
        return None
    params = _parameter_names(fn, 2)
    if (
        params is None
        or not _name(target.value, params[0])
        or not _name(value, params[1])
    ):
        return None
    if not _native_decorator(tracer, unit, fn, "builtins.classmethod"):
        return None
    writes, computed = attribute_write_names(
        unit.tree, isolated_writes=frozenset({id(target)})
    )
    if (
        computed
        or writes & {slot, fn.name, decorator_name}
        or has_mock_api_patching(unit.tree)
        or _reflected_write(tracer, cls, {slot, fn.name, decorator_name})
    ):
        return None
    for member in (fn.name, decorator_name):
        for writer, attr, _, _, owner_scope in project.attr_stores.get(member, ()):
            if any(
                owner.kind in {"cls", "inst"} and owner.node is cls
                for owner in project.values(writer, owner_scope, attr.value) or ()
            ):
                return None
    return fn


def _reflected_write(tracer, cls, members):
    project = tracer.project
    native = {"builtins.setattr", "builtins.delattr"}
    names = {"setattr", "delattr"}
    for unit in project.units:
        for node in unit.tree.body:
            if (
                isinstance(node, ast.ImportFrom)
                and not node.level
                and node.module == "builtins"
            ):
                names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name in {"setattr", "delattr"}
                )
    for name in names:
        for unit, call, scope in project.calls_by_name.get(name, ()):
            if (
                unit.is_test
                or len(call.args) < 2
                or not tracer._external_call(unit, scope, call, native)
            ):
                continue
            owner, key = call.args[:2]
            targets = project.values(unit, scope, owner) or ()
            if any(value.kind == "cls" and value.node is cls for value in targets) and (
                not isinstance(key, ast.Constant) or key.value in members
            ):
                return True
    return False


def _worker_instance(project, setter_unit, setter):
    sites = project.call_sites(setter_unit, setter)
    if sites.possible or sites.entries or (site := _one(sites.resolved)) is None:
        return None
    unit, call, scope = site.unit, site.call, site.scope
    fn = scope.node
    if (
        not isinstance(fn, ast.FunctionDef)
        or fn.name != "__init__"
        or fn.decorator_list
        or not site.skip_first
        or not isinstance(call, ast.Call)
    ):
        return None
    args = [*fn.args.posonlyargs, *fn.args.args]
    statement = unit.parents.get(id(call))
    if (
        not args
        or not isinstance(statement, ast.Expr)
        or statement not in fn.body
        or len(call.args) != 1
        or call.keywords
        or not _name(call.args[0], args[0].arg)
        or _unique_argument(unit, scope, call.args[0], "param") is None
        or not _reachable(unit, call, fn)
        or unit.is_test
    ):
        return None
    receiver = _one(project.values(unit, scope, call.args[0]))
    if (
        receiver is None
        or receiver.kind != "inst"
        or receiver.node is not scope.parent.node
    ):
        return None
    return receiver.unit, receiver.node, call


def deferred_entry(tracer, method_unit, method_scope):
    """Resolve a classmethod decorator that forwards its callable and arguments."""
    fn = method_scope.node
    if (
        not isinstance(fn, ast.FunctionDef)
        or len(fn.decorator_list) != 1
        or method_scope.parent.kind != "class"
    ):
        return None
    expr = fn.decorator_list[0]
    value = _one(tracer.project.values(method_unit, method_scope.parent, expr))
    if (
        value is None
        or value.kind != "fn"
        or not value.bound
        or not isinstance(value.node, ast.FunctionDef)
    ):
        return None
    decorator, unit = value.node, value.unit
    owner_scope = unit.function_scopes[id(decorator)].parent
    owner = owner_scope.node
    if (
        not isinstance(owner, ast.ClassDef)
        or owner.bases
        or owner.keywords
        or owner.decorator_list
        or unit.star_import
        or unit.rebinding()[0]
    ):
        return None
    if not _native_decorator(tracer, unit, decorator, "builtins.classmethod"):
        return None
    if (forward := _forwarded_call(tracer, unit, decorator)) is None:
        return None
    slot, scheduler = forward
    fields = owner_scope.binds.get(slot, ())
    if (
        len(fields) != 1
        or fields[0].kind != "assign"
        or not isinstance(fields[0].value, ast.Constant)
        or fields[0].value.value is not None
    ):
        return None
    setter = _slot_setter(tracer, owner, slot, decorator.name)
    if (
        setter is None
        or (worker := _worker_instance(tracer.project, unit, setter)) is None
    ):
        return None
    worker_unit, worker_class, initializer = worker
    return DeferredEntry(worker_unit, worker_class, scheduler, expr, initializer)


def _unique_argument(unit, scope, expr, kind):
    if not isinstance(expr, ast.Name):
        return None
    found = unit.lookup(scope, expr.id)
    if (
        found is None
        or found[0] is not scope
        or len(found[1]) != 1
        or found[1][0].kind != kind
    ):
        return None
    return found[1][0]


def _row_projection(unit, scope, expr):
    assignment = _unique_argument(unit, scope, expr, "assign")
    if assignment is not None:
        if assignment.node not in set(_prior(unit, expr, scope.node)):
            return None
        for ref, use_scope in unit.loads:
            if ref is expr or not _name(ref, expr.id) or ref.lineno > expr.lineno:
                continue
            owner = unit.lookup(use_scope, expr.id)
            if owner is not None and owner[0] is scope:
                return None
        expr = assignment.value
    if not (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "join"
        and isinstance(expr.func.value, ast.Constant)
        and isinstance(expr.func.value.value, str)
        and not expr.keywords
        and len(expr.args) == 1
        and isinstance(generator := expr.args[0], (ast.GeneratorExp, ast.ListComp))
        and len(generator.generators) == 1
        and isinstance(element := generator.elt, ast.Subscript)
        and isinstance(element.slice, ast.Constant)
        and type(element.slice.value) is int
    ):
        return None
    clause = generator.generators[0]
    if (
        clause.ifs
        or clause.is_async
        or not isinstance(clause.target, ast.Name)
        or not _name(element.value, clause.target.id)
    ):
        return None
    return (
        clause.iter
        if _unique_argument(unit, scope, clause.iter, "param") is not None
        else None
    )


def _unmodified_rows(unit, scope, parameter, sink):
    """Allow earlier ordinary SQLite value binding on the same receiver."""
    for ref, use_scope in unit.loads:
        if ref is parameter or not _name(ref, parameter.id) or ref.lineno > sink.lineno:
            continue
        owner = unit.lookup(use_scope, parameter.id)
        if owner is None or owner[0] is not scope:
            continue
        call = unit.parents.get(id(ref))
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "executemany"
            and len(call.args) == 2
            and call.args[1] is ref
            and not call.keywords
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
            and ast.dump(call.func.value) == ast.dump(sink.func.value)
        ):
            continue
        return False
    return True


def row_argument(tracer, unit, scope, operand, sink):
    """Return the projected row parameter and its exact SQL operand trace."""
    if (
        not isinstance(sink.func, ast.Attribute)
        or not isinstance(operand, ast.JoinedStr)
        or not _reachable(unit, sink, scope.node)
    ):
        return None
    evidence = tracer.trace(unit, scope, operand, (id(scope.node), None, None))
    for part in operand.values:
        if (
            not isinstance(part, ast.FormattedValue)
            or part.conversion not in {-1, 115}
            or part.format_spec is not None
        ):
            continue
        parameter = _row_projection(unit, scope, part.value)
        if parameter is None or not _unmodified_rows(unit, scope, parameter, sink):
            continue
        chains = [
            chain for chain in evidence.chains[PARAMETER] if chain[0] == parameter.id
        ]
        if chains:
            return parameter.id, chains[0]
    return None
