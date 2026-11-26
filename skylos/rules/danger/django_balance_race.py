"""Review guarded decrements written back from a stale Django model instance."""

import ast
from pathlib import Path

from .danger_fs.path_provenance import _ResolutionLimit
from .project_security_sources import security_project_from_snapshot, wheel_source_roots
from .project_source import project_source_snapshot

_NUMERIC_FIELDS = {
    f"django.db.models.{name}Field"
    for name in (
        "Decimal",
        "Integer",
        "BigInteger",
        "SmallInteger",
        "PositiveInteger",
        "PositiveBigInteger",
        "PositiveSmallInteger",
    )
}
_ATOMIC = "django.db.transaction.atomic"
_VIEW_DECORATORS = {
    _ATOMIC,
    "django.views.decorators.http.require_POST",
    "django.contrib.auth.decorators.login_required",
}


def _amount(node, parameters):
    return (isinstance(node, ast.Name) and node.id in parameters) or (
        isinstance(node, ast.Constant) and type(node.value) is int and node.value > 0
    )


def _checked_write(body, row, parameters):
    guard = body[1]
    if not isinstance(guard, ast.If):
        return None
    match guard.test:
        case ast.Compare(left=left, ops=[op], comparators=[right]):
            pass
        case _:
            return None
    for field, amount, insufficient, sufficient in (
        (left, right, ast.Lt, ast.GtE),
        (right, left, ast.Gt, ast.LtE),
    ):
        if not (
            isinstance(field, ast.Attribute)
            and isinstance(field.value, ast.Name)
            and field.value.id == row
            and _amount(amount, parameters)
        ):
            continue
        if (
            isinstance(op, insufficient)
            and not guard.orelse
            and len(guard.body) == 1
            and isinstance(guard.body[0], (ast.Return, ast.Raise))
        ):
            return field.attr, amount, body[2:]
        if isinstance(op, sufficient):
            return field.attr, amount, guard.body
    return None


def _decrement(body, parameters):
    if len(body) < 2:
        return None
    read, guard = body[:2]
    match read:
        case ast.Assign(
            targets=[ast.Name(id=row)],
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Attribute(value=model, attr="objects"), attr="get"
                ),
                args=[],
                keywords=filters,
            ),
        ) if filters and all(
            kw.arg and isinstance(kw.value, (ast.Name, ast.Constant)) for kw in filters
        ):
            pass
        case _:
            return None
    checked = _checked_write(body, row, parameters)
    if checked is None:
        return None
    field, amount, writes = checked
    if len(writes) < 2:
        return None
    change, write = writes[:2]
    match change:
        case ast.AugAssign(
            target=ast.Attribute(value=ast.Name(id=changed), attr=changed_field),
            op=ast.Sub(),
            value=spent,
        ) if (changed, changed_field) == (row, field):
            pass
        case ast.Assign(
            targets=[ast.Attribute(value=ast.Name(id=changed), attr=changed_field)],
            value=ast.BinOp(
                left=ast.Attribute(value=ast.Name(id=loaded), attr=loaded_field),
                op=ast.Sub(),
                right=spent,
            ),
        ) if (changed, changed_field) == (loaded, loaded_field) == (row, field):
            pass
        case _:
            return None
    if ast.dump(spent) != ast.dump(amount):
        return None
    match write:
        case ast.Expr(
            value=ast.Call(
                func=ast.Attribute(value=ast.Name(id=saved), attr="save"),
                args=[],
                keywords=options,
            )
        ) if saved == row:
            if not options or (
                len(options) == 1
                and options[0].arg == "update_fields"
                and isinstance(options[0].value, (ast.List, ast.Tuple))
                and all(
                    isinstance(item, ast.Constant) and isinstance(item.value, str)
                    for item in options[0].value.elts
                )
                and any(item.value == field for item in options[0].value.elts)
            ):
                return model, field, read, guard, write
    return None


def _external(project, unit, node):
    refs = project.values(unit, unit.scope_of(node), node)
    if refs and len(refs) == 1:
        ref = next(iter(refs))
        if ref.kind == "ext":
            return ref.name
    return None


def _registered_views(project):
    registered = set()
    for unit in project.units:
        if unit.is_test or unit.path.name != "urls.py" or unit.star_import:
            continue
        for stmt in unit.tree.body:
            match stmt:
                case ast.Assign(
                    targets=[ast.Name(id="urlpatterns")],
                    value=ast.List(elts=entries) | ast.Tuple(elts=entries),
                ):
                    pass
                case _:
                    continue
            # An overwritten or dynamically assembled route table is ambiguous.
            if (
                stmt is not unit.tree.body[-1]
                or len(unit.module.binds.get("urlpatterns", ())) != 1
            ):
                continue
            for entry in entries:
                if (
                    not isinstance(entry, ast.Call)
                    or len(entry.args) < 2
                    or _external(project, unit, entry.func)
                    not in {"django.urls.path", "django.urls.re_path"}
                ):
                    continue
                refs = project.values(unit, unit.module, entry.args[1])
                if refs and len(refs) == 1:
                    ref = next(iter(refs))
                    if ref.kind == "fn":
                        registered.add(ref.node)
    return registered


def _display_metadata(node):
    if node.name != "Meta" or node.bases or node.keywords or node.decorator_list:
        return False
    for statement in node.body:
        match statement:
            case ast.Assign(
                targets=[ast.Name(id=name)], value=ast.Constant(value=str())
            ) if name in {
                "verbose_name",
                "verbose_name_plural",
                "db_table_comment",
            }:
                continue
            case ast.Assign(
                targets=[ast.Name(id="ordering")],
                value=ast.List(elts=items) | ast.Tuple(elts=items),
            ) if all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in items
            ):
                continue
            case _:
                return False
    return True


def _ordinary_model_field(project, unit, receiver, field):
    refs = project.values(unit, unit.scope_of(receiver), receiver)
    if not refs or len(refs) != 1:
        return False
    model = next(iter(refs))
    if (
        model.kind != "cls"
        or len(model.node.bases) != 1
        or model.node.decorator_list
        or model.node.keywords
    ):
        return False
    if _external(project, model.unit, model.node.bases[0]) != "django.db.models.Model":
        return False
    found = False
    for stmt in model.node.body:
        match stmt:
            case ast.Assign(
                targets=[ast.Name(id=name)], value=ast.Call(func=constructor)
            ):
                provider = _external(project, model.unit, constructor) or ""
                if (
                    not provider.startswith("django.db.models.")
                    or not provider.endswith("Field")
                    or name in {"save", "objects"}
                ):
                    return False
                if name == field:
                    found = provider in _NUMERIC_FIELDS
            case ast.Expr(value=ast.Constant(value=str())) | ast.Pass():
                pass
            case ast.FunctionDef(
                name="__str__",
                decorator_list=[],
                args=ast.arguments(defaults=[], kw_defaults=[]),
            ):
                # The framework does not call __str__ to load or save this row.
                pass
            case ast.ClassDef() if _display_metadata(stmt):
                pass
            case _:
                # Custom save hooks, managers, or model metadata can change the write.
                return False
    if found:
        for name in ("save", "objects"):
            for writer, target, _, _, scope in project.attr_stores.get(name, ()):
                if writer.is_test:
                    continue
                if model in (project.values(writer, scope, target.value) or ()):
                    return False
    return found


def _candidate(view):
    # Unknown operations before the read may already hold a database or
    # application lock. Only open a transaction scope we can later resolve.
    body = view.body[1:] if ast.get_docstring(view) is not None else view.body
    if not body:
        return None
    context = None
    if isinstance(body[0], ast.With) and len(body[0].items) == 1:
        expr = body[0].items[0].context_expr
        if not isinstance(expr, ast.Call):
            return None
        context = expr
        body = body[0].body
    parameters = {
        arg.arg
        for arg in (*view.args.posonlyargs, *view.args.args, *view.args.kwonlyargs)
    }
    start = 0
    for statement in body:
        match statement:
            case ast.Assign(targets=[ast.Name(id=name)], value=value) if _amount(
                value, parameters
            ):
                parameters.add(name)
                start += 1
            case _:
                break
    result = _decrement(body[start:], parameters)
    return (context, *result) if result else None


def _default_connection(args, keywords):
    if not args and not keywords:
        return True
    if not args and len(keywords) == 1 and keywords[0].arg == "using":
        args = [keywords[0].value]
    elif keywords:
        return False
    return (
        len(args) == 1
        and isinstance(args[0], ast.Constant)
        and args[0].value in (None, "default")
    )


def _uses_default_write_and_rollback(project):
    """Require an ordinary default write and unmodified transaction helpers."""
    state_attrs = {"routers", "atomic", "set_rollback", "HttpResponse"}
    if any(
        not writer.is_test
        for name in state_attrs
        for writer, *_ in project.attr_stores.get(name, ())
    ):
        return False
    for unit in project.units:
        if unit.is_test:
            continue
        for node in ast.walk(unit.tree):
            if isinstance(node, ast.Name) and node.id == "DATABASES":
                parent = unit.parents.get(id(node))
                if (
                    isinstance(parent, ast.Assign)
                    and parent.targets == [node]
                    and isinstance(parent.value, ast.Dict)
                    and len(parent.value.keys) == 1
                    and isinstance(parent.value.keys[0], ast.Constant)
                    and parent.value.keys[0].value == "default"
                ):
                    continue
                return False
            match node:
                case (
                    ast.Name(id="DATABASE_ROUTERS")
                    | ast.Attribute(attr="DATABASES" | "DATABASE_ROUTERS")
                ):
                    return False
                case (
                    ast.keyword(arg="DATABASES" | "DATABASE_ROUTERS")
                    | ast.Constant(value="DATABASES" | "DATABASE_ROUTERS")
                ):
                    return False
                case ast.FunctionDef(name="db_for_write" | "db_for_read"):
                    return False
                case ast.Call(
                    func=ast.Name(id="setattr" | "delattr"),
                    args=[_, ast.Constant(value=attr), *_],
                ) if attr in state_attrs:
                    return False
    return True


def _preview_rolled_back(project, unit, view, context, write):
    # Stay on the path that saved this instance. A statement after a branch or
    # transaction can undo a rollback decision or issue another save.
    tail = []
    child = write
    for parent in unit.ancestors(write):
        if (
            not isinstance(parent, (ast.If, ast.With, ast.FunctionDef))
            or child not in parent.body
        ):
            return False
        tail.extend(parent.body[parent.body.index(child) + 1 :])
        if child is write and not tail:
            return False  # A later rollback may be outside this transaction.
        if parent is view:
            break
        child = parent
    if not tail or not isinstance(tail[0], ast.Expr):
        return False
    rollback = tail[0].value
    if not (
        isinstance(rollback, ast.Call)
        and rollback.args
        and isinstance(rollback.args[0], ast.Constant)
        and rollback.args[0].value is True
        and _default_connection(rollback.args[1:], rollback.keywords)
        and _external(project, unit, rollback.func)
        == "django.db.transaction.set_rollback"
    ):
        return False
    match tail[1:]:
        case [] | [ast.Return(value=None | ast.Constant())]:
            pass
        case [
            ast.Return(value=ast.Call(func=make_response, args=args, keywords=kws))
        ] if (
            _external(project, unit, make_response) == "django.http.HttpResponse"
            and all(isinstance(arg, ast.Constant) for arg in args)
            and all(kw.arg and isinstance(kw.value, ast.Constant) for kw in kws)
        ):
            pass
        case _:
            return False
    # The rollback and save must share an atomic block on the default connection.
    scopes = [context] if context is not None else view.decorator_list
    for scope in scopes:
        func = scope.func if isinstance(scope, ast.Call) else scope
        if _external(project, unit, func) == _ATOMIC and (
            not isinstance(scope, ast.Call)
            or _default_connection(scope.args, scope.keywords)
        ):
            return _uses_default_write_and_rollback(project)
    return False


def scan(tree, file_path, findings, *, project_root=None):
    if not project_root or not any(
        _candidate(node) for node in tree.body if isinstance(node, ast.FunctionDef)
    ):
        return
    root = Path(project_root).resolve()
    snapshot, complete = project_source_snapshot(root)
    if not complete:
        return
    try:
        project = security_project_from_snapshot(
            root, wheel_source_roots(root), tuple(snapshot.items())
        )
        unit = project.by_path.get(Path(file_path).resolve())
        if (
            unit is None
            or unit.is_test
            or unit.star_import
            or ast.dump(unit.tree, include_attributes=True)
            != ast.dump(tree, include_attributes=True)
        ):
            return
        registered = _registered_views(project)
        for view in unit.tree.body:
            if view not in registered:
                continue
            if any(
                _external(project, unit, dec.func if isinstance(dec, ast.Call) else dec)
                not in _VIEW_DECORATORS
                for dec in view.decorator_list
            ):
                continue
            candidate = _candidate(view)
            if candidate is None:
                continue
            context, model, field, read, guard, write = candidate
            if (
                context is not None
                and _external(project, unit, context.func) != _ATOMIC
            ):
                continue
            if not _ordinary_model_field(project, unit, model, field):
                continue
            if _preview_rolled_back(project, unit, view, context, write):
                continue
            findings.append(
                {
                    "rule_id": "SKY-D385",
                    "severity": "MEDIUM",
                    "file": str(file_path),
                    "symbol": view.name,
                    "line": write.lineno,
                    "col": write.col_offset,
                    "message": (
                        f"Django view checks {field} at line {guard.lineno} and saves a "
                        f"decrement based on the row read at line {read.lineno}. "
                        "Concurrent writes can lose a decrement. Review locking or use a "
                        "database update conditional on the remaining amount."
                    ),
                }
            )
    except (_ResolutionLimit, RecursionError):
        security_project_from_snapshot.cache_clear()
