"""Resolve a Django form's initial field value through a source-defined registry."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .danger_sql.sql_syntax import _reachable, _valid_call
from .django_field_providers import (
    django_field_is_available,
    form_base_preserves_scalar_read,
)
from .import_proof import provider_binding_is_stable
from .oslo_config_options import (
    _body,
    _imports_at_startup,
    _literal,
    _method_args,
    _name,
)


def _method(cls, name):
    members = [s for s in cls.body if isinstance(s, ast.FunctionDef) and s.name == name]
    return members[0] if len(members) == 1 and not members[0].decorator_list else None


def _returned(fn):
    return fn.body[-1].value if fn and isinstance(fn.body[-1], ast.Return) else None


def _assignment(stmt):
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        return stmt.targets[0], stmt.value
    return None, None


def _access(expr):
    """Split a field/map read into its base and ordered attribute or index selectors."""
    parts = []
    while isinstance(expr, (ast.Subscript, ast.Attribute)):
        if isinstance(expr, ast.Attribute):
            parts.append(("attr", expr.attr))
        elif isinstance(expr.slice, ast.Name):
            parts.append(("name", expr.slice.id))
        elif isinstance(expr.slice, ast.Constant) and isinstance(expr.slice.value, str):
            parts.append(("key", expr.slice.value))
        else:
            break
        expr = expr.value
    return expr, list(reversed(parts))


def _ref(expr, name, selectors=()):
    base, parts = _access(expr)
    return _name(base) == name and parts == list(selectors)


def _constructor_argument(ctor, creation, attr):
    """Bind a direct self.attr = parameter assignment to its constructor argument."""
    args = _method_args(ctor)
    if not args:
        return None, None
    writes = [
        node
        for node in ast.walk(ctor)
        if isinstance(node, ast.Attribute)
        and _ref(node, args[0], [("attr", attr)])
        and not isinstance(node.ctx, ast.Load)
    ]
    for stmt in _body(ctor):
        dst, source = _assignment(stmt)
        if writes == [dst] and _name(source) in args[1:]:
            index = args.index(source.id) - 1
            if index < len(creation.args):
                return source.id, creation.args[index]
    return None, None


def _iter_items(expr, unit):
    if (
        isinstance(expr, ast.Call)
        and _name(expr.func) == "list"
        and len(expr.args) == 1
    ):
        if expr.keywords or unit.lookup(unit.scope_of(expr), "list") is not None:
            return None
        expr = expr.args[0]
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "items"
        and not expr.args
        and not expr.keywords
    ):
        return expr.func.value
    return None


def _registrars(project, consumer):
    """Modules imported by the reader and registrars invoked by Django startup."""
    owners = {u.tree for u in _imports_at_startup(project, consumer)}
    for unit in project.units:
        if unit.is_test:
            continue
        for scope in unit.class_scopes.values():
            ready = _method(scope.node, "ready")
            if not ready or "django.apps.AppConfig" not in project.mro(scope.node)[1]:
                continue
            owners.add(ready)
            owners.update(u.tree for u in _imports_at_startup(project, unit))
            for stmt in _body(ready):
                if (
                    isinstance(stmt, ast.Expr)
                    and isinstance(stmt.value, ast.Call)
                    and _reachable(unit, stmt, ready)
                ):
                    target = project.target(unit, stmt.value.func)
                    if (
                        target
                        and target.kind == "fn"
                        and not target.node.decorator_list
                        and _valid_call(target.node, stmt.value, bound=target.bound)
                    ):
                        owners.add(target.node)
    return owners


def _implicit_app(project, wrapper_unit, stmt, argument, consumer):
    # Only interpret a literal sequence of optional package prefixes followed
    # by the first module component. Never execute a project-provided regex.
    if not (
        isinstance(stmt, ast.If)
        and not stmt.orelse
        and len(stmt.body) == 1
        and ast.unparse(stmt.test) == f"{argument} is None"
    ):
        return None
    dst, call = _assignment(stmt.body[0])
    if (
        _name(dst) != argument
        or not isinstance(call, ast.Call)
        or call.args
        or call.keywords
    ):
        return None
    target = project.target(wrapper_unit, call.func)
    if not target or target.kind != "fn" or target.node.decorator_list:
        return None
    body = _body(target.node)
    if len(body) != 4:
        return None
    mod, name_expr = _assignment(body[0])
    match, matcher = _assignment(body[1])
    if not (
        _name(mod)
        and _name(match)
        and isinstance(name_expr, ast.Attribute)
        and name_expr.attr == "__name__"
        and isinstance(name_expr.value, ast.Call)
        and len(name_expr.value.args) == 1
        and not name_expr.value.keywords
        and project.external(target.unit, name_expr.value.func) == "inspect.getmodule"
        and isinstance(matcher, ast.Call)
        and len(matcher.args) == 2
        and not matcher.keywords
        and project.external(target.unit, matcher.func) == "re.match"
        and _name(matcher.args[1]) == mod.id
    ):
        return None
    frame = name_expr.value.args[0]
    if not (
        isinstance(frame, ast.Subscript)
        and _literal(frame.slice) == 0
        and isinstance(frame.value, ast.Subscript)
        and _literal(frame.value.slice) == 2
        and isinstance(frame.value.value, ast.Call)
        and not frame.value.value.args
        and not frame.value.value.keywords
        and project.external(target.unit, frame.value.value.func) == "inspect.stack"
    ):
        return None
    pattern = _literal(matcher.args[0])
    branch = body[2]
    if not (
        isinstance(pattern, str)
        and len(pattern) <= 300
        and isinstance(branch, ast.If)
        and not branch.orelse
        and len(branch.body) == 1
        and ast.unparse(branch.test) == f"{match.id} is not None"
        and isinstance(branch.body[0], ast.Return)
        and ast.unparse(branch.body[0].value) == f"{match.id}.group(1)"
        and isinstance(body[3], ast.Return)
        and isinstance(body[3].value, ast.Constant)
        and body[3].value.value is None
    ):
        return None
    parts = consumer.rel.removesuffix(".py").split("/")
    if parts[:1] == ["src"]:
        parts = parts[1:]
    while match := re.match(r"^\(\?:([a-zA-Z_]\w*)\\\.\)\?", pattern):
        if parts[:1] == [match[1]]:
            parts = parts[1:]
        pattern = pattern[match.end() :]
    return parts[0] if parts and pattern in {r"([^\.$]+)", r"([^.]+)"} else None


def _singleton(project, unit, expr):
    """Require the same module-level instance, even across imported module aliases."""
    if isinstance(expr, ast.Attribute):
        base = project.target(unit, expr.value)
        if not base or base.kind != "mod":
            return None
        unit, name = base.unit, expr.attr
    elif isinstance(expr, ast.Name) and unit.lookup(unit.scope_of(expr), expr.id):
        owner, _ = unit.lookup(unit.scope_of(expr), expr.id)
        if owner.node is not unit.tree:
            return None
        name = expr.id
    else:
        return None
    candidates = [
        v for s in unit.tree.body for t, v in [_assignment(s)] if _name(t) == name
    ]
    if (
        len(candidates) != 1
        or len(unit.module.binds.get(name, ())) != 1
        or not isinstance(candidates[0], ast.Call)
    ):
        return None
    target = project.target(unit, candidates[0].func)
    return (unit, name, target.node) if target and target.kind == "cls" else None


@dataclass(frozen=True)
class _Layout:
    instance: tuple
    store: str
    form_key: str
    defaults_key: str
    level: str
    form_kwargs: tuple


def _layout(project, registry_unit, registry, loader, getter, level):
    """Connect data[defaults][key] = field.initial to the reader's returned slot."""
    ls, gs = _method_args(loader), _method_args(getter)
    if len(ls) != 2 or len(gs) != 4:
        return None
    base, slots = _access(_returned(getter))
    if (
        _name(base) != gs[0]
        or len(slots) != 5
        or slots[0][0] != "attr"
        or slots[1:3] != [("name", gs[1]), ("name", gs[2])]
        or slots[3][0] != "key"
        or slots[4] != ("name", gs[3])
    ):
        return None
    store, defaults = slots[0][1], slots[3][1]
    for guard in _body(getter)[:-1]:
        if not (
            isinstance(guard, ast.If)
            and not guard.orelse
            and all(isinstance(s, ast.Raise) for s in guard.body)
            and isinstance(guard.test, ast.Compare)
            and len(guard.test.ops) == 1
            and isinstance(guard.test.ops[0], ast.NotIn)
        ):
            return None
        index = _name(guard.test.left)
        preceding = {gs[2]: slots[:2], gs[3]: slots[:4]}
        if index not in preceding or not _ref(
            guard.test.comparators[0], gs[0], preceding[index]
        ):
            return None
    ctor = _method(registry[2], "__init__")
    if not ctor or len(_method_args(ctor)) != 1:
        return None
    stores = [
        v
        for stmt in _body(ctor)
        for dst, v in [_assignment(stmt)]
        if _ref(dst, _method_args(ctor)[0], [("attr", store)])
    ]
    if len(stores) != 1 or not isinstance(stores[0], ast.Dict):
        return None
    initial = {_literal(k): v for k, v in zip(stores[0].keys, stores[0].values)}
    if not isinstance(initial.get(level), ast.Dict) or initial[level].keys:
        return None
    body = _body(loader)
    if len(body) != 1 or not isinstance(body[0], ast.For):
        return None
    outer = body[0]
    if not (
        _ref(
            _iter_items(outer.iter, registry_unit),
            ls[0],
            [("attr", store), ("name", ls[1])],
        )
        and isinstance(outer.target, ast.Tuple)
        and len(outer.target.elts) == 2
        and len(outer.body) == 2
        and not outer.orelse
    ):
        return None
    entry = _name(outer.target.elts[1])
    form, factory = _assignment(outer.body[0])
    loop = outer.body[1]
    if not (
        entry
        and _name(form)
        and isinstance(factory, ast.Call)
        and not factory.args
        and isinstance(factory.func, ast.Subscript)
        and _name(factory.func.value) == entry
        and isinstance(_literal(factory.func.slice), str)
        and all(k.arg and isinstance(k.value, ast.Constant) for k in factory.keywords)
        and isinstance(loop, ast.For)
        and isinstance(loop.target, ast.Tuple)
        and len(loop.target.elts) == 2
        and not loop.orelse
        and _ref(_iter_items(loop.iter, registry_unit), form.id, [("attr", "fields")])
    ):
        return None
    key, field = map(_name, loop.target.elts)
    dst, value = _assignment(loop.body[-1])
    if not (
        key
        and field
        and _ref(dst, entry, [("key", defaults), ("name", key)])
        and _ref(value, field, [("attr", "initial")])
    ):
        return None
    for guard in loop.body[:-1]:
        # Allow skipping separately typed, non-Django separator fields.
        if not (
            isinstance(guard, ast.If)
            and not guard.orelse
            and len(guard.body) == 1
            and isinstance(guard.body[0], ast.Continue)
            and isinstance(guard.test, ast.Compare)
            and len(guard.test.ops) == 1
            and isinstance(guard.test.ops[0], ast.Is)
            and ast.unparse(guard.test.left) == f"type({field})"
            and registry_unit.lookup(registry_unit.scope_of(guard.test.left), "type")
            is None
        ):
            return None
        excluded = project.target(registry_unit, guard.test.comparators[0])
        if not excluded or excluded.kind != "cls" or excluded.node.decorator_list:
            return None
    return _Layout(
        registry,
        store,
        _literal(factory.func.slice),
        defaults,
        level,
        tuple((k.arg, k.value.value) for k in factory.keywords),
    )


_FIELD_TYPES = {
    "django.forms.ChoiceField",
    "django.forms.fields.ChoiceField",
    "django.forms.IntegerField",
    "django.forms.fields.IntegerField",
    "django.forms.TypedChoiceField",
    "django.forms.fields.TypedChoiceField",
}


def _model_manager(project, unit, factory_expr, manager_attr):
    """Find the manager actually attached to the model returned by an ORM read."""
    factory = project.target(unit, factory_expr.func)
    if not factory or factory.kind != "fn" or factory.node.decorator_list:
        return None
    source = _returned(factory.node)
    if not (
        isinstance(source, ast.Call)
        and isinstance(source.func, ast.Attribute)
        and source.func.attr == "first"
        and not source.args
        and not source.keywords
        and isinstance(source.func.value, ast.Attribute)
        and source.func.value.attr == "objects"
        and _reachable(factory.unit, source, factory.node)
    ):
        return None
    model = project.target(factory.unit, source.func.value.value)
    if not (
        model
        and model.kind == "cls"
        and "django.db.models.Model" in project.mro(model.node)[1]
        and not any(
            "objects" in u.class_scopes[id(c)].binds
            for u, c in project.mro(model.node)[0]
        )
    ):
        return None
    ctor = _method(model.node, "__init__")
    if not ctor or not _method_args(ctor):
        return None
    values = [
        v
        for stmt in _body(ctor)
        for dst, v in [_assignment(stmt)]
        if _ref(dst, _method_args(ctor)[0], [("attr", manager_attr)])
    ]
    if len(values) != 1 or not isinstance(values[0], ast.Call) or not values[0].args:
        return None
    manager = project.target(model.unit, values[0].func)
    if manager and manager.kind == "cls" and _reachable(model.unit, values[0], ctor):
        return manager, values[0], model


def _mapping_fallback(project, stmt, getter_args, default, ctor, creation, model):
    self_name, key, app = getter_args
    if not (
        isinstance(stmt, ast.If)
        and not stmt.orelse
        and len(stmt.body) == 1
        and isinstance(stmt.body[0], ast.Return)
        and isinstance(stmt.test, ast.Compare)
        and len(stmt.test.ops) == 1
        and isinstance(stmt.test.ops[0], ast.In)
        and _name(stmt.test.left) == app
        and isinstance(stmt.test.comparators[0], ast.Attribute)
    ):
        return False
    backing = stmt.test.comparators[0].attr
    override = stmt.body[0].value
    if not (
        _ref(stmt.test.comparators[0], self_name, [("attr", backing)])
        and isinstance(override, ast.Call)
        and not override.keywords
        and _ref(
            override.func,
            self_name,
            [("attr", backing), ("name", app), ("attr", "get")],
        )
        and [_name(arg) for arg in override.args] == [key, default]
    ):
        return False
    _, value = _constructor_argument(ctor, creation, backing)
    if isinstance(value, ast.Dict):
        return not value.keys
    model_ctor = _method(model.node, "__init__")
    if (
        not isinstance(value, ast.Attribute)
        or _name(value.value) != _method_args(model_ctor)[0]
        or any(
            n is not value
            and isinstance(n, ast.Attribute)
            and n.attr == value.attr
            and _name(n.value) == _name(value.value)
            for n in ast.walk(model_ctor)
        )
    ):
        return False
    bindings = model.unit.class_scopes[id(model.node)].binds.get(value.attr, ())
    if len(bindings) != 1:
        return False
    field = bindings[0].value
    return (
        isinstance(field, ast.Call)
        and project.external(model.unit, field.func)
        in {
            "django.db.models.JSONField",
            "django.contrib.postgres.fields.JSONField",
            "jsonfield.JSONField",
        }
        and any(
            kw.arg == "default" and isinstance(kw.value, ast.Dict) and not kw.value.keys
            for kw in field.keywords
        )
    )


def _manager_layout(project, manager, creation, model, getter_name, key, namespace_arg):
    unit, cls = manager.unit, manager.node
    ctor, getter = _method(cls, "__init__"), _method(cls, getter_name)
    if not ctor or not getter or len(_method_args(getter)) < 3:
        return None
    self_name, key_arg, app_arg = _method_args(getter)[:3]
    if namespace_arg != app_arg:
        return None
    body = _body(getter)
    returned = _name(_returned(getter))
    reads = []
    for stmt in body:
        operation = stmt
        if (
            isinstance(stmt, ast.Try)
            and len(stmt.body) == 1
            and not stmt.finalbody
            and not stmt.orelse
        ):
            operation = stmt.body[0]
        dst, value = _assignment(operation)
        if returned and _name(dst) == returned and isinstance(value, ast.Call):
            reads.append((stmt, dst, value))
    if len(reads) != 1:
        return None
    read, default, select = reads[0]
    if not (
        _name(default)
        and isinstance(select, ast.Call)
        and not select.keywords
        and isinstance(select.func, ast.Attribute)
        and len(select.args) == 3
        and _name(select.args[1]) == app_arg
        and _name(select.args[2]) == key_arg
        and isinstance(select.args[0], ast.Attribute)
        and _name(select.args[0].value) == self_name
        and _name(_returned(getter)) == default.id
    ):
        return None
    # Only normalize case or supply an app when the caller did not supply one.
    for stmt in body[: body.index(read)]:
        if (
            isinstance(stmt, ast.If)
            and ast.unparse(stmt.test) == f"{app_arg} is None"
            and not stmt.orelse
        ):
            continue
        dst, value = _assignment(stmt)
        if _name(dst) == key_arg and ast.unparse(value) == f"{key_arg}.lower()":
            key = key.lower()
            continue
        return None
    for stmt in body[body.index(read) + 1 : -1]:
        if not _mapping_fallback(
            project,
            stmt,
            (self_name, key_arg, app_arg),
            default.id,
            ctor,
            creation,
            model,
        ):
            return None
    registry = _singleton(project, unit, select.func.value)
    if not registry:
        return None
    getter_fn = project.function(unit, select.func)
    if getter_fn is None:
        return None
    param, level_arg = _constructor_argument(ctor, creation, select.args[0].attr)
    level = _literal(level_arg)
    if not isinstance(level, str):
        return None
    statements = _body(ctor)
    if not statements or not _valid_call(ctor, creation, bound=True):
        return None
    ctor_args = _method_args(ctor)
    for stmt in statements[:-1]:
        dst, source = _assignment(stmt)
        if not (
            isinstance(dst, ast.Attribute)
            and _name(dst.value) == ctor_args[0]
            and _name(source) in ctor_args[1:]
        ):
            return None
    stmt = statements[-1]
    site = stmt.value if isinstance(stmt, ast.Expr) else None
    if not (
        isinstance(site, ast.Call)
        and isinstance(site.func, ast.Attribute)
        and len(site.args) == 1
        and not site.keywords
        and _name(site.args[0]) == param
        and _singleton(project, unit, site.func.value) == registry
    ):
        return None
    load = project.function(unit, site.func)
    if load:
        layout = _layout(project, registry[0], registry, load, getter_fn, level)
        if layout:
            return key, layout


def _registration(project, unit, call, layout):
    if (
        not isinstance(call.func, ast.Attribute)
        or not any(_literal(arg) == layout.level for arg in call.args)
        or _singleton(project, unit, call.func.value) != layout.instance
    ):
        return None
    fn = project.function(unit, call.func)
    if (
        not fn
        or len(_body(fn)) != 1
        or call.keywords
        or not _valid_call(fn, call, bound=True)
    ):
        return None
    dst, value = _assignment(_body(fn)[0])
    args = _method_args(fn)
    if not (
        isinstance(dst, ast.Subscript)
        and isinstance(dst.slice, ast.Attribute)
        and isinstance(dst.value, ast.Subscript)
        and _name(dst.value.slice) in args[1:]
        and _name(dst.slice.value) in args[1:]
        and isinstance(value, ast.Dict)
        and _ref(dst.value.value, args[0], [("attr", layout.store)])
    ):
        return None
    level_index = args.index(dst.value.slice.id) - 1
    form_index = args.index(dst.slice.value.id) - 1
    entries = {_literal(k): v for k, v in zip(value.keys, value.values)}
    if not (
        _name(entries.get(layout.form_key)) == dst.slice.value.id
        and isinstance(entries.get(layout.defaults_key), ast.Dict)
        and not entries[layout.defaults_key].keys
        and len(call.args) > max(level_index, form_index)
        and _literal(call.args[level_index]) == layout.level
    ):
        return None
    form = project.target(unit, call.args[form_index])
    return form if form and form.kind == "cls" else None, dst.slice.attr


def _constructor_preserves_field(unit, ctor, key, options):
    """Follow the load mode used by the registry when instantiating a form."""
    args = _method_args(ctor)
    if not args or ctor.decorator_list:
        return False
    kwarg = ctor.args.kwarg.arg if ctor.args.kwarg else None
    scope = unit.scope_of(ctor.body[0])
    false_flags = {}
    for stmt in _body(ctor):
        dst, value = _assignment(stmt)
        if not (
            _name(dst)
            and isinstance(value, ast.Call)
            and len(value.args) == 2
            and kwarg
            and _ref(value.func, kwarg, [("attr", "pop")])
            and len(scope.binds.get(dst.id, ())) == 1
        ):
            continue
        option = _literal(value.args[0])
        if (
            isinstance(option, str)
            and options.get(option, _literal(value.args[1])) is False
        ):
            false_flags[dst.id] = stmt.lineno
    for node in ast.walk(ctor):
        if (
            isinstance(node, ast.Subscript)
            and not isinstance(node.ctx, ast.Load)
            and _name(node.value) == kwarg
            and (
                not isinstance(_literal(node.slice), str)
                or _literal(node.slice) in options
            )
        ):
            return False
        if not isinstance(node, ast.Attribute):
            continue
        parent = unit.parents.get(id(node))
        if node.attr in {"fields", "base_fields"}:
            if not (
                isinstance(parent, ast.Subscript)
                and isinstance(_literal(parent.slice), str)
                and _literal(parent.slice) != key
            ):
                return False
        elif (
            isinstance(parent, ast.Call)
            and parent.func is node
            and _name(node.value) == args[0]
        ):
            # An unknown self method can replace field.initial. Ignore it only if
            # instantiating with the actual registry options skips that branch.
            child = node
            for ancestor in unit.ancestors(node):
                if isinstance(ancestor, ast.If) and child in ancestor.body:
                    test = ancestor.test
                    terms = (
                        test.values
                        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And)
                        else [test]
                    )
                    if any(
                        _name(term) in false_flags
                        and false_flags[term.id] < node.lineno
                        for term in terms
                    ):
                        break
                child = ancestor
            else:
                return False
    return True


def _class_value(project, form, name):
    for unit, cls in project.mro(form.node)[0]:
        bindings = unit.class_scopes[id(cls)].binds.get(name, ())
        if bindings:
            if len(bindings) == 1 and bindings[0].top_level:
                return unit, bindings[0].value
            break
    return None, None


def _field_initial(project, form, key, app, options):
    classes, bases = project.mro(form.node)
    django_forms = {
        "django.forms.Form",
        "django.forms.forms.Form",
        "django.forms.ModelForm",
    }
    if not bases or not set(bases) <= django_forms:
        return None
    for unit, cls in classes:
        if cls.decorator_list:
            return None
        for stmt in cls.body:
            if (
                options is not None
                and isinstance(stmt, ast.FunctionDef)
                and stmt.name == "__init__"
                and not _constructor_preserves_field(unit, stmt, key, options)
            ):
                return None
    unit, field = _class_value(project, form, key)
    if not isinstance(field, ast.Call):
        return None
    provider = project.external(unit, field.func)
    if provider not in _FIELD_TYPES or not django_field_is_available(
        project, unit, provider
    ):
        return None
    kw = {k.arg: k.value for k in field.keywords}
    if provider.endswith(".TypedChoiceField") and not _builtin_int(
        project, unit, kw.get("coerce")
    ):
        return None
    value = _literal(kw.get("initial"))
    if type(value) is str and value.isascii() and value.isdecimal() and len(value) <= 5:
        value = int(value)
    if type(value) is int and value > 0 and None not in kw:
        return unit.path, field, f"{app}.{key}", value


def _builtin_int(project, unit, expr):
    return (
        expr is not None
        and (
            _name(expr) == "int"
            and unit.lookup(unit.scope_of(expr), "int") is None
            or project.external(unit, expr) == "builtins.int"
        )
        and provider_binding_is_stable(
            "builtins.int", unit.tree, unit.path, project.root
        )
    )


def _unwrap_int(project, unit, expr):
    if (
        isinstance(expr, ast.Call)
        and len(expr.args) == 1
        and not expr.keywords
        and _builtin_int(project, unit, expr.func)
    ):
        return expr.args[0]
    return expr


def _literal_map_lacks(expr, key):
    return (
        isinstance(expr, ast.Dict)
        and all(isinstance(v, ast.Constant) for v in expr.values)
        and all(
            isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value != key
            for k in expr.keys
        )
    )


def _mapping_can_lack(project, unit, lookup, expr, key, forwarded=None):
    if _literal_map_lacks(expr, key):
        return True
    scope = unit.scope_of(lookup)
    fn = scope.node
    name = _name(expr)
    if not isinstance(fn, ast.FunctionDef) or fn.decorator_list or name is None:
        return False
    positional = [*fn.args.posonlyargs, *fn.args.args]
    required = positional[: len(positional) - len(fn.args.defaults)]
    formal = next((a for a in required if a.arg == name), None)
    if not formal or len(scope.binds.get(name, ())) != 1:
        return False
    if scope.parent.kind == "class" and (
        formal is positional[0] or scope.parent.node.decorator_list
    ):
        return False
    annotation = formal.annotation
    if isinstance(annotation, ast.Subscript):
        annotation = annotation.value
    if annotation is not None and not (
        _name(annotation) == "dict"
        and unit.lookup(unit.scope_of(annotation), "dict") is None
        or project.external(unit, annotation)
        in {
            "builtins.dict",
            "typing.Dict",
            "typing.Mapping",
            "typing.MutableMapping",
            "collections.abc.Mapping",
            "collections.abc.MutableMapping",
        }
    ):
        return False
    # A prior guard, alias or mutation can guarantee an override exists. Only
    # model an incoming parameter when this lookup is its first use.
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Name)
            and node.id == name
            and (node.lineno, node.col_offset) < (expr.lineno, expr.col_offset)
        ):
            return False
    if forwarded is not None:
        caller_unit, method_call, arguments = forwarded
        return _mapping_can_lack(
            project, caller_unit, method_call, arguments.get(name), key
        )
    # If direct source callers exist, require a concrete missing-key call.
    # An externally callable, unguarded input can itself be an empty mapping.
    callers = False
    for other in project.units:
        if other.is_test:
            continue
        project.charge(len(other.calls))
        for site, owner in other.calls:
            target = project.target(other, site.func)
            if not target or target.node is not fn:
                continue
            callers = True
            if not _valid_call(fn, site, bound=target.bound) or not _reachable(
                other, site, owner.node
            ):
                continue
            index = positional.index(formal) - int(target.bound)
            supplied = (
                site.args[index]
                if 0 <= index < len(site.args)
                else next((k.value for k in site.keywords if k.arg == name), None)
            )
            if _literal_map_lacks(supplied, key):
                return True
    return (
        not callers
        and scope.parent is not None
        and scope.parent.kind in {"module", "class"}
    )


def _default_return(project, unit, fn, key, mapping):
    """Select the return reached when the given setting has no stored override."""
    body = _body(fn)
    if mapping is None:
        return (
            body[0].value
            if len(body) == 1 and isinstance(body[0], ast.Return)
            else None
        )
    match body:
        case [
            ast.If(test=condition, body=[ast.Return(value=yes)], orelse=[]),
            ast.Return(value=no),
        ]:
            pass
        case [
            ast.If(
                test=condition,
                body=[ast.Return(value=yes)],
                orelse=[ast.Return(value=no)],
            )
        ]:
            pass
        case [ast.Return(value=ast.IfExp(test=condition, body=yes, orelse=no))]:
            pass
        case _:
            return None
    if not (
        isinstance(condition, ast.Compare)
        and len(condition.ops) == 1
        and isinstance(condition.ops[0], (ast.In, ast.NotIn))
        and _name(condition.left) == key
        and _name(condition.comparators[0]) == mapping
    ):
        return None
    present, missing = (yes, no) if isinstance(condition.ops[0], ast.In) else (no, yes)
    if _ref(_unwrap_int(project, unit, present), mapping, [("name", key)]):
        return missing


def _native_form_default(project, wrapper, caller_unit, lookup, forwarded):
    """Read the declared Field object in Django's class-level field map."""
    fn, unit = wrapper.node, wrapper.unit
    args = _method_args(fn)
    if not (
        isinstance(fn, ast.FunctionDef)
        and len(args) in (1, 2)
        and len(lookup.args) == len(args)
        and not lookup.keywords
        and _valid_call(fn, lookup)
    ):
        return ()
    keys = [i for i, arg in enumerate(lookup.args) if isinstance(_literal(arg), str)]
    if len(keys) != 1:
        return ()
    index = keys[0]
    key = _literal(lookup.args[index])
    mapping = None
    if len(args) == 2:
        if fn.args.defaults or fn.args.kwonlyargs or fn.args.vararg or fn.args.kwarg:
            return ()
        mapping = args[1 - index]
    ret = _unwrap_int(
        project, unit, _default_return(project, unit, fn, args[index], mapping)
    )
    if not (
        isinstance(ret, ast.Attribute)
        and ret.attr == "initial"
        and isinstance(ret.value, ast.Subscript)
        and _name(ret.value.slice) == args[index]
        and isinstance(ret.value.value, ast.Attribute)
        and ret.value.value.attr == "base_fields"
    ):
        return ()
    if mapping is not None and not _mapping_can_lack(
        project, caller_unit, lookup, lookup.args[1 - index], key, forwarded
    ):
        return ()
    form = project.target(unit, ret.value.value.value)
    if not form or form.kind != "cls":
        return ()
    row = _field_initial(project, form, key, form.node.name, options=None)
    if not row:
        return ()
    classes, native = project.mro(form.node)
    classes = tuple(classes)
    if any(
        len(c.bases) != 1
        or c.keywords
        or u.scope_of(c).kind != "module"
        or {"base_fields", "declared_fields", "__init_subclass__"}
        & u.class_scopes[id(c)].binds.keys()
        for u, c in classes
    ):
        return ()
    base_unit, _ = classes[-1]
    if not all(
        form_base_preserves_scalar_read(project, base_unit, base, unit, ret)
        for base in native
    ):
        return ()
    field_owner = next(c for u, c in classes if key in u.class_scopes[id(c)].binds)
    if not _field_table_stable(project, field_owner, key, [*classes, (unit, fn)]):
        return ()
    return (row,)


def _field_table_stable(project, owner, key, definitions):
    """Django shares declared Field objects with subclasses. Reject writes or escapes."""
    names = {(u, definition.name) for u, definition in definitions}
    modules = {u for u, _ in definitions}
    for unit in project.units:
        if unit.is_test:
            continue
        project.charge(len(unit.parents))
        for node in ast.walk(unit.tree):
            if (
                isinstance(node, ast.Name)
                and node.id == key
                and isinstance(node.ctx, ast.Load)
                and unit.scope_of(node).node is owner
            ):
                # The freshly allocated Field escaped before Django's metaclass collected it.
                return False
            if not isinstance(node, (ast.Attribute, ast.Name)):
                continue
            parent = unit.parents.get(id(node))
            if not isinstance(node, ast.Attribute) or node.attr not in {
                "base_fields",
                "declared_fields",
            }:
                if isinstance(node, ast.Attribute) and not isinstance(
                    node.ctx, ast.Load
                ):
                    module = project.target(unit, node.value)
                    if (
                        module
                        and module.kind == "mod"
                        and (module.unit, node.attr) in names
                    ):
                        return False
                if not isinstance(node.ctx, ast.Load):
                    continue
                if (
                    isinstance(parent, ast.Attribute)
                    and parent.value is node
                    and parent.attr not in {"__dict__", "__class__", "__getattribute__"}
                ):
                    continue
                if isinstance(parent, ast.ClassDef) and node in parent.bases:
                    continue
                if isinstance(parent, ast.Call) and parent.func is node:
                    continue
                target = project.target(unit, node)
                if target and (
                    target.kind == "mod"
                    and target.unit in modules
                    or target.kind == "cls"
                    and any(c is owner for _, c in project.mro(target.node)[0])
                ):
                    return False
                continue
            slot = unit.parents.get(id(node))
            value = unit.parents.get(id(slot))
            if (
                isinstance(slot, ast.Subscript)
                and slot.value is node
                and isinstance(value, ast.Attribute)
                and value.value is slot
                and value.attr == "initial"
                and isinstance(value.ctx, ast.Load)
            ):
                continue
            target = project.target(unit, node.value)
            if (
                not target
                or target.kind not in {"cls", "inst"}
                or any(c is owner for _, c in project.mro(target.node)[0])
            ):
                return False
    return True


def django_defaults_for(project, unit, lookup_call, *, forwarded=None):
    """Yield unique registered form defaults for a particular proven lookup."""
    if not (
        isinstance(lookup_call, ast.Call)
        and 1 <= len(lookup_call.args) <= 2
        and any(isinstance(_literal(arg), str) for arg in lookup_call.args)
    ):
        return ()
    wrapper = project.target(unit, lookup_call.func)
    if not wrapper or wrapper.kind != "fn" or wrapper.node.decorator_list:
        return ()
    fn = wrapper.node
    args = _method_args(fn)
    ret = _returned(fn)
    if not (
        len(args) == 2
        and isinstance(_literal(lookup_call.args[0]), str)
        and isinstance(ret, ast.Call)
        and len(ret.args) == 1
        and _name(ret.args[0]) == args[0]
        and isinstance(ret.func, ast.Attribute)
        and isinstance(ret.func.value, ast.Attribute)
        and isinstance(ret.func.value.value, ast.Call)
        and not ret.func.value.value.args
        and not ret.func.value.value.keywords
        and any(k.arg == args[1] and _name(k.value) == args[1] for k in ret.keywords)
    ):
        return _native_form_default(project, wrapper, unit, lookup_call, forwarded)
    body = _body(fn)
    if (
        len(body) > 2
        or any(k.arg != args[1] for k in lookup_call.keywords)
        or not _valid_call(fn, lookup_call)
        or any(
            k.arg != args[1]
            and not (
                k.arg is None and fn.args.kwarg and _name(k.value) == fn.args.kwarg.arg
            )
            for k in ret.keywords
        )
    ):
        return ()
    supplied = (
        lookup_call.args[1]
        if len(lookup_call.args) == 2
        else next(
            (k.value for k in lookup_call.keywords),
            fn.args.defaults[-1] if fn.args.defaults else None,
        )
    )
    if supplied is not None and not isinstance(supplied, ast.Constant):
        return ()
    app = _literal(supplied)
    if len(body) == 2 and not (
        isinstance(body[0], ast.If)
        and not body[0].orelse
        and ast.unparse(body[0].test) == f"{args[1]} is None"
    ):
        return ()
    if app is None and len(body) == 2:
        app = _implicit_app(project, wrapper.unit, body[0], args[1], unit)
    if not isinstance(app, str):
        return ()
    owner = _model_manager(
        project, wrapper.unit, ret.func.value.value, ret.func.value.attr
    )
    if not owner:
        return ()
    match = _manager_layout(
        project, *owner, ret.func.attr, _literal(lookup_call.args[0]), args[1]
    )
    if not match:
        return ()
    key, layout = match
    matches = []
    owners = _registrars(project, unit)
    for candidate in project.units:
        if candidate.is_test:
            continue
        project.charge(len(candidate.calls))
        for call, scope in candidate.calls:
            if scope.node not in owners:
                continue
            stmt = candidate.parents.get(id(call))
            if not (
                isinstance(stmt, ast.Expr)
                and stmt in scope.node.body
                and _reachable(candidate, call, scope.node)
            ):
                continue
            registration = _registration(project, candidate, call, layout)
            if not registration:
                continue
            form, app_attr = registration
            if form is None:
                return ()
            _, namespace = _class_value(project, form, app_attr)
            if not isinstance(namespace, ast.Constant):
                return ()
            if _literal(namespace) == app:
                matches.append(form)
                if len(matches) > 1:
                    return ()
    if matches:
        row = _field_initial(project, matches[0], key, app, dict(layout.form_kwargs))
        return (row,) if row else ()
    return ()
