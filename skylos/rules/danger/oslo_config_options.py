"""Source-only identity, registration, and override checks for oslo.config options."""

from __future__ import annotations

import ast
from collections import defaultdict

from .danger_fs.path_provenance import _V, _Project, _ResolutionLimit
from .danger_sql.sql_syntax import _one, _reachable, _valid_call
from .import_proof import provider_binding_is_stable

_CONFIG = {"oslo.config.cfg.CONF", "oslo_config.cfg.CONF"}
_SINGLE = {"register_opt", "register_cli_opt"}
_BULK = {"register_opts", "register_cli_opts"}


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _literal(node):
    return node.value if isinstance(node, ast.Constant) else None


def _keys(call):
    return {kw.arg: kw.value for kw in call.keywords}


def _method_args(fn):
    return [arg.arg for arg in [*fn.args.posonlyargs, *fn.args.args]]


def _body(fn):
    return [
        stmt
        for stmt in fn.body
        if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
    ]


class ConfigProject(_Project):
    def __init__(self, root, complete):
        super().__init__(root, complete)
        self.remaining_steps = 100_000

    def charge(self, count=1):
        self.remaining_steps -= count
        if self.remaining_steps < 0:
            raise _ResolutionLimit("RSA configuration lookup budget reached")

    def _import_values(self, unit, bind, depth):
        # A source checkout or namespace package may omit the parent __init__.
        # Resolve a present child module before treating it as an installed API.
        module, member, level = bind.value
        if member and not self.find_module(unit, module, level):
            dotted = ".".join(x for x in (module, member) if x)
            targets = self.find_module(unit, dotted, level)
            if targets:
                return frozenset(_V("mod", target) for target in targets)
        return super()._import_values(unit, bind, depth)

    def target(self, unit, expr):
        values = (
            self.values(unit, unit.scope_of(expr), expr) if expr is not None else None
        )
        return _one(values)

    def external(self, unit, expr):
        target = self.target(unit, expr)
        return target.name if target and target.kind == "ext" else ""

    def function(self, unit, expr):
        target = self.target(unit, expr)
        return target.node if target and target.kind == "fn" else None


def _pop_assignment(stmt, kwargs):
    if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
        return None
    call = stmt.value
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and _name(call.func.value) == kwargs
        and call.func.attr == "pop"
        and len(call.args) == 2
        and not call.keywords
    ):
        return None
    return _literal(call.args[0]), _name(stmt.targets[0]), call.args[1]


def _registrar(project, unit, fn):
    """Prove a forwarding *args/**kwargs wrapper from its implementation."""
    body = _body(fn)
    args = fn.args
    if (
        fn.decorator_list
        or _method_args(fn)
        or args.kwonlyargs
        or not args.vararg
        or not args.kwarg
        or len(body) != 3
    ):
        return None
    pops = [_pop_assignment(s, args.kwarg.arg) for s in body[:2]]
    if not all(pops) or not isinstance(body[-1], ast.Return):
        return None
    fields = {key: (local, default) for key, local, default in pops}
    if (
        set(fields) != {"group", "conf"}
        or not isinstance(fields["group"][1], ast.Constant)
        or fields["group"][1].value is not None
    ):
        return None
    conf = project.external(unit, fields["conf"][1])
    call = body[-1].value
    if conf not in _CONFIG or not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and _name(call.func.value) == fields["conf"][0]
        and call.func.attr in _SINGLE
        and len(call.args) == 1
        and set(_keys(call)) == {"group"}
        and _name(_keys(call)["group"]) == fields["group"][0]
    ):
        return None
    option = call.args[0]
    if (
        isinstance(option, ast.Call)
        and len(option.args) == 1
        and isinstance(option.args[0], ast.Starred)
        and _name(option.args[0].value) == args.vararg.arg
        and len(option.keywords) == 1
        and option.keywords[0].arg is None
        and _name(option.keywords[0].value) == args.kwarg.arg
        and project.external(unit, option.func) == conf.removesuffix("CONF") + "IntOpt"
    ):
        return conf
    return None


def _activated(project, modules, fn):
    project.charge(sum(len(unit.tree.body) for unit in modules))
    return any(
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and project.function(unit, stmt.value.func) is fn
        and _valid_call(fn, stmt.value)
        and _reachable(unit, stmt, unit.tree)
        for unit in modules
        for stmt in unit.tree.body
    )


def _option_list(project, modules, unit, scope, expr):
    """A direct sequence or a single-use literal with no aliases or writes."""
    if isinstance(expr, ast.Name):
        found = unit.lookup(scope, expr.id)
        if not found or len(found[1]) != 1:
            return None
        owner, (bind,) = found
        if (
            bind.kind != "assign"
            or bind.node not in owner.node.body
            or bind.node.lineno >= expr.lineno
        ):
            return None
        if (
            not isinstance(bind.node, ast.Assign)
            or len(bind.node.targets) != 1
            or _name(bind.node.targets[0]) != expr.id
        ):
            return None
        for other in modules:
            project.charge(len(other.parents))
            for ref, _ in other.loads:
                if ref is not expr and (
                    isinstance(ref, ast.Attribute)
                    and ref.attr == expr.id
                    or _name(ref) == expr.id
                ):
                    return None
            if other is not unit and any(
                isinstance(stmt, ast.ImportFrom)
                and any(a.name in {expr.id, "*"} for a in stmt.names)
                for stmt in other.tree.body
            ):
                return None
        expr = bind.value
    if isinstance(expr, (ast.List, ast.Tuple)) and len(expr.elts) <= 64:
        return expr.elts
    return None


def _direct_entries(project, modules, unit, scope, call, conf):
    arg = call.args[0]
    bulk = call.func.attr in _BULK
    values = _option_list(project, modules, unit, scope, arg) if bulk else [arg]
    if values is None:
        yield None, None, call
        return
    for item in values:
        if not isinstance(item, ast.Call):
            yield None, None, call
            continue
        option = project.external(unit, item.func)
        name = _literal(item.args[0]) if len(item.args) == 1 else None
        # Unknown option constructors can choose an arbitrary registered name.
        if (
            not isinstance(name, str)
            or not name.isidentifier()
            or not option.startswith(conf.removesuffix("CONF"))
            or not option.endswith("Opt")
        ):
            yield None, None, call
            continue
        kw = _keys(item)
        if "dest" in kw or None in kw:
            yield None, None, call
            continue
        default = (
            _literal(kw.get("default"))
            if option == conf.removesuffix("CONF") + "IntOpt"
            and set(kw) <= {"default", "help"}
            else None
        )
        yield name, default, item if bulk else call


def _registered(project, modules, unit):
    wrappers = {
        fn: conf
        for fn in unit.tree.body
        if isinstance(fn, ast.FunctionDef) and (conf := _registrar(project, unit, fn))
    }
    activated = {}
    for call, scope in unit.calls:
        kw = _keys(call)
        if "group" not in kw:
            continue
        group = _literal(kw["group"])
        if group is None and isinstance(kw["group"], ast.Constant):
            continue  # Explicit None selects the unnamed default group.
        if group is not None and (
            not isinstance(group, str) or not group.isidentifier()
        ):
            continue
        if isinstance(call.func, ast.Attribute) and call.func.attr in _SINGLE | _BULK:
            conf = project.external(unit, call.func.value)
            if conf not in _CONFIG or len(call.args) != 1 or set(kw) != {"group"}:
                continue
            entries = _direct_entries(project, modules, unit, scope, call, conf)
        else:
            conf = wrappers.get(project.function(unit, call.func))
            if conf is None or set(kw) - {"group", "default"}:
                continue
            name = _literal(call.args[0]) if len(call.args) == 1 else None
            if not isinstance(name, str) or not name.isidentifier():
                name = None
            entries = [(name, _literal(kw.get("default")), call)]
        # Registrations in a setup function count when a project module calls
        # it unconditionally at import, with this declaration in its main body.
        owner = scope.node
        if not isinstance(owner, (ast.Module, ast.FunctionDef)):
            continue
        if not any(
            isinstance(s, ast.Expr) and s.value is call for s in owner.body
        ) or not _reachable(unit, call, owner):
            continue
        if isinstance(owner, ast.FunctionDef):
            if owner not in activated:
                activated[owner] = _activated(project, modules, owner)
            if not activated[owner]:
                continue
        for name, default, site in entries:
            yield (conf, group, name), default, site


def _overrides(project, unit):
    overridden = set()

    # Registration legitimately mutates the singleton. Track writes to its
    # identity, groups and options separately from the vetted IntOpt provider.
    def block(qualified):
        for conf in _CONFIG:
            if (
                qualified == conf
                or qualified.removeprefix(conf + ".") in _SINGLE | _BULK
            ):
                overridden.add((conf, None, None))
            elif qualified.startswith(conf + "."):
                path = qualified[len(conf) + 1 :].split(".")
                overridden.add((conf, path[0], path[1] if len(path) > 1 else None))

    for target, _, _, scope in unit.attribute_stores:
        if _reachable(unit, target, scope.node):
            block(project.external(unit, target))
    for call, scope in unit.calls:
        name = (
            call.func.attr if isinstance(call.func, ast.Attribute) else _name(call.func)
        )
        if name not in {
            "setattr",
            "delattr",
            "set_default",
            "set_override",
            "unregister_opt",
        } or not _reachable(unit, call, scope.node):
            continue
        if (
            isinstance(call.func, ast.Name)
            and call.func.id in {"setattr", "delattr"}
            and len(call.args) >= 2
        ):
            base = project.external(unit, call.args[0])
            member = _literal(call.args[1])
            if isinstance(member, str):
                block(f"{base}.{member}")
            else:
                block(base)
        if isinstance(call.func, ast.Attribute) and call.func.attr in {
            "set_default",
            "set_override",
            "unregister_opt",
        }:
            conf = project.external(unit, call.func.value)
            if conf in _CONFIG:
                kw = _keys(call)
                pos = 1 if call.func.attr == "unregister_opt" else 2
                group = kw.get(
                    "group", call.args[pos] if len(call.args) > pos else None
                )
                opt = call.args[0] if call.args else kw.get("name")
                overridden.add((conf, _literal(group), _literal(opt)))
    return overridden


def _imports_at_startup(project, source):
    modules = {source}
    pending = [source]
    while pending:
        unit = pending.pop()
        for binds in unit.module.binds.values():
            for bind in binds:
                if bind.kind != "import" or bind.node not in unit.tree.body:
                    continue
                project.charge()
                module, member, level = bind.value
                imported = set(project.find_module(unit, module, level))
                if member:
                    full_name = ".".join(x for x in (module, member) if x)
                    imported.update(project.find_module(unit, full_name, level))
                for target in imported - modules:
                    modules.add(target)
                    pending.append(target)
    return modules


def defaults_for(project, consumer, used):
    """Yield a unique, effective weak default from the consumer's imported modules."""
    modules = _imports_at_startup(project, consumer)
    schemas = defaultdict(list)
    overridden = set()
    for unit in modules:
        if unit.is_test:
            continue
        project.charge(len(unit.parents))
        for key, size, site in _registered(project, modules, unit):
            if key[1] is None or key[2] is None:
                overridden.add(key)
            elif key in used and provider_binding_is_stable(
                key[0].removesuffix("CONF") + "IntOpt",
                unit.tree,
                unit.path,
                project.root,
            ):
                schemas[key].append((size, site, unit.path))
        overridden.update(_overrides(project, unit))
    for key, registrations in schemas.items():
        if len(registrations) != 1 or any(
            c == key[0] and (g is None or g == key[1]) and (o is None or o == key[2])
            for c, g, o in overridden
        ):
            continue
        size, call, path = registrations[0]
        if type(size) is int and 0 < size < 2048:
            yield path, call, key, size


def config_group(project, unit, expr):
    name = project.external(unit, expr)
    base, _, group = name.rpartition(".")
    return (base, group) if base in _CONFIG else None
