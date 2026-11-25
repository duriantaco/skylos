"""Attribute weak OpenSSL key generation to a source-proven configuration default."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from skylos.rules.quality._test_code import is_python_test_file

from .danger_fs.path_provenance import _ResolutionLimit, _Unit
from .danger_sql.sql_syntax import _reachable, _valid_call
from .import_proof import provider_binding_is_stable
from .oslo_config_options import (
    ConfigProject,
    _body,
    _literal,
    _method_args,
    _name,
    config_group,
    defaults_for,
)
from .project_source import project_source_snapshot
from .rsa_key_sizes import _VECTOR_RUNNERS, openssl_size_operand

_SIZE_SLOT = re.compile(r"%\(([a-zA-Z_]\w*)\)[ds]")


def _single_local(unit, expr, scope):
    if not isinstance(expr, ast.Name):
        return expr
    binds = scope.binds.get(expr.id, ())
    if len(binds) == 1 and binds[0].kind == "assign":
        stmt = binds[0].node
        if stmt in scope.node.body and stmt.lineno < expr.lineno:
            return binds[0].value
    return expr


def _parameter(unit, fn, node):
    name = _name(node)
    binds = unit.function_scopes[id(fn)].binds.get(name, ())
    return name if len(binds) == 1 and binds[0].kind == "param" else None


def _command_mapping(project, unit, call, scope):
    """Recognize a method executing command % self.mapping as subprocess argv."""
    fn = scope.node
    if (
        not isinstance(fn, ast.FunctionDef)
        or fn.decorator_list
        or len(_method_args(fn)) != 2
        or len(call.args) != 1
        or call.keywords
    ):
        return None
    vector = call.args[0]
    if not (
        isinstance(vector, ast.Call)
        and isinstance(vector.func, ast.Attribute)
        and vector.func.attr in {"split", "rsplit"}
        and not vector.keywords
        and (
            not vector.args or len(vector.args) == 1 and _literal(vector.args[0]) == " "
        )
    ):
        return None
    fmt = _single_local(unit, vector.func.value, scope)
    receiver, command = _method_args(fn)
    if (
        isinstance(fmt, ast.BinOp)
        and isinstance(fmt.op, ast.Mod)
        and _parameter(unit, fn, fmt.left) == command
        and isinstance(fmt.right, ast.Attribute)
        and _parameter(unit, fn, fmt.right.value) == receiver
    ):
        return fmt.right.attr
    return None


def _size_slot(template):
    if not isinstance(template, str):
        return None
    # Since the runner splits on spaces without invoking a shell, each
    # literal argument can be fed to the existing genrsa operand parser.
    vector = ast.List(elts=[ast.Constant(s) for s in template.split(" ")])
    call = ast.Call(func=ast.Name(id="run"), args=[vector], keywords=[])
    operand = _literal(openssl_size_operand(call, "subprocess.run"))
    match = _SIZE_SLOT.fullmatch(operand) if isinstance(operand, str) else None
    return match.group(1) if match else None


def _dictionary_option(unit, ctor, field, key):
    args = _method_args(ctor)
    if not args or ctor.decorator_list:
        return None
    origin = None
    for stmt in ctor.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        target = stmt.targets[0]
        if not (
            isinstance(target, ast.Attribute)
            and target.attr == field
            and _parameter(unit, ctor, target.value) == args[0]
            and isinstance(stmt.value, ast.Dict)
        ):
            continue
        entries = [(_literal(k), v) for k, v in zip(stmt.value.keys, stmt.value.values)]
        if any(not isinstance(k, str) for k, _ in entries) or len(dict(entries)) != len(
            entries
        ):
            return None
        value = dict(entries).get(key)
        if (
            isinstance(value, ast.Call)
            and _name(value.func) == "int"
            and len(value.args) == 1
            and not value.keywords
        ):
            if unit.lookup(unit.scope_of(value), "int") is not None:
                return None
            value = value.args[0]
        if (
            isinstance(value, ast.Attribute)
            and _parameter(unit, ctor, value.value) in args[1:]
        ):
            if not _reachable(unit, stmt, ctor) or any(
                isinstance(ref, ast.Attribute)
                and ref.attr == value.attr
                and _name(ref.value) == value.value.id
                for guard in ast.walk(ctor)
                if isinstance(guard, (ast.If, ast.While, ast.Assert, ast.IfExp))
                for ref in ast.walk(guard.test)
            ):
                return None
            origin = target, args.index(value.value.id), value.attr
    if not origin:
        return None
    # The map can be read by several inherited methods. Any other assignment,
    # mutating call, subscript write or escape invalidates its constructor value.
    cls = unit.function_scopes[id(ctor)].parent.node
    for node in ast.walk(cls):
        if (
            not isinstance(node, ast.Attribute)
            or node.attr != field
            or node is origin[0]
        ):
            continue
        parent = unit.parents[id(node)]
        if isinstance(parent, ast.Subscript) and isinstance(parent.ctx, ast.Load):
            continue
        if (
            isinstance(parent, ast.BinOp)
            and isinstance(parent.op, ast.Mod)
            and parent.right is node
        ):
            continue
        use = unit.parents.get(id(parent))
        if (
            isinstance(parent, ast.Attribute)
            and parent.attr == "update"
            and isinstance(use, ast.Call)
            and len(use.args) == 1
            and not use.keywords
            and ctor.args.kwarg
            and _name(use.args[0]) == ctor.args.kwarg.arg
            and unit.scope_of(use).node is ctor
            and use in [s.value for s in ctor.body if isinstance(s, ast.Expr)]
            and use.lineno > origin[0].lineno
            and all(
                isinstance(x.ctx, ast.Load) and unit.parents[id(x)] is use
                for x in ast.walk(ctor)
                if isinstance(x, ast.Name) and x.id == ctor.args.kwarg.arg
            )
        ):
            continue
        return None
    return origin[1:]


def _tests_option(project, unit, site, option):
    # Without evaluating a configuration-dependent guard we cannot establish
    # that its weak default is allowed to reach this generation operation.
    scope = unit.scope_of(site).node
    return any(
        project.external(unit, value) == option
        for guard in ast.walk(scope)
        if isinstance(guard, (ast.If, ast.While, ast.Assert, ast.IfExp))
        and guard.lineno <= site.lineno
        for value in ast.walk(guard.test)
        if isinstance(value, (ast.Name, ast.Attribute))
    )


def _subclass_options(project, unit, base, ctor, index, option):
    for child_unit, init, child_scope in project.calls_by_name.get("__init__", ()):
        project.charge()
        if child_unit is not unit:
            continue
        child = child_scope.parent
        if (
            child is None
            or child.kind != "class"
            or not isinstance(child_scope.node, ast.FunctionDef)
            or child_scope.node.name != "__init__"
        ):
            continue
        # Restrict the path to direct subclasses that delegate initialization
        # and inherit both the generation method and its executor unchanged.
        if (
            len(child.node.bases) != 1
            or (target := project.target(unit, child.node.bases[0])) is None
            or target.kind != "cls"
            or target.node is not base
            or child.node.decorator_list
            or _body(child.node) != [child_scope.node]
            or len(_body(child_scope.node)) != 1
            or not isinstance(_body(child_scope.node)[0], ast.Expr)
            or _body(child_scope.node)[0].value is not init
            or not _valid_call(ctor, init, bound=True)
            or len(init.args) < index
            or init.keywords
            or not isinstance(init.func, ast.Attribute)
            or init.func.attr != "__init__"
            or project.function(unit, init.func) is not ctor
            or any(isinstance(v, ast.Starred) for v in init.args)
        ):
            continue
        if group := config_group(project, unit, init.args[index - 1]):
            yield (*group, option)


def _uses(project, unit):
    """Resolve key-size sources from proven command consumers in one module."""
    uses = set()
    for runner, scope in unit.calls:
        if not isinstance(runner.func, (ast.Name, ast.Attribute)):
            continue
        argv = (
            runner.args[0]
            if runner.args
            else next((kw.value for kw in runner.keywords if kw.arg == "args"), None)
        )
        if not (
            isinstance(argv, (ast.List, ast.Tuple))
            or isinstance(argv, ast.Call)
            and isinstance(argv.func, ast.Attribute)
            and argv.func.attr in {"split", "rsplit"}
        ):
            continue
        provider = project.external(unit, runner.func)
        if provider not in _VECTOR_RUNNERS or not _reachable(unit, runner, scope.node):
            continue
        if not provider_binding_is_stable(provider, unit.tree, unit.path, project.root):
            continue
        operand = openssl_size_operand(runner, provider)
        if operand is not None:
            if (
                isinstance(operand, ast.Call)
                and _name(operand.func) == "str"
                and len(operand.args) == 1
                and not operand.keywords
                and unit.lookup(scope, "str") is None
            ):
                operand = operand.args[0]
            if (
                isinstance(operand, ast.Attribute)
                and (group := config_group(project, unit, operand.value))
                and not _tests_option(
                    project, unit, runner, ".".join((*group, operand.attr))
                )
            ):
                uses.add((*group, operand.attr))
        field = _command_mapping(project, unit, runner, scope)
        if not field or scope.parent is None or scope.parent.kind != "class":
            continue
        base = scope.parent.node
        ctor = next(
            (
                s
                for s in base.body
                if isinstance(s, ast.FunctionDef) and s.name == "__init__"
            ),
            None,
        )
        if not ctor:
            continue
        for origin_unit, call, method_scope in project.calls_by_name.get(
            scope.node.name, ()
        ):
            project.charge()
            if origin_unit is not unit:
                continue
            if (
                method_scope.parent is not scope.parent
                or len(call.args) != 1
                or call.keywords
            ):
                continue
            slot = _size_slot(_literal(call.args[0]))
            if not slot or not isinstance(call.func, ast.Attribute):
                continue
            fn = method_scope.node
            if (
                not isinstance(fn, ast.FunctionDef)
                or fn.decorator_list
                or not _method_args(fn)
                or _parameter(unit, fn, call.func.value) != _method_args(fn)[0]
                or project.function(unit, call.func) is not scope.node
                or not _reachable(unit, call, fn)
            ):
                continue
            project.charge(len(unit.parents))
            path = _dictionary_option(unit, ctor, field, slot)
            if not path or any(
                isinstance(ref, ast.Subscript)
                and isinstance(ref.value, ast.Attribute)
                and ref.value.attr == field
                and _literal(ref.slice) == slot
                for guard in ast.walk(fn)
                if isinstance(guard, (ast.If, ast.While, ast.Assert, ast.IfExp))
                and guard.lineno <= call.lineno
                for ref in ast.walk(guard.test)
            ):
                continue
            index, option = path
            uses.update(_subclass_options(project, unit, base, ctor, index, option))
    return uses


def _django_key_defaults(project, consumer):
    from .django_registry_defaults import django_defaults_for
    from .django_rsa_consumers import rsa_setting_lookups

    for lookup_unit, lookup, _generation, forwarded in rsa_setting_lookups(
        project, consumer
    ):
        for path, field, setting, size in django_defaults_for(
            project, lookup_unit, lookup, forwarded=forwarded
        ):
            yield path, field, setting, setting.rsplit(".", 1)[-1], size


@lru_cache(maxsize=2)
def _project_findings(root, snapshot, framework):
    consumers = {
        path
        for path, tree in snapshot
        if any(
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and "genrsa" in n.value
            for n in ast.walk(tree)
        )
    }
    if not consumers:
        return {}
    project = ConfigProject(root, True)
    for path, tree in snapshot:
        unit = _Unit(
            path,
            path.relative_to(root).as_posix(),
            tree,
            is_python_test_file(path, root),
        )
        unit.module_names = project._module_names(unit)
        project.units.append(unit)
        project.by_path[path] = unit
        for name in unit.module_names:
            project.modules.setdefault(name, []).append(unit)
    project._index()
    found = defaultdict(set)
    for unit in project.units:
        if unit.is_test or unit.path not in consumers:
            continue
        if framework == "django":
            for path, field, setting, symbol, size in _django_key_defaults(
                project, unit
            ):
                if type(size) is int and 0 < size < 2048:
                    found[path].add((field, setting, symbol, size))
        else:
            used = _uses(project, unit)
            if used:
                for path, call, (_, group, option), size in defaults_for(
                    project, unit, used
                ):
                    found[path].add((call, f"{group}.{option}", option, size))
    return {
        path: sorted(rows, key=lambda row: (row[0].lineno, row[0].col_offset, row[1]))
        for path, rows in found.items()
    }


def _declaration_frameworks(tree):
    imports = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom) and not stmt.level and stmt.module:
            imports.add(stmt.module.split(".")[0])
        elif isinstance(stmt, ast.Import):
            imports.update(a.name.split(".")[0] for a in stmt.names)
    if imports.intersection({"oslo", "oslo_config"}):
        yield "oslo"
    if "django" in imports:
        for kw in ast.walk(tree):
            if not isinstance(kw, ast.keyword) or kw.arg != "initial":
                continue
            value = _literal(kw.value)
            if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
                value = int(value)
            if type(value) is int and 0 < value < 2048:
                yield "django"
                return


def scan_configured_rsa(tree, file_path, findings, project_root):
    if not project_root:
        return
    frameworks = tuple(_declaration_frameworks(tree))
    if not frameworks:
        return
    root = Path(project_root).resolve()
    source = Path(file_path).resolve()
    snapshot, complete = project_source_snapshot(root)
    if not complete or source not in snapshot:
        return
    rows = []
    for framework in frameworks:
        try:
            rows.extend(
                _project_findings(root, tuple(snapshot.items()), framework).get(
                    source, ()
                )
            )
        except (_ResolutionLimit, RecursionError, ValueError):
            continue
    if rows and ast.dump(tree) == ast.dump(snapshot[source]):
        for call, setting, option, size in rows:
            findings.append(
                {
                    "rule_id": "SKY-D383",
                    "severity": "MEDIUM",
                    "file": str(file_path),
                    "line": call.lineno,
                    "col": call.col_offset,
                    "symbol": option,
                    "message": f"The {setting} default can supply {size} bits to OpenSSL RSA key generation when no override is set. Use at least 2048 bits.",
                }
            )
