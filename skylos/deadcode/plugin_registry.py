from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from skylos.deadcode.python_ast import ParsedPythonFile


_PLUGIN_TARGET_RE = re.compile(
    r"^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*):([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$"
)
_ENTRY_ROOT_NAMES = {"main", "cli", "run", "app", "create_app"}
_ROOT_EVIDENCE_MARKERS = {
    "framework_root",
    "package_entrypoint",
    "test_entrypoint",
    "top_level_execution",
    "coverage_hit",
    "trace_hit",
}


@dataclass(frozen=True)
class _ImportContext:
    name_aliases: dict[str, str]
    module_aliases: dict[str, str]
    importlib_names: set[str]
    import_module_names: set[str]


_DefByName = dict[str, Any]
_DefByFileSimple = dict[tuple[str, str], Any]
_DefByFileLine = dict[tuple[str, int], Any]


def find_literal_plugin_registry_targets(
    definitions: dict[str, Any],
    parsed_files: Sequence[ParsedPythonFile],
) -> list[Any]:
    definitions_by_name = _definitions_by_name(definitions)
    definitions_by_file_simple = _definitions_by_file_simple(definitions)
    definitions_by_file_line = _definitions_by_file_line(definitions)

    registries = _collect_literal_plugin_registries(
        parsed_files,
        definitions_by_file_simple,
        definitions_by_name,
    )
    if not registries:
        return []

    reachable_functions = _reachable_live_functions(definitions)
    if not reachable_functions:
        return []

    live_registries = _collect_live_plugin_registry_uses(
        parsed_files,
        definitions_by_file_simple,
        definitions_by_file_line,
        set(registries),
        reachable_functions,
    )
    if not live_registries:
        return []

    targets: list[Any] = []
    seen: set[str] = set()
    for registry_qname in sorted(live_registries):
        for target_qname in sorted(registries.get(registry_qname, ())):
            target = definitions_by_name.get(target_qname)
            if target is None:
                continue
            if getattr(target, "type", None) not in {"class", "function", "method"}:
                continue
            target_name = str(getattr(target, "name", ""))
            if target_name in seen:
                continue
            seen.add(target_name)
            targets.append(target)
    return targets


# Definition indexes


def _definitions_by_file_simple(definitions: dict[str, Any]) -> _DefByFileSimple:
    lookup: _DefByFileSimple = {}
    for defn in definitions.values():
        simple = str(getattr(defn, "simple_name", ""))
        if not simple:
            continue
        try:
            filename = str(Path(getattr(defn, "filename", "")).resolve())
        except (OSError, TypeError):
            continue
        key = (filename, simple)
        if key not in lookup:
            lookup[key] = defn
    return lookup


def _definitions_by_name(definitions: dict[str, Any]) -> _DefByName:
    lookup: _DefByName = {}
    for defn in definitions.values():
        name = str(getattr(defn, "name", ""))
        if not name:
            continue
        existing = lookup.get(name)
        if existing is None:
            lookup[name] = defn
            continue
        existing_type = getattr(existing, "type", None)
        defn_type = getattr(defn, "type", None)
        if existing_type == "import" and defn_type != "import":
            lookup[name] = defn
    return lookup


def _definitions_by_file_line(definitions: dict[str, Any]) -> _DefByFileLine:
    lookup: _DefByFileLine = {}
    for defn in definitions.values():
        if getattr(defn, "type", None) not in {"function", "method"}:
            continue
        try:
            filename = str(Path(getattr(defn, "filename", "")).resolve())
            line = int(getattr(defn, "line", 0) or 0)
        except (OSError, TypeError, ValueError):
            continue
        if line:
            lookup[(filename, line)] = defn
    return lookup


# Registry discovery


def _collect_literal_plugin_registries(
    parsed_files: Sequence[ParsedPythonFile],
    definitions_by_file_simple: _DefByFileSimple,
    definitions_by_name: _DefByName,
) -> dict[str, set[str]]:
    registries: dict[str, set[str]] = {}
    for parsed in parsed_files:
        try:
            file_key = str(parsed.path.resolve())
        except OSError:
            continue
        for stmt in parsed.tree.body:
            value = _assignment_value(stmt)
            if value is None:
                continue
            targets = _module_assignment_names(stmt)
            if not targets:
                continue
            plugin_targets: set[str] = set()
            for raw in _literal_strings(value):
                target = _plugin_target_qname(raw)
                if target not in definitions_by_name:
                    continue
                plugin_targets.add(target)
            if not plugin_targets:
                continue
            for target_name in targets:
                registry_def = definitions_by_file_simple.get((file_key, target_name))
                if registry_def is None:
                    continue
                registry_qname = str(getattr(registry_def, "name", ""))
                registries.setdefault(registry_qname, set()).update(plugin_targets)
    return registries


def _assignment_value(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Assign):
        return node.value
    if isinstance(node, ast.AnnAssign):
        return node.value
    return None


def _module_assignment_names(node: ast.AST) -> list[str]:
    targets: list[ast.AST] = []
    if isinstance(node, ast.Assign):
        targets.extend(node.targets)
    elif isinstance(node, ast.AnnAssign):
        targets.append(node.target)

    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
    return names


def _literal_strings(node: ast.AST) -> set[str]:
    strings: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            strings.add(child.value)
    return strings


def _plugin_target_qname(value: str) -> str:
    match = _PLUGIN_TARGET_RE.match(value.strip())
    if not match:
        return ""
    module_name, member_name = match.groups()
    return f"{module_name}.{member_name}"


# Live registry use detection


def _collect_live_plugin_registry_uses(
    parsed_files: Sequence[ParsedPythonFile],
    definitions_by_file_simple: _DefByFileSimple,
    definitions_by_file_line: _DefByFileLine,
    registry_qnames: set[str],
    reachable_functions: set[str],
) -> set[str]:
    live_registries: set[str] = set()
    for parsed in parsed_files:
        try:
            file_key = str(parsed.path.resolve())
        except OSError:
            continue
        import_ctx = _collect_import_context(parsed.tree)
        for node in ast.walk(parsed.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            defn = definitions_by_file_line.get((file_key, node.lineno))
            if defn is None:
                continue
            defn_name = str(getattr(defn, "name", ""))
            if defn_name not in reachable_functions:
                continue
            live_registries.update(
                _registries_used_by_importlib_getattr_flow(
                    node,
                    file_key,
                    definitions_by_file_simple,
                    import_ctx,
                    registry_qnames,
                )
            )
    return live_registries


def _collect_import_context(tree: ast.Module) -> _ImportContext:
    name_aliases: dict[str, str] = {}
    module_aliases: dict[str, str] = {}
    importlib_names: set[str] = set()
    import_module_names: set[str] = set()

    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                if alias.name == "importlib":
                    importlib_names.add(bound_name)
                if alias.asname:
                    module_aliases[bound_name] = alias.name
                elif "." not in alias.name:
                    module_aliases[bound_name] = alias.name
        elif isinstance(stmt, ast.ImportFrom) and stmt.module:
            for alias in stmt.names:
                bound_name = alias.asname or alias.name
                target = f"{stmt.module}.{alias.name}"
                name_aliases[bound_name] = target
                if stmt.module == "importlib" and alias.name == "import_module":
                    import_module_names.add(bound_name)

    return _ImportContext(
        name_aliases=name_aliases,
        module_aliases=module_aliases,
        importlib_names=importlib_names,
        import_module_names=import_module_names,
    )


def _registries_used_by_importlib_getattr_flow(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    file_key: str,
    definitions_by_file_simple: _DefByFileSimple,
    import_ctx: _ImportContext,
    registry_qnames: set[str],
) -> set[str]:
    path_vars: dict[str, str] = {}
    split_vars: dict[tuple[str, str], str] = {}
    live_registries: set[str] = set()

    for child in ast.walk(function):
        for target, value in _iter_simple_assignments(child):
            registry_qname = _registry_qname_from_lookup(
                value,
                file_key,
                definitions_by_file_simple,
                import_ctx,
            )
            if registry_qname in registry_qnames:
                path_vars[_target_name(target)] = registry_qname

            split_source = _split_source_var(value)
            if split_source and split_source in path_vars:
                module_var, func_var = _split_assignment_pair(target)
                if module_var and func_var:
                    split_vars[(module_var, func_var)] = path_vars[split_source]

        if not isinstance(child, ast.Call):
            continue
        split_key = _importlib_getattr_split_key(child, import_ctx)
        if split_key and split_key in split_vars:
            live_registries.add(split_vars[split_key])

    return live_registries


# Reachability


def _reachable_live_functions(definitions: dict[str, Any]) -> set[str]:
    definitions_by_name = _definitions_by_name(definitions)
    callable_names = _callable_definition_names(definitions_by_name)
    roots = _root_callable_names(definitions_by_name, callable_names)
    if not roots:
        return set()
    simple_callable_names = _callable_names_by_simple_name(callable_names)
    return _walk_reachable_functions(
        roots,
        definitions_by_name,
        callable_names,
        simple_callable_names,
    )


def _callable_definition_names(definitions_by_name: _DefByName) -> set[str]:
    callable_names: set[str] = set()
    for name, defn in definitions_by_name.items():
        if getattr(defn, "type", None) not in {"function", "method"}:
            continue
        callable_names.add(name)
    return callable_names


def _callable_names_by_simple_name(
    callable_names: set[str],
) -> dict[str, list[str]]:
    simple_callable_names: dict[str, list[str]] = defaultdict(list)
    for name in callable_names:
        simple_callable_names[name.rsplit(".", 1)[-1]].append(name)
    return simple_callable_names


def _root_callable_names(
    definitions_by_name: _DefByName,
    callable_names: set[str],
) -> set[str]:
    roots: set[str] = set()
    for name, defn in definitions_by_name.items():
        if name not in callable_names:
            continue
        if not _is_hard_liveness_root(defn):
            continue
        roots.add(name)
    return roots


def _walk_reachable_functions(
    roots: set[str],
    definitions_by_name: _DefByName,
    callable_names: set[str],
    simple_callable_names: dict[str, list[str]],
) -> set[str]:
    reachable: set[str] = set()
    stack = list(roots)
    while stack:
        current = stack.pop()
        if current in reachable:
            continue
        reachable.add(current)
        current_def = definitions_by_name.get(current)
        if current_def is None:
            continue
        callees = _reachable_callees_for_definition(
            current_def,
            callable_names,
            simple_callable_names,
        )
        for callee in callees:
            if callee not in reachable:
                stack.append(callee)
    return reachable


def _reachable_callees_for_definition(
    defn: Any,
    callable_names: set[str],
    simple_callable_names: dict[str, list[str]],
) -> list[str]:
    callees: list[str] = []
    for raw_callee in getattr(defn, "calls", set()) or ():
        callee = _resolve_callable_name(
            str(raw_callee),
            callable_names,
            simple_callable_names,
        )
        if not callee:
            continue
        callees.append(callee)
    return callees


def _is_hard_liveness_root(defn: Any) -> bool:
    if getattr(defn, "type", None) not in {"function", "method"}:
        return False
    filename = str(getattr(defn, "filename", ""))
    if filename.endswith("__main__.py"):
        return True
    if bool(getattr(defn, "is_exported", False)):
        return True
    simple_name = str(getattr(defn, "simple_name", ""))
    if simple_name.startswith("test_") or simple_name in _ENTRY_ROOT_NAMES:
        return True
    refs = getattr(defn, "heuristic_refs", {}) or {}
    if not isinstance(refs, dict):
        return False
    for marker in _ROOT_EVIDENCE_MARKERS:
        if marker in refs:
            return True
    return False


def _resolve_callable_name(
    raw_callee: str,
    callable_names: set[str],
    simple_callable_names: dict[str, list[str]],
) -> str:
    if raw_callee in callable_names:
        return raw_callee
    simple = raw_callee.rsplit(".", 1)[-1]
    candidates = simple_callable_names.get(simple, [])
    if len(candidates) == 1:
        return candidates[0]
    return ""


# AST expression helpers


def _iter_simple_assignments(node: ast.AST):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            yield target, node.value
    elif isinstance(node, ast.AnnAssign):
        yield node.target, node.value


def _target_name(target: ast.AST) -> str:
    if isinstance(target, ast.Name):
        return target.id
    return ""


def _split_assignment_pair(target: ast.AST) -> tuple[str | None, str | None]:
    if not isinstance(target, (ast.Tuple, ast.List)) or len(target.elts) != 2:
        return None, None
    left, right = target.elts
    if isinstance(left, ast.Name) and isinstance(right, ast.Name):
        return left.id, right.id
    return None, None


def _split_source_var(value: ast.AST | None) -> str:
    if not isinstance(value, ast.Call):
        return ""
    func = value.func
    if not (
        isinstance(func, ast.Attribute)
        and func.attr == "split"
        and isinstance(func.value, ast.Name)
    ):
        return ""
    if not value.args:
        return ""
    sep = value.args[0]
    if isinstance(sep, ast.Constant) and sep.value == ":":
        return func.value.id
    return ""


def _registry_qname_from_lookup(
    value: ast.AST | None,
    file_key: str,
    definitions_by_file_simple: _DefByFileSimple,
    import_ctx: _ImportContext,
) -> str:
    registry_expr: ast.AST | None = None
    if isinstance(value, ast.Subscript):
        registry_expr = value.value
    elif (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "get"
    ):
        registry_expr = value.func.value

    if registry_expr is None:
        return ""
    return _registry_qname_from_expr(
        registry_expr,
        file_key,
        definitions_by_file_simple,
        import_ctx,
    )


def _registry_qname_from_expr(
    expr: ast.AST,
    file_key: str,
    definitions_by_file_simple: _DefByFileSimple,
    import_ctx: _ImportContext,
) -> str:
    if isinstance(expr, ast.Name):
        alias = import_ctx.name_aliases.get(expr.id)
        if alias:
            return alias
        local_def = definitions_by_file_simple.get((file_key, expr.id))
        if local_def is not None:
            return str(getattr(local_def, "name", ""))
        return ""

    parts = _attribute_parts(expr)
    if len(parts) >= 2 and parts[0] in import_ctx.module_aliases:
        return ".".join([import_ctx.module_aliases[parts[0]], *parts[1:]])
    return ""


def _attribute_parts(expr: ast.AST) -> list[str]:
    parts: list[str] = []
    current = expr
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return list(reversed(parts))
    return []


def _importlib_getattr_split_key(
    node: ast.Call,
    import_ctx: _ImportContext,
) -> tuple[str, str] | None:
    if not (isinstance(node.func, ast.Name) and node.func.id == "getattr"):
        return None
    if len(node.args) < 2:
        return None
    module_call, func_arg = node.args[0], node.args[1]
    if not isinstance(func_arg, ast.Name):
        return None
    module_var = _import_module_arg_name(module_call, import_ctx)
    if not module_var:
        return None
    return module_var, func_arg.id


def _import_module_arg_name(node: ast.AST, import_ctx: _ImportContext) -> str:
    if not isinstance(node, ast.Call) or not node.args:
        return ""
    first_arg = node.args[0]
    if not isinstance(first_arg, ast.Name):
        return ""

    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "import_module":
        value = func.value
        if isinstance(value, ast.Name) and value.id in import_ctx.importlib_names:
            return first_arg.id
    if isinstance(func, ast.Name) and func.id in import_ctx.import_module_names:
        return first_arg.id
    return ""
