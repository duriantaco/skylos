from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Iterable, Sequence

from skylos.deadcode.plugin_registry import _reachable_live_functions
from skylos.deadcode.python_ast import ParsedPythonFile

_TARGET_TYPES = {"class", "function"}
_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _definitions_by_name(definitions: dict[str, Any]) -> dict[str, list[Any]]:
    by_name: dict[str, list[Any]] = {}
    for defn in definitions.values():
        if getattr(defn, "type", None) not in _TARGET_TYPES:
            continue
        if not str(getattr(defn, "filename", "")).endswith((".py", ".pyw")):
            continue
        name = str(getattr(defn, "name", ""))
        if "." in name:
            by_name.setdefault(name, []).append(defn)
    return by_name


# Dynamic ``getattr(import_module(...), ...)`` over literal tables


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            target, value = stmt.target, stmt.value
        else:
            continue
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            constants[target.id] = value.value
    return constants


def _string_tuple(node: ast.AST) -> tuple[str, ...] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if isinstance(node, (ast.Tuple, ast.List)):
        values = []
        for element in node.elts:
            if not (
                isinstance(element, ast.Constant) and isinstance(element.value, str)
            ):
                return None
            values.append(element.value)
        return tuple(values)
    return None


def _literal_tables(tree: ast.Module) -> dict[str, ast.AST]:
    tables: dict[str, ast.AST] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            target, value = stmt.target, stmt.value
        else:
            continue
        if isinstance(target, ast.Name) and isinstance(
            value, (ast.Dict, ast.List, ast.Tuple, ast.Set)
        ):
            tables[target.id] = value
    return tables


def _table_entries(table: ast.AST, view: str) -> list[tuple[str, ...]] | None:
    if isinstance(table, ast.Dict):
        rows = []
        for key, value in zip(table.keys, table.values):
            key_row = None if key is None else _string_tuple(key)
            if key_row is None or len(key_row) != 1:
                return None
            if view == "keys":
                rows.append(key_row)
                continue
            value_row = _string_tuple(value)
            if value_row is None:
                return None
            if view == "values":
                rows.append(value_row)
            elif len(value_row) == 1:
                rows.append((key_row[0], value_row[0]))
            else:
                return None
        return rows
    if view != "keys":
        return None
    rows = []
    for element in table.elts:
        row = _string_tuple(element)
        if row is None:
            return None
        rows.append(row)
    return rows


def _loop_rows(loop: ast.For, tables: dict[str, ast.AST]):
    iterator = loop.iter
    view = "keys"
    if (
        isinstance(iterator, ast.Call)
        and isinstance(iterator.func, ast.Attribute)
        and not iterator.args
        and iterator.func.attr in {"items", "keys", "values"}
    ):
        view = iterator.func.attr
        iterator = iterator.func.value
    if not isinstance(iterator, ast.Name) or iterator.id not in tables:
        return None
    return _table_entries(tables[iterator.id], view)


def _bind_row(target: ast.AST, row: tuple[str, ...]) -> dict[str, str] | None:
    if isinstance(target, ast.Name):
        return {target.id: row[0]} if len(row) == 1 else None
    if isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == len(row):
        bound = {}
        for element, value in zip(target.elts, row):
            if not isinstance(element, ast.Name):
                return None
            bound[element.id] = value
        return bound
    return None


def _evaluate_string(node: ast.AST, env: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif (
                isinstance(value, ast.FormattedValue)
                and value.format_spec is None
                and value.conversion in (-1, None)
            ):
                part = _evaluate_string(value.value, env)
                if part is None:
                    return None
                parts.append(part)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _evaluate_string(node.left, env)
        right = _evaluate_string(node.right, env)
        if left is None or right is None:
            return None
        return left + right
    return None


def _import_module_names(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Names bound to ``import_module`` and to the ``importlib`` module."""
    functions: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    functions.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    modules.add(alias.asname or alias.name)
    return functions, modules


def _import_module_argument(
    node: ast.AST, functions: set[str], modules: set[str]
) -> ast.AST | None:
    if not isinstance(node, ast.Call) or len(node.args) != 1 or node.keywords:
        return None
    func = node.func
    if isinstance(func, ast.Name) and func.id in functions:
        return node.args[0]
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in modules
    ):
        return node.args[0]
    return None


def _loop_lookup_paths(
    loop: ast.For,
    rows: Iterable[tuple[str, ...]],
    constants: dict[str, str],
    functions: set[str],
    modules: set[str],
) -> set[str]:
    body_nodes = [child for stmt in loop.body for child in ast.walk(stmt)]
    module_vars: dict[str, ast.AST] = {}
    lookups: list[ast.Call] = []
    for child in body_nodes:
        if (
            isinstance(child, ast.Assign)
            and len(child.targets) == 1
            and isinstance(child.targets[0], ast.Name)
        ):
            argument = _import_module_argument(child.value, functions, modules)
            if argument is not None:
                module_vars[child.targets[0].id] = argument
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id in {"getattr", "hasattr"}
            and len(child.args) >= 2
        ):
            lookups.append(child)
    if not lookups:
        return set()

    paths: set[str] = set()
    for row in rows:
        bound = _bind_row(loop.target, row)
        if bound is None:
            continue
        env = {**constants, **bound}
        for call in lookups:
            module_node = call.args[0]
            argument = _import_module_argument(module_node, functions, modules)
            if argument is None and isinstance(module_node, ast.Name):
                argument = module_vars.get(module_node.id)
            if argument is None:
                continue
            module_name = _evaluate_string(argument, env)
            attr_name = _evaluate_string(call.args[1], env)
            if not module_name or not attr_name:
                continue
            paths.add(f"{module_name}.{attr_name}")
    return paths


def _loops_with_owner(tree: ast.Module):
    """``for`` loops with their innermost enclosing function, or None for a
    loop that runs at import time (module or class body)."""
    stack: list[tuple[ast.AST, ast.AST | None]] = [(tree, None)]
    while stack:
        node, owner = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _FUNCTION_NODES):
                stack.append((child, child))
                continue
            if isinstance(child, ast.For):
                yield child, owner
            stack.append((child, owner))


def find_dynamic_module_attribute_targets(
    definitions: dict[str, Any],
    parsed_files: Sequence[ParsedPythonFile],
) -> list[Any]:
    """Definitions loaded by ``getattr(import_module(m), n)`` over a table."""
    by_name: dict[str, list[Any]] | None = None
    functions_by_line: dict[tuple[str, int], Any] | None = None
    reachable: set[str] | None = None
    targets: list[Any] = []
    seen: set[int] = set()
    for parsed in parsed_files:
        import_functions, importlib_modules = _import_module_names(parsed.tree)
        if not import_functions and not importlib_modules:
            continue
        tables = _literal_tables(parsed.tree)
        if not tables:
            continue
        constants = _module_string_constants(parsed.tree)
        for loop, owner in _loops_with_owner(parsed.tree):
            rows = _loop_rows(loop, tables)
            if not rows:
                continue
            paths = _loop_lookup_paths(
                loop, rows, constants, import_functions, importlib_modules
            )
            if not paths:
                continue
            if owner is not None:
                if functions_by_line is None:
                    functions_by_line = _functions_by_line(definitions)
                    reachable = _reachable_live_functions(definitions)
                owner_def = functions_by_line.get(
                    (_resolved(parsed.path), owner.lineno)
                )
                if owner_def is None or str(owner_def.name) not in reachable:
                    continue
            if by_name is None:
                by_name = _definitions_by_name(definitions)
            for path in sorted(paths):
                for defn in by_name.get(path, ()):
                    if id(defn) in seen:
                        continue
                    seen.add(id(defn))
                    targets.append(defn)
    return targets


def _resolved(path: Path) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(path)


def _functions_by_line(definitions: dict[str, Any]) -> dict[tuple[str, int], Any]:
    lookup: dict[tuple[str, int], Any] = {}
    for defn in definitions.values():
        if getattr(defn, "type", None) not in {"function", "method"}:
            continue
        try:
            line = int(getattr(defn, "line", 0) or 0)
        except (TypeError, ValueError):
            continue
        lookup.setdefault((_resolved(getattr(defn, "filename", "")), line), defn)
    return lookup
