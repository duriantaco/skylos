"""Decorator factories and tag/collector contracts discovered in source."""

from __future__ import annotations
import ast
from pathlib import Path
from typing import Any, Sequence
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.deadcode._registration_common import (
    _FUNCTION_NODES,
    _resolved,
    _first_param,
    _own_body_nodes,
    _import_aliases,
    _decorator_reference,
)
from skylos.visitors.registration_decorators import (
    collect_local_registration_decorators,
)

_MAX_ALIAS_HOPS = 8


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        ):
            constants[stmt.targets[0].id] = stmt.value.value
    return constants


def _key_value(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _tag_keys_on_param(
    node: ast.FunctionDef | ast.AsyncFunctionDef, constants: dict[str, str]
) -> set[str]:
    param = _first_param(node)
    if param is None:
        return set()
    keys: set[str] = set()
    returns_param = False
    for child in _own_body_nodes(node):
        if isinstance(child, ast.Return):
            if isinstance(child.value, ast.Name) and child.value.id == param:
                returns_param = True
        elif (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id == "setattr"
            and len(child.args) == 3
            and isinstance(child.args[0], ast.Name)
            and child.args[0].id == param
        ):
            key = _key_value(child.args[1], constants)
            if key:
                keys.add(key)
        elif isinstance(child, (ast.Assign, ast.AnnAssign)):
            if isinstance(child, ast.Assign):
                targets = child.targets
            else:
                targets = [child.target]
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == param
                ):
                    keys.add(target.attr)
    if returns_param:
        return keys
    return set()


def _tagging_keys(
    node: ast.FunctionDef | ast.AsyncFunctionDef, constants: dict[str, str]
) -> set[str]:
    """Keys a decorator (or a decorator factory, at any depth) tags with."""
    keys = _tag_keys_on_param(node, constants)
    if keys:
        return keys
    nested = {}
    for stmt in node.body:
        if isinstance(stmt, _FUNCTION_NODES):
            nested[stmt.name] = stmt
    for stmt in node.body:
        if (
            isinstance(stmt, ast.Return)
            and isinstance(stmt.value, ast.Name)
            and stmt.value.id in nested
        ):
            keys |= _tagging_keys(nested[stmt.value.id], constants)
    return keys


def _collected_keys(tree: ast.Module, constants: dict[str, str]) -> set[str]:
    keys: set[str] = set()

    def scan(target: ast.AST, nodes) -> None:
        names = set()
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.add(node.id)
        if not names:
            return
        for root in nodes:
            for child in ast.walk(root):
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Name)
                    and child.func.id in {"getattr", "hasattr"}
                    and len(child.args) >= 2
                    and isinstance(child.args[0], ast.Name)
                    and child.args[0].id in names
                ):
                    key = _key_value(child.args[1], constants)
                    if key:
                        keys.add(key)

    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            scan(node.target, node.body)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            for generator in node.generators:
                scan(generator.target, [node.elt, *generator.ifs])
        elif isinstance(node, ast.DictComp):
            for generator in node.generators:
                scan(generator.target, [node.key, node.value, *generator.ifs])
    return keys


def find_registered_decorator_targets(
    definitions: dict[str, Any],
    parsed_files: Sequence[ParsedPythonFile],
    module_names: dict[str, str] | None = None,
) -> list[Any]:
    resolved_files: dict[Path, str] = {}
    modules_by_file = {}
    for path, name in (module_names or {}).items():
        modules_by_file[_resolved(Path(path), resolved_files)] = name

    file_info = []
    registration: dict[str, set[str]] = {}  # leaf name -> qualified names
    tagging: dict[str, dict[str, set[str]]] = {}  # leaf -> {qualified: keys}
    collected: set[str] = set()
    aliases: dict[str, str] = {}
    for parsed in parsed_files:
        file_key = _resolved(parsed.path, resolved_files)
        module = modules_by_file.get(file_key, "")
        names, modules = _import_aliases(parsed.tree, module or None, parsed.path)
        file_info.append((parsed, file_key, module, names, modules))
        if module:
            for local, target in names.items():
                aliases[f"{module}.{local}"] = target
        constants = _module_string_constants(parsed.tree)
        collected |= _collected_keys(parsed.tree, constants)

        def qualified(name: str) -> str:
            if module:
                return f"{module}.{name}"
            return name

        for name in collect_local_registration_decorators(parsed.tree):
            registration.setdefault(name, set()).add(qualified(name))
        local_tagging: dict[str, set[str]] = {}
        for stmt in parsed.tree.body:
            if isinstance(stmt, _FUNCTION_NODES):
                keys = _tagging_keys(stmt, constants)
                if keys:
                    local_tagging[stmt.name] = keys
            elif (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ):
                # ``parse_frame = _parse_frame_factory(KIND)`` or a plain alias.
                value = stmt.value
                while isinstance(value, ast.Call):
                    value = value.func
                if isinstance(value, ast.Name) and value.id in local_tagging:
                    local_tagging[stmt.targets[0].id] = local_tagging[value.id]
        for name, keys in local_tagging.items():
            tagging.setdefault(name, {})[qualified(name)] = keys

    live_tagging: dict[str, set[str]] = {}
    for leaf, entries in tagging.items():
        for qualified_name, keys in entries.items():
            if keys & collected:
                live_tagging.setdefault(leaf, set()).add(qualified_name)
    factories: dict[str, set[str]] = {}
    for source in (registration, live_tagging):
        for leaf, qualified_names in source.items():
            factories.setdefault(leaf, set()).update(qualified_names)
    if not factories:
        return []
    known = set()
    for names in factories.values():
        known.update(names)

    def resolve(name: str | None) -> str | None:
        for _ in range(_MAX_ALIAS_HOPS):
            if name is None or name in known:
                return name
            name = aliases.get(name)
        return None

    defs_by_line: dict[tuple[str, int], Any] = {}
    for defn in definitions.values():
        if getattr(defn, "type", None) not in {"function", "method"}:
            continue
        try:
            path = Path(getattr(defn, "filename", ""))
            line = int(getattr(defn, "line", 0) or 0)
        except (TypeError, ValueError):
            continue
        defs_by_line.setdefault((_resolved(path, resolved_files), line), defn)

    targets: list[Any] = []
    seen: set[int] = set()
    for parsed, file_key, module, names, modules in file_info:
        for node in ast.walk(parsed.tree):
            if not isinstance(node, _FUNCTION_NODES) or not node.decorator_list:
                continue
            for decorator in node.decorator_list:
                leaf, qualified_name = _decorator_reference(
                    decorator, names, modules, module
                )
                candidates = factories.get(leaf)
                if not candidates:
                    continue
                if module_names:
                    if resolve(qualified_name) is None:
                        continue
                elif len(candidates) != 1:
                    continue
                defn = defs_by_line.get((file_key, node.lineno))
                if defn is not None and id(defn) not in seen:
                    seen.add(id(defn))
                    targets.append(defn)
                break
    return targets
