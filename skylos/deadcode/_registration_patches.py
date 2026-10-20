"""Executed patches exporting an instance through an external module."""

from __future__ import annotations
import ast
from pathlib import Path
from typing import Any, Sequence
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.deadcode._reachability_bindings import bound_names
from skylos.deadcode._registration_common import (
    _FUNCTION_NODES,
    _resolved,
    _attribute_root,
    _executed_nodes,
)
from skylos.deadcode._registration_receivers import _RegistrationReceivers


def _external_module_aliases(tree: ast.Module, project_roots: set[str]) -> set[str]:
    aliases: set[str] = set()
    counts = bound_names(tree.body).counts
    for stmt in tree.body:
        if not isinstance(stmt, ast.Import):
            continue
        for alias in stmt.names:
            if alias.name.split(".", 1)[0] in project_roots:
                continue
            name = alias.asname or alias.name.split(".", 1)[0]
            if counts[name] == 1:
                aliases.add(name)
    return aliases


def find_patched_instance_methods(
    definitions: dict[str, Any],
    parsed_files: Sequence[ParsedPythonFile],
) -> list[Any]:
    project_roots: set[str] = set()
    classes_by_file_name: dict[tuple[str, str], Any] = {}
    methods_by_owner: dict[str, list[Any]] = {}
    resolved_files: dict[Path, str] = {}
    for defn in definitions.values():
        kind = getattr(defn, "type", None)
        name = str(getattr(defn, "name", ""))
        if kind in {"class", "function", "variable", "method"} and name:
            project_roots.add(name.split(".", 1)[0])
        if kind == "class":
            file_key = _resolved(Path(getattr(defn, "filename", "")), resolved_files)
            classes_by_file_name[(file_key, getattr(defn, "simple_name", ""))] = defn
        elif kind == "method" and "." in name:
            methods_by_owner.setdefault(name.rsplit(".", 1)[0], []).append(defn)
    if not classes_by_file_name:
        return []

    receivers = _RegistrationReceivers(definitions, parsed_files)
    reachable = None
    executed = {}
    targets: list[Any] = []
    seen: set[int] = set()
    for parsed in parsed_files:
        external = _external_module_aliases(parsed.tree, project_roots)
        if not external:
            continue
        file_key = _resolved(parsed.path, resolved_files)
        receivers.prepare(parsed)
        for stmt in ast.walk(parsed.tree):
            if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
                continue
            if _attribute_root(stmt.targets[0]) not in external:
                continue
            context = receivers.context(stmt)
            enclosing = context
            owner = None
            while enclosing is not None:
                if isinstance(enclosing, _FUNCTION_NODES):
                    owner = enclosing
                    break
                enclosing = receivers.context(enclosing)
            if owner is not None:
                if reachable is None:
                    reachable = receivers.reachable_functions(definitions)
                if owner not in reachable:
                    continue
                root = _attribute_root(stmt.targets[0])
                local, scope = receivers._lookup(root, context)
                if not isinstance(local, ast.Import) or not isinstance(
                    scope, ast.Module
                ):
                    continue
            execution_owner = owner or parsed.tree
            if execution_owner not in executed:
                executed[execution_owner] = set(_executed_nodes(execution_owner.body))
            if stmt not in executed[execution_owner]:
                continue
            value = stmt.value
            if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)):
                continue
            class_def = classes_by_file_name.get((file_key, value.func.id))
            if class_def is None:
                continue
            actual = receivers.resolve(value, context)
            if actual is None or actual[0].lineno != class_def.line:
                continue
            for method in methods_by_owner.get(str(class_def.name), ()):
                simple = str(getattr(method, "simple_name", ""))
                if not simple or simple.startswith("_") or id(method) in seen:
                    continue
                seen.add(id(method))
                targets.append(method)
    return targets
