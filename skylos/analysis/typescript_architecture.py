"""Build file-level architecture inputs from discovered TypeScript/JavaScript files.

The import graph is supplied by the existing TypeScript resolver. Only files
already selected by discovery participate, so excluded dependencies cannot
silently enter the architecture report.
"""

from __future__ import annotations

import os
import stat
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Mapping

from skylos.visitors.languages.typescript.core import TypeScriptCore


_TS_JS_SUFFIXES = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"}
)
_MAX_SOURCE_BYTES = 2_000_000
_FUNCTION_NODES = frozenset({"function_declaration", "generator_function_declaration"})


def _selected_file(path: str | Path, root: Path) -> Path | None:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    if candidate.suffix.lower() not in _TS_JS_SUFFIXES or candidate.is_symlink():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError, RuntimeError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def _module_names(paths: set[Path], root: Path) -> dict[Path, str]:
    by_base: dict[str, list[Path]] = defaultdict(list)
    for path in paths:
        relative = path.relative_to(root)
        base = ".".join(relative.with_suffix("").parts)
        by_base[base].append(path)

    names: dict[Path, str] = {}
    reserved = set(by_base)
    used: set[str] = set()
    for base, group in sorted(by_base.items()):
        if len(group) == 1:
            names[group[0]] = base
            used.add(base)

    for base, group in sorted(by_base.items()):
        if len(group) == 1:
            continue
        for path in sorted(group):
            candidate = f"{base}__{path.suffix[1:].lower()}"
            while candidate in used or candidate in reserved:
                candidate += "_"
            names[path] = candidate
            used.add(candidate)
    return names


def _read_source(path: Path) -> bytes | None:
    # O_NOFOLLOW prevents a changed final path from redirecting a source read;
    # O_NONBLOCK avoids hanging if a source file is replaced with a FIFO.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(_MAX_SOURCE_BYTES + 1)
        return data if len(data) <= _MAX_SOURCE_BYTES else None
    except OSError:
        return None
    finally:
        os.close(fd)


def _abstractness(source: bytes, path: Path) -> dict | None:
    parsed = TypeScriptCore(str(path), source)
    root = parsed.root_node
    if root is None or root.has_error:
        return None

    total_classes = abstract_classes = total_functions = protocols = 0
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "interface_declaration":
            total_classes += 1
            abstract_classes += 1
            protocols += 1
        elif node.type == "abstract_class_declaration":
            total_classes += 1
            abstract_classes += 1
        elif node.type == "class_declaration":
            total_classes += 1
        elif node.type in _FUNCTION_NODES:
            total_functions += 1
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in {
                "arrow_function",
                "function_expression",
            }:
                total_functions += 1
        stack.extend(node.named_children)

    total = total_classes + total_functions
    return {
        "abstractness": abstract_classes / total if total else 0.0,
        "total_classes": total_classes,
        "abstract_classes": abstract_classes,
        "total_functions": total_functions,
        "abstract_methods": 0,
        "type_vars": 0,
        "protocols": protocols,
    }


def build_ts_architecture_inputs(
    files: Iterable[str | Path],
    root: str | Path,
    ts_importers_of: Mapping[str | Path, Iterable[str | Path]],
) -> tuple[dict[str, set[str]], dict[str, str], dict[str, dict], dict[str, int]]:
    """Return graph, module paths, abstractness and LOC for scanned TS/JS files.

    ``ts_importers_of`` maps a resolved target path to its importing paths.
    Both endpoints must occur in ``files``; package and tsconfig resolution is
    deliberately left to the existing import resolver.
    """
    try:
        project_root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError):
        return {}, {}, {}, {}

    selected = {
        selected_file
        for file in files
        if (selected_file := _selected_file(file, project_root)) is not None
    }
    names = _module_names(selected, project_root)
    graph = {name: set() for name in names.values()}
    module_files = {name: str(path) for path, name in names.items()}
    module_abstractness: dict[str, dict] = {}
    module_loc: dict[str, int] = {}

    for target, importers in ts_importers_of.items():
        target_path = _selected_file(target, project_root)
        if target_path not in names:
            continue
        target_name = names[target_path]
        for importer in importers:
            importer_path = _selected_file(importer, project_root)
            if importer_path in names and importer_path != target_path:
                graph[names[importer_path]].add(target_name)

    for path, name in names.items():
        source = _read_source(path)
        # Supplying LOC even for unreadable/oversize files prevents the generic
        # architecture analyzer from falling back to an unbounded source read.
        module_loc[name] = (
            sum(1 for line in source.splitlines() if line.strip())
            if source is not None
            else 0
        )
        if source is not None:
            abstraction = _abstractness(source, path)
            if abstraction is not None:
                module_abstractness[name] = abstraction

    return graph, module_files, module_abstractness, module_loc
