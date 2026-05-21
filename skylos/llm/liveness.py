from __future__ import annotations

import ast
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._grounding import (
    SymbolDef,
    _ParsedFile,
    _ProjectGraph,
    _build_call_edges,
    _dotted_name,
    _norm_path,
    _parse_project_graph,
    read_bounded_bytes,
)


MAX_CONFIG_BYTES = 256_000
MAX_TRACE_DEPTH = 5
MAX_TRACE_BRANCHING = 6

ENTRYPOINT_BASENAMES = {
    "__main__.py",
    "app.py",
    "asgi.py",
    "cli.py",
    "main.py",
    "manage.py",
    "server.py",
    "tasks.py",
    "wsgi.py",
}

DYNAMIC_ENTRY_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "command",
    "callback",
    "task",
}


@dataclass(frozen=True)
class SymbolLiveness:
    symbol: SymbolDef
    reachable: bool
    traces: tuple[str, ...] = ()


@dataclass
class LivenessIndex:
    symbols: dict[str, SymbolLiveness]
    by_short_name: dict[str, list[str]]
    has_entrypoints: bool

    def resolve_symbol(
        self, symbol: str | None, file_path: str | Path | None = None, line: int = 0
    ) -> SymbolLiveness | None:
        path = _norm_path(file_path) if file_path else ""
        name = (symbol or "").strip()

        if name:
            resolved = self._resolve_named_symbol(name, path, line)
            if resolved:
                return resolved

        if path and line:
            return self.owner_at(path, line)
        return None

    def owner_at(self, file_path: str | Path, line: int) -> SymbolLiveness | None:
        path = _norm_path(file_path)
        best: SymbolLiveness | None = None
        for item in self.symbols.values():
            symbol = item.symbol
            if symbol.path != path:
                continue
            if symbol.line <= line <= max(symbol.line, symbol.end_line):
                if best is None or symbol.line >= best.symbol.line:
                    best = item
        return best

    def _resolve_named_symbol(
        self, name: str, path: str, line: int
    ) -> SymbolLiveness | None:
        candidates = self._symbol_candidates(name)
        if path:
            same_file = self._same_file_candidates(candidates, path)
            if line:
                owner = self.owner_at(path, line)
                if owner and owner.symbol.name in same_file:
                    return owner
            if same_file:
                return self.symbols[same_file[0]]
        if candidates:
            return self.symbols[candidates[0]]
        return None

    def _symbol_candidates(self, name: str) -> list[str]:
        candidates = []
        if name in self.symbols:
            candidates.append(name)
        for candidate in self.by_short_name.get(name.split(".")[-1], []):
            if candidate not in candidates:
                candidates.append(candidate)
        return candidates

    def _same_file_candidates(self, candidates: list[str], path: str) -> list[str]:
        return [
            candidate
            for candidate in candidates
            if self.symbols[candidate].symbol.path == path
        ]


def build_liveness_index(
    project_root: str | Path,
    files: list[str | Path],
    *,
    entrypoint_paths: set[str] | None = None,
) -> LivenessIndex:
    graph = _parse_project_graph(project_root, files)
    call_edges, _reverse_edges = _build_call_edges(graph)
    roots = _liveness_roots(graph, entrypoint_paths)
    reachable, traces = _walk_reachable_symbols(roots, call_edges)
    return _index_symbols(graph.symbols, reachable, traces, has_entrypoints=bool(roots))


def _liveness_roots(
    graph: _ProjectGraph, entrypoint_paths: set[str] | None
) -> list[str]:
    selected_entrypoints = entrypoint_paths or _conventional_entrypoint_paths(graph)
    roots = _path_entry_roots(graph.parsed, selected_entrypoints)
    roots.extend(_decorator_entry_roots(graph.parsed))
    roots.extend(_string_reference_roots(graph.parsed, graph.symbols))
    roots.extend(_pyproject_entry_roots(graph.root, graph.symbols))
    return sorted(set(roots))


def _conventional_entrypoint_paths(graph: _ProjectGraph) -> set[str]:
    return {
        _norm_path(path)
        for path in graph.file_paths
        if path.name.lower() in ENTRYPOINT_BASENAMES
        and _norm_path(path) not in graph.test_paths
    }


def _path_entry_roots(
    parsed: dict[str, _ParsedFile], entrypoint_paths: set[str]
) -> list[str]:
    return [
        symbol.name
        for parsed_file in parsed.values()
        if parsed_file.path in entrypoint_paths
        for symbol in parsed_file.defs
        if symbol.kind in {"function", "method"}
    ]


def _decorator_entry_roots(parsed: dict[str, _ParsedFile]) -> list[str]:
    roots: list[str] = []
    for parsed_file in parsed.values():
        roots.extend(_decorated_defs(parsed_file))
    return roots


def _decorated_defs(parsed_file: _ParsedFile) -> list[str]:
    roots: list[str] = []
    for node in getattr(parsed_file.tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _has_entry_decorator(node.decorator_list):
                roots.append(f"{parsed_file.module}.{node.name}")
        elif isinstance(node, ast.ClassDef):
            roots.extend(_decorated_methods(parsed_file, node))
    return roots


def _decorated_methods(parsed_file: _ParsedFile, node: ast.ClassDef) -> list[str]:
    class_name = f"{parsed_file.module}.{node.name}"
    return [
        f"{class_name}.{item.name}"
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _has_entry_decorator(item.decorator_list)
    ]


def _has_entry_decorator(decorators: list[ast.expr]) -> bool:
    for decorator in decorators:
        name = _dotted_name(decorator)
        if name and name.split(".")[-1] in DYNAMIC_ENTRY_DECORATORS:
            return True
    return False


def _string_reference_roots(
    parsed: dict[str, _ParsedFile], symbols: dict[str, SymbolDef]
) -> list[str]:
    roots: list[str] = []
    for parsed_file in parsed.values():
        for node in ast.walk(parsed_file.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                roots.extend(_matched_string_targets(node.value, symbols))
    return roots


def _matched_string_targets(value: str, symbols: dict[str, SymbolDef]) -> list[str]:
    candidates = [value.strip()]
    if ":" in value:
        module, name = value.split(":", 1)
        candidates.append(f"{module}.{name}".strip("."))
    return [candidate for candidate in candidates if candidate in symbols]


def _pyproject_entry_roots(root: Path, symbols: dict[str, SymbolDef]) -> list[str]:
    data = _load_pyproject(root)
    if not isinstance(data, dict):
        return []
    return _entrypoint_targets(_pyproject_script_values(data), symbols)


def _load_pyproject(root: Path) -> dict[str, Any] | None:
    data = read_bounded_bytes(root / "pyproject.toml", MAX_CONFIG_BYTES, root=root)
    if data is None:
        return None
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return None


def _pyproject_script_values(data: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        values.extend(_table_values(project, "scripts"))
        values.extend(_table_values(project, "gui-scripts"))

    poetry = data.get("tool", {}).get("poetry", {})
    if isinstance(poetry, dict):
        values.extend(_table_values(poetry, "scripts"))
    return values


def _table_values(parent: dict[str, Any], key: str) -> list[Any]:
    table = parent.get(key, {})
    return list(table.values()) if isinstance(table, dict) else []


def _entrypoint_targets(values: list[Any], symbols: dict[str, SymbolDef]) -> list[str]:
    roots: list[str] = []
    for raw in values:
        target = _entrypoint_target(raw)
        if target in symbols:
            roots.append(target)
    return roots


def _entrypoint_target(raw: Any) -> str:
    target = raw
    if isinstance(raw, dict):
        target = raw.get("callable") or raw.get("reference")
    if not isinstance(target, str):
        return ""
    return target.split("[", 1)[0].strip().replace(":", ".")


def _walk_reachable_symbols(
    roots: list[str], call_edges: dict[str, set[str]]
) -> tuple[set[str], dict[str, list[str]]]:
    reachable: set[str] = set()
    traces: dict[str, list[str]] = defaultdict(list)
    queue = deque((root, [root]) for root in sorted(set(roots)))

    while queue:
        current, path = queue.popleft()
        if current in reachable and len(path) > 1:
            continue
        reachable.add(current)
        if len(path) > 1:
            traces[current].append(" -> ".join(path))
        if len(path) >= MAX_TRACE_DEPTH:
            continue
        for child in sorted(call_edges.get(current, set()))[:MAX_TRACE_BRANCHING]:
            if child not in path:
                queue.append((child, [*path, child]))

    return reachable, traces


def _index_symbols(
    raw_symbols: dict[str, SymbolDef],
    reachable: set[str],
    traces: dict[str, list[str]],
    *,
    has_entrypoints: bool,
) -> LivenessIndex:
    by_short_name: dict[str, list[str]] = defaultdict(list)
    symbols: dict[str, SymbolLiveness] = {}
    for name, symbol in raw_symbols.items():
        by_short_name[name.split(".")[-1]].append(name)
        symbols[name] = SymbolLiveness(
            symbol=symbol,
            reachable=name in reachable,
            traces=tuple(traces.get(name, ())),
        )

    return LivenessIndex(
        symbols=symbols,
        by_short_name={key: sorted(value) for key, value in by_short_name.items()},
        has_entrypoints=has_entrypoints,
    )
