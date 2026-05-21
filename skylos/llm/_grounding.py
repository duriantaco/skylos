from __future__ import annotations

import ast
import os
import stat
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

MAX_SOURCE_BYTES = 1_000_000
MAX_CALL_FACTS = 6
MAX_TRACE_FACTS = 4
MAX_TRACE_DEPTH = 5
MAX_TRACE_BRANCHING = 6


@dataclass(frozen=True)
class SymbolDef:
    name: str
    path: str
    line: int
    end_line: int
    kind: str


@dataclass
class _ParsedFile:
    path: str
    module: str
    tree: ast.AST
    import_aliases: dict[str, str] = field(default_factory=dict)
    local_symbols: dict[str, str] = field(default_factory=dict)
    defs: list[SymbolDef] = field(default_factory=list)
    raw_calls: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))


@dataclass
class _ProjectGraph:
    root: Path
    file_paths: list[Path]
    test_paths: set[str]
    parsed: dict[str, _ParsedFile]
    symbols: dict[str, SymbolDef]


def build_grounding_context(
    project_root: str | Path,
    files: list[str | Path],
    *,
    entrypoint_paths: set[str] | None = None,
    related_tests_by_path: dict[str, list[str]] | None = None,
) -> dict[str, list[str]]:
    """Build bounded static graph facts for LLM repo context.

    This intentionally stays conservative: only local Python symbols resolved through
    direct definitions and imports are emitted. Dynamic dispatch and framework magic
    are not modeled.
    """

    graph = _parse_project_graph(project_root, files)
    call_edges, reverse_edges = _build_call_edges(graph, include_reverse=True)

    facts_by_path: dict[str, list[str]] = {path: [] for path in graph.parsed}
    _add_call_facts(facts_by_path, graph.parsed, call_edges, reverse_edges)
    _add_trace_facts(
        facts_by_path,
        graph.parsed,
        call_edges,
        graph.symbols,
        entrypoint_paths=entrypoint_paths or set(),
    )
    _add_related_test_facts(facts_by_path, related_tests_by_path or {})

    for path, facts in list(facts_by_path.items()):
        if facts:
            facts.append(
                "- graph evidence: static_ast/import_graph; partial graph, dynamic dispatch not modeled"
            )
            facts_by_path[path] = facts[: MAX_CALL_FACTS + MAX_TRACE_FACTS + 3]

    return facts_by_path


def _parse_project_graph(
    project_root: str | Path, files: list[str | Path]
) -> _ProjectGraph:
    root = Path(project_root).resolve()
    file_paths = [Path(path).resolve() for path in files if Path(path).suffix == ".py"]
    test_paths = {_norm_path(path) for path in file_paths if _is_test_path(path)}
    module_by_path = {_norm_path(path): _module_name(root, path) for path in file_paths}
    path_by_module = {module: path for path, module in module_by_path.items() if module}

    parsed: dict[str, _ParsedFile] = {}
    symbols: dict[str, SymbolDef] = {}
    for file_path in file_paths:
        parsed_file = _parse_file(
            file_path, module_by_path[_norm_path(file_path)], root
        )
        if not parsed_file:
            continue
        parsed[parsed_file.path] = parsed_file
        for symbol in parsed_file.defs:
            symbols[symbol.name] = symbol

    for parsed_file in parsed.values():
        _resolve_import_aliases(parsed_file, path_by_module, symbols)

    return _ProjectGraph(
        root=root,
        file_paths=file_paths,
        test_paths=test_paths,
        parsed=parsed,
        symbols=symbols,
    )


def _build_call_edges(
    graph: _ProjectGraph, *, include_reverse: bool = False
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    call_edges: dict[str, set[str]] = defaultdict(set)
    reverse_edges: dict[str, set[str]] = defaultdict(set)
    for parsed_file in graph.parsed.values():
        if parsed_file.path in graph.test_paths:
            continue
        for source, raw_calls in parsed_file.raw_calls.items():
            for raw_call in raw_calls:
                target = _resolve_call(raw_call, parsed_file, graph.symbols)
                if target and target != source:
                    call_edges[source].add(target)
                    if include_reverse:
                        reverse_edges[target].add(source)
    return call_edges, reverse_edges


def _parse_file(file_path: Path, module: str, root: Path) -> _ParsedFile | None:
    source_bytes = read_bounded_bytes(file_path, MAX_SOURCE_BYTES, root=root)
    if source_bytes is None:
        return None
    try:
        source = source_bytes.decode("utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return None

    parsed = _ParsedFile(path=_norm_path(file_path), module=module, tree=tree)
    parsed.local_symbols = _collect_defs(parsed, tree)
    parsed.defs = [
        SymbolDef(name=name, path=parsed.path, line=line, end_line=end_line, kind=kind)
        for name, line, end_line, kind in _iter_defs(parsed, tree)
    ]
    parsed.raw_calls = _collect_calls(parsed, tree)
    return parsed


def _collect_defs(parsed: _ParsedFile, tree: ast.AST) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for name, _line, _end_line, _kind in _iter_defs(parsed, tree):
        short = name.removeprefix(f"{parsed.module}.")
        symbols[short] = name
        symbols[short.split(".")[-1]] = name
    return symbols


def _iter_defs(parsed: _ParsedFile, tree: ast.AST):
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield (
                f"{parsed.module}.{node.name}",
                node.lineno,
                getattr(node, "end_lineno", node.lineno),
                "function",
            )
        elif isinstance(node, ast.ClassDef):
            class_name = f"{parsed.module}.{node.name}"
            yield class_name, node.lineno, getattr(node, "end_lineno", node.lineno), "class"
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield (
                        f"{class_name}.{item.name}",
                        item.lineno,
                        getattr(item, "end_lineno", item.lineno),
                        "method",
                    )


def _collect_calls(parsed: _ParsedFile, tree: ast.AST) -> dict[str, set[str]]:
    calls: dict[str, set[str]] = defaultdict(set)
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = f"{parsed.module}.{node.name}"
            calls[owner].update(_calls_in_node(node))
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = f"{parsed.module}.{node.name}.{item.name}"
                    calls[owner].update(_calls_in_node(item))
    return calls


def _calls_in_node(node: ast.AST) -> set[str]:
    calls: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _dotted_name(child.func)
            if name:
                calls.add(name)
    return calls


def _resolve_import_aliases(
    parsed: _ParsedFile,
    path_by_module: dict[str, str],
    symbols: dict[str, SymbolDef],
) -> None:
    for node in ast.walk(parsed.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name
                local = alias.asname or module.split(".", 1)[0]
                if _known_module_or_parent(module, path_by_module):
                    parsed.import_aliases[local] = module
        elif isinstance(node, ast.ImportFrom):
            module = _resolve_from_module(parsed.module, node.module or "", node.level)
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                imported_symbol = f"{module}.{alias.name}".strip(".")
                imported_module = imported_symbol if imported_symbol in path_by_module else module
                if imported_symbol in symbols:
                    parsed.import_aliases[local] = imported_symbol
                elif imported_module in path_by_module:
                    parsed.import_aliases[local] = imported_module


def _resolve_call(
    raw_call: str,
    parsed: _ParsedFile,
    symbols: dict[str, SymbolDef],
) -> str | None:
    if raw_call in parsed.local_symbols:
        return parsed.local_symbols[raw_call]

    parts = raw_call.split(".")
    first = parts[0]
    if first in parsed.import_aliases:
        mapped = parsed.import_aliases[first]
        suffix = ".".join(parts[1:])
        candidate = f"{mapped}.{suffix}" if suffix else mapped
        if candidate in symbols:
            return candidate

    local_candidate = f"{parsed.module}.{raw_call}"
    if local_candidate in symbols:
        return local_candidate

    return None


def _add_call_facts(
    facts_by_path: dict[str, list[str]],
    parsed: dict[str, _ParsedFile],
    call_edges: dict[str, set[str]],
    reverse_edges: dict[str, set[str]],
) -> None:
    for path, parsed_file in parsed.items():
        file_symbols = [symbol.name for symbol in parsed_file.defs]

        caller_facts: list[str] = []
        for symbol in file_symbols:
            for caller in sorted(reverse_edges.get(symbol, set())):
                caller_facts.append(f"{caller} -> {symbol}")
        if caller_facts:
            facts_by_path[path].append(
                "- graph callers: " + "; ".join(caller_facts[:MAX_CALL_FACTS])
            )

        callee_facts: list[str] = []
        for symbol in file_symbols:
            for callee in sorted(call_edges.get(symbol, set())):
                callee_facts.append(f"{symbol} -> {callee}")
        if callee_facts:
            facts_by_path[path].append(
                "- graph callees: " + "; ".join(callee_facts[:MAX_CALL_FACTS])
            )


def _add_trace_facts(
    facts_by_path: dict[str, list[str]],
    parsed: dict[str, _ParsedFile],
    call_edges: dict[str, set[str]],
    symbols: dict[str, SymbolDef],
    *,
    entrypoint_paths: set[str],
) -> None:
    traces_by_path: dict[str, list[str]] = defaultdict(list)
    seen_by_path: dict[str, set[str]] = defaultdict(set)

    entry_symbols = [
        symbol.name
        for parsed_file in parsed.values()
        if parsed_file.path in entrypoint_paths
        for symbol in parsed_file.defs
        if symbol.kind in {"function", "method"}
    ]

    for entry_symbol in sorted(entry_symbols):
        for path in _walk_paths(entry_symbol, call_edges):
            if len(path) < 3:
                continue
            trace = " -> ".join(path)
            for symbol_name in path[1:]:
                symbol = symbols.get(symbol_name)
                if not symbol:
                    continue
                if trace in seen_by_path[symbol.path]:
                    continue
                seen_by_path[symbol.path].add(trace)
                traces_by_path[symbol.path].append(trace)

    for path, traces in traces_by_path.items():
        if traces:
            facts_by_path[path].append(
                "- graph entrypoint traces: " + "; ".join(traces[:MAX_TRACE_FACTS])
            )


def _walk_paths(entry_symbol: str, call_edges: dict[str, set[str]]) -> list[list[str]]:
    paths: list[list[str]] = []
    queue = deque([[entry_symbol]])

    while queue and len(paths) < MAX_TRACE_FACTS * 8:
        path = queue.popleft()
        source = path[-1]
        children = sorted(call_edges.get(source, set()))[:MAX_TRACE_BRANCHING]
        if not children or len(path) >= MAX_TRACE_DEPTH:
            if len(path) > 1:
                paths.append(path)
            continue
        for child in children:
            if child in path:
                continue
            next_path = [*path, child]
            paths.append(next_path)
            queue.append(next_path)

    return paths


def _add_related_test_facts(
    facts_by_path: dict[str, list[str]],
    related_tests_by_path: dict[str, list[str]],
) -> None:
    for path, tests in related_tests_by_path.items():
        if path in facts_by_path and tests:
            names = [Path(test).name for test in tests[:4]]
            facts_by_path[path].append("- graph related tests: " + ", ".join(names))


def _resolve_from_module(current_module: str, module: str, level: int) -> str:
    if not level:
        return module
    base_parts = current_module.split(".")
    keep = max(0, len(base_parts) - level)
    prefix = ".".join(base_parts[:keep])
    return f"{prefix}.{module}".strip(".") if module else prefix


def _known_module_or_parent(module: str, path_by_module: dict[str, str]) -> bool:
    parts = module.split(".")
    for i in range(len(parts), 0, -1):
        if ".".join(parts[:i]) in path_by_module:
            return True
    return False


def _module_name(project_root: Path, file_path: Path) -> str:
    try:
        rel = file_path.resolve().relative_to(project_root.resolve())
    except ValueError:
        rel = Path(file_path.name)
    parts = list(rel.parts)
    if not parts:
        return file_path.stem
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = Path(parts[-1]).stem
    return ".".join(p for p in parts if p)


def _dotted_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def read_bounded_bytes(
    path: str | Path, max_bytes: int, *, root: str | Path
) -> bytes | None:
    candidate = _resolve_bounded_read_path(path, root)
    if candidate is None:
        return None

    try:
        mode = candidate.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            return None

        flags = os.O_RDONLY
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow

        fd = os.open(  # skylos: ignore[SKY-D215] validated bounded path
            candidate, flags
        )
    except OSError:
        return None

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            return None
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            return None
        return data
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _resolve_bounded_read_path(path: str | Path, root: str | Path) -> Path | None:
    candidate = Path(path)
    try:
        if candidate.is_symlink():
            return None
        resolved_root = Path(root).resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError):
        return None
    return resolved


def _norm_path(path: str | Path) -> str:
    try:
        return str(Path(path).resolve())
    except Exception:
        return str(path)


def _is_test_path(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith("test_") or name.endswith("_test.py") or "tests" in path.parts
