from __future__ import annotations

import ast
import builtins
import collections
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from skylos.changemap.facts import (
    FUNCTION_NODES,
    class_attributes,
    dependencies_of,
    dotted,
    guards_of,
    params_of,
    rejections_of,
)
from skylos.visitors.base import Visitor

KIND_FUNCTION = "function"
KIND_METHOD = "method"
KIND_CLASS = "class"
_GRAPH_KINDS = frozenset({KIND_FUNCTION, KIND_METHOD, KIND_CLASS})
_BUILTIN_NAMES = frozenset(dir(builtins))
_BUILTIN_TYPES = frozenset({"dict", "list", "set", "str", "tuple", "bytes", "int", "float", "frozenset"})
_EXCEPTION_NAME = re.compile(r"(?:Error|Exception|Warning)$")


@dataclass
class Symbol:
    qual: str
    full_name: str
    kind: str
    start: int
    end: int
    signature: str
    decorators: list[str]
    node: ast.AST = field(repr=False, compare=False)
    calls: set[str] = field(default_factory=set)
    owned_lines: set[int] = field(default_factory=set)
    guards: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    params: tuple = ()
    attributes: dict[str, str] = field(default_factory=dict)
    reads: set[str] = field(default_factory=set)
    rejections: list[str] = field(default_factory=list)
    cached_shape: str | None = field(default=None, repr=False, compare=False)

    @property
    def shape(self) -> str:
        if self.cached_shape is None:
            if self.kind == KIND_CLASS:
                self.cached_shape = _class_shell(self.node)
            else:
                self.cached_shape = _shape(self.node)
        return self.cached_shape


@dataclass
class ParsedFile:
    module: str
    symbols: dict[str, Symbol]
    graph: dict[str, set[str]]
    nodes: dict[str, ast.AST]
    assignments: dict[str, tuple[int, int, str]] = field(default_factory=dict)
    imported: set[str] = field(default_factory=set)
    language: str = "python"
    call_sites: dict[str, dict[str, int]] = field(default_factory=dict)
    call_shapes: dict[str, dict[str, list]] = field(default_factory=dict)
    unresolved: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    star_from: list[str] = field(default_factory=list)


def owner_of(name: str, full_names) -> str | None:
    candidate = name
    while candidate:
        if candidate in full_names:
            return candidate
        if "." not in candidate:
            return None
        candidate = candidate.rsplit(".", 1)[0]
    return None


def _field_signature(params: tuple) -> str:
    return ", ".join(name + ("=..." * has_default) for _, name, has_default in params)


def _signature(node: ast.AST) -> str:
    if isinstance(node, ast.ClassDef):
        return _field_signature(params_of(node))
    if not isinstance(node, FUNCTION_NODES):
        return ""
    text = ast.unparse(node.args)
    if node.returns is not None:
        text += " -> " + ast.unparse(node.returns)
    return text


def _start(node: ast.AST) -> int:
    return min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])


def _shape(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=False, include_attributes=False)


def _class_shell(node: ast.ClassDef) -> str:
    kept = [child for child in node.body if not isinstance(child, FUNCTION_NODES)]
    shell = ast.ClassDef(
        name=node.name,
        bases=node.bases,
        keywords=node.keywords,
        body=kept or [ast.Pass()],
        decorator_list=node.decorator_list,
        type_params=getattr(node, "type_params", []),
    )
    return _shape(shell)


def _decorators(node: ast.AST) -> list[str]:
    names = []
    for decorator in getattr(node, "decorator_list", []):
        name = dotted(decorator)
        if name:
            names.append(name)
    return names


def _symbol(module: str, qual: str, kind: str, node: ast.AST) -> Symbol:
    start = _start(node)
    return Symbol(
        qual=qual,
        full_name=module + "." + qual,
        kind=kind,
        start=start,
        end=node.end_lineno,
        signature=_signature(node),
        decorators=_decorators(node),
        node=node,
        owned_lines=set(range(start, node.end_lineno + 1)),
        guards=guards_of(node),
        dependencies=dependencies_of(node),
        params=params_of(node),
        attributes=class_attributes(node),
        rejections=rejections_of(node),
    )


def _extract_class(module: str, node: ast.ClassDef, symbols: dict, nodes: dict) -> None:
    cls = _symbol(module, node.name, KIND_CLASS, node)
    methods = [child for child in node.body if isinstance(child, FUNCTION_NODES)]
    for child in methods:
        qual = node.name + "." + child.name
        method = _symbol(module, qual, KIND_METHOD, child)
        symbols[qual] = method
        nodes[qual] = child
        cls.owned_lines -= method.owned_lines
    symbols[node.name] = cls
    nodes[node.name] = node


def _extract(module: str, tree: ast.Module) -> tuple[dict[str, Symbol], dict[str, ast.AST]]:
    symbols: dict[str, Symbol] = {}
    nodes: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, FUNCTION_NODES):
            symbols[node.name] = _symbol(module, node.name, KIND_FUNCTION, node)
            nodes[node.name] = node
        elif isinstance(node, ast.ClassDef):
            _extract_class(module, node, symbols, nodes)
    return symbols, nodes


def _noise(name: str, owner: str, module: str) -> bool:
    if name.startswith(owner + "."):
        return True
    root, _, rest = name.partition(".")
    if root in _BUILTIN_TYPES:
        return True
    if not rest:
        return name in _BUILTIN_NAMES
    return name.startswith(module + ".") and name[len(module) + 1:] in _BUILTIN_NAMES


def _result_attribute(name: str, names: set[str]) -> bool:
    parts = name.split(".")
    if _EXCEPTION_NAME.search(parts[-1]):
        return True
    return any(".".join(parts[:size]) in names for size in range(len(parts) - 1, 1, -1))


def _dotted_prefixes(names: set[str]) -> set[str]:
    prefixes = set()
    for name in names:
        parts = name.split(".")
        prefixes.update(".".join(parts[:size]) for size in range(1, len(parts)))
    return prefixes


def _clean_calls(calls: set[str], owner: str, module: str) -> set[str]:
    kept = {c for c in calls if not _noise(c, owner, module)}
    kept = {c for c in kept if not _result_attribute(c, kept)}
    return kept - _dotted_prefixes(kept)


def _visitor_graph(module: str, path: str, tree: ast.Module) -> dict[str, set[str]]:
    visitor = Visitor(module, path)
    try:
        visitor.visit(tree)
        visitor.finalize()
    except (RecursionError, ValueError, AttributeError, TypeError):
        return {}
    return {d.name: set(d.calls) for d in visitor.defs if d.type in _GRAPH_KINDS}


def _assignments(tree: ast.Module) -> dict[str, tuple[int, int, str]]:
    found = {}
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                found[target.id] = (node.lineno, node.end_lineno, ast.dump(node.value, include_attributes=False))
    return found


def _imported(tree: ast.Module) -> set[str]:
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
    return names


def parse_source(module: str, path: str, source: str) -> ParsedFile | None:
    try:
        tree = ast.parse(source)
        visit_tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    symbols, nodes = _extract(module, tree)
    graph = _visitor_graph(module, path, visit_tree)
    callables = {s.full_name: s for s in symbols.values() if s.kind != KIND_CLASS}
    owned = collections.defaultdict(set)
    for name, targets in graph.items():
        owner = owner_of(name, callables)
        if owner is not None:
            owned[owner].update(targets)
    for full_name, symbol in callables.items():
        symbol.calls = _clean_calls(owned.get(full_name, set()), full_name, module)
    return ParsedFile(
        module=module, symbols=symbols, graph=graph, nodes=nodes,
        assignments=_assignments(tree), imported=_imported(tree),
    )


@lru_cache(maxsize=1)
def _analyzer():
    from skylos.analyzer import Skylos

    return Skylos()


def module_name(root: Path, path: str) -> str:
    return _analyzer()._module(root, root / path)
