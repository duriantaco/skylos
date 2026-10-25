from __future__ import annotations

import ast

from skylos.changemap.facts import dotted
from skylos.changemap.graph import HeadGraph
from skylos.changemap import receivers
from skylos.changemap.risk import is_test_file, simple_name
from skylos.changemap.symbols import KIND_CLASS, KIND_METHOD, ParsedFile, Symbol
from skylos.changemap.ts_nodes import PYTHON

_OWN_RECEIVERS = frozenset({"self", "cls"})


def _owner_node(parsed: ParsedFile, owner_full: str):
    return parsed.nodes.get(owner_full[len(parsed.module) + 1:])


def _call_lines(node, simple: str) -> list[int]:
    return sorted(
        child.lineno for child in ast.walk(node)
        if isinstance(child, ast.Call) and simple_name(dotted(child.func) or "") == simple
    )


def _site_line(graph: HeadGraph, parsed: ParsedFile, owner_full: str, target: str) -> int | None:
    sites = parsed.call_sites.get(owner_full, {})
    lines = [sites[alias] for alias in graph._aliases(target) if alias in sites]
    return min(lines, default=None)


def _call_line(graph: HeadGraph, parsed: ParsedFile, owner_full: str, target: str, default: int) -> int:
    if parsed.language != PYTHON:
        line = _site_line(graph, parsed, owner_full, target)
        if line is None:
            return default
        return line
    node = _owner_node(parsed, owner_full)
    if node is None:
        return default
    return min(_call_lines(node, simple_name(target)), default=default)


def call_targets(symbol: Symbol) -> list[str]:
    if symbol.kind == KIND_METHOD and symbol.qual.endswith((".__init__", ".constructor")):
        return [symbol.full_name, symbol.full_name.rsplit(".", 1)[0]]
    return [symbol.full_name]


def _record(owner: str, owner_path: str, line: int, changed_full: set[str]) -> dict:
    return {
        "name": owner,
        "file": owner_path,
        "line": line,
        "in_change": owner in changed_full,
        "is_test": is_test_file(owner_path),
    }


def _constructs(graph: HeadGraph, parsed: ParsedFile, owner: str, class_full: str) -> bool:
    if parsed.language != PYTHON:
        return _site_line(graph, parsed, owner, class_full) is not None
    node = _owner_node(parsed, owner)
    return node is not None and bool(_call_lines(node, simple_name(class_full)))


def callers_of_symbol(graph: HeadGraph, symbol: Symbol, changed_full: set[str]) -> list[dict]:
    callers = {}
    owner_class = symbol.full_name.rsplit(".", 1)[0]
    for target in call_targets(symbol):
        constructor = target != symbol.full_name
        for owner, owner_path in graph.callers_of(target):
            if owner in callers or (constructor and owner.startswith(owner_class + ".")):
                continue
            parsed = graph.parsed[owner_path]
            if constructor and not _constructs(graph, parsed, owner, target):
                continue
            start = parsed.symbols[owner[len(parsed.module) + 1:]].start
            line = _call_line(graph, parsed, owner, target, start)
            callers[owner] = _record(owner, owner_path, line, changed_full)
    return [callers[name] for name in sorted(callers)]


_PROPERTY_DECORATORS = frozenset({"property", "cached_property"})


def _is_property(symbol: Symbol) -> bool:
    return any(simple_name(d) in _PROPERTY_DECORATORS for d in symbol.decorators)


def _class_node(graph: HeadGraph, class_full: str):
    owner = graph.symbol(class_full)
    if owner is None or owner.kind != KIND_CLASS:
        return None
    return owner.node


def _file_candidates(graph: HeadGraph, classes: set[str]) -> list[tuple[str, ParsedFile, Symbol]]:
    paths = [path for path in graph.parsed if classes & graph.tokens(path)]
    return [
        (path, graph.parsed[path], candidate) for path in paths
        for candidate in graph.parsed[path].symbols.values() if candidate.kind != KIND_CLASS
    ]


def _verdict(types: set[str], own: str, supers: set[str]) -> str:
    if own in types:
        return "typed"
    if not types or types & supers:
        return "possible"
    return "unrelated"


def _classify_uses(parsed: ParsedFile, candidate: Symbol, *, member: str, is_property: bool, own: str, supers: set[str]):
    container = parsed.nodes.get(candidate.qual.split(".")[0])
    local = receivers.function_env(candidate.node)
    attributes = receivers.class_env(container)
    identity = receivers.class_identity(container)
    overrides = getattr(container, "name", own) != own and receivers.defines_member(container, member)
    for line, receiver in receivers.member_uses(candidate.node, member, is_property=is_property):
        own_receiver = isinstance(receiver, ast.Name) and receiver.id in _OWN_RECEIVERS
        if own_receiver and (candidate.kind != KIND_METHOD or overrides):
            continue
        types = receivers.receiver_types(receiver, local, attributes, identity)
        if own_receiver and not types & ({own} | supers):
            continue
        yield line, _verdict(types, own, supers)


def _first_verdicts(parsed: ParsedFile, candidate: Symbol, **target) -> dict[str, int]:
    verdicts = {}
    for line, verdict in _classify_uses(parsed, candidate, **target):
        verdicts.setdefault(verdict, line)
    return verdicts


def _ts_possible(graph: HeadGraph, symbol: Symbol, known: set[str], classes: set[str], changed_full: set[str]) -> list[dict]:
    member = simple_name(symbol.full_name)
    found = {}
    for path, parsed in graph.parsed.items():
        if parsed.language == PYTHON or not classes & graph.tokens(path):
            continue
        for owner, calls in parsed.unresolved.items():
            lines = sorted(line for name, line in calls if name == member)
            if lines and owner not in known:
                found[owner] = _record(owner, path, lines[0], changed_full)
    return [found[name] for name in sorted(found)]


def _ts_receiver_callers(graph: HeadGraph, symbol: Symbol, resolved: list[dict], changed_full: set[str]):
    class_full = symbol.full_name.rsplit(".", 1)[0]
    known = {c["name"] for c in resolved} | {symbol.full_name}
    return [], _ts_possible(graph, symbol, known, {simple_name(class_full)}, changed_full)


def _python_receiver_callers(graph: HeadGraph, symbol: Symbol, resolved: list[dict], changed_full: set[str]):
    class_full = symbol.full_name.rsplit(".", 1)[0]
    own = simple_name(class_full)
    supers = receivers.class_identity(_class_node(graph, class_full)) - {own}
    target = {"member": simple_name(symbol.full_name), "is_property": _is_property(symbol), "own": own, "supers": supers}
    known = {c["name"] for c in resolved} | {symbol.full_name}
    found = {"typed": {}, "possible": {}}
    for path, parsed, candidate in _file_candidates(graph, {own} | supers):
        if candidate.full_name in known:
            continue
        verdicts = _first_verdicts(parsed, candidate, **target)
        verdict = next((v for v in ("typed", "possible") if v in verdicts), None)
        if verdict is not None:
            found[verdict][candidate.full_name] = _record(candidate.full_name, path, verdicts[verdict], changed_full)
    return [found["typed"][n] for n in sorted(found["typed"])], [found["possible"][n] for n in sorted(found["possible"])]


def receiver_callers(graph: HeadGraph, symbol: Symbol, resolved: list[dict], changed_full: set[str]):
    if symbol.kind != KIND_METHOD or symbol.qual.endswith((".__init__", ".constructor")):
        return [], []
    if symbol.node is None:
        return _ts_receiver_callers(graph, symbol, resolved, changed_full)
    return _python_receiver_callers(graph, symbol, resolved, changed_full)
