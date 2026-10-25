from __future__ import annotations

import collections
from pathlib import Path

from skylos.changemap.callers import call_targets, callers_of_symbol, receiver_callers
from skylos.changemap.changes import call_changes, classify_signature, move_index
from skylos.changemap.class_values import values_changed
from skylos.changemap.compat import affected_callers
from skylos.changemap.graph import CALLER_DEPTH, HeadGraph, reach
from skylos.changemap.inputs import ChangeInputs, FileChange, collect_inputs
from skylos.changemap.risk import (
    STATUS_ADDED,
    STATUS_DELETED,
    STATUS_MODIFIED,
    is_alarm,
    is_test_file,
    reasons_and_risk,
)
from skylos.changemap.module_values import module_changes
from skylos.changemap.languages import any_module_name, parse_any
from skylos.changemap.symbols import KIND_CLASS, ParsedFile, Symbol
from skylos.changemap.ts_imports import Resolver, is_ts_path

SCHEMA_VERSION = 1
CODE_LINE_CAP = 400
READ_FIRST_LIMIT = 3
GROUP_MIN = 3
_NOTES = (
    "Callers are searched in files that mention a changed name, up to the caller depth.",
    "Dynamic calls, callbacks and registries are not modeled.",
    "Tests are not run or matched yet.",
)


def _code(source: str | None, symbol: Symbol | None) -> dict | None:
    if symbol is None or source is None:
        return None
    lines = source.splitlines()[symbol.start - 1:symbol.end]
    return {
        "start": symbol.start,
        "end": symbol.end,
        "signature": symbol.signature,
        "code": "\n".join(lines[:CODE_LINE_CAP]),
        "truncated": len(lines) > CODE_LINE_CAP,
    }


def _parse_side(modules: dict[str, str], path: str, source: str | None, resolver: Resolver):
    if source is None:
        return None, False
    parsed = parse_any(modules[path], path, source, resolver)
    return parsed, parsed is None


def _parse_changed(inputs: ChangeInputs, modules: dict[str, str], resolver: Resolver):
    base_parsed: dict[str, ParsedFile] = {}
    head_parsed: dict[str, ParsedFile] = {}
    unparsed = []
    for path, change in inputs.files.items():
        before, before_broken = _parse_side(modules, path, change.base_source, resolver)
        after, after_broken = _parse_side(modules, path, change.head_source, resolver)
        if before_broken or after_broken:
            unparsed.append(path)
            continue
        if before is not None:
            base_parsed[path] = before
        if after is not None:
            head_parsed[path] = after
    return base_parsed, head_parsed, unparsed


def _symbols_of(parsed: dict[str, ParsedFile], path: str) -> dict[str, Symbol]:
    if path in parsed:
        return parsed[path].symbols
    return {}


def _unchanged(before: Symbol | None, after: Symbol | None) -> bool:
    if before is None or after is None:
        return False
    return before.shape == after.shape and before.calls == after.calls


def _changed_names(change: FileChange, base_symbols: dict, head_symbols: dict) -> set[str]:
    names = {q for q, s in head_symbols.items() if s.owned_lines & change.new_lines}
    names |= {q for q, s in base_symbols.items() if s.owned_lines & change.old_lines}
    shared = base_symbols.keys() & head_symbols.keys()
    names |= {q for q in shared if base_symbols[q].calls != head_symbols[q].calls}
    names |= base_symbols.keys() ^ head_symbols.keys()
    return names


def _changed_pairs(inputs: ChangeInputs, base_parsed: dict, head_parsed: dict, unparsed: list) -> list:
    pairs = []
    for path, change in inputs.files.items():
        if path in unparsed:
            continue
        base_symbols = _symbols_of(base_parsed, path)
        head_symbols = _symbols_of(head_parsed, path)
        for qual in sorted(_changed_names(change, base_symbols, head_symbols)):
            before = base_symbols.get(qual)
            after = head_symbols.get(qual)
            if not _unchanged(before, after):
                pairs.append((path, qual, before, after))
    return pairs


def _status(before: Symbol | None, after: Symbol | None) -> str:
    if before is None:
        return STATUS_ADDED
    if after is None:
        return STATUS_DELETED
    return STATUS_MODIFIED


def _lines_changed(change: FileChange, before: Symbol | None, after: Symbol | None) -> int:
    total = 0
    if after is not None:
        total += len(after.owned_lines & change.new_lines)
    if before is not None:
        total += len(before.owned_lines & change.old_lines)
    return total


def _still_referenced(graph: HeadGraph, callers: list[dict], path: str, qual: str, moved_to: str | None) -> list[str]:
    if moved_to is not None:
        parsed = graph.parsed.get(path)
        if parsed is not None and qual.split(".")[0] in parsed.imported:
            return []
    return sorted({c["name"] for c in callers})


def _entry(graph: HeadGraph, inputs: ChangeInputs, pair: tuple, changed_full: set[str], moves: tuple) -> dict:
    path, qual, before, after = pair
    moved_from_index, moved_to_index, full_moves = moves
    change = inputs.files[path]
    symbol = after or before
    status = _status(before, after)
    entry_id = f"{path}::{qual}"
    origin = moved_from_index.get(entry_id)
    diff_before = before
    if origin is not None:
        diff_before = origin[2]
    signature_change, new_optional = classify_signature(status, before, after)
    signature_changed = signature_change is not None
    callers = callers_of_symbol(graph, symbol, changed_full)
    typed, possible = receiver_callers(graph, symbol, callers, changed_full)
    callers = sorted(callers + typed, key=lambda c: c["name"])
    affected = affected_callers(graph, callers, signature_change, before, after)
    still_referenced_by = []
    if status == STATUS_DELETED:
        still_referenced_by = _still_referenced(graph, callers, path, qual, moved_to_index.get(entry_id))
        callers = []
    entry = {
        "id": entry_id,
        "file": path,
        "name": qual,
        "full_name": symbol.full_name,
        "kind": symbol.kind,
        "status": status,
        "is_test": is_test_file(path),
        "binding_changed": status == STATUS_MODIFIED and before.shape == after.shape,
        "before": _code(change.base_source, before),
        "after": _code(change.head_source, after),
        "moved_from": None,
        "moved_to": moved_to_index.get(entry_id),
        **call_changes(graph, diff_before, after, full_moves),
        "signature_changed": signature_changed,
        "signature_change": signature_change,
        "new_optional_params": new_optional,
        "values_changed": values_changed(graph, path, before, after),
        "callers": callers,
        "possible_callers": possible,
        "callers_not_updated": affected["production"],
        "test_callers_not_updated": affected["tests"],
        "breaking_callers": affected["breaking"],
        "still_referenced_by": still_referenced_by,
        "reach": 0,
        "lines_changed": _lines_changed(change, before, after),
    }
    return _finish_entry(graph, entry, origin, symbol)


def _finish_entry(graph: HeadGraph, entry: dict, origin: tuple | None, symbol: Symbol) -> dict:
    if origin is not None:
        entry["moved_from"] = f"{origin[0]}::{origin[1]}"
        entry["lines_changed"] = 0
    if entry["status"] != STATUS_DELETED:
        entry["reach"] = reach(graph, call_targets(symbol)[-1])
    entry["risk"], entry["reasons"] = reasons_and_risk(entry)
    return entry


def _start_line(entry: dict) -> int:
    return (entry["after"] or entry["before"])["start"]


def _groups(production: list[dict], flagged: list[str]) -> list[dict]:
    shapes = collections.defaultdict(list)
    for entry in production:
        if entry["id"] in flagged or not (entry["calls_added"] or entry["calls_removed"]):
            continue
        key = (entry["status"], tuple(entry["calls_added"]), tuple(entry["calls_removed"]))
        shapes[key].append(entry["id"])
    groups = [
        {"status": status, "calls_added": list(added), "calls_removed": list(removed), "members": sorted(members)}
        for (status, added, removed), members in shapes.items()
        if len(members) >= GROUP_MIN
    ]
    return sorted(groups, key=lambda g: (-len(g["members"]), g["members"][0]))


def _changed_targets(pairs: list) -> list[tuple[str, str]]:
    targets = set()
    for _, _, before, after in pairs:
        symbol = after or before
        targets.add((symbol.full_name, symbol.kind))
        if len(call_targets(symbol)) > 1:
            targets.add((call_targets(symbol)[-1], KIND_CLASS))
    return sorted(targets)


def _read_first(production: list[dict], groups: list[dict], flagged: list[str]) -> list[str]:
    grouped = {member for group in groups for member in group["members"]}
    top = [s["id"] for s in production if s["id"] not in grouped][:READ_FIRST_LIMIT]
    return top + [entry_id for entry_id in flagged if entry_id not in top]


def _flagged(production: list[dict]) -> list[str]:
    return [s["id"] for s in production if is_alarm(s)]


def _languages(inputs: ChangeInputs) -> list[str]:
    names = set()
    for path in inputs.files:
        if is_ts_path(path):
            names.add("TypeScript/JavaScript")
        else:
            names.add("Python")
    return sorted(names) or ["Python"]


def _coverage(inputs: ChangeInputs, unparsed: list[str], graph: HeadGraph) -> dict:
    return {
        "languages": _languages(inputs),
        "not_mapped": inputs.not_mapped,
        "unparsed": sorted(unparsed),
        "caller_depth": CALLER_DEPTH,
        "reach_is_lower_bound": graph.reach_capped,
        "notes": list(_NOTES),
    }


def build_change_map(root: str | Path, base_ref: str) -> dict:
    inputs = collect_inputs(root, base_ref)
    paths = set(inputs.project_python_files) | set(inputs.files)
    modules = {path: any_module_name(inputs.root, path) for path in sorted(paths)}
    resolver = Resolver(inputs.root)
    base_parsed, head_parsed, unparsed = _parse_changed(inputs, modules, resolver)
    graph = HeadGraph(inputs, modules, resolver)
    for path, parsed in head_parsed.items():
        graph.add(path, parsed)
    pairs = _changed_pairs(inputs, base_parsed, head_parsed, unparsed)
    changed = _changed_targets(pairs)
    graph.expand_for(changed)
    changed_full = {name for name, _ in changed}
    moves = move_index(pairs)
    symbols = [_entry(graph, inputs, pair, changed_full, moves) for pair in pairs]
    symbols.sort(key=lambda s: (-s["risk"], s["file"], _start_line(s), s["name"]))
    production = [s for s in symbols if not s["is_test"]]
    flagged = _flagged(production)
    groups = _groups(production, flagged)
    read_first = _read_first(production, groups, flagged)
    return {
        "schema_version": SCHEMA_VERSION,
        "base_commit": inputs.base_commit,
        "head": "working_tree",
        "symbols": symbols,
        "read_first": read_first,
        "flagged": flagged,
        "groups": groups,
        "module_changes": module_changes(inputs, base_parsed, head_parsed),
        "coverage": _coverage(inputs, unparsed, graph),
    }
