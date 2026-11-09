from __future__ import annotations

import collections

from skylos.changemap.graph import HeadGraph
from skylos.changemap.risk import (
    RISKY_CALL,
    STATUS_MODIFIED,
    is_guard_call,
    is_security_call,
    is_security_decorator,
    simple_name,
)
from skylos.changemap.symbols import KIND_CLASS, Symbol

SIGNATURE_BREAKING = "breaking"
SIGNATURE_COMPATIBLE = "compatible"


def _attr(symbol: Symbol | None, name: str, default):
    if symbol is None:
        return default
    return getattr(symbol, name)


def _decorator_changes(before: Symbol | None, after: Symbol | None) -> tuple[list[str], list[str]]:
    before_decorators = _attr(before, "decorators", [])
    after_decorators = _attr(after, "decorators", [])
    removed = [d for d in before_decorators if d not in after_decorators]
    added = [d for d in after_decorators if d not in before_decorators]
    return removed, added


def _call_sets(before: Symbol | None, after: Symbol | None, ignored: set[str]) -> tuple[set[str], set[str]]:
    before_calls = _calls_of(before)
    after_calls = _calls_of(after)
    added = {c for c in after_calls - before_calls if simple_name(c) not in ignored}
    removed = {c for c in before_calls - after_calls if simple_name(c) not in ignored}
    return added, removed


def _moved(graph: HeadGraph, after: Symbol | None, removed: set[str]) -> set[str]:
    if after is None or not removed:
        return set()
    return removed & graph.closure(after.full_name)


def _calls_of(symbol: Symbol | None) -> set[str]:
    if symbol is None:
        return set()
    return symbol.calls


def _guard_changes(before: Symbol | None, after: Symbol | None) -> list[str]:
    if before is None or after is None:
        return []
    lost = collections.Counter(before.guards) - collections.Counter(after.guards)
    return sorted(lost)


def _security_additions(before: Symbol | None, after: Symbol | None, added: set[str], decorators_added: list[str]) -> list[str]:
    dependencies = set(_attr(after, "dependencies", [])) - set(_attr(before, "dependencies", []))
    names = {d for d in dependencies if is_security_call(d)}
    names |= {d for d in decorators_added if is_security_decorator(d)}
    names |= {c for c in added if is_guard_call(c)}
    return sorted({simple_name(n) for n in names})


def _retarget(removed: set[str], added: set[str], after: Symbol | None, moves: dict) -> list[str]:
    retargeted = sorted(f"{old} → {moves[old]}" for old in removed if moves.get(old) in added)
    added -= {moves[old] for old in removed if moves.get(old) in added}
    removed -= {old for old in removed if moves.get(old) in _calls_of(after)}
    return retargeted


def _security_removed(removed: set[str], decorators_removed: list[str], unreplaced_guards: list[str]) -> list[str]:
    security = sorted(c for c in removed if is_security_call(c))
    security += [f"@{d}" for d in decorators_removed if is_security_decorator(d)]
    return security + unreplaced_guards


def _rejections_removed(graph: HeadGraph, before: Symbol | None, after: Symbol | None) -> list[str]:
    if before is None or after is None:
        return []
    lost = collections.Counter(before.rejections) - collections.Counter(after.rejections)
    if not lost:
        return []
    kept_below = set()
    for name in graph.closure(after.full_name):
        callee = graph.symbol(name)
        if callee is not None:
            kept_below.update(callee.rejections)
    return sorted(label for label in lost if label not in kept_below)


def call_changes(graph: HeadGraph, before: Symbol | None, after: Symbol | None, moves: dict) -> dict:
    decorators_removed, decorators_added = _decorator_changes(before, after)
    ignored = {simple_name(d) for d in decorators_removed + decorators_added}
    added, removed = _call_sets(before, after, ignored)
    retargeted = _retarget(removed, added, after, moves)
    moved = _moved(graph, after, removed)
    removed -= moved
    guards_removed = _guard_changes(before, after)
    replaced_by = []
    if guards_removed:
        replaced_by = _security_additions(before, after, added, decorators_added)
    unreplaced = []
    if not replaced_by:
        unreplaced = guards_removed
    return {
        "decorators_removed": decorators_removed,
        "decorators_added": decorators_added,
        "calls_added": sorted(added),
        "calls_removed": sorted(removed),
        "calls_moved": sorted(moved),
        "calls_retargeted": retargeted,
        "security_removed": _security_removed(removed, decorators_removed, unreplaced),
        "guards_removed": guards_removed,
        "rejections_removed": _rejections_removed(graph, before, after),
        "guards_replaced_by": replaced_by,
        "risky_calls_added": sorted(c for c in added if RISKY_CALL.match(c)),
    }


def _positional(params: tuple) -> list[str]:
    return [name for kind, name, _ in params if kind == "positional"]


def _param_table(params: tuple) -> dict[str, tuple[str, bool]]:
    return {name: (kind, has_default) for kind, name, has_default in params}


def _breaks_existing(old: dict, new: dict) -> bool:
    for name, (kind, has_default) in old.items():
        if name not in new or new[name][0] != kind or (has_default and not new[name][1]):
            return True
    return False


def _requires_new(old: dict, new: dict) -> bool:
    return any(name not in old and not has_default for name, (_, has_default) in new.items())


def _signature_kind(before: Symbol, after: Symbol) -> str:
    old_positional = _positional(before.params)
    if _positional(after.params)[:len(old_positional)] != old_positional:
        return SIGNATURE_BREAKING
    old = _param_table(before.params)
    new = _param_table(after.params)
    if _breaks_existing(old, new) or _requires_new(old, new):
        return SIGNATURE_BREAKING
    return SIGNATURE_COMPATIBLE


def _comparable(status: str, before: Symbol | None, after: Symbol | None) -> bool:
    if status != STATUS_MODIFIED or before.signature == after.signature:
        return False
    return after.kind != KIND_CLASS or bool(before.params and after.params)


def classify_signature(status: str, before: Symbol | None, after: Symbol | None) -> tuple[str | None, list[str]]:
    if not _comparable(status, before, after):
        return None, []
    old_names = {name for _, name, _ in before.params}
    optional = [name for kind, name, has_default in after.params
                if name not in old_names and has_default and kind in ("positional", "keyword")]
    return _signature_kind(before, after), optional


def move_index(pairs: list) -> tuple[dict, dict, dict]:
    deleted = {}
    for path, qual, before, after in pairs:
        if after is None:
            deleted.setdefault(before.shape, (path, qual, before))
    moved_from, moved_to, full_names = {}, {}, {}
    for path, qual, before, after in pairs:
        if before is not None or after.shape not in deleted:
            continue
        old_path, old_qual, old_symbol = deleted[after.shape]
        if old_path == path and old_qual == qual:
            continue
        moved_from[f"{path}::{qual}"] = (old_path, old_qual, old_symbol)
        moved_to[f"{old_path}::{old_qual}"] = f"{path}::{qual}"
        full_names[old_symbol.full_name] = after.full_name
    return moved_from, moved_to, full_names
