from __future__ import annotations

from skylos.changemap.render import (
    MAX_SKIM,
    _constant_line,
    _coverage_line,
    _fact_lines,
    _flag,
    _group_line,
    _header,
    _location,
    _partition,
    _skim_line,
    _tests_line,
)


def _plain(text: str) -> str:
    return text.replace("`", "")


def _text_read_first(read_first: list[dict], flagged: set[str]) -> list[str]:
    out = ["READ FIRST"]
    if not read_first:
        out.append("  Nothing to read first. Skim the list below.")
    for number, entry in enumerate(read_first, 1):
        start, _ = _location(entry)
        mark = _flag(entry, flagged, "  FLAGGED")
        out.append(f"  {number}. {entry['name']}  {entry['status']}{mark}  {entry['file']}:{start}")
        out.extend(f"     {_plain(line)}" for line in _fact_lines(entry))
    return out


def _text_groups(groups: list[dict], by_id: dict) -> list[str]:
    if not groups:
        return []
    return ["", "SAME CHANGE IN MANY PLACES", *(f"  {_plain(_group_line(g, by_id))}" for g in groups)]


def _text_skim(rest: list[dict]) -> list[str]:
    if not rest:
        return []
    out = ["", "SAFE TO SKIM"]
    for entry in rest[:MAX_SKIM]:
        start, _ = _location(entry)
        out.append(f"  {entry['name']}  {entry['status']}  {entry['file']}:{start}  {_plain(_skim_line(entry))}")
    if len(rest) > MAX_SKIM:
        out.append(f"  +{len(rest) - MAX_SKIM} more (use --format json)")
    return out


def render_text(change_map: dict) -> str:
    read_first, groups, rest, tests = _partition(change_map)
    by_id = {s["id"]: s for s in change_map["symbols"]}
    out = ["Skylos change map", *_header(change_map), _coverage_line(change_map), ""]
    out.extend(_text_read_first(read_first, set(change_map["flagged"])))
    if change_map["module_changes"]:
        out.extend(["", "MODULE VALUES CHANGED", *(f"  {_plain(_constant_line(i))}" for i in change_map["module_changes"])])
    out.extend(_text_groups(groups, by_id))
    out.extend(_text_skim(rest))
    if tests:
        out.extend(["", _plain(_tests_line(tests))])
    return "\n".join(out) + "\n"
