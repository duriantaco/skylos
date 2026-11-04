from __future__ import annotations

from skylos.changemap.render import (
    MAX_SKIM,
    _constant_line,
    _coverage_line,
    _fact_lines,
    _flag,
    _header,
    _location,
    _partition,
    _extra_why,
    _tests_line,
    evidence_lines,
    read_line,
    review_line,
    why_line,
)


def _plain(text: str) -> str:
    return text.replace("`", "")


def _text_read_first(read_first: list[dict], flagged: set[str]) -> list[str]:
    out = ["READ FIRST"]
    if not read_first:
        out.append("  Nothing to read first.")
    for number, entry in enumerate(read_first, 1):
        start, _ = _location(entry)
        mark = _flag(entry, flagged, "  FLAGGED")
        out.append(f"  {number}. {entry['name']}  {entry['status']}{mark}  {entry['file']}:{start}")
        out.extend(f"     {_plain(line)}" for line in _fact_lines(entry))
        why = _extra_why(entry)
        if why:
            out.append(f"     {_plain(why)}")
        out.extend(f"     {line}" for line in evidence_lines(entry))
    return out


def _text_list(title: str, entries: list[dict], describe) -> list[str]:
    if not entries:
        return []
    out = ["", title]
    for entry in entries[:MAX_SKIM]:
        start, _ = _location(entry)
        out.append(f"  {entry['name']}  {entry['status']}  {entry['file']}:{start}  {_plain(describe(entry))}")
        out.extend(f"      {line}" for line in evidence_lines(entry))
    if len(entries) > MAX_SKIM:
        out.append(f"  +{len(entries) - MAX_SKIM} more (use --format json)")
    return out


def render_text(change_map: dict) -> str:
    parts = _partition(change_map)
    out = ["Skylos change map", *_header(change_map)]
    summary = review_line(change_map)
    if summary:
        out.append(summary)
    out.extend([_coverage_line(change_map), ""])
    out.extend(_text_read_first(parts["read_first"], set(change_map["flagged"])))
    if change_map["module_changes"]:
        out.extend(["", "MODULE VALUES CHANGED", *(f"  {_plain(_constant_line(i))}" for i in change_map["module_changes"])])
    out.extend(_text_list("READ", parts["read"], read_line))
    out.extend(_text_list("SKIM", parts["skim"], why_line))
    out.extend(_text_list("SKIP: SAME LOGIC, PROVEN", parts["skip"], why_line))
    if parts["tests"]:
        out.extend(["", _plain(_tests_line(parts["tests"]))])
    return "\n".join(out) + "\n"
