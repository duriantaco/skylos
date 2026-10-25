from __future__ import annotations

MAX_CALLERS = 5
MAX_CALLS = 6
MAX_CODE_LINES = 40
MAX_SKIM = 40
MAX_TESTS = 8
MARKDOWN_CHAR_LIMIT = 60000


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _location(entry: dict) -> tuple[int, int]:
    side = entry["after"] or entry["before"]
    return side["start"], side["end"]


def _link(entry: dict, repo_url: str | None, head_sha: str | None, base_sha: str | None) -> str:
    start, end = _location(entry)
    label = f"{entry['file']}:{start}"
    if not repo_url:
        return label
    sha = head_sha
    if entry["after"] is None:
        sha = base_sha
    if not sha:
        return label
    return f"[{label}]({repo_url}/blob/{sha}/{entry['file']}#L{start}-L{end})"


def _calls(names: list[str]) -> str:
    shown = ", ".join(f"`{n}`" for n in names[:MAX_CALLS])
    if len(names) > MAX_CALLS:
        shown += f" +{len(names) - MAX_CALLS} more"
    return shown


def _caller_text(caller: dict) -> str:
    text = f"`{_short(caller['name'])}` {caller['file']}:{caller['line']}"
    if caller["in_change"]:
        text += " (changed here)"
    elif caller["is_test"]:
        text += " (test)"
    return text


def _possible_line(entry: dict) -> str | None:
    possible = entry.get("possible_callers", [])
    if not possible:
        return None
    shown = "; ".join(f"`{_short(c['name'])}` {c['file']}:{c['line']}" for c in possible[:3])
    if len(possible) > 3:
        shown += f"; +{len(possible) - 3} more"
    return f"Maybe called by (same method name, receiver type not proven): {shown}"


def _callers_line(entry: dict) -> str:
    callers = entry["callers"]
    if not callers:
        return "Called by: none found"
    shown = "; ".join(_caller_text(c) for c in callers[:MAX_CALLERS])
    if len(callers) > MAX_CALLERS:
        shown += f"; +{len(callers) - MAX_CALLERS} more"
    return "Called by: " + shown


def _rejection_lines(entry: dict) -> list[str]:
    if not entry.get("rejections_removed"):
        return []
    return ["Stopped rejecting: " + _calls(entry["rejections_removed"])]


def _value_lines(entry: dict) -> list[str]:
    lines = []
    for value in entry.get("values_changed", []):
        readers = ", ".join(f"`{u}`" for u in value["used_by"][:MAX_CALLS]) or "no method in this class"
        lines.append(f"Value changed: `{value['name']}` {value['before']} → {value['after']} (read by {readers})")
    return lines


def _fact_lines(entry: dict) -> list[str]:
    lines = []
    if entry["reasons"]:
        lines.append("Why: " + "; ".join(entry["reasons"]))
    if entry["security_removed"]:
        lines.append("Removed security checks: " + _calls(entry["security_removed"]))
    if entry["signature_changed"]:
        lines.append(f"Signature: `({entry['before']['signature']})` → `({entry['after']['signature']})`")
    if entry["calls_removed"]:
        lines.append("Stopped calling: " + _calls(entry["calls_removed"]))
    if entry["calls_added"]:
        lines.append("Now calls: " + _calls(entry["calls_added"]))
    lines.extend(_value_lines(entry))
    lines.extend(_rejection_lines(entry))
    if entry["calls_moved"]:
        lines.append(f"Moved into a callee, still called: {_calls(entry['calls_moved'])}")
    if entry["still_referenced_by"]:
        lines.append("Still called by: " + _calls(entry["still_referenced_by"]))
    elif entry["status"] != "deleted":
        lines.append(_callers_line(entry))
        possible = _possible_line(entry)
        if possible:
            lines.append(possible)
    return lines


def _code_block(label: str, side: dict | None, path: str) -> list[str]:
    if side is None:
        return []
    suffix = path.rsplit(".", 1)[-1]
    fences = {"py": ("python", "#"), "mjs": ("js", "//"), "cjs": ("js", "//"), "mts": ("ts", "//"), "cts": ("ts", "//")}
    language, comment = fences.get(suffix, (suffix, "//"))
    code = side["code"].splitlines()
    shown = code[:MAX_CODE_LINES]
    if len(code) > MAX_CODE_LINES or side["truncated"]:
        shown.append(f"{comment} ... cut for length")
    return [f"{label} (lines {side['start']}-{side['end']}):", f"```{language}", *shown, "```"]


def _skim_line(entry: dict) -> str:
    bits = [f"{len(entry['callers'])} caller(s)"]
    if entry["calls_removed"]:
        bits.insert(0, "−" + _calls(entry["calls_removed"][:3]))
    if entry["calls_added"]:
        bits.insert(0, "+" + _calls(entry["calls_added"][:3]))
    return " · ".join(bits)


def _header(change_map: dict) -> list[str]:
    symbols = change_map["symbols"]
    production = [s for s in symbols if not s["is_test"]]
    return [
        f"base {change_map['base_commit'][:8]} → working tree · {len(production)} production symbol(s) changed · "
        f"{len(symbols) - len(production)} test symbol(s) · {len(change_map['flagged'])} flagged",
    ]


def _coverage_line(change_map: dict) -> str:
    coverage = change_map["coverage"]
    parts = [f"Coverage: {', '.join(coverage['languages'])} only; callers up to {coverage['caller_depth']} levels"]
    if coverage["reach_is_lower_bound"]:
        parts.append("caller counts are a lower bound")
    parts.append("dynamic calls not modeled; tests not run")
    text = "; ".join(parts) + "."
    if coverage["not_mapped"]:
        text += f" Not mapped: {len(coverage['not_mapped'])} file(s) that are not Python or TypeScript/JavaScript."
    if coverage["unparsed"]:
        text += " Could not parse: " + ", ".join(coverage["unparsed"]) + "."
    return text


def _partition(change_map: dict) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    by_id = {s["id"]: s for s in change_map["symbols"]}
    read_first = [by_id[i] for i in change_map["read_first"]]
    grouped = {member for group in change_map["groups"] for member in group["members"]}
    taken = set(change_map["read_first"]) | grouped
    production = [s for s in change_map["symbols"] if not s["is_test"] and s["id"] not in taken]
    tests = [s for s in change_map["symbols"] if s["is_test"]]
    return read_first, change_map["groups"], production, tests


def _group_line(group: dict, by_id: dict) -> str:
    names = ", ".join(f"`{by_id[m]['name']}`" for m in group["members"][:8])
    if len(group["members"]) > 8:
        names += f" +{len(group['members']) - 8} more"
    change = []
    if group["calls_added"]:
        change.append("+" + _calls(group["calls_added"]))
    if group["calls_removed"]:
        change.append("−" + _calls(group["calls_removed"]))
    return f"{len(group['members'])} symbols {group['status']} the same way ({' · '.join(change)}): {names}"


def _tests_line(tests: list[dict]) -> str:
    names = ", ".join(f"`{t['name']}` {t['status']}" for t in tests[:MAX_TESTS])
    if len(tests) > MAX_TESTS:
        names += f" +{len(tests) - MAX_TESTS} more"
    return f"Tests changed: {len(tests)} — {names}"


def _flag(entry: dict, flagged: set[str], marker: str) -> str:
    if entry["id"] in flagged:
        return marker
    return ""


def _markdown_read_first(read_first: list[dict], links: tuple, flagged: set[str]) -> list[str]:
    out = ["#### Read first"]
    if not read_first:
        out.append("Nothing to read first. Skim the list below.")
    for number, entry in enumerate(read_first, 1):
        mark = _flag(entry, flagged, " · **flagged**")
        out.append(f"**{number}. `{entry['name']}`** {entry['status']}{mark} · {_link(entry, *links)}")
        out.extend(f"- {line}" for line in _fact_lines(entry))
        out.extend(["<details><summary>before / after</summary>", ""])
        out.extend(_code_block("Before", entry["before"], entry["file"]))
        out.extend(_code_block("After", entry["after"], entry["file"]))
        out.extend(["</details>", ""])
    return out


def _constant_line(item: dict) -> str:
    users = ", ".join(f"`{u}`" for u in item["used_by"][:MAX_CALLS])
    if len(item["used_by"]) > MAX_CALLS:
        users += f" +{len(item['used_by']) - MAX_CALLS} more"
    return f"`{item['name']}` changed at {item['file']}:{item['line']}; used by {users}"


def _markdown_constants(items: list[dict]) -> list[str]:
    if not items:
        return []
    return ["#### Module values changed", *(f"- {_constant_line(i)}" for i in items), ""]


def _markdown_groups(groups: list[dict], by_id: dict) -> list[str]:
    if not groups:
        return []
    return ["#### Same change in many places", *(f"- {_group_line(g, by_id)}" for g in groups), ""]


def _markdown_skim(rest: list[dict], links: tuple) -> list[str]:
    if not rest:
        return []
    out = ["#### Safe to skim"]
    out.extend(f"- `{e['name']}` {e['status']} · {_link(e, *links)} · {_skim_line(e)}" for e in rest[:MAX_SKIM])
    if len(rest) > MAX_SKIM:
        out.append(f"- +{len(rest) - MAX_SKIM} more in the JSON output")
    out.append("")
    return out


def _markdown_tests(tests: list[dict]) -> list[str]:
    if not tests:
        return []
    return [_tests_line(tests), ""]


def render_markdown(change_map: dict, *, repo_url: str | None = None, head_sha: str | None = None) -> str:
    read_first, groups, rest, tests = _partition(change_map)
    by_id = {s["id"]: s for s in change_map["symbols"]}
    links = (repo_url, head_sha, change_map["base_commit"])
    out = ["### Skylos change map", "", *_header(change_map), "", _coverage_line(change_map), ""]
    out.extend(_markdown_read_first(read_first, links, set(change_map["flagged"])))
    out.extend(_markdown_constants(change_map["module_changes"]))
    out.extend(_markdown_groups(groups, by_id))
    out.extend(_markdown_skim(rest, links))
    out.extend(_markdown_tests(tests))
    out.append("_Same commit, same map: computed from the code, not written by a model._")
    text = "\n".join(out) + "\n"
    if len(text) > MARKDOWN_CHAR_LIMIT:
        text = text[:MARKDOWN_CHAR_LIMIT] + "\n\n_Map cut for length; see the JSON output._\n"
    return text


