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


def _module_of(entry: dict) -> str:
    full_name = entry.get("full_name") or ""
    suffix = "." + (entry.get("name") or "")
    if suffix != "." and full_name.endswith(suffix):
        return full_name[: -len(suffix)]
    return ""


def _local_calls(entry: dict, key: str) -> list[str]:
    module = _module_of(entry)
    names = list(entry.get(key) or ())
    if not module:
        return names
    prefix = module + "."
    shown = []
    for name in names:
        if name.startswith(prefix) and len(name) > len(prefix):
            shown.append(name[len(prefix):])
        else:
            shown.append(name)
    return shown


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
        lines.append("Stopped calling: " + _calls(_local_calls(entry, "calls_removed")))
    if entry["calls_added"]:
        lines.append("Now calls: " + _calls(_local_calls(entry, "calls_added")))
    lines.extend(_value_lines(entry))
    lines.extend(_rejection_lines(entry))
    if entry["calls_moved"]:
        lines.append(f"Moved into a callee, still called: {_calls(_local_calls(entry, 'calls_moved'))}")
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
    fence = "`" * max(3, _longest_backticks(shown) + 1)
    return [f"{label} (lines {side['start']}-{side['end']}):", f"{fence}{language}", *shown, fence]


def _longest_backticks(lines: list[str]) -> int:
    longest = 0
    for line in lines:
        run = 0
        for char in line:
            if char == "`":
                run += 1
                longest = max(longest, run)
            else:
                run = 0
    return longest


def _skim_line(entry: dict) -> str:
    bits = [f"{len(entry['callers'])} caller(s)"]
    if entry["calls_removed"]:
        bits.insert(0, "−" + _calls(_local_calls(entry, "calls_removed")[:3]))
    if entry["calls_added"]:
        bits.insert(0, "+" + _calls(_local_calls(entry, "calls_added")[:3]))
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


def _partition(change_map: dict) -> dict[str, list[dict]]:
    by_id = {s["id"]: s for s in change_map["symbols"]}
    buckets = change_map["review"]["buckets"]
    parts = {name: [by_id[i] for i in ids] for name, ids in buckets.items()}
    parts["tests"] = [s for s in change_map["symbols"] if s["is_test"]]
    return parts


REVIEW_WORDS = (
    ("read_first", "to read first"),
    ("read", "to read"),
    ("skim", "to skim"),
    ("skip", "to skip (same logic, proven)"),
)


def review_counts_text(counts: dict) -> str:
    parts = [f"{counts.get(key, 0)} {words}" for key, words in REVIEW_WORDS if counts.get(key, 0)]
    return ", ".join(parts)


def review_line(change_map: dict) -> str:
    review = change_map["review"]
    if not review["total"]:
        return ""
    lines = review["lines"]
    read_lines = lines["read_first"] + lines["read"]
    return (
        f"Review: {review_counts_text(review['counts'])}. "
        f"{read_lines} of {review['total_lines']} changed lines need reading."
    )


_MD_SPECIAL = frozenset("\\`*_[]<>!|#~")


def md_text(text: str) -> str:
    out = []
    for char in text:
        if char in _MD_SPECIAL:
            out.append("\\" + char)
        elif char == "@":
            out.append("@\u200b")
        elif char in "\r\n":
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def why_line(entry: dict) -> str:
    return (entry["review_why"] or entry["verdict_text"]).replace("`", "")


def why_markdown(entry: dict) -> str:
    return md_text(entry["review_why"] or entry["verdict_text"])


def _extra_why(entry: dict) -> str:
    from skylos.changemap.review import VERDICT_TEXT

    why = entry["review_why"]
    if not why or why.startswith("Flagged"):
        return ""
    if why == VERDICT_TEXT.get(entry["verdict"]):
        return ""
    return why


def read_line(entry: dict) -> str:
    text = _skim_line(entry)
    why = _extra_why(entry)
    if why:
        text += " · " + why.replace("`", "")
    return text


def read_markdown(entry: dict) -> str:
    text = _skim_line(entry)
    why = _extra_why(entry)
    if why:
        text += " · " + md_text(why)
    return text


def evidence_lines(entry: dict) -> list[str]:
    return list(entry.get("test_evidence") or [])[:3]


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
        out.append("Nothing to read first.")
    for number, entry in enumerate(read_first, 1):
        mark = _flag(entry, flagged, " · **flagged**")
        out.append(f"**{number}. `{entry['name']}`** {entry['status']}{mark} · {_link(entry, *links)}")
        out.extend(f"- {line}" for line in _fact_lines(entry))
        why = _extra_why(entry)
        if why:
            out.append(f"- {md_text(why)}")
        out.extend(f"- {md_text(line)}" for line in evidence_lines(entry))
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


def _markdown_list(title: str, entries: list[dict], links: tuple, describe) -> list[str]:
    if not entries:
        return []
    out = [title]
    for entry in entries[:MAX_SKIM]:
        out.append(f"- `{entry['name']}` {entry['status']} · {_link(entry, *links)} · {describe(entry)}")
        out.extend(f"  - {md_text(line)}" for line in evidence_lines(entry))
    if len(entries) > MAX_SKIM:
        out.append(f"- +{len(entries) - MAX_SKIM} more in the JSON output")
    out.append("")
    return out


def _markdown_tests(tests: list[dict]) -> list[str]:
    if not tests:
        return []
    return [_tests_line(tests), ""]


def render_markdown(change_map: dict, *, repo_url: str | None = None, head_sha: str | None = None) -> str:
    parts = _partition(change_map)
    links = (repo_url, head_sha, change_map["base_commit"])
    out = ["### Skylos change map", "", *_header(change_map), ""]
    summary = review_line(change_map)
    if summary:
        out.extend([f"**{summary}**", ""])
    out.extend([_coverage_line(change_map), ""])
    out.extend(_markdown_read_first(parts["read_first"], links, set(change_map["flagged"])))
    out.extend(_markdown_constants(change_map["module_changes"]))
    out.extend(_markdown_list("#### Read", parts["read"], links, read_markdown))
    out.extend(_markdown_list("#### Skim", parts["skim"], links, why_markdown))
    out.extend(_markdown_list("#### Skip: same logic, proven", parts["skip"], links, why_markdown))
    out.extend(_markdown_tests(parts["tests"]))
    out.append("_Same commit, same map: computed from the code, not written by a model._")
    text = "\n".join(out) + "\n"
    if len(text) > MARKDOWN_CHAR_LIMIT:
        text = text[:MARKDOWN_CHAR_LIMIT] + "\n\n_Map cut for length; see the JSON output._\n"
    return text


