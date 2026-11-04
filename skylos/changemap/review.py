from __future__ import annotations

import ast
import collections
import re
import textwrap

from skylos.changemap.risk import STATUS_ADDED, STATUS_DELETED, is_test_file
from skylos.changemap.sameness import SAME_DOCS, SAME_RENAMED, same_logic

VERDICT_NEW = "new"
VERDICT_REMOVED = "removed"
VERDICT_MOVED = "same_moved"
VERDICT_SAME_DOCS = "same_docs"
VERDICT_SAME_RENAMED = "same_renamed"
VERDICT_BINDING = "changed_binding"
VERDICT_CHANGED = "changed"
VERDICT_SAME_CALLEE_MOVED = "same_callee_moved"

SAME_VERDICTS = frozenset({VERDICT_MOVED, VERDICT_SAME_DOCS, VERDICT_SAME_RENAMED, VERDICT_SAME_CALLEE_MOVED})

VERDICT_TEXT = {
    VERDICT_NEW: "New code.",
    VERDICT_REMOVED: "Removed.",
    VERDICT_MOVED: "Same code, only moved.",
    VERDICT_SAME_DOCS: "Same logic. Only the docstring changed.",
    VERDICT_SAME_RENAMED: "Same logic. Only local variable names changed.",
    VERDICT_BINDING: "The text looks the same, but a name now points to different code.",
    VERDICT_CHANGED: "Logic changed.",
    VERDICT_SAME_CALLEE_MOVED: "Same logic. Its code is unchanged; only functions it calls moved, unchanged.",
}

WHY_MOVED_UNRESOLVED = "Moved to {file}, but it reads {names}, which {file} does not define or import."

READ_FIRST = "read_first"
READ = "read"
SKIM = "skim"
SKIP = "skip"
BUCKETS = (READ_FIRST, READ, SKIM, SKIP)
READ_FIRST_LIMIT = 3

_DOC_RUNTIME = re.compile(r"__doc__|^\s*(?:from|import)\s+(?:ply|docopt)\b|getdoc\(", re.MULTILINE)
_DOC_RUNTIME_NAMES = ("p_", "t_")

WHY_DOC_RUNTIME = "This file reads docstrings while it runs (__doc__, getdoc, PLY or docopt), so the docstring can be logic."
WHY_DOC_DECORATED = "Decorated, so the docstring may be shown while the program runs (CLI help, API docs)."
WHY_DOC_DOCTEST = "The docstring's doctest examples changed."
WHY_DOC_CLASS = "The class has a base class, so its docstrings may become help text, a schema or an API description."
WHY_TESTS_EDITED = "Its tests' expected answers changed in this same change."
WHY_REMOVED_UNUSED = "Removed, and nothing in this repository still calls it."
WHY_MOVED = (
    "Same code, moved to {file}. Its import path changed, which matters if anything refers to it by path: "
    "API schema names, task names, pickled data or mock.patch targets."
)
WHY_MOVED_ORIGIN = "Moved to {file}; reviewed there."
WHY_SPECIAL_REMOVED = "Removed a special method Python calls on its own ({name}), so the class behaves differently."
WHY_CLASS_METHODS = "Only the class's own docstring changed, but some of its methods changed and are listed separately."

_PLAIN_DECORATORS = frozenset({
    "property", "setter", "getter", "deleter", "classmethod", "staticmethod", "abstractmethod",
    "cached_property", "overload", "override", "final",
})


def verdict_for(entry: dict) -> str:
    status = entry["status"]
    if status == STATUS_ADDED and not entry.get("moved_from"):
        return VERDICT_NEW
    if status == STATUS_DELETED and not entry.get("moved_to"):
        return VERDICT_REMOVED
    if status == STATUS_DELETED:
        return VERDICT_MOVED
    if entry.get("binding_changed"):
        return VERDICT_BINDING
    for key in ("signature_changed", "values_changed", "calls_added", "calls_removed", "calls_retargeted"):
        if entry.get(key):
            return VERDICT_CHANGED
    if entry.get("moved_from"):
        return VERDICT_MOVED
    found = None
    if str(entry.get("file", "")).endswith(".py"):
        found = same_logic(entry.get("before"), entry.get("after"))
    if found == SAME_DOCS:
        return VERDICT_SAME_DOCS
    if found == SAME_RENAMED:
        return VERDICT_SAME_RENAMED
    return VERDICT_CHANGED


def case_record(case, js: bool) -> dict:
    from skylos.done.expected_answers import _NONLIT, _show

    calls = []
    for call in case.calls:
        args = []
        for value in call.args:
            if value == _NONLIT:
                args.append("…")
            else:
                args.append(_show(value, js))
        for name, value in call.kwargs:
            if value == _NONLIT:
                args.append(f"{name}=…")
            else:
                args.append(f"{name}={_show(value, js)}")
        calls.append({"name": call.name, "text": f"{call.name}({', '.join(args)})"})
    expected = sorted(_show(value, js) for value in case.expected)
    return {"test": case.test, "calls": calls, "expected": expected}


def _cases(path: str, source: str | None) -> list[dict]:
    if not source:
        return []
    from skylos.changemap.ts_imports import is_ts_path
    from skylos.done.expected_answers import js_cases, python_cases

    try:
        if path.endswith(".py"):
            found = python_cases(path, source)
        else:
            found = js_cases(path, source)
    except (RecursionError, ValueError, SyntaxError):
        return []
    return [case_record(case, is_ts_path(path)) for case in found]


def _by_name(cases: list[dict]) -> dict[str, dict[str, set[str]]]:
    grouped: dict[str, dict[str, set[str]]] = collections.defaultdict(lambda: collections.defaultdict(set))
    for case in cases:
        for call in case["calls"]:
            simple = call["name"].rsplit(".", 1)[-1]
            grouped[simple][call["text"]].update(case["expected"])
    return grouped


def test_edits(inputs) -> dict[str, dict]:
    before_cases: list[dict] = []
    after_cases: list[dict] = []
    for path, change in inputs.files.items():
        if not is_test_file(path):
            continue
        before_cases.extend(_cases(path, change.base_source))
        after_cases.extend(_cases(path, change.head_source))
    before = _by_name(before_cases)
    after = _by_name(after_cases)
    edits: dict[str, dict] = {}
    for name in set(before) | set(after):
        old = before.get(name, {})
        new = after.get(name, {})
        changed = []
        for call in sorted(set(old) & set(new)):
            if old[call] != new[call]:
                changed.append({"call": call, "before": sorted(old[call]), "after": sorted(new[call])})
        removed = [{"call": c, "expected": sorted(old[c])} for c in sorted(set(old) - set(new))]
        added = [{"call": c, "expected": sorted(new[c])} for c in sorted(set(new) - set(old))]
        if changed or removed or added:
            edits[name] = {"changed": changed[:10], "removed": removed[:10], "added": added[:10]}
    return edits


def test_edit_lines(name: str, edits: dict) -> list[str]:
    simple = name.rsplit(".", 1)[-1]
    edit = edits.get(simple)
    if not edit:
        return []
    lines = []
    for item in edit["changed"][:3]:
        lines.append(f"Tests now expect {item['call']} to give {', '.join(item['after'])} (was {', '.join(item['before'])}).")
    if edit["removed"]:
        lines.append(f"{len(edit['removed'])} test check(s) for {simple} were removed.")
    if edit["added"]:
        lines.append(f"{len(edit['added'])} new test check(s) for {simple}.")
    return lines


def _expectations_weakened(name: str, edits: dict) -> bool:
    edit = edits.get(name.rsplit(".", 1)[-1])
    if not edit:
        return False
    return bool(edit["changed"] or edit["removed"])


def _decorated(code: str) -> bool:
    for line in code.splitlines():
        text = line.strip()
        if not text:
            continue
        if not text.startswith("@"):
            return False
        name = text[1:].split("(", 1)[0].strip()
        if name.rsplit(".", 1)[-1] not in _PLAIN_DECORATORS:
            return True
    return False


class _Sources:
    def __init__(self, inputs):
        self.inputs = inputs
        self.trees: dict[str, ast.Module | None] = {}

    def head(self, path: str) -> str:
        change = self.inputs.files.get(path)
        if change is None:
            return ""
        return change.head_source or change.base_source or ""

    def class_has_bases(self, path: str, class_name: str) -> bool:
        if path not in self.trees:
            try:
                self.trees[path] = ast.parse(self.head(path))
            except (SyntaxError, ValueError, RecursionError):
                self.trees[path] = None
        tree = self.trees[path]
        if tree is None:
            return True
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                return bool(node.bases or node.keywords)
        return False


def _code(entry: dict, side: str) -> str:
    return (entry.get(side) or {}).get("code") or ""


def _parsed_class_has_bases(code: str) -> bool:
    try:
        tree = ast.parse(textwrap.dedent(code))
    except (SyntaxError, ValueError, RecursionError):
        return True
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            return bool(node.bases or node.keywords)
    return True


def _docs_bucket(entry: dict, sources: _Sources) -> tuple[str, str]:
    simple = entry["name"].rsplit(".", 1)[-1]
    if _DOC_RUNTIME.search(sources.head(entry["file"])) or simple.startswith(_DOC_RUNTIME_NAMES):
        return READ, WHY_DOC_RUNTIME
    before = _code(entry, "before")
    after = _code(entry, "after")
    if _decorated(before) or _decorated(after):
        return SKIM, WHY_DOC_DECORATED
    if ">>>" in before or ">>>" in after:
        return SKIM, WHY_DOC_DOCTEST
    if entry["kind"] == "class" and _parsed_class_has_bases(after):
        return SKIM, WHY_DOC_CLASS
    if "." in entry["name"] and sources.class_has_bases(entry["file"], entry["name"].split(".")[0]):
        return SKIM, WHY_DOC_CLASS
    return SKIP, VERDICT_TEXT[VERDICT_SAME_DOCS]


def _flag_reason(entry: dict) -> str:
    if entry["reasons"]:
        return "Flagged: " + "; ".join(entry["reasons"][:2]) + "."
    return "Flagged."


def _group_leads(groups: list[dict]) -> dict[str, str]:
    leads = {}
    for group in groups:
        members = group["members"]
        for member in members:
            leads[member] = members[0]
    return leads


def _bucket(entry: dict, flagged: set[str], leads: dict[str, str], names: dict[str, str], edits: dict, sources: _Sources) -> tuple[str, str]:
    if entry["id"] in flagged:
        return READ_FIRST, _flag_reason(entry)
    if _expectations_weakened(entry["name"], edits):
        return READ, WHY_TESTS_EDITED
    if _moved_origin(entry):
        return SKIM, entry["verdict_text"]
    verdict = entry["verdict"]
    if verdict == VERDICT_SAME_DOCS:
        return _docs_bucket(entry, sources)
    if verdict == VERDICT_MOVED:
        return SKIM, WHY_MOVED.format(file=entry["file"])
    if verdict in SAME_VERDICTS:
        return SKIP, entry["verdict_text"]
    lead = leads.get(entry["id"])
    if lead is not None and lead != entry["id"]:
        return SKIM, f"Same edit as {names[lead]}."
    if entry["status"] == STATUS_DELETED and not entry.get("moved_to"):
        simple = entry["name"].rsplit(".", 1)[-1]
        if "." in entry["name"] and simple.startswith("__") and simple.endswith("__"):
            return READ, WHY_SPECIAL_REMOVED.format(name=simple)
        if not entry["still_referenced_by"]:
            return SKIM, WHY_REMOVED_UNUSED
    return READ, entry["verdict_text"]


def _read_first(production: list[dict], grouped: set[str], flagged: list[str]) -> list[str]:
    candidates = [s["id"] for s in production if s["review"] in (READ_FIRST, READ) and s["id"] not in grouped]
    top = candidates[:READ_FIRST_LIMIT]
    return top + [entry_id for entry_id in flagged if entry_id not in top]


def _check_moves(symbols: list[dict], by_id: dict, sources) -> dict[str, str]:
    from skylos.changemap.moves import unresolved_names

    safe = {}
    for entry in symbols:
        origin = by_id.get(entry.get("moved_from") or "")
        if entry["verdict"] not in (VERDICT_MOVED, VERDICT_CHANGED) or origin is None or not entry["file"].endswith(".py"):
            continue
        missing = unresolved_names(_code(entry, "after"), sources.head(entry["file"]))
        if missing:
            entry["verdict"] = VERDICT_CHANGED
            entry["verdict_text"] = WHY_MOVED_UNRESOLVED.format(file=entry["file"], names=", ".join(missing[:5]))
            continue
        if missing is not None and entry["verdict"] == VERDICT_MOVED:
            safe[origin["full_name"]] = entry["full_name"]
    return safe


def _callee_moves_only(entry: dict, safe_moves: dict[str, str]) -> bool:
    if entry["verdict"] != VERDICT_BINDING or not entry.get("calls_retargeted"):
        return False
    for key in ("signature_changed", "values_changed", "calls_added", "calls_removed"):
        if entry.get(key):
            return False
    for text in entry["calls_retargeted"]:
        old, _sep, new = str(text).partition(" → ")
        if safe_moves.get(old) != new:
            return False
    return True


def _set_verdicts(symbols: list[dict], sources) -> None:
    for entry in symbols:
        verdict = verdict_for(entry)
        entry["verdict"] = verdict
        entry["verdict_text"] = VERDICT_TEXT[verdict]
    by_id = {s["id"]: s for s in symbols}
    safe_moves = _check_moves(symbols, by_id, sources)
    for entry in symbols:
        if _callee_moves_only(entry, safe_moves):
            moved = ", ".join(entry["calls_retargeted"][:3])
            entry["verdict"] = VERDICT_SAME_CALLEE_MOVED
            entry["verdict_text"] = f"Same logic. Its code is unchanged; only functions it calls moved, unchanged: {moved}."
    for entry in symbols:
        target = by_id.get(entry.get("moved_to") or "")
        if entry["status"] != STATUS_DELETED or target is None or target["verdict"] == VERDICT_MOVED:
            continue
        entry["verdict"] = target["verdict"]
        entry["verdict_text"] = f"Moved to {target['file']}, where it changed: {target['verdict_text']}"
    for entry in symbols:
        entry["same_logic"] = entry["verdict"] in SAME_VERDICTS


def _moved_origin(entry: dict) -> bool:
    return entry["status"] == STATUS_DELETED and bool(entry.get("moved_to")) and entry["verdict"] != VERDICT_MOVED


def _classes_with_changed_methods(production: list[dict]) -> None:
    changed = {(s["file"], s["name"].split(".")[0]) for s in production if "." in s["name"] and s["review"] in (READ_FIRST, READ)}
    for entry in production:
        if entry["kind"] == "class" and entry["review"] == SKIP and (entry["file"], entry["name"]) in changed:
            entry["review"] = SKIM
            entry["review_why"] = WHY_CLASS_METHODS


def _origin_target(entry: dict, by_id: dict) -> dict | None:
    if entry["status"] != STATUS_DELETED or not entry.get("moved_to"):
        return None
    target = by_id.get(entry["moved_to"])
    if target is None or target["is_test"]:
        return None
    return target


def build_review(inputs, symbols: list[dict], flagged: list[str], groups: list[dict]) -> dict:
    edits = test_edits(inputs)
    sources = _Sources(inputs)
    leads = _group_leads(groups)
    names = {s["id"]: s["name"] for s in symbols}
    flagged_set = set(flagged)
    production = []
    _set_verdicts(symbols, sources)
    for entry in symbols:
        entry["test_evidence"] = test_edit_lines(entry["name"], edits)
        if entry["is_test"]:
            entry["review"] = None
            entry["review_why"] = None
            continue
        entry["review"], entry["review_why"] = _bucket(entry, flagged_set, leads, names, edits, sources)
        production.append(entry)
    _classes_with_changed_methods(production)
    by_id = {s["id"]: s for s in production}
    origins = {}
    for entry in production:
        target = _origin_target(entry, by_id)
        if target is not None:
            origins[entry["id"]] = target
    listed = [entry for entry in production if entry["id"] not in origins]
    grouped = set(leads)
    read_first = _read_first(listed, grouped, flagged)
    first = set(read_first)
    buckets: dict[str, list[str]] = {name: [] for name in BUCKETS}
    lines = dict.fromkeys(BUCKETS, 0)
    for entry in listed:
        if entry["id"] in first:
            entry["review"] = READ_FIRST
        elif entry["review"] == READ_FIRST:
            entry["review"] = READ
        buckets[entry["review"]].append(entry["id"])
        lines[entry["review"]] += entry["lines_changed"]
    for origin_id, target in origins.items():
        origin = by_id[origin_id]
        origin["review"] = target["review"]
        origin["review_why"] = WHY_MOVED_ORIGIN.format(file=target["file"])
        lines[target["review"]] += origin["lines_changed"]
    buckets[READ_FIRST] = read_first
    return {
        "buckets": buckets,
        "counts": {name: len(ids) for name, ids in buckets.items()},
        "lines": lines,
        "total": len(listed),
        "total_lines": sum(lines.values()),
        "test_edits": edits,
    }
