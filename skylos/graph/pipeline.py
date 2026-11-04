"""The stage view behind the viewer's Pipeline tab.

Every `skylos done` run leaves a receipt in .skylos/receipts/. Each receipt
becomes one row; its checks are grouped into stages a person can scan left to
right, the way a CI stage view reads. The review summary from the change map
for the same base and head commits is attached when one was saved.
"""

from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

from skylos.done.receipt import FIXES, HISTORY_NAME, LABELS, LATEST_NAME, RECEIPTS_DIR, UNCHECKED, _status_word, validate_receipt
from skylos.graph.store import ensure_dir, graph_dir, read_json, write_json

REVIEWS_DIR = "reviews"
RUN_LIMIT = 30
FILE_LIMIT = 1_000_000
FINDING_LIMIT = 20
SHA_PREFIX = 12

STATE_FAIL = "fail"
STATE_UNFINISHED = "unfinished"
STATE_WARN = "warn"
STATE_SKIPPED = "skipped"
STATE_PASS = "pass"
STATE_NOT_RUN = "not_run"
STATE_INFO = "info"

_WORST_FIRST = (STATE_FAIL, STATE_UNFINISHED, STATE_WARN, STATE_SKIPPED, STATE_PASS)
_WORD_STATE = {
    "PASS": STATE_PASS,
    "FAIL": STATE_FAIL,
    "UNFINISHED": STATE_UNFINISHED,
    "WARN": STATE_WARN,
    "SKIP": STATE_SKIPPED,
    "OFF": STATE_SKIPPED,
}

STAGES = (
    ("tests", "Tests", ("tests_pass",)),
    ("honest", "Tests not gamed", ("test_tampering", "test_special_casing")),
    ("guards", "Checks not silenced", ("silenced_checks", "guardrail_tampering", "gate_tampering", "agent_edits")),
    ("security", "Security", ("secrets", "security_controls", "unknown_imports")),
    ("coverage", "Changed lines tested", ("changed_lines_checked",)),
    ("unused", "Unused code", ("branch_orphans",)),
)
OTHER_STAGE = ("other", "Other checks")
REVIEW_STAGE = ("review", "Review")
VERDICT_STAGE = ("verdict", "Verdict")


def columns() -> list[dict]:
    keys = [(key, title) for key, title, _ids in STAGES] + [OTHER_STAGE, REVIEW_STAGE, VERDICT_STAGE]
    return [{"key": key, "title": title} for key, title in keys]


def review_key(base: str | None, head: str | None) -> str | None:
    if not base or not head:
        return None
    return f"{base[:SHA_PREFIX]}-{head[:SHA_PREFIX]}"


def save_review(root: str | Path, change_map: dict) -> Path | None:
    from skylos.graph.files import list_repo_files

    repo = list_repo_files(root)
    key = review_key(change_map.get("base_commit"), repo.head)
    review = change_map.get("review")
    if key is None or not isinstance(review, dict):
        return None
    by_id = {s["id"]: s for s in change_map.get("symbols", ())}
    record = {
        "base": change_map["base_commit"],
        "head": repo.head,
        "dirty": repo.dirty,
        "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counts": review.get("counts", {}),
        "lines": review.get("lines", {}),
        "total": review.get("total", 0),
        "total_lines": review.get("total_lines", 0),
        "read_first": [_review_item(by_id[i]) for i in review.get("buckets", {}).get("read_first", ()) if i in by_id],
    }
    directory = ensure_dir(repo.root) / REVIEWS_DIR
    directory.mkdir(exist_ok=True)
    path = directory / f"{key}.json"
    write_json(path, record, indent=2)
    return path


def _review_item(entry: dict) -> dict:
    side = entry.get("after") or entry.get("before") or {}
    return {
        "name": entry.get("name"),
        "file": entry.get("file"),
        "line": side.get("start"),
        "why": entry.get("review_why") or entry.get("verdict_text"),
    }


def _load_review(root: Path, base: str | None, head: str | None) -> dict | None:
    key = review_key(base, head)
    if key is None:
        return None
    path = graph_dir(root) / REVIEWS_DIR / f"{key}.json"
    if path.is_symlink():
        return None
    data = read_json(path)
    if not isinstance(data, dict):
        return None
    return data


def _json_files(directory: Path) -> list[Path]:
    if directory.is_symlink() or not directory.is_dir():
        return []
    found = []
    for path in directory.glob("*.json"):
        if path.name == LATEST_NAME or path.is_symlink() or not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= FILE_LIMIT:
            found.append(path)
    return found


def _receipt_files(root: Path) -> list[Path]:
    directory = root / RECEIPTS_DIR
    if directory.is_symlink():
        return []
    history = _json_files(directory / HISTORY_NAME)
    recorded = {path.name.split("-", 1)[-1] for path in history}
    legacy = [path for path in _json_files(directory) if path.name not in recorded]
    return sorted(history + legacy, key=_modified, reverse=True)[:RUN_LIMIT]


def _modified(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _read_receipt(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if validate_receipt(data):
        return None
    return data


def _check_state(check: dict) -> str:
    return _WORD_STATE.get(_status_word(check), STATE_SKIPPED)


def _worst(states: list[str]) -> str:
    for state in _WORST_FIRST:
        if state in states:
            return state
    return STATE_NOT_RUN


def _finding(item: dict) -> dict:
    return {
        "rule": item.get("rule"),
        "file": item.get("file"),
        "line": item.get("line"),
        "message": item.get("message"),
    }


def _check_detail(check: dict) -> dict:
    findings = list(check.get("findings") or [])
    state = _check_state(check)
    detail = {
        "id": check["id"],
        "rule": check.get("rule"),
        "label": LABELS.get(check["id"], check["id"]),
        "state": state,
        "word": _status_word(check),
        "findings": [_finding(item) for item in findings[:FINDING_LIMIT]],
        "more": max(0, len(findings) - FINDING_LIMIT),
        "fix": None,
        "problem": None,
    }
    if state in (STATE_FAIL, STATE_WARN):
        detail["fix"] = FIXES.get(check["id"])
    if state in (STATE_UNFINISHED, STATE_SKIPPED):
        detail["problem"] = UNCHECKED.get(check["id"])
    return detail


def _stage(key: str, title: str, checks: list[dict]) -> dict:
    details = [_check_detail(check) for check in checks]
    state = _worst([detail["state"] for detail in details])
    count = sum(len(detail["findings"]) + detail["more"] for detail in details if detail["state"] != STATE_PASS)
    return {"key": key, "title": title, "state": state, "count": count, "checks": details}


def _stages(receipt: dict) -> list[dict]:
    checks = [check for check in receipt.get("checks", ()) if isinstance(check, dict) and check.get("id")]
    grouped = set()
    stages = []
    for key, title, ids in STAGES:
        members = [check for check in checks if check["id"] in ids]
        grouped.update(check["id"] for check in members)
        stages.append(_stage(key, title, members))
    others = [check for check in checks if check["id"] not in grouped]
    stages.append(_stage(OTHER_STAGE[0], OTHER_STAGE[1], others))
    return stages


def _review_stage(review: dict | None, base: str | None) -> dict:
    key, title = REVIEW_STAGE
    if review is None:
        hint = "No review saved for this commit. Run: skylos done map"
        if base:
            hint += f" --base {base[:SHA_PREFIX]}"
        return {"key": key, "title": title, "state": STATE_NOT_RUN, "count": 0, "label": "Not run", "hint": hint, "review": None}
    counts = review.get("counts") or {}
    lines = review.get("lines") or {}
    from skylos.changemap.render import review_counts_text

    read_lines = int(lines.get("read_first", 0)) + int(lines.get("read", 0))
    label = "Nothing to read"
    if counts.get("read_first"):
        label = f"{counts['read_first']} to read first"
    elif counts.get("read"):
        label = f"{counts['read']} to read"
    elif review.get("total"):
        label = "Skim or skip only"
    return {
        "key": key,
        "title": title,
        "state": STATE_INFO,
        "count": int(counts.get("read_first", 0)),
        "label": label,
        "hint": f"{review_counts_text(counts) or 'Nothing changed outside tests'}. {read_lines} of {review.get('total_lines', 0)} changed lines need reading.",
        "review": review,
    }


def _verdict_stage(verdict: str) -> dict:
    key, title = VERDICT_STAGE
    states = {"pass": STATE_PASS, "fail": STATE_FAIL, "incomplete": STATE_UNFINISHED}
    labels = {"pass": "Pass", "fail": "Fail", "incomplete": "Unfinished"}
    return {"key": key, "title": title, "state": states.get(verdict, STATE_NOT_RUN), "count": 0, "label": labels.get(verdict, verdict)}


_BRIEF_ORDER = (STATE_FAIL, STATE_UNFINISHED, STATE_WARN)


def _brief_checks(run: dict) -> list[dict]:
    checks = [check for stage in run["stages"] for check in stage.get("checks", ())]
    ordered = []
    for state in _BRIEF_ORDER:
        ordered.extend(check for check in checks if check["state"] == state)
    return ordered


def fix_brief(run: dict) -> str:
    lines = []
    for check in _brief_checks(run):
        lines.append(f"- {check['label']} ({check['word']})")
        for item in check["findings"][:8]:
            where = item.get("file") or ""
            if item.get("line"):
                where = f"{where}:{item['line']}"
            lines.append(f"  - {where} {item.get('message') or ''}".rstrip())
        if check.get("fix"):
            lines.append(f"  Fix: {check['fix']}")
        if check.get("problem"):
            lines.append(f"  Not checked: {check['problem']}")
    if not lines:
        return ""
    head = [f"Skylos done found problems in this change (base {run['base']}, head {run['head']}):"]
    if run.get("verdict") == "pass":
        head = [f"Skylos done passed this change, with warnings worth fixing (base {run['base']}, head {run['head']}):"]
    tail = [
        "",
        "Fix the code, not the checks: do not delete, skip or loosen tests, settings or hooks to make these pass.",
        f"When you are done, run: {run['rerun']}",
    ]
    return "\n".join(head + lines + tail)


def _run(root: Path, path: Path, receipt: dict, claimed: set) -> dict:
    base = (receipt.get("base") or {}).get("sha")
    head = (receipt.get("head") or {}).get("sha")
    dirty = bool((receipt.get("head") or {}).get("dirty"))
    agent = receipt.get("agent") or {}
    stages = _stages(receipt)
    review = None
    key = (review_key(base, head), dirty)
    if key not in claimed:
        claimed.add(key)
        review = _load_review(root, base, head)
        if review is not None and bool(review.get("dirty")) != dirty:
            review = None
    stages.append(_review_stage(review, base))
    stages.append(_verdict_stage(receipt.get("verdict", "")))
    rerun = "skylos done"
    if base:
        rerun = f"skylos done --base {shlex.quote(base[:SHA_PREFIX])}"
    run = {
        "id": path.stem,
        "when": datetime.fromtimestamp(_modified(path), timezone.utc).isoformat(timespec="seconds"),
        "base": (base or "")[:SHA_PREFIX],
        "head": (head or "")[:SHA_PREFIX],
        "dirty": dirty,
        "agent": agent.get("client") or "unknown",
        "verdict": receipt.get("verdict"),
        "skylos_version": receipt.get("skylos_version"),
        "stages": stages,
        "rerun": rerun,
    }
    run["brief"] = fix_brief(run)
    return run


def pipeline(root: str | Path) -> dict:
    root = Path(root).resolve()
    runs = []
    skipped = 0
    claimed: set = set()
    for path in _receipt_files(root):
        receipt = _read_receipt(path)
        if receipt is None:
            skipped += 1
            continue
        runs.append(_run(root, path, receipt, claimed))
    return {"columns": columns(), "runs": runs, "unreadable": skipped, "start": "skylos done --base origin/main"}
