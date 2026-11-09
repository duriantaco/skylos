from __future__ import annotations

import logging
from dataclasses import dataclass, field

from skylos.graph.changes import SAME_VERDICTS, VERDICT_BINDING

logger = logging.getLogger(__name__)

REPORT_PATH = "/api/graph/reports"
DESCRIBE_PATH = "/api/graph/describe"
REPORT_SYMBOL_LIMIT = 400
LINES_PER_SYMBOL = 6
LINE_LIMIT = 300
SYMBOLS_PER_REQUEST = 100
CHANGES_PER_REQUEST = 20
UPLOAD_TIMEOUT = 60
DESCRIBE_TIMEOUT = 200
ID_LIMIT = 400
CALLERS_PER_CHANGE = 8
CALLER_STEPS = 3
TESTS_PER_CHANGE = 10
REPORT_ID_LIMIT = 800
KINDS = frozenset({"function", "method", "class"})


@dataclass
class CloudResult:
    ok: bool
    status: int
    message: str
    data: dict = field(default_factory=dict)


def _clip(value, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = value.replace("\0", "")
    if len(text) > limit:
        return text[:limit]
    return text


def _lines(values) -> list[str]:
    found = []
    for value in list(values or [])[:LINES_PER_SYMBOL]:
        text = " ".join(str(value).split())
        if text:
            found.append(text[:LINE_LIMIT])
    return found


_BUCKET_ORDER = {"read_first": 0, "read": 1, "skim": 2, "skip": 3}


def _priority(entry: dict, flagged: set[str]) -> int:
    if entry["id"] in flagged or entry["verdict"] == VERDICT_BINDING:
        return 0
    return _BUCKET_ORDER.get(entry.get("review") or "read", 1)


def _within(path: str, project_root: str) -> bool:
    if not project_root:
        return True
    return path == project_root or path.startswith(project_root.rstrip("/") + "/")


def _line(entry: dict) -> int:
    side = entry.get("after") or entry.get("before") or {}
    start = side.get("start")
    if isinstance(start, int) and start > 0:
        return start
    return 0


def _names(values, limit: int = 3) -> str:
    shown = [str(value) for value in list(values or [])[:limit]]
    extra = len(list(values or [])) - len(shown)
    text = ", ".join(shown)
    if extra > 0:
        text += f" and {extra} more"
    return text


def what_changed(entry: dict) -> list[str]:
    if entry.get("verdict") in SAME_VERDICTS or entry.get("verdict") in ("new", "removed"):
        return []
    lines = []
    if entry.get("calls_added"):
        lines.append(f"Now calls {_names(entry['calls_added'])}")
    if entry.get("calls_removed"):
        lines.append(f"No longer calls {_names(entry['calls_removed'])}")
    if entry.get("calls_retargeted"):
        lines.append(f"{len(entry['calls_retargeted'])} call(s) now reach different code")
    changed = entry.get("lines_changed")
    if isinstance(changed, int) and changed > 0 and not lines:
        unit = "lines"
        if changed == 1:
            unit = "line"
        lines.append(f"{changed} {unit} added or removed")
    return lines


def _record_reasons(entry: dict, flagged: bool) -> list[str]:
    if flagged:
        return list(entry.get("reasons") or []) + what_changed(entry)
    why = entry.get("review_why")
    if entry.get("review") in ("skim", "skip") and why:
        return [why]
    reasons = what_changed(entry) + list(entry.get("reasons") or [])
    if why and why != entry.get("verdict_text"):
        reasons.insert(0, why)
    return reasons


def _symbol_record(entry: dict, flagged: bool) -> dict:
    reasons = _record_reasons(entry, flagged)
    review = entry.get("review") or "read"
    if flagged:
        review = "read_first"
    return {
        "id": entry["id"],
        "name": _clip(entry.get("name"), 300) or "?",
        "file": _clip(entry.get("file"), 420) or "?",
        "kind": entry["kind"],
        "line": _line(entry),
        "verdict": entry["verdict"],
        "flagged": flagged,
        "review": review,
        "lines_changed": max(0, int(entry.get("lines_changed") or 0)),
        "reasons": _lines(reasons),
        "evidence": _lines(entry.get("evidence")),
        "moved_from": _clip(entry.get("moved_from"), REPORT_ID_LIMIT) or None,
        "moved_to": _clip(entry.get("moved_to"), REPORT_ID_LIMIT) or None,
    }


def build_report(changes: dict, *, commit: str, overview: dict | None = None, project_root: str = "",
                 pr_number: int | None = None, branch: str | None = None) -> dict:
    from skylos import __version__

    flagged = set(changes.get("flagged") or ())
    production = []
    tests_changed = 0
    for entry in changes.get("symbols", ()):
        if not _within(entry.get("file", ""), project_root):
            continue
        if entry.get("is_test"):
            tests_changed += 1
            continue
        if entry.get("kind") not in KINDS or len(entry.get("id", "")) > REPORT_ID_LIMIT:
            continue
        production.append(entry)
    production.sort(key=lambda entry: (_priority(entry, flagged), entry.get("file", ""), _line(entry)))
    symbols = [_symbol_record(entry, entry["id"] in flagged) for entry in production[:REPORT_SYMBOL_LIMIT]]
    report = {
        "kind": "skylos-graph-report",
        "schema_version": 1,
        "skylos_version": __version__,
        "commit": commit,
        "base": _clip(str(changes.get("base") or "HEAD"), 255),
        "base_commit": changes.get("base_commit"),
        "project_root": project_root,
        "pr_number": pr_number,
        "branch": branch,
        "symbols": symbols,
        "symbols_total": len(production),
        "tests_changed": tests_changed,
    }
    if overview:
        report["graph"] = {key: int(overview.get(key) or 0) for key in ("files", "functions", "methods", "classes", "links")}
    return report


def _post(path: str, token: str, payload: dict, timeout: int) -> CloudResult:
    import requests

    from skylos.api import BASE_URL, _build_auth_headers, _validate_api_request_url

    base = BASE_URL
    if base.endswith("/api"):
        base = base[: -len("/api")]
    try:
        url = _validate_api_request_url(f"{base}{path}")
    except ValueError as exc:
        return CloudResult(False, 0, f"Skylos Cloud address is not valid: {exc}")
    headers = dict(_build_auth_headers(token))
    headers["Content-Type"] = "application/json"
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=timeout, allow_redirects=False)
    except requests.RequestException as exc:
        logger.debug("graph cloud request failed", exc_info=True)
        return CloudResult(False, 0, f"Could not reach Skylos Cloud ({type(exc).__name__}).")
    try:
        data = response.json()
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    if response.status_code == 200:
        return CloudResult(True, 200, "", data)
    message = str(data.get("error") or f"Skylos Cloud answered {response.status_code}.")
    if response.status_code == 404 and not data.get("error"):
        message = "Skylos Cloud does not accept this yet: its codebase graph support has not shipped."
    return CloudResult(False, response.status_code, message[:500], data)


def upload_report(token: str, report: dict) -> CloudResult:
    result = _post(REPORT_PATH, token, report, UPLOAD_TIMEOUT)
    if not result.ok:
        return result
    data = result.data
    parts = ["Logic-change report sent"]
    if data.get("charged"):
        parts.append(f"{data['charged']} credit used")
    if data.get("comment") == "posted":
        parts.append("PR comment updated")
    if data.get("url"):
        parts.append(str(data["url"]))
    return CloudResult(True, 200, " · ".join(parts), data)


def fit_symbol(item: dict) -> dict | None:
    if len(item.get("id", "")) > ID_LIMIT:
        return None
    fitted = {
        "id": item["id"],
        "kind": _clip(item.get("kind"), 40) or "function",
        "name": _clip(item.get("name"), 300) or item["id"][:300],
        "file": _clip(item.get("file"), 420) or "?",
        "signature": _clip(item.get("signature"), 600),
        "docstring": _clip(item.get("docstring"), 400),
        "code": _clip(item.get("code"), 4200),
    }
    for key in ("used_by", "uses", "methods"):
        values = [_clip(value, 200) for value in list(item.get(key) or [])[:30]]
        fitted[key] = [value for value in values if value.strip()]
    return fitted


def fit_change(item: dict) -> dict | None:
    if len(item.get("id", "")) > ID_LIMIT:
        return None
    before = _clip(item.get("before"), 4200)
    after = _clip(item.get("after"), 4200)
    if not before.strip() and not after.strip():
        return None
    proven = [_clip(value, 400) for value in list(item.get("proven") or [])[:12]]
    tests = [_clip(value, 300) for value in list(item.get("tests") or [])[:TESTS_PER_CHANGE]]
    return {
        "id": item["id"],
        "name": _clip(item.get("name"), 300) or "?",
        "file": _clip(item.get("file"), 420) or "?",
        "verdict": _clip(item.get("verdict"), 200) or "Logic changed.",
        "proven": [value for value in proven if value.strip()],
        "before": before,
        "after": after,
        "callers": fit_callers(item.get("callers")),
        "tests": [value for value in tests if value.strip()],
    }


def fit_callers(rows) -> list[dict]:
    fitted = []
    seen = set()
    for row in list(rows or []):
        if len(fitted) >= CALLERS_PER_CHANGE:
            break
        if not isinstance(row, dict):
            continue
        caller = row.get("id")
        if not isinstance(caller, str) or not caller.strip() or len(caller) > ID_LIMIT or "\0" in caller or caller in seen:
            continue
        steps = row.get("steps")
        if not isinstance(steps, int) or isinstance(steps, bool) or steps < 1 or steps > CALLER_STEPS:
            continue
        line = row.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 0:
            line = 0
        seen.add(caller)
        fitted.append({
            "id": caller,
            "name": _clip(row.get("name"), 300) or caller[:300],
            "file": _clip(row.get("file"), 420) or "?",
            "line": line,
            "steps": steps,
            "is_test": row.get("is_test") is True,
            "description": _clip(row.get("description"), 400),
        })
    return fitted


def per_request(kind: str) -> int:
    if kind == "symbols":
        return SYMBOLS_PER_REQUEST
    return CHANGES_PER_REQUEST


def credits_needed(kind: str, count: int) -> int:
    size = per_request(kind)
    return (count + size - 1) // size


def describe_batch(token: str, kind: str, items: list[dict]) -> CloudResult:
    return _post(DESCRIBE_PATH, token, {"kind": kind, "items": items}, DESCRIBE_TIMEOUT)
