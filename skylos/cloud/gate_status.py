from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from skylos.cloud.upload_destination import _clean_project_id, _clean_ref

_COMMIT = re.compile(r"[0-9a-fA-F]{7,64}")
_TIMESTAMP = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?"
    r"(Z|[+-]\d{2}:?\d{2})?",
    re.ASCII,
)
_TIMESTAMP_LIMIT = 64
_PR_NUMBER_LIMIT = 10**9
_NEW_ISSUE_MODES = frozenset({"baseline", "pr-diff", "first-scan-baseline"})
_MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


@dataclass(frozen=True)
class GateContext:
    subject: str
    history: str | None
    details_url: str

    def status(self, passed: bool) -> str:
        word = "FAILED"
        if passed:
            word = "PASSED"
        text = f"{self.subject}: {word}"
        if self.history:
            text = f"{text} ({self.history})"
        return text


def clean_previous_gate(value) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        value = {}
    passed = value.get("passed")
    if not isinstance(passed, bool):
        passed = None
    cleaned = {
        "scan_id": _clean_project_id(value.get("scan_id")),
        "created_at": _clean_timestamp(value.get("created_at")),
        "commit": _clean_commit(value.get("commit")),
        "passed": passed,
        "overridden": value.get("overridden") is True,
    }
    if isinstance(value.get("trusted"), bool):
        cleaned["trusted"] = value["trusted"]
    return cleaned


def clean_pr_number(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if 0 < value < _PR_NUMBER_LIMIT:
        return value
    return None


def clean_new_issue_baseline(explain) -> dict | None:
    if not isinstance(explain, dict):
        return None
    mode = explain.get("detection_mode")
    if not isinstance(mode, str) or mode not in _NEW_ISSUE_MODES:
        return None
    baseline = explain.get("baseline")
    if not isinstance(baseline, dict):
        baseline = {}
    return {"mode": mode, "branch": _clean_ref(baseline.get("branch"))}


def new_issues_text(count: int, baseline) -> str:
    noun = "issues"
    if count == 1:
        noun = "issue"
    text = f"{count} new {noun}"
    if not isinstance(baseline, dict):
        return text
    if baseline.get("mode") == "pr-diff":
        return f"{text} (on lines this pull request changed)"
    if baseline.get("mode") != "baseline":
        return text
    branch = _clean_ref(baseline.get("branch"))
    if branch is None:
        return f"{text} (not in the last passing scan)"
    return f"{text} (not in the last passing scan of {branch})"


def details_url(base_url: str, project_id, scan_id) -> str | None:
    scan = _clean_project_id(scan_id)
    if scan is None:
        return None
    base = base_url.rstrip("/")
    project = _clean_project_id(project_id)
    if project is None:
        return f"{base}/dashboard/scans/{quote(scan, safe='')}"
    return (
        f"{base}/dashboard/projects/{quote(project, safe='')}"
        f"/scans/{quote(scan, safe='')}"
    )


def format_gate_time(value) -> str | None:
    moment = _parse_timestamp(value)
    if moment is None:
        return None
    try:
        moment = moment.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None
    month = _MONTHS[moment.month - 1]
    return f"{moment.day:02d} {month} {moment.hour:02d}:{moment.minute:02d} UTC"


def history_text(passed: bool, previous: dict | None) -> str | None:
    if previous is None:
        return "first result on this branch"
    if previous["overridden"]:
        text = "was OVERRIDDEN"
    elif previous["passed"] is None:
        return None
    elif previous["passed"] == passed:
        text = "same as last run"
    elif previous["passed"]:
        text = "was PASSED"
    else:
        text = "was FAILED"
    when = format_gate_time(previous["created_at"])
    if when:
        text = f"{text} on {when}"
    if previous["commit"]:
        text = f"{text}, {previous['commit'][:7]}"
    if previous.get("trusted") is False:
        text = f"{text}, unverified upload"
    return text


def gate_context(result: dict, base_url: str) -> GateContext | None:
    if not isinstance(result, dict) or "previous_gate" not in result:
        return None
    destination = result.get("destination")
    if not isinstance(destination, dict):
        destination = {}
    url = details_url(base_url, destination.get("project_id"), result.get("scan_id"))
    if url is None:
        return None
    branch = _clean_ref(destination.get("branch"))
    if branch is None:
        return GateContext(subject="Quality gate", history=None, details_url=url)
    subject = f"Quality gate on {branch}"
    pr_number = clean_pr_number(destination.get("pr_number"))
    if pr_number is not None:
        subject = f"{subject} (PR #{pr_number})"
    if result.get("quality_gate_reported") is False:
        return GateContext(subject=subject, history=None, details_url=url)
    passed = bool(result.get("quality_gate_passed"))
    previous = clean_previous_gate(result["previous_gate"])
    return GateContext(
        subject=subject,
        history=history_text(passed, previous),
        details_url=url,
    )


def formatted_gate_line(result: dict, base_url: str) -> str | None:
    context = gate_context(result, base_url)
    if context is None:
        return None
    if result.get("quality_gate_reported") is False:
        return None
    passed = result.get("quality_gate_passed")
    if not isinstance(passed, bool):
        return None
    return f"{context.status(passed)} — View details: {context.details_url}"


def _clean_commit(value) -> str | None:
    if isinstance(value, str) and _COMMIT.fullmatch(value):
        return value
    return None


def _clean_timestamp(value) -> str | None:
    if _parse_timestamp(value) is None:
        return None
    return value


def _parse_timestamp(value) -> datetime | None:
    if not isinstance(value, str) or len(value) > _TIMESTAMP_LIMIT:
        return None
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        return None
    year, month, day, hour, minute = (int(part) for part in match.group(1, 2, 3, 4, 5))
    second = int(match.group(6) or 0)
    try:
        return datetime(
            year, month, day, hour, minute, second, tzinfo=_zone(match.group(7))
        )
    except ValueError:
        return None


def _zone(text: str | None) -> timezone:
    if not text or text == "Z":
        return timezone.utc
    digits = text[1:].replace(":", "")
    offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    if text[0] == "-":
        offset = -offset
    return timezone(offset)
