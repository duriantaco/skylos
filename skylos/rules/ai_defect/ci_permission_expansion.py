"""SKY-A103: diff-aware CI permission expansion detection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

RULE_ID = "SKY-A103"

_HUNK_RE = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_PERMISSION_WRITE_RE = re.compile(
    r"^(?P<permission>[A-Za-z0-9_-]+)\s*:\s*['\"]?write['\"]?\s*(?:#.*)?$"
)
_INLINE_PERMISSIONS_RE = re.compile(r"\b([A-Za-z0-9_-]+)\s*:\s*write\b")
_PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}
_GITHUB_ACTIONS_WORKFLOW_SUFFIXES = {".yml", ".yaml"}
_WRITE_PERMISSIONS = {
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
}


@dataclass(frozen=True)
class _DiffLine:
    line_no: int
    text: str


def detect_ci_permission_expansion(diff_text: str, file_path: str) -> list[dict]:
    """Return findings when a GitHub Actions diff adds privileged CI behavior."""
    if not _is_github_actions_workflow(file_path):
        return []

    removed, added = _parse_changed_lines(diff_text)
    removed_normalized: set[str] = set()
    for line in removed:
        normalized_removed = _normalize_yaml_line(line.text)
        if normalized_removed:
            removed_normalized.add(normalized_removed)

    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for line in added:
        normalized = _normalize_yaml_line(line.text)
        if not normalized or normalized in removed_normalized:
            continue

        signal = _signal_for_added_line(normalized)
        if signal is None:
            continue

        key = (signal["expansion_type"], signal["value"])
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            _make_finding(
                file_path,
                line.line_no,
                expansion_type=signal["expansion_type"],
                value=signal["value"],
                severity=signal["severity"],
            )
        )

    return findings


def _is_github_actions_workflow(file_path: str) -> bool:
    normalized = str(file_path).replace("\\", "/")
    normalized_path = f"/{normalized}"
    if "/.github/workflows/" not in normalized_path:
        return False

    suffix = Path(normalized).suffix.lower()
    if suffix not in _GITHUB_ACTIONS_WORKFLOW_SUFFIXES:
        return False

    return True


def _parse_changed_lines(diff_text: str) -> tuple[list[_DiffLine], list[_DiffLine]]:
    removed: list[_DiffLine] = []
    added: list[_DiffLine] = []
    old_line = 0
    new_line = 0

    for raw_line in diff_text.splitlines():
        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            old_line = int(hunk_match.group(1))
            new_line = int(hunk_match.group(2))
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            removed.append(_DiffLine(old_line, raw_line[1:]))
            old_line += 1
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added.append(_DiffLine(new_line, raw_line[1:]))
            new_line += 1
            continue

        old_line += 1
        new_line += 1

    return removed, added


def _normalize_yaml_line(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    return stripped.strip("'\"")


def _signal_for_added_line(line: str) -> dict | None:
    for trigger in _PRIVILEGED_TRIGGERS:
        if _line_adds_trigger(line, trigger):
            return {
                "expansion_type": "privileged_trigger",
                "value": trigger,
                "severity": "HIGH",
            }

    if re.match(r"^permissions\s*:\s*['\"]?write-all['\"]?\s*(?:#.*)?$", line):
        return {
            "expansion_type": "write_all_permissions",
            "value": "permissions: write-all",
            "severity": "HIGH",
        }

    if line.startswith("permissions:") and "{" in line:
        inline_writes: list[str] = []
        for permission in _INLINE_PERMISSIONS_RE.findall(line):
            if permission in _WRITE_PERMISSIONS:
                inline_writes.append(permission)

        if inline_writes:
            return {
                "expansion_type": "write_permission",
                "value": f"{inline_writes[0]}: write",
                "severity": "HIGH",
            }

    match = _PERMISSION_WRITE_RE.match(line)
    if match and match.group("permission") in _WRITE_PERMISSIONS:
        permission = match.group("permission")
        return {
            "expansion_type": "write_permission",
            "value": f"{permission}: write",
            "severity": "HIGH",
        }

    return None


def _line_adds_trigger(line: str, trigger: str) -> bool:
    if trigger not in line:
        return False

    trigger_pattern = (
        rf"(?:^|[\s\[,{{:-]){re.escape(trigger)}(?:\s*:|[\s\],}}]|$)"
    )
    match = re.search(trigger_pattern, line)
    return match is not None


def _make_finding(
    file_path: str,
    line: int,
    *,
    expansion_type: str,
    value: str,
    severity: str,
) -> dict:
    return {
        "rule_id": RULE_ID,
        "kind": "ci_permission_expansion",
        "severity": severity,
        "message": (
            "AI defect signal: CI workflow privilege expanded in this diff "
            f"({value}). Review whether this permission or trigger is intended."
        ),
        "file": file_path,
        "line": max(line, 1),
        "col": 0,
        "category": "ai_defect",
        "defect_type": "ci_permission_expansion",
        "vibe_category": "ci_permission_expansion",
        "metadata": {
            "expansion_type": expansion_type,
            "added_value": value,
            "signal_only": False,
            "blocking_recommended": True,
        },
    }
