"""SKY-A104: diff-aware public CLI surface drift detection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

RULE_ID = "SKY-A104"

_HUNK_RE = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_CLI_FLAG_RE = re.compile(r"(?<![\w-])--[A-Za-z][A-Za-z0-9-]*")
_CLI_OPTION_HINTS = (
    ".add_argument(",
    "add_argument(",
    "@click.option(",
    "click.option(",
    "typer.Option(",
    "Option(",
)
_CLI_FILE_NAMES = {"cli.py", "commands.py", "main.py"}
_CLI_PATH_MARKERS = ("/cli/", "/commands/")


@dataclass(frozen=True)
class _DiffLine:
    line_no: int
    text: str


def detect_cli_surface_drift(diff_text: str, file_path: str) -> list[dict]:
    """Return findings when a public CLI flag is removed without same-flag replacement."""
    if not _is_likely_cli_file(file_path, diff_text):
        return []

    removed, added = _parse_changed_lines(diff_text)
    added_flags = {
        flag
        for line in added
        for flag in _option_flags(line.text)
    }

    findings: list[dict] = []
    seen: set[str] = set()
    for line in removed:
        for flag in _option_flags(line.text):
            if flag in added_flags or flag in seen:
                continue
            seen.add(flag)
            findings.append(_make_finding(file_path, line.line_no, flag))

    return findings


def _is_likely_cli_file(file_path: str, diff_text: str) -> bool:
    normalized = str(file_path).replace("\\", "/").lower()
    basename = Path(normalized).name
    if basename in _CLI_FILE_NAMES:
        return True
    normalized_path = f"/{normalized}"
    for marker in _CLI_PATH_MARKERS:
        if marker in normalized_path:
            return True

    for hint in _CLI_OPTION_HINTS:
        if hint in diff_text:
            return True

    return False


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


def _option_flags(line: str) -> list[str]:
    has_option_hint = False
    for hint in _CLI_OPTION_HINTS:
        if hint in line:
            has_option_hint = True
            break

    if not has_option_hint:
        return []

    stripped = line.strip()
    if stripped.startswith("#"):
        return []

    flags: set[str] = set()
    for match in _CLI_FLAG_RE.finditer(stripped):
        flags.add(match.group(0))

    ordered_flags = sorted(flags)
    return ordered_flags


def _make_finding(file_path: str, line: int, flag: str) -> dict:
    return {
        "rule_id": RULE_ID,
        "kind": "public_api_surface_drift",
        "severity": "MEDIUM",
        "message": (
            "AI defect signal: public CLI flag removed in this diff "
            f"({flag}). Confirm this compatibility change is intentional."
        ),
        "file": file_path,
        "line": max(line, 1),
        "col": 0,
        "category": "ai_defect",
        "defect_type": "public_api_surface_drift",
        "vibe_category": "public_api_surface_drift",
        "metadata": {
            "surface": "cli_flag",
            "removed_flag": flag,
            "signal_only": True,
            "blocking_recommended": False,
        },
    }
