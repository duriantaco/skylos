"""Readable terminal reports for verification, without exposing symbolic internals."""

from __future__ import annotations

from typing import Any

_DISPLAY_LIMIT = 20
_TEXT_LIMIT = 1000


def _text(value: Any, default: str = "") -> str:
    """Keep repository-controlled text on its own printable terminal line."""
    if not isinstance(value, str):
        return default
    escaped = []
    for character in value[:_TEXT_LIMIT]:
        if character.isprintable():
            escaped.append(character)
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        else:
            number = ord(character)
            prefix, width = ("x", 2) if number < 256 else ("u", 4)
            if number > 65535:
                prefix, width = "U", 8
            escaped.append(f"\\{prefix}{number:0{width}x}")
    if len(value) > _TEXT_LIMIT:
        escaped.append("... (truncated)")
    return "".join(escaped) or default


def _rows(value: Any) -> list[dict]:
    return (
        [row for row in value if isinstance(row, dict)]
        if isinstance(value, list)
        else []
    )


def _location(row: dict, *, behavior: bool = False) -> str:
    keys = ("after_range", "before_range") if behavior else ("range",)
    bounds = next((row[key] for key in keys if isinstance(row.get(key), dict)), {})
    filename = _text(row.get("file") or bounds.get("file"), "<unknown file>")
    line = bounds.get("start_line", row.get("line"))
    if isinstance(line, int) and not isinstance(line, bool) and line > 0:
        filename += f":{line}"
    if behavior:
        filename += f" — {_text(row.get('symbol'), '<unknown function>')}"
    return filename


def _reasons(value: Any, *, indent: str = "  ") -> list[str]:
    reasons = value if isinstance(value, list) else []
    lines = [
        f"{indent}{_text(reason)}"
        for reason in reasons[:_DISPLAY_LIMIT]
        if isinstance(reason, str) and reason
    ]
    if len(reasons) > _DISPLAY_LIMIT:
        lines.append(f"{indent}{len(reasons) - _DISPLAY_LIMIT} more reasons omitted.")
    return lines


def _findings(payload: dict) -> list[str]:
    findings = _rows(payload.get("findings"))
    if not findings:
        return []
    lines = ["", f"Code issues ({len(findings)})"]
    for finding in findings[:_DISPLAY_LIMIT]:
        rule = _text(finding.get("rule_id"), "Finding")
        severity = _text(finding.get("severity"))
        label = f"{rule} [{severity}]" if severity else rule
        lines.append(f"  {_location(finding)} — {label}")
        lines.append(f"    {_text(finding.get('message'), 'Review this finding.')}")
        fix = _text(finding.get("suggested_fix"))
        if fix:
            lines.append(f"    Suggested fix: {fix}")
    if len(findings) > _DISPLAY_LIMIT:
        lines.append(f"  {len(findings) - _DISPLAY_LIMIT} more code issues omitted.")
    return lines


def _difference(comparison: dict) -> list[str]:
    lines = [f"  {_location(comparison, behavior=True)}"]
    differences = _rows(comparison.get("differences"))
    for difference in differences[:_DISPLAY_LIMIT]:
        explanation = difference.get("explanation")
        explanation = explanation if isinstance(explanation, dict) else {}
        title = _text(explanation.get("title"), "Behavior changed")
        lines.append(f"    {title}")
        explained = False
        for key, label in (
            ("before", "Before"),
            ("after", "After"),
            ("impact", "Impact"),
            ("review", "Review"),
        ):
            message = _text(explanation.get(key))
            if message:
                lines.append(f"    {label}: {message}")
                explained = True
        if not explained:
            lines.append(
                "    The supported static model found a change, but no readable detail is available."
            )
            lines.append(
                "    Review the function's calls, return value, and error handling."
            )
    if not differences:
        lines.append(
            "    Behavior changed; details are unavailable. Review whether the edit was intentional."
        )
    if len(differences) > _DISPLAY_LIMIT:
        lines.append(
            f"    {len(differences) - _DISPLAY_LIMIT} more differences omitted."
        )
    return lines


def _behavior(payload: dict) -> list[str]:
    behavior = payload.get("behavior")
    if not isinstance(behavior, dict) or not behavior:
        return []
    status = behavior.get("status")
    comparisons = _rows(behavior.get("comparisons"))
    changed = [row for row in comparisons if row.get("status") == "different"]
    unknown = [
        row
        for row in comparisons
        if row.get("status") not in ("different", "equivalent")
    ]
    equivalent = sum(row.get("status") == "equivalent" for row in comparisons)
    lines = ["", "Behavior comparison with HEAD"]
    displayed = (changed + unknown)[:_DISPLAY_LIMIT]
    for comparison in displayed:
        if comparison.get("status") == "different":
            lines.extend(_difference(comparison))
        else:
            lines.append(f"  {_location(comparison, behavior=True)}")
            lines.append("    Could not establish whether behavior is preserved.")
            lines.extend(_reasons(comparison.get("reasons"), indent="    "))
    omitted = len(changed) + len(unknown) - len(displayed)
    if omitted:
        lines.append(f"  {omitted} more function comparisons needing review omitted.")
    if equivalent:
        noun = "function" if equivalent == 1 else "functions"
        lines.append(
            f"  {equivalent} affected {noun} equivalent within the supported static model."
        )
    if changed or status == "different":
        if not changed:
            lines.append(
                "  Modeled behavior changed; function details are unavailable."
            )
            lines.append("  Review whether the behavior change was intentional.")
    if status == "unknown":
        lines.append("  Behavior comparison is incomplete.")
    elif status == "unavailable":
        lines.append("  Behavior comparison is unavailable.")
    elif status == "unchanged" and not comparisons:
        lines.append("  No affected Python functions found in the selected scope.")
    elif status == "equivalent" and not equivalent:
        lines.append("  Equivalent within the supported static model.")
    elif status not in (
        "different",
        "equivalent",
        "unchanged",
        "unknown",
        "unavailable",
    ):
        lines.append("  Behavior comparison status is unavailable.")
    lines.extend(_reasons(behavior.get("reasons")))
    if changed or equivalent:
        lines.append(
            "  Static comparison only; target code was not executed and external behavior is assumed stable."
        )
    if omitted or any(
        len(_rows(row.get("differences"))) > _DISPLAY_LIMIT for row in displayed
    ):
        lines.append("  The JSON report contains all recorded comparisons.")
    return lines


def render_verify_report(payload: dict[str, Any]) -> str:
    """Return plain text for an interactive ``skylos verify`` terminal."""
    headline = {
        "pass": "Verification passed",
        "fail": "Verification found issues",
        "incomplete": "Verification needs review",
    }.get(payload.get("status"), "Verification status unavailable")
    lines = [headline]
    summary = _text(payload.get("summary"))
    behavior = payload.get("behavior")
    behavior_needs_review = isinstance(behavior, dict) and behavior.get("status") in {
        "different",
        "unknown",
    }
    if summary and not (
        behavior_needs_review and summary.startswith("No AI-code issues found")
    ):
        lines.append(summary)
    lines.extend(_findings(payload))
    lines.extend(_behavior(payload))
    return "\n".join(lines)
