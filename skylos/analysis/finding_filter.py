from __future__ import annotations

from typing import Any


def finding_is_inline_ignored(
    finding: dict[str, Any],
    ignore_lines: set[int] | None,
    ignore_rules_by_line: dict[int, set[str]] | None,
) -> bool:
    """Return whether a finding is suppressed by a line-scoped comment."""
    line = finding.get("line")
    if ignore_lines and line in ignore_lines:
        return True

    rule_id = str(finding.get("rule_id") or "").upper()
    return bool(
        rule_id
        and ignore_rules_by_line
        and rule_id in ignore_rules_by_line.get(line, set())
    )


def partition_inline_ignored_findings(
    findings: list[dict[str, Any]],
    category: str,
    ignore_lines: set[int] | None,
    ignore_rules_by_line: dict[int, set[str]] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into active and line-comment-suppressed results."""
    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        if not finding_is_inline_ignored(
            finding,
            ignore_lines,
            ignore_rules_by_line,
        ):
            active.append(finding)
            continue
        suppressed.append(
            {
                **finding,
                "category": category,
                "reason": "inline ignore comment",
            }
        )
    return active, suppressed
