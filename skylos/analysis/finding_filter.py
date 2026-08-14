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
