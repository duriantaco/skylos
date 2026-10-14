from __future__ import annotations

from typing import Any

# A bare noqa comment (no codes) names no tool and no rule. It still hides dead-code,
# quality and LOW/MEDIUM findings, but a HIGH/CRITICAL security finding (a
# danger, secret or dependency-hallucination rule) stays reported and is
# marked ``bare_noqa_ignored``. Accepting one takes a Skylos-specific marker:
# ``skylos: ignore[SKY-D211]`` with a reason.
_SECURITY_RULE_PREFIXES = ("SKY-D", "SKY-S")
_BARE_NOQA_PROTECTED_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


def bare_noqa_cannot_hide(finding: dict[str, Any]) -> bool:
    rule_id = str(finding.get("rule_id") or "").upper()
    severity = str(finding.get("severity") or "").upper()
    return (
        rule_id.startswith(_SECURITY_RULE_PREFIXES)
        and severity in _BARE_NOQA_PROTECTED_SEVERITIES
    )


def finding_is_inline_ignored(
    finding: dict[str, Any],
    ignore_lines: set[int] | None,
    ignore_rules_by_line: dict[int, set[str]] | None,
) -> bool:
    """Return whether a finding is suppressed by a line-scoped comment."""
    line = finding.get("line")
    if ignore_lines and line in ignore_lines:
        bare_noqa_lines = getattr(ignore_lines, "bare_noqa_lines", ())
        if line not in bare_noqa_lines or not bare_noqa_cannot_hide(finding):
            return True
        finding["bare_noqa_ignored"] = True

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
