"""Which findings to fix first.

Ranking: findings that fail the gate on their own come first, then higher
severity, production code before test code, then higher confidence. Only
listed risk findings are ranked: advice and dead-code candidates are not
risks, and hidden findings stay hidden.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from skylos.core.test_paths import is_test_code_path
from skylos.reporting.advice_display import SEVERITY_RANK, default_display_severity
from skylos.reporting.finding_types import get_finding_type, iter_result_findings
from skylos.reporting.listing import is_listed
from skylos.rules.catalog import get_rule_name
from skylos.rules.guidance import finding_fix, finding_rule_id, rule_docs_url

TOP_RISK_LIMIT = 5
_NEUTRAL_CONFIDENCE = 50
_CATEGORY_RANK = {
    "security": 0,
    "secrets": 1,
    "dependencies": 2,
    "ai_defects": 3,
    "reliability": 4,
    "quality": 5,
    "custom_rules": 6,
}
_SECTION_FOR_CATEGORY = {
    "security": "danger",
    "dependencies": "dependency_vulnerabilities",
}


@dataclass(frozen=True)
class RiskRow:
    category: str
    finding: Mapping
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    fix: str
    docs_url: str
    blocking: bool
    in_tests: bool
    confidence: float | None
    more: int = 0

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "blocking": self.blocking,
            "in_tests": self.in_tests,
            "fix": self.fix,
            "docs_url": self.docs_url,
            "more_like_this": self.more,
        }


def _identity(finding: Mapping) -> tuple:
    return (
        str(finding.get("rule_id") or finding.get("id") or "").upper(),
        str(finding.get("file") or finding.get("file_path") or ""),
        str(finding.get("line") or ""),
        str(finding.get("col") or finding.get("column") or ""),
        str(finding.get("message") or ""),
    )


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    return value


def _display_path(path, project_root) -> str:
    text = str(path or "?")
    if project_root is None:
        return text
    try:
        return str(Path(text).resolve().relative_to(Path(project_root).resolve()))
    except (OSError, RuntimeError, ValueError):
        return text


def _line(finding: Mapping) -> int:
    for key in ("line", "line_number", "lineno"):
        value = finding.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return 1


def finding_severity(finding: Mapping, category=None) -> str:
    section = _SECTION_FOR_CATEGORY.get(str(category or ""), category)
    return str(finding.get("severity") or default_display_severity(section)).upper()


def is_risk_finding(finding, category) -> bool:
    """A listed finding that is neither advice nor a dead-code candidate."""
    if category == "dead_code":
        return False
    if get_finding_type(finding, category) == "advice":
        return False
    return is_listed(finding, category)


def blocking_identities(result, config=None) -> set[tuple]:
    from skylos.core.gatekeeper import blocking_gate_issues

    try:
        issues = blocking_gate_issues(result, config or {})
    except Exception:
        return set()
    return {_identity(issue) for issue in issues if isinstance(issue, Mapping)}


def _sort_key(row: RiskRow) -> tuple:
    confidence = row.confidence
    if confidence is None:
        confidence = _NEUTRAL_CONFIDENCE
    return (
        int(not row.blocking),
        SEVERITY_RANK.get(row.severity, 99),
        int(row.in_tests),
        -confidence,
        _CATEGORY_RANK.get(row.category, 9),
    )


def rank_risks(result, *, project_root=None, config=None) -> list[RiskRow]:
    """Every listed risk finding, most urgent first. A risk finding that fails
    the gate on its own is ranked even when the default listing hides it;
    advice and dead code are never top risks."""
    blocking = blocking_identities(result, config)
    rows = []
    for category, finding in iter_result_findings(result):
        if not is_risk_finding(finding, category):
            if (
                category == "dead_code"
                or get_finding_type(finding, category) == "advice"
            ):
                continue
            if _identity(finding) not in blocking:
                continue
        is_blocking = _identity(finding) in blocking
        rule_id = finding_rule_id(finding, category)
        file_value = finding.get("file") or finding.get("file_path")
        rows.append(
            RiskRow(
                category=category,
                finding=finding,
                rule_id=rule_id,
                severity=finding_severity(finding, category),
                title=get_rule_name(rule_id, "Finding"),
                file=_display_path(file_value, project_root),
                line=_line(finding),
                fix=finding_fix(finding, category),
                docs_url=rule_docs_url(rule_id),
                blocking=is_blocking,
                in_tests=is_test_code_path(file_value, project_root),
                confidence=_number(finding.get("confidence")),
            )
        )
    return sorted(rows, key=lambda row: (*_sort_key(row), row.file, row.line))


def top_risks(
    result, *, project_root=None, config=None, limit=TOP_RISK_LIMIT, rows=None
) -> list[RiskRow]:
    """The first rows to fix. A blocking finding is always its own row; other
    findings of one rule share a row that counts the rest."""
    if rows is None:
        rows = rank_risks(result, project_root=project_root, config=config)
    groups = {}
    order = []
    for row in rows:
        if row.blocking:
            key = ("blocking", len(order))
        else:
            key = ("rule", row.rule_id, row.in_tests)
        if key not in groups:
            groups[key] = [row]
            order.append(key)
        else:
            groups[key].append(row)
    ranked = sorted(
        order,
        key=lambda key: (
            *_sort_key(groups[key][0]),
            -len(groups[key]),
            groups[key][0].file,
            groups[key][0].line,
        ),
    )
    rows = []
    for key in ranked[: max(0, limit)]:
        rows.append(replace(groups[key][0], more=len(groups[key]) - 1))
    return rows


def scan_verdict(result, *, project_root=None, config=None, rows=None) -> dict:
    """A one-line answer: is anything blocking, and what is left to review."""
    from skylos.core.gatekeeper import _analysis_blocking_reasons

    if rows is None:
        rows = rank_risks(result, project_root=project_root, config=config)
    blocking = sum(1 for row in rows if row.blocking)
    high = sum(1 for row in rows if row.severity in {"CRITICAL", "HIGH"})
    try:
        incomplete = bool(_analysis_blocking_reasons(result or {}, config=config or {}))
    except Exception:
        incomplete = False
    if incomplete:
        status = "incomplete"
        text = "Incomplete: analysis did not finish, so these results are partial"
    elif blocking:
        status = "not_ready"
        noun = _plural(blocking, "blocking issue", "blocking issues")
        text = f"Not ready: {blocking} {noun}"
    elif high:
        status = "review"
        noun = _plural(high, "high-severity issue", "high-severity issues")
        text = f"Needs review: {high} {noun} (nothing blocks the gate)"
    elif rows:
        status = "review"
        noun = _plural(len(rows), "issue", "issues")
        text = f"Needs review: {len(rows)} {noun} (nothing blocks the gate)"
    else:
        status = "ready"
        text = "No blocking issues or risk findings"
    return {
        "status": status,
        "text": text,
        "blocking": blocking,
        "high_or_critical": high,
        "risk_findings": len(rows),
    }


def _plural(count, singular, plural):
    if count == 1:
        return singular
    return plural


def add_report_guidance(result, *, project_root=None, config=None):
    """For JSON output: a ``fix`` and ``docs_url`` on every finding, plus the
    ranked ``top_risks`` and the one ``issue_summary`` the terminal shows."""
    from skylos.reporting.finding_types import _all_result_findings
    from skylos.reporting.issue_summary import issue_summary

    if not isinstance(result, dict):
        return result
    for category, finding, section in _all_result_findings(result):
        if str(section).startswith("unused_"):
            category = section
        rule_id = finding_rule_id(finding, category)
        finding.setdefault("fix", finding_fix(finding, category))
        finding.setdefault("docs_url", rule_docs_url(rule_id))
    rows = rank_risks(result, project_root=project_root, config=config)
    result["top_risks"] = [row.to_dict() for row in top_risks(result, rows=rows)]
    result["issue_summary"] = {
        **issue_summary(result),
        "verdict": scan_verdict(result, config=config, rows=rows),
    }
    return result
