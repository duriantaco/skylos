"""One issue total for every view, and which checks did not run.

The total counts listed findings: the records the closing line, the gate's
quality limit, Skylos Cloud and the report all count. Advice hidden by the
default listing is reported separately and never added to it. A check that
did not run is "not checked", never 0.
"""

from __future__ import annotations

from collections.abc import Mapping

from skylos.reporting.assessment_display import listed_issue_counts

NOT_CHECKED = "not checked"
ISSUE_CATEGORIES = (
    ("security", "Security"),
    ("secrets", "Secrets"),
    ("dependencies", "Dependency vulnerabilities"),
    ("ai_defects", "AI defects"),
    ("reliability", "Reliability"),
    ("quality", "Quality"),
    ("custom_rules", "Custom rules"),
    ("dead_code", "Dead code"),
)
_CATEGORY_CHECKS = {
    "security": "security",
    "reliability": "security",
    "secrets": "secrets",
    "dependencies": "dependencies",
    "ai_defects": "ai_defects",
    "quality": "quality",
    "dead_code": "dead_code",
}
_RESULT_KEYS = {
    "security": ("danger",),
    "reliability": ("reliability",),
    "secrets": ("secrets",),
    "dependencies": ("dependency_vulnerabilities",),
    "ai_defects": ("ai_defects",),
    "quality": ("quality",),
    "dead_code": (
        "unused_functions",
        "unused_imports",
        "unused_variables",
        "unused_classes",
        "unused_parameters",
        "unused_files",
    ),
}


def _mapping(value):
    if isinstance(value, Mapping):
        return value
    return {}


def _count(value):
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def scanned_checks(result):
    """The checks this scan ran, or None when the result does not say."""
    checks = _mapping(_mapping(result).get("analysis_summary")).get("grade_categories")
    if isinstance(checks, (list, tuple)):
        return {str(check) for check in checks}
    return None


def dependencies_queried(result) -> bool:
    """Whether any package was looked up for known vulnerabilities."""
    result = _mapping(result)
    if result.get("dependency_vulnerabilities"):
        return True
    sca = _mapping(_mapping(result.get("analysis_summary")).get("sca_coverage"))
    queried = _count(sca.get("queried_dependency_count"))
    return bool(queried)


def category_checked(result, category) -> bool:
    result = _mapping(result)
    if category == "custom_rules":
        return True
    own_keys = _RESULT_KEYS.get(category, ())
    if any(result.get(key) for key in own_keys):
        return True
    checks = scanned_checks(result)
    check = _CATEGORY_CHECKS.get(category)
    if checks is not None and check is not None:
        ran = check in checks
    else:
        keys = (*own_keys, *_RESULT_KEYS.get(check or category, ()))
        ran = any(isinstance(result.get(key), (list, tuple)) for key in keys)
    if ran and category == "dependencies":
        return dependencies_queried(result)
    return ran


def not_checked(result, counts=None) -> list[str]:
    if counts is None:
        counts = listed_issue_counts(_mapping(result))
    return [
        category
        for category, _label in ISSUE_CATEGORIES
        if category != "custom_rules"
        and not counts.get(category)
        and not category_checked(result, category)
    ]


def issue_summary(result) -> dict:
    """The listed total, per-category counts (None when not checked), hidden
    advice and suppressed counts."""
    result = _mapping(result)
    counts = listed_issue_counts(result)
    by_category = {}
    missing = not_checked(result, counts)
    for category, _label in ISSUE_CATEGORIES:
        if category in missing:
            by_category[category] = None
        else:
            by_category[category] = counts.get(category, 0)
    visibility = _mapping(result.get("advice_visibility"))
    held_back = suppressed_breakdown(result)
    reviewed = result.get("reviewed_findings")
    if not isinstance(reviewed, (list, tuple)):
        reviewed = ()
    return {
        "total": sum(counts.values()),
        "by_category": by_category,
        "not_checked": missing,
        "hidden_advice": _count(visibility.get("omitted_checks")) or 0,
        "suppressed": held_back["ignore_comments"] + held_back["unproven"],
        "suppressed_by_ignore_comments": held_back["ignore_comments"],
        "held_back_unproven": held_back["unproven"],
        "dismissed": len(reviewed),
    }


INLINE_IGNORE_REASON = "inline ignore comment"


def suppressed_breakdown(result) -> dict[str, int]:
    """``suppressed`` holds two kinds of records: findings a ``skylos: ignore``
    comment silenced, and candidates the detector held back as unproven."""
    rows = _mapping(result).get("suppressed")
    if not isinstance(rows, (list, tuple)):
        rows = ()
    ignored = sum(
        1
        for row in rows
        if isinstance(row, Mapping) and row.get("reason") == INLINE_IGNORE_REASON
    )
    return {"ignore_comments": ignored, "unproven": len(rows) - ignored}


def count_text(value) -> str:
    if value is None:
        return NOT_CHECKED
    return str(value)


def listed_severity_counts(result, category) -> dict[str, int]:
    """Listed findings of one category by their JSON severity."""
    from skylos.reporting.finding_types import iter_result_findings
    from skylos.reporting.listing import is_listed

    counts = {}
    for row_category, finding in iter_result_findings(result):
        if row_category != category or not is_listed(finding, row_category):
            continue
        severity = str(finding.get("severity") or "").strip().upper()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def gate_only_counts(result) -> dict[str, int]:
    """Findings the gate counts that the default list hides, by category.

    The gate counts every security, secret and dependency finding; the list
    hides proven low-risk ones and shows one advisory per package version.
    """
    result = _mapping(result)
    listed = listed_issue_counts(result)
    extra = {}
    for category, key in (
        ("security", "danger"),
        ("secrets", "secrets"),
        ("dependencies", "dependency_vulnerabilities"),
    ):
        rows = result.get(key)
        if not isinstance(rows, (list, tuple)):
            continue
        hidden = len(rows) - listed.get(category, 0)
        if hidden > 0:
            extra[category] = hidden
    return extra


_TOTAL_LABELS = {
    "security": "security",
    "secrets": "secrets",
    "dependencies": "dependency vulnerabilities",
    "ai_defects": "AI defects",
    "reliability": "reliability",
    "quality": "quality",
    "custom_rules": "custom rules",
    "dead_code": "dead code",
}


def total_text(summary) -> str:
    """``656 issues: security 123, AI defects 120, ...`` for :func:`issue_summary`."""
    total = summary["total"]
    noun = "issues"
    if total == 1:
        noun = "issue"
    parts = [
        f"{_TOTAL_LABELS[category]} {count}"
        for category, _label in ISSUE_CATEGORIES
        if (count := summary["by_category"].get(category))
    ]
    text = f"{total} {noun}"
    if parts:
        text = f"{text}: {', '.join(parts)}"
    return text


def category_label(category) -> str:
    return _TOTAL_LABELS.get(category, str(category).replace("_", " "))
