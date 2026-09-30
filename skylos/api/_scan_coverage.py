"""Small, conservative scan-coverage and quality-classification upload receipts.

These are client observations, not authorization. Cloud must validate the
receipt against the authenticated upload and its normalized findings before
using absence of a finding to resolve an issue.
"""

from __future__ import annotations

from typing import Any

from skylos.constants import DEFAULT_EXCLUDE_FOLDERS

_CHECKS = frozenset(
    {"security", "quality", "ai_defects", "dead_code", "dependencies", "secrets"}
)
_IAD_RULES = ("SKY-Q802", "SKY-Q803")
_MAX_SELECTED_RULES = 100
_MAX_RULE_ID_LENGTH = 120
_MAX_COUNT = 2_147_483_647


def _selected_rules(summary: dict[str, Any]) -> tuple[list[str], bool]:
    raw = summary.get("selected_rules", [])
    if not isinstance(raw, list):
        return [], False
    if len(raw) > _MAX_SELECTED_RULES:
        return [], False
    selected = []
    for rule in raw:
        if not isinstance(rule, str) or not 0 < len(rule.strip()) <= _MAX_RULE_ID_LENGTH:
            return [], False
        selected.append(rule.strip().upper())
    return selected, True


def scan_coverage_receipt(
    result: Any, *, analyzer_owned: bool, analysis_mode: str
) -> dict[str, Any] | None:
    """Describe whether an upload may represent every finding in its checks.

    A complete repository receipt still covers only the checks listed in
    ``scanned_checks``. Missing analyzer evidence never becomes a complete
    receipt. This is intentionally separate from Cloud's trust decision.
    """
    if not isinstance(result, dict):
        return None
    summary = result.get("analysis_summary")
    if not isinstance(summary, dict):
        return None

    reasons: list[str] = []
    selected, valid_selection = _selected_rules(summary)
    if not valid_selection or selected:
        reasons.append("selected_rules")
    if analyzer_owned is not True or analysis_mode != "static":
        reasons.append("unverified_origin")

    scope = summary.get("comparison_scope")
    standard_root = False
    if isinstance(scope, dict) and scope.get("changed_files_only") is False:
        exclusions = scope.get("excluded_folders")
        standard_root = (
            scope.get("kind") == "repository_root"
            and scope.get("complete_repository") is True
            and exclusions == []
        ) or (
            scope.get("kind") == "repository_root_with_exclusions"
            and scope.get("complete_repository") is False
            and isinstance(exclusions, list)
            and bool(exclusions)
            and all(
                isinstance(folder, str) and folder in DEFAULT_EXCLUDE_FOLDERS
                for folder in exclusions
            )
        )
    if not standard_root:
        reasons.append("partial_repository")

    checks = summary.get("grade_categories")
    if not (
        isinstance(checks, list)
        and checks
        and all(isinstance(check, str) and check in _CHECKS for check in checks)
        and len(set(checks)) == len(checks)
    ):
        reasons.append("missing_checks")

    # Rule selection, baseline filtering and display filtering remove the
    # aggregate grade. A grade-less finding set must not close old issues.
    if not isinstance(result.get("grade"), dict) or not result["grade"]:
        reasons.append("filtered_findings")
    if summary.get("resolution_scope_limited") is not False:
        reasons.append("configured_suppression")
    if result.get("suppressed") != []:
        reasons.append("suppressed_findings")

    errors = result.get("analysis_errors")
    if (
        not isinstance(errors, list)
        or errors
        or type(summary.get("analysis_error_count")) is not int
        or summary["analysis_error_count"] != 0
        or summary.get("grade_unavailable_reason")
        or summary.get("incomplete_languages")
    ):
        reasons.append("analysis_incomplete")
    engines = summary.get("language_engines")
    if engines is not None and (
        not isinstance(engines, dict)
        or any(
            not isinstance(engine, dict)
            or engine.get("status") != "available"
            or engine.get("complete") is False
            for engine in engines.values()
        )
    ):
        reasons.append("analysis_incomplete")
    grep = summary.get("grep_verify")
    if isinstance(grep, dict) and grep.get("complete") is False:
        reasons.append("analysis_incomplete")
    # SCA can fail independently of source analysis (for example, OSV is
    # offline). That removes dependency absence coverage below, but must not
    # erase complete quality/security coverage from the same scan.
    complete = not reasons
    covered_checks = []
    if complete:
        for check in checks:
            if check == "dependencies" and not _dependency_coverage_complete(summary):
                continue
            if check == "dead_code" and isinstance(grep, dict) and grep.get("enabled") is False:
                continue
            if check == "quality" and not _architecture_coverage_present(result):
                continue
            covered_checks.append(check)
    return {
        "version": 1,
        "scope": "full_repository" if complete else "partial",
        "complete": complete,
        "selected_rules": selected,
        "resolution_covered_checks": covered_checks,
        "reasons": reasons,
    }


def _dependency_coverage_complete(summary: dict[str, Any]) -> bool:
    coverage = summary.get("sca_coverage")
    if not isinstance(coverage, dict):
        return False
    if coverage.get("status") != "complete" or coverage.get("complete") is not True:
        return False
    if coverage.get("category_complete") is False:
        return False
    for key in (
        "parse_error_count",
        "unresolved_dependency_count",
        "unresolved_lockfile_dependency_count",
        "lockfile_limitation_count",
    ):
        count = coverage.get(key, 0)
        if type(count) is not int or count != 0:
            return False
    query = coverage.get("query")
    return query is None or (isinstance(query, dict) and query.get("complete") is True)


def _architecture_coverage_present(result: dict[str, Any]) -> bool:
    metrics = result.get("architecture_metrics")
    if not isinstance(metrics, dict) or type(metrics.get("iad_enforced")) is not bool:
        return False
    # The architecture pass suppresses Q802/Q803 for TypeScript modules whose
    # source could not be measured. Absence is not evidence that a prior
    # finding in one of those modules has been fixed.
    unavailable = metrics.get("abstractness_unavailable_modules", [])
    return isinstance(unavailable, list) and not unavailable


def quality_rule_classification(result: Any) -> dict[str, Any] | None:
    """State the scanner's Q802/Q803 policy, including zero-signal scans."""
    if not isinstance(result, dict):
        return None
    metrics = result.get("architecture_metrics")
    if not isinstance(metrics, dict):
        return None
    enforced = metrics.get("iad_enforced")
    if type(enforced) is not bool:
        return {"version": 1, "architecture_iad": "unknown"}
    actionable = result.get("quality")
    if (
        not enforced
        and isinstance(actionable, list)
        and any(
            isinstance(finding, dict)
            and finding.get("rule_id") in _IAD_RULES
            for finding in actionable
        )
    ):
        return {"version": 1, "architecture_iad": "unknown"}
    advisories = metrics.get("advisories")
    if enforced and isinstance(advisories, list) and advisories:
        return {"version": 1, "architecture_iad": "unknown"}
    return {
        "version": 1,
        "architecture_iad": "enforced" if enforced else "advisory",
    }


def architecture_advisory_summary(result: Any) -> dict[str, Any] | None:
    """Send bounded counts, without source paths, names, or messages."""
    if not isinstance(result, dict):
        return None
    metrics = result.get("architecture_metrics")
    if not isinstance(metrics, dict):
        return None
    advisories = metrics.get("advisories")
    if not isinstance(advisories, list):
        return None

    by_rule = dict.fromkeys(_IAD_RULES, 0)
    module_count = 0
    for advisory in advisories:
        if not isinstance(advisory, dict) or advisory.get("advisory") is not True:
            continue
        signals = advisory.get("signals")
        if not isinstance(signals, list):
            continue
        rules = {
            signal.get("rule_id")
            for signal in signals
            if isinstance(signal, dict)
            and signal.get("advisory") is True
            and signal.get("rule_id") in by_rule
        }
        if not rules:
            continue
        module_count = min(module_count + 1, _MAX_COUNT)
        for rule in rules:
            by_rule[rule] = min(by_rule[rule] + 1, _MAX_COUNT)

    return {
        "version": 1,
        "module_count": module_count,
        "signal_count": min(sum(by_rule.values()), _MAX_COUNT),
        "by_rule": by_rule,
    }
