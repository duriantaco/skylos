"""Explain scan observations without averaging unrelated risks into a grade.

Risk describes open observations, not a probability of exploitation. Advice
is measured against the units actually checked; missing measurements stay
unknown. Gate policy is deliberately outside this reporting module.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import PurePath

from skylos.reporting.finding_types import (
    get_finding_type,
    iter_result_findings,
    summarize_finding_types,
)
from skylos.rules.catalog import get_rule_name

CHECKS = ("security", "quality", "dead_code", "ai_defects", "dependencies", "secrets")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_LANGUAGES = {
    ".py": "Python",
    ".pyi": "Python",
    ".pyw": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".go": "Go",
    ".java": "Java",
    ".php": "PHP",
    ".rs": "Rust",
    ".dart": "Dart",
}


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return value if math.isfinite(value) else None
    except OverflowError:
        return None


def _language(finding):
    path = str(finding.get("file") or finding.get("file_path") or "")
    return _LANGUAGES.get(PurePath(path).suffix.lower(), "Other")


def _severity(finding):
    value = str(finding.get("severity") or "").upper()
    return {"WARN": "MEDIUM", "WARNING": "MEDIUM", "INFO": "LOW", "ERROR": "HIGH"}.get(
        value, value
    )


def _risk_bucket(findings, *, assessed):
    counts = Counter(_severity(finding) for finding in findings)
    highest = next((severity for severity in SEVERITIES if counts[severity]), None)
    unknown = sum(
        count for severity, count in counts.items() if severity not in SEVERITIES
    )
    return {
        "status": highest.lower()
        if highest
        else "unknown"
        if unknown
        else "none"
        if assessed
        else "not_assessed",
        "highest_severity": highest,
        "finding_count": len(findings),
        "severity_counts": {
            **{severity: counts[severity] for severity in SEVERITIES},
            "UNKNOWN": unknown,
        },
    }


def _coverage(result, scanned_checks):
    summary = result.get("analysis_summary") or {}
    reasons = []
    incomplete_checks = []
    # Checks incomplete for a reason other than files that were not analysed
    # (those files affect every check, so listing every check says nothing).
    limited_checks = []
    if result.get("analysis_errors") or summary.get("incomplete_languages"):
        reasons.append("analysis_incomplete")
        incomplete_checks.extend(scanned_checks)
    engines = summary.get("language_engines")
    if isinstance(engines, Mapping) and any(
        not isinstance(engine, Mapping)
        or engine.get("status") != "available"
        or engine.get("complete") is False
        for engine in engines.values()
    ):
        reasons.append("language_engine_incomplete")
        incomplete_checks.extend(scanned_checks)
    sca = summary.get("sca_coverage")
    if "dependencies" in scanned_checks and (
        not isinstance(sca, Mapping)
        or sca.get("complete") is not True
        or sca.get("status") != "complete"
        or sca.get("category_complete") is False
        or any(
            sca.get(key, 0) != 0
            for key in (
                "parse_error_count",
                "unresolved_dependency_count",
                "unresolved_lockfile_dependency_count",
                "lockfile_limitation_count",
            )
        )
        or isinstance(sca.get("query"), Mapping)
        and sca["query"].get("complete") is False
    ):
        reasons.append("dependency_coverage_unavailable")
        incomplete_checks.append("dependencies")
        limited_checks.append("dependencies")
    grep = summary.get("grep_verify")
    if (
        "dead_code" in scanned_checks
        and isinstance(grep, Mapping)
        and grep.get("complete") is False
    ):
        reasons.append("dead_code_verification_incomplete")
        incomplete_checks.append("dead_code")
        limited_checks.append("dead_code")
    verification = summary.get("ai_verification")
    if "ai_defects" in scanned_checks and (
        not isinstance(verification, Mapping)
        or verification.get("state") != "complete"
        or verification.get("missing_checks")
    ):
        reasons.append("ai_verification_incomplete")
        incomplete_checks.append("ai_defects")
        limited_checks.append("ai_defects")
    scope = summary.get("comparison_scope")
    partial = isinstance(scope, Mapping) and (
        scope.get("changed_files_only") is True
        or scope.get("kind")
        not in {"repository_root", "repository_root_with_exclusions"}
    )
    if partial:
        reasons.append("selected_scan_scope")
    if summary.get("selected_rules"):
        partial = True
        reasons.append("selected_rules")
    if summary.get("resolution_scope_limited") is True or result.get("suppressed"):
        partial = True
        reasons.append("configured_suppression")
    return {
        "status": "incomplete"
        if incomplete_checks
        else "partial"
        if partial
        else "complete"
        if isinstance(scope, Mapping)
        else "unknown",
        "not_assessed": [check for check in CHECKS if check not in scanned_checks],
        "incomplete_checks": list(dict.fromkeys(incomplete_checks)),
        "reasons": list(dict.fromkeys(reasons)),
        **_analysis_coverage_counts(summary, limited_checks),
    }


def _analysis_coverage_counts(summary, limited_checks):
    """File and candidate counts from ``analysis_summary.analysis_coverage``."""
    record = summary.get("analysis_coverage")
    if not isinstance(record, Mapping):
        return {}
    counts = {"limited_checks": list(dict.fromkeys(limited_checks))}
    for key in (
        "unchecked_file_count",
        "source_file_count",
        "unverified_dead_code_candidates",
    ):
        value = record.get(key)
        if type(value) is int and value >= 0:
            counts[key] = value
    return counts


def _maintainability(result, advice, assessed):
    inventory = (result.get("analysis_summary") or {}).get(
        "maintainability_inventory"
    ) or []
    measured = {}
    line_counts = {}
    groups = defaultdict(list)
    for item in inventory:
        if isinstance(item, Mapping) and isinstance(item.get("file"), str):
            measured[item["file"]] = item
            line_counts[item["file"]] = Counter(item.get("function_lines", []))
            for rule in item.get("rule_units", {}):
                groups[(rule, item.get("language", "Other"))]
    for finding in advice:
        groups[
            (str(finding.get("rule_id") or finding.get("id") or ""), _language(finding))
        ].append(finding)
    checks = []
    function_locations = set()
    function_count_complete = True
    for (rule, language), findings in sorted(groups.items()):
        units = {
            (
                str(finding.get("file") or finding.get("file_path") or ""),
                finding.get("line"),
                str(finding.get("name") or ""),
            )
            for finding in findings
        }
        measured_files = {
            file: item
            for file, item in measured.items()
            if item.get("language") == language and rule in item.get("rule_units", {})
        }
        relevant_files = {file for file, _, _ in units}
        locations = {(file, line) for file, line, _ in units}
        denominator = sum(item["rule_units"][rule] for item in measured_files.values())
        ambiguous = any(
            line_counts[file][line] > 1
            for file, line, _ in units
            if file in measured_files
        )
        known = (
            bool(measured_files)
            and relevant_files <= measured_files.keys()
            and all(line in line_counts[file] for file, line in locations)
            and not ambiguous
            and len(locations) <= denominator
        )
        if findings and not known:
            function_count_complete = False
        values = [
            (value, threshold)
            for finding in findings
            if (value := _number(finding.get("value"))) is not None
            and (threshold := _number(finding.get("threshold"))) is not None
            and threshold > 0
            and _number(value / threshold) is not None
        ]
        worst = max(values, key=lambda pair: pair[0] / pair[1], default=(None, None))
        checks.append(
            {
                "rule_id": rule,
                "name": get_rule_name(rule, "Maintainability advice"),
                "language": language,
                "count": len(findings),
                "affected_units": len(locations) if known else len(findings),
                "unit": "function" if known else "finding",
                "analyzed_units": denominator if known else None,
                "affected_percent": round(100 * len(locations) / denominator, 2)
                if known and denominator
                else None,
                "max_value": worst[0],
                "max_threshold": worst[1],
                "max_excess_ratio": round(worst[0] / worst[1], 3) if worst[1] else None,
            }
        )
        if known:
            function_locations.update((file, line) for file, line, _ in units)
    return {
        "status": "measured" if assessed or advice else "not_assessed",
        "advice_count": len(advice),
        "rule_count": len({rule for rule, _ in groups if rule}),
        "affected_files": len(
            {
                str(finding.get("file") or finding.get("file_path") or "")
                for finding in advice
                if finding.get("file") or finding.get("file_path")
            }
        ),
        "affected_functions": len(function_locations)
        if measured and function_count_complete
        else None,
        "checks": checks,
    }


def compute_assessment(result: dict, *, scanned_checks=None) -> dict:
    """Summarize canonical observations; do not mutate findings or gate inputs."""
    # The complete report retains unlisted Advice. Repeated assessment calls
    # (including the CLI's final pass) must use the same decision as the gate.
    if result.get("listing_policy_version") == 1:
        from skylos.reporting.listing import listed_result

        result = listed_result(result)
    raw_checks = (
        scanned_checks
        if scanned_checks is not None
        else (result.get("analysis_summary") or {}).get("grade_categories", [])
    )
    checks = (
        [check for check in CHECKS if check in raw_checks]
        if isinstance(raw_checks, (list, tuple))
        else []
    )
    buckets = defaultdict(list)
    advice = []
    dead_code = []
    for category, finding in iter_result_findings(result):
        if get_finding_type(finding, category) == "advice":
            advice.append(finding)
        elif category == "dead_code":
            dead_code.append(finding)
        else:
            buckets[
                category
                if category in {"security", "secrets", "dependencies"}
                else "correctness"
            ].append(finding)
    category_checks = {
        "security": ["security"],
        "secrets": ["secrets"],
        "dependencies": ["dependencies"],
        "correctness": ["quality", "ai_defects"],
    }
    categories = {
        name: _risk_bucket(
            buckets[name], assessed=any(check in checks for check in required)
        )
        for name, required in category_checks.items()
    }
    risk = _risk_bucket(
        [finding for rows in buckets.values() for finding in rows],
        assessed=any(check != "dead_code" for check in checks),
    )
    coverage = _coverage(result, checks)
    for name, category in categories.items():
        if category["status"] == "none" and (
            coverage["status"] == "unknown"
            or any(
                check in coverage["incomplete_checks"]
                for check in category_checks[name]
            )
        ):
            category["status"] = "unknown"
    if risk["status"] == "none" and any(
        category["status"] == "unknown" for category in categories.values()
    ):
        risk["status"] = "unknown"
    risk["categories"] = categories
    confidence = [
        value
        for finding in dead_code
        if (value := _number(finding.get("confidence"))) is not None
    ]
    return {
        "version": 1,
        "scope": "all_analyzed_findings",
        "scanned_checks": checks,
        "coverage": coverage,
        "risk": risk,
        "maintainability": _maintainability(result, advice, "quality" in checks),
        "dead_code": {
            "status": "review"
            if dead_code
            else "not_assessed"
            if "dead_code" not in checks
            else "unknown"
            if coverage["status"] == "unknown"
            or "dead_code" in coverage["incomplete_checks"]
            else "none",
            "candidate_count": len(dead_code),
            "confidence_range": [min(confidence), max(confidence)]
            if confidence
            else None,
        },
        "finding_counts": summarize_finding_types(result),
    }
