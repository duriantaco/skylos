"""Validate and compare captured deterministic evaluation receipts.

This module compares evidence; it does not select cases or execute scanners.
Artifact integrity is verified by the caller before receipts reach this module.
"""

from __future__ import annotations

import json
import math
from typing import Any


_HASH_FIELDS = ("dataset_sha256", "harness_sha256", "environment_sha256")
_STATUSES = {"passed", "failed", "incomplete"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _object_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)


def _valid_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _inspect(
    receipt: Any, phase: str
) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, int]]:
    issues: list[str] = []
    cases: dict[str, dict[str, Any]] = {}
    counts = dict.fromkeys(("passed", "failed", "incomplete", "unresolved"), 0)
    if not isinstance(receipt, dict):
        return [f"{phase}: receipt is not an object"], cases, counts

    if type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1:
        issues.append(f"{phase}: unsupported schema_version")
    if receipt.get("phase") != phase:
        issues.append(f"{phase}: receipt phase does not match")
    if not isinstance(receipt.get("suite"), str) or receipt["suite"] not in {
        "security",
        "dead-code",
    }:
        issues.append(f"{phase}: unsupported suite")
    if receipt.get("source_unchanged") is not True:
        issues.append(f"{phase}: source stability was not established")

    elapsed = receipt.get("elapsed_seconds")
    if (
        type(elapsed) not in (int, float)
        or (type(elapsed) is float and not math.isfinite(elapsed))
        or elapsed < 0
    ):
        issues.append(f"{phase}: elapsed_seconds must be finite and nonnegative")

    errors = receipt.get("runtime_errors")
    if not isinstance(errors, list) or any(not isinstance(e, str) for e in errors):
        issues.append(f"{phase}: runtime_errors must be a list of strings")
    elif errors:
        issues.append(f"{phase}: execution reported runtime errors")

    inputs = receipt.get("inputs")
    if not isinstance(inputs, dict):
        issues.append(f"{phase}: inputs is not an object")
    else:
        for key in _HASH_FIELDS:
            if not _valid_hash(inputs.get(key)):
                issues.append(f"{phase}: {key} must be a SHA256 digest")
        if not isinstance(inputs.get("options"), dict):
            issues.append(f"{phase}: inputs.options must be an object")
        try:
            _canonical(inputs)
        except (TypeError, ValueError):
            issues.append(f"{phase}: inputs is not valid finite JSON")

    requested = receipt.get("case_ids")
    if (
        not isinstance(requested, list)
        or not requested
        or any(
            not isinstance(case_id, str) or not case_id.strip() for case_id in requested
        )
    ):
        issues.append(f"{phase}: case_ids must be a nonempty list of identifiers")
        requested = []
    elif len(set(requested)) != len(requested):
        issues.append(f"{phase}: duplicate requested case identifiers")

    records = receipt.get("cases")
    if not isinstance(records, list):
        issues.append(f"{phase}: cases must be a list")
        records = []
    for record in records:
        if not isinstance(record, dict):
            issues.append(f"{phase}: case record is not an object")
            continue
        case_id = record.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            issues.append(f"{phase}: case record has no valid identifier")
            continue
        if case_id in cases:
            issues.append(f"{phase}: duplicate case record {case_id}")
            continue
        cases[case_id] = record

        status = record.get("status")
        if not isinstance(status, str) or status not in _STATUSES:
            issues.append(f"{phase}: {case_id} has an unsupported status")
            counts["incomplete"] += 1
        else:
            counts[status] += 1
            if status == "incomplete":
                issues.append(f"{phase}: {case_id} analysis is incomplete")

        for key in ("failures", "findings", "unresolved_findings"):
            values = record.get(key)
            if not _object_list(values):
                issues.append(f"{phase}: {case_id}.{key} must be a list of objects")
                continue
            try:
                _canonical(values)
            except (TypeError, ValueError):
                issues.append(f"{phase}: {case_id}.{key} is not valid finite JSON")
            if key == "unresolved_findings":
                counts["unresolved"] += len(values)

        failures = record.get("failures")
        if _object_list(failures):
            if any(not failure for failure in failures):
                issues.append(f"{phase}: {case_id} has an empty failure object")
            for failure in failures:
                if any(
                    key in failure and not isinstance(failure[key], str)
                    for key in ("failure_type", "category", "mode", "expected")
                ):
                    issues.append(f"{phase}: {case_id} failure identity is invalid")
                if "found" in failure and not isinstance(failure["found"], list):
                    issues.append(f"{phase}: {case_id} failure found must be a list")
                if failure.get("failure_type") in (
                    "analysis",
                    "execution",
                    "runtime",
                    "unsupported",
                    "incomplete",
                ):
                    issues.append(
                        f"{phase}: {case_id} has an execution/completeness failure"
                    )
            if status == "passed" and failures:
                issues.append(f"{phase}: {case_id} is marked passed despite failures")
            if status == "failed" and not failures:
                issues.append(f"{phase}: {case_id} is marked failed without failures")

    missing = set(requested) - cases.keys()
    extra = cases.keys() - set(requested)
    if missing:
        counts["incomplete"] += len(missing)
        issues.append(f"{phase}: missing case records: {', '.join(sorted(missing))}")
    if extra:
        issues.append(f"{phase}: unexpected case records: {', '.join(sorted(extra))}")
    return issues, cases, counts


def _failure_key(failure: dict[str, Any]) -> str:
    # One expectation remains the same failing contract when evidence text changes.
    # Unexpected findings need their actual identity: replacing one noisy finding
    # with another must not disappear behind the same count/placeholder expected.
    identity = {
        key: failure[key]
        for key in ("failure_type", "category", "mode", "expected")
        if key in failure
    }
    if not identity:
        return _canonical(failure)
    kind = failure.get("failure_type", "expectation")
    mode = failure.get("mode", "")
    if kind in {"unlabeled", "unexpected"} or mode in {
        "strict_labels",
        "unexpected",
    }:
        identity["found"] = sorted(
            (_canonical(item) for item in failure.get("found", []))
        )
    return _canonical(identity)


def _failures(
    cases: dict[str, dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (case_id, _failure_key(failure)): {"case_id": case_id, "failure": failure}
        for case_id, case in cases.items()
        for failure in case["failures"]
    }


def compare_receipts(before: Any, after: Any) -> dict[str, Any]:
    """Compare a baseline and candidate, refusing incomplete/incompatible pairs.

    ``no_new_regressions`` is separate from absolute candidate health. Unresolved
    candidate output prevents both an overall pass and a clean regression claim.
    """
    base_issues, base_cases, base_counts = _inspect(before, "baseline")
    head_issues, head_cases, head_counts = _inspect(after, "candidate")
    issues = base_issues + head_issues
    if isinstance(before, dict) and isinstance(after, dict):
        if before.get("suite") != after.get("suite"):
            issues.append("baseline/candidate suite mismatch")
        if set(base_cases) != set(head_cases):
            issues.append("baseline/candidate case inventory mismatch")
        try:
            matching_inputs = _canonical(before.get("inputs")) == _canonical(
                after.get("inputs")
            )
        except (TypeError, ValueError):
            matching_inputs = False
        if not matching_inputs:
            issues.append("baseline/candidate evaluation inputs mismatch")

    report: dict[str, Any] = {
        "comparable": not issues,
        "comparison_issues": list(dict.fromkeys(issues)),
        "suite": before.get("suite") if isinstance(before, dict) else None,
        "case_ids": sorted(base_cases),
        "baseline_counts": base_counts,
        "candidate_counts": head_counts,
        "new_failures": [],
        "resolved_failures": [],
        "existing_failures": [],
        "finding_changes": [],
        "elapsed_seconds": {
            "baseline": before.get("elapsed_seconds")
            if isinstance(before, dict)
            else None,
            "candidate": after.get("elapsed_seconds")
            if isinstance(after, dict)
            else None,
        },
        "no_new_regressions": False,
        "candidate_passed": not head_issues
        and head_counts["failed"] == 0
        and head_counts["incomplete"] == 0
        and head_counts["unresolved"] == 0,
        "exit_code": 1,
    }
    if issues:
        return report

    base_failures, head_failures = _failures(base_cases), _failures(head_cases)
    for field, identities in (
        ("new_failures", head_failures.keys() - base_failures.keys()),
        ("resolved_failures", base_failures.keys() - head_failures.keys()),
        ("existing_failures", base_failures.keys() & head_failures.keys()),
    ):
        source = base_failures if field == "resolved_failures" else head_failures
        report[field] = [source[identity] for identity in sorted(identities)]

    for case_id in sorted(base_cases):
        base_findings = {
            _canonical(finding): finding for finding in base_cases[case_id]["findings"]
        }
        head_findings = {
            _canonical(finding): finding for finding in head_cases[case_id]["findings"]
        }
        added = head_findings.keys() - base_findings.keys()
        removed = base_findings.keys() - head_findings.keys()
        if added or removed:
            report["finding_changes"].append(
                {
                    "case_id": case_id,
                    "added": [head_findings[key] for key in sorted(added)],
                    "removed": [base_findings[key] for key in sorted(removed)],
                }
            )

    report["no_new_regressions"] = (
        not report["new_failures"] and not head_counts["unresolved"]
    )
    report["exit_code"] = (
        0 if report["no_new_regressions"] and report["candidate_passed"] else 1
    )
    return report


def format_comparison(report: dict[str, Any]) -> str:
    """Return a short terminal summary that preserves scope and missing evidence."""
    baseline = report["baseline_counts"]
    candidate = report["candidate_counts"]
    lines = [
        f"Scope: {report.get('suite')} / {len(report['case_ids'])} selected cases (scoped)",
        f"Before: {baseline['passed']} passed, {baseline['failed']} failed, "
        f"{baseline['incomplete']} incomplete",
        f"After:  {candidate['passed']} passed, {candidate['failed']} failed, "
        f"{candidate['incomplete']} incomplete",
        f"Unresolved findings: {baseline['unresolved']} before, "
        f"{candidate['unresolved']} after",
        f"Elapsed seconds: {report['elapsed_seconds']['baseline']} before, "
        f"{report['elapsed_seconds']['candidate']} after",
    ]
    if report["comparable"]:
        lines.extend(
            [
                f"New failures: {len(report['new_failures'])}",
                f"Resolved failures: {len(report['resolved_failures'])}",
                f"Existing failures: {len(report['existing_failures'])}",
                "Finding changes: "
                + str(sum(len(change["added"]) for change in report["finding_changes"]))
                + " added, "
                + str(
                    sum(len(change["removed"]) for change in report["finding_changes"])
                )
                + " removed (review details)",
                "No new regressions: "
                + ("yes" if report["no_new_regressions"] else "not established"),
            ]
        )
    else:
        lines.append("Comparison: blocked; no clean regression claim")
        lines.extend(f"- {issue}" for issue in report["comparison_issues"])
    lines.append(
        "Candidate checks: "
        + ("passed" if report["candidate_passed"] else "not passed")
    )
    lines.append("Broader validation: separate required checks")
    return "\n".join(lines)
