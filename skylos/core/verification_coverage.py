from __future__ import annotations

from typing import Any


SCHEMA_VERSION = 1


def build_ai_verification_coverage(
    checks: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    *,
    expected_checks: list[Any] | tuple[Any, ...] | None = None,
) -> dict[str, Any]:
    from skylos.core.verification_registry import (
        expectation_payloads,
        reconcile_expected_verification_checks,
    )

    expectations = list(expected_checks or ())
    normalized = reconcile_expected_verification_checks(checks, expectations)
    completed = [
        str(check.get("id"))
        for check in normalized
        if check.get("status") == "completed" and check.get("id")
    ]
    skipped = [
        {
            "id": str(check.get("id")),
            "reasons": _reason_codes(check),
        }
        for check in normalized
        if check.get("status") == "skipped" and check.get("id")
    ]
    state = "complete"
    if any(_check_proof_incomplete(check) for check in normalized):
        state = "incomplete"
    expectation_data = expectation_payloads(expectations)
    missing_checks = [
        str(check.get("id"))
        for check in normalized
        if _reason_codes(check) == ["expected_check_missing"] and check.get("id")
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "state": state,
        "detected_languages": sorted(
            {
                language
                for expectation in expectation_data
                for language in expectation.get("languages", [])
                if isinstance(language, str)
            }
        ),
        "expected_checks": expectation_data,
        "missing_checks": missing_checks,
        "language_support": _language_support(expectation_data),
        "completed_checks": completed,
        "skipped_checks": skipped,
        "checks": normalized,
    }


def _language_support(expectations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    support: list[dict[str, Any]] = []
    for expectation in expectations:
        for language in expectation.get("languages", []):
            if not isinstance(language, str):
                continue
            item = {
                "language": language,
                "capability": expectation.get("capability"),
                "status": expectation.get("support"),
                "check_id": expectation.get("id"),
            }
            if expectation.get("reason"):
                item["reason"] = expectation["reason"]
            support.append(item)
    return sorted(
        support, key=lambda item: (str(item["language"]), str(item["check_id"]))
    )


def reconcile_check_findings(
    check: dict[str, Any],
    finding_count: int,
    *,
    suppressed_count: int = 0,
) -> dict[str, Any]:
    reconciled = dict(check)
    reconciled["finding_count"] = max(0, int(finding_count))
    reconciled["suppressed_findings"] = max(0, int(suppressed_count))
    if reconciled["suppressed_findings"]:
        reconciled["reasons"] = _reconciled_reasons(
            reconciled.get("reasons"),
            "finding_suppressed",
            reconciled["suppressed_findings"],
        )
    if reconciled["finding_count"]:
        reconciled["outcome"] = "fail"
    elif int(reconciled.get("skipped_references") or 0):
        reconciled["outcome"] = "incomplete"
    else:
        reconciled["outcome"] = "pass"
    return reconciled


def _reconciled_reasons(
    reasons: Any,
    code: str,
    count: int,
) -> list[dict[str, Any]]:
    normalized = (
        [dict(reason) for reason in reasons if isinstance(reason, dict)]
        if isinstance(reasons, list)
        else []
    )
    for reason in normalized:
        if reason.get("code") != code:
            continue
        reason["count"] = max(0, int(reason.get("count") or 0)) + count
        return normalized
    normalized.append({"code": code, "count": count})
    return sorted(normalized, key=lambda reason: str(reason.get("code", "")))


def _reason_codes(check: dict[str, Any]) -> list[str]:
    reasons = check.get("reasons")
    if not isinstance(reasons, list):
        return []
    codes = []
    for reason in reasons:
        if not isinstance(reason, dict):
            continue
        code = reason.get("code")
        if isinstance(code, str) and code:
            codes.append(code)
    return codes


def _check_proof_incomplete(check: dict[str, Any]) -> bool:
    if check.get("outcome") == "incomplete":
        return True
    return int(check.get("skipped_references") or 0) > 0
