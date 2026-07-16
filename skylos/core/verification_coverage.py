from __future__ import annotations

from typing import Any


SCHEMA_VERSION = 1


def build_ai_verification_coverage(
    checks: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    normalized = [dict(check) for check in checks if isinstance(check, dict)]
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
    if any(check.get("outcome") == "incomplete" for check in normalized):
        state = "incomplete"
    return {
        "schema_version": SCHEMA_VERSION,
        "state": state,
        "completed_checks": completed,
        "skipped_checks": skipped,
        "checks": normalized,
    }


def reconcile_check_findings(
    check: dict[str, Any],
    finding_count: int,
) -> dict[str, Any]:
    reconciled = dict(check)
    reconciled["finding_count"] = max(0, int(finding_count))
    if reconciled["finding_count"]:
        reconciled["outcome"] = "fail"
    elif int(reconciled.get("skipped_references") or 0):
        reconciled["outcome"] = "incomplete"
    else:
        reconciled["outcome"] = "pass"
    return reconciled


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
