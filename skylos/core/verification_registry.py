from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


LOCAL_API_CAPABILITY = "local_workspace_api_surface"


@dataclass(frozen=True)
class VerificationExpectation:
    check_id: str
    languages: tuple[str, ...]
    applicable_files: int
    supported: bool
    capability: str = LOCAL_API_CAPABILITY
    unsupported_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.check_id,
            "languages": list(self.languages),
            "applicable_files": self.applicable_files,
            "capability": self.capability,
            "support": "supported" if self.supported else "unsupported",
        }
        if self.unsupported_reason:
            payload["reason"] = self.unsupported_reason
        return payload


_LANGUAGE_SUFFIXES = {
    ".py": "python",
    ".pyi": "python",
    ".pyw": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".rs": "rust",
    ".dart": "dart",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".bats": "shell",
}

_CHECK_ORDER = {
    "python_local_api_reference": 0,
    "typescript_local_api_surface": 1,
    "go_workspace_api_surface": 2,
    "java_workspace_api_surface": 3,
    "php_workspace_api_surface": 4,
    "rust_workspace_api_surface": 5,
    "dart_workspace_api_surface": 6,
    "csharp_workspace_api_surface": 7,
    "kotlin_workspace_api_surface": 8,
    "shell_workspace_api_surface": 9,
}

_UNSUPPORTED_REASON = "local_api_verification_not_implemented"


def expected_ai_verification_checks(
    files: Iterable[str | Path],
) -> list[VerificationExpectation]:
    counts = detected_verification_languages(files)
    expectations: list[VerificationExpectation] = []
    _append_single_language_expectation(
        expectations,
        counts,
        language="python",
        check_id="python_local_api_reference",
        supported=True,
    )
    _append_js_expectation(expectations, counts)
    _append_single_language_expectation(
        expectations,
        counts,
        language="go",
        check_id="go_workspace_api_surface",
        supported=True,
    )
    _append_single_language_expectation(
        expectations,
        counts,
        language="java",
        check_id="java_workspace_api_surface",
        supported=True,
    )
    for language in ("php", "rust", "dart", "csharp", "kotlin", "shell"):
        _append_single_language_expectation(
            expectations,
            counts,
            language=language,
            check_id=f"{language}_workspace_api_surface",
            supported=False,
        )
    return sorted(expectations, key=lambda item: _CHECK_ORDER[item.check_id])


def detected_verification_languages(
    files: Iterable[str | Path],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in files:
        language = _LANGUAGE_SUFFIXES.get(Path(value).suffix.lower())
        if language is None:
            continue
        counts[language] = counts.get(language, 0) + 1
    return counts


def reconcile_expected_verification_checks(
    checks: Iterable[dict[str, Any]],
    expectations: Iterable[VerificationExpectation | dict[str, Any]],
) -> list[dict[str, Any]]:
    normalized_checks = [dict(check) for check in checks if isinstance(check, dict)]
    normalized_expectations = _normalize_expectations(expectations)
    checks_by_id, malformed_checks = _checks_by_id(normalized_checks)
    reconciled: list[dict[str, Any]] = []
    expected_ids: set[str] = set()

    for expectation in normalized_expectations:
        expected_ids.add(expectation.check_id)
        actual_records = checks_by_id.get(expectation.check_id, [])
        if not expectation.supported:
            reconciled.append(_incomplete_check(expectation, "unsupported_capability"))
        elif not actual_records:
            reconciled.append(_incomplete_check(expectation, "expected_check_missing"))
        else:
            reconciled.append(
                _enrich_actual_check(
                    _merge_actual_checks(actual_records),
                    expectation,
                )
            )

    for check_id, records in checks_by_id.items():
        if check_id not in expected_ids:
            reconciled.append(_merge_actual_checks(records))
    reconciled.extend(malformed_checks)
    return reconciled


def expectation_payloads(
    expectations: Iterable[VerificationExpectation | dict[str, Any]],
) -> list[dict[str, Any]]:
    return [item.to_dict() for item in _normalize_expectations(expectations)]


def _append_single_language_expectation(
    expectations: list[VerificationExpectation],
    counts: dict[str, int],
    *,
    language: str,
    check_id: str,
    supported: bool,
) -> None:
    file_count = counts.get(language, 0)
    if not file_count:
        return
    expectations.append(
        VerificationExpectation(
            check_id=check_id,
            languages=(language,),
            applicable_files=file_count,
            supported=supported,
            unsupported_reason=None if supported else _UNSUPPORTED_REASON,
        )
    )


def _append_js_expectation(
    expectations: list[VerificationExpectation],
    counts: dict[str, int],
) -> None:
    languages = tuple(
        language for language in ("typescript", "javascript") if counts.get(language, 0)
    )
    if not languages:
        return
    expectations.append(
        VerificationExpectation(
            check_id="typescript_local_api_surface",
            languages=languages,
            applicable_files=sum(counts[language] for language in languages),
            supported=True,
        )
    )


def _normalize_expectations(
    expectations: Iterable[VerificationExpectation | dict[str, Any]],
) -> list[VerificationExpectation]:
    normalized: list[VerificationExpectation] = []
    for expectation in expectations:
        if isinstance(expectation, VerificationExpectation):
            normalized.append(expectation)
            continue
        if not isinstance(expectation, dict):
            continue
        check_id = expectation.get("id")
        languages = expectation.get("languages")
        if not isinstance(check_id, str) or not check_id:
            continue
        if not isinstance(languages, list) or not all(
            isinstance(language, str) and language for language in languages
        ):
            continue
        normalized.append(
            VerificationExpectation(
                check_id=check_id,
                languages=tuple(languages),
                applicable_files=max(0, int(expectation.get("applicable_files") or 0)),
                supported=expectation.get("support") != "unsupported",
                capability=str(expectation.get("capability") or LOCAL_API_CAPABILITY),
                unsupported_reason=(
                    str(expectation.get("reason"))
                    if expectation.get("reason")
                    else None
                ),
            )
        )
    return sorted(normalized, key=lambda item: _CHECK_ORDER.get(item.check_id, 100))


def _incomplete_check(
    expectation: VerificationExpectation,
    reason: str,
) -> dict[str, Any]:
    return {
        "id": expectation.check_id,
        "status": "skipped",
        "outcome": "incomplete",
        "scope": expectation.capability,
        "languages": list(expectation.languages),
        "applicable_files": expectation.applicable_files,
        "raw_imports": 0,
        "references": 0,
        "checked_references": 0,
        "verified_references": 0,
        "skipped_references": 0,
        "finding_count": 0,
        "reasons": [{"code": reason, "count": 1}],
    }


def _enrich_actual_check(
    check: dict[str, Any],
    expectation: VerificationExpectation,
) -> dict[str, Any]:
    enriched = dict(check)
    actual_applicable_files = max(0, int(enriched.get("applicable_files") or 0))
    enriched["expected_applicable_files"] = expectation.applicable_files
    enriched["scope"] = str(enriched.get("scope") or expectation.capability)
    enriched["languages"] = sorted(
        {
            *expectation.languages,
            *(
                language
                for language in enriched.get("languages", [])
                if isinstance(language, str) and language
            ),
        }
    )
    enriched["applicable_files"] = actual_applicable_files
    if enriched.get("status") == "skipped":
        enriched["outcome"] = "incomplete"
    elif actual_applicable_files < expectation.applicable_files:
        if enriched.get("outcome") != "fail":
            enriched["outcome"] = "incomplete"
        enriched["skipped_references"] = max(
            1,
            int(enriched.get("skipped_references") or 0),
        )
        _append_reason(enriched, "expected_file_coverage_mismatch")
    return enriched


def _checks_by_id(
    checks: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    malformed = []
    for check in checks:
        check_id = check.get("id")
        if not isinstance(check_id, str) or not check_id:
            malformed.append(_malformed_check())
            continue
        grouped.setdefault(check_id, []).append(check)
    return grouped, malformed


def _merge_actual_checks(records: list[dict[str, Any]]) -> dict[str, Any]:
    normalized = [_normalize_actual_check(record) for record in records]
    if len(normalized) == 1:
        return normalized[0]
    merged = dict(normalized[0])
    merged["languages"] = _merged_check_languages(normalized)
    _merge_max_check_counts(merged, normalized)
    merged["skipped_references"] = (
        sum(int(check.get("skipped_references") or 0) for check in normalized) + 1
    )
    merged["reasons"] = _merged_reasons(normalized)
    _append_reason(merged, "duplicate_check_record")
    merged["status"] = _merged_check_status(normalized)
    merged["outcome"] = _merged_check_outcome(normalized, merged)
    return merged


def _merged_check_languages(checks: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            language
            for check in checks
            for language in check.get("languages", [])
            if isinstance(language, str) and language
        }
    )


def _merge_max_check_counts(
    merged: dict[str, Any],
    checks: list[dict[str, Any]],
) -> None:
    for key in (
        "applicable_files",
        "raw_imports",
        "references",
        "checked_references",
        "verified_references",
        "finding_count",
        "suppressed_findings",
    ):
        merged[key] = max(int(check.get(key) or 0) for check in checks)


def _merged_check_status(checks: list[dict[str, Any]]) -> str:
    if all(check.get("status") == "completed" for check in checks):
        return "completed"
    return "skipped"


def _merged_check_outcome(
    checks: list[dict[str, Any]],
    merged: dict[str, Any],
) -> str:
    if int(merged.get("finding_count") or 0):
        return "fail"
    if any(check.get("outcome") == "fail" for check in checks):
        return "fail"
    return "incomplete"


def _normalize_actual_check(check: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(check)
    malformed = False
    if normalized.get("status") not in {"completed", "skipped"}:
        normalized["status"] = "skipped"
        malformed = True
    if normalized.get("outcome") not in {"pass", "fail", "incomplete"}:
        normalized["outcome"] = "incomplete"
        malformed = True
    for key in (
        "applicable_files",
        "raw_imports",
        "references",
        "checked_references",
        "verified_references",
        "skipped_references",
        "finding_count",
        "suppressed_findings",
    ):
        normalized[key] = max(0, int(normalized.get(key) or 0))
    if normalized["finding_count"]:
        normalized["outcome"] = "fail"
    elif normalized["skipped_references"] or (
        normalized["status"] == "skipped" and not _is_not_applicable_check(normalized)
    ):
        normalized["outcome"] = "incomplete"
    if malformed:
        normalized["skipped_references"] = max(
            1,
            normalized["skipped_references"],
        )
        if normalized["outcome"] != "fail":
            normalized["outcome"] = "incomplete"
        _append_reason(normalized, "malformed_check_record")
    return normalized


def _is_not_applicable_check(check: dict[str, Any]) -> bool:
    reasons = check.get("reasons")
    return (
        check.get("outcome") == "pass"
        and int(check.get("applicable_files") or 0) == 0
        and isinstance(reasons, list)
        and any(
            isinstance(reason, dict) and reason.get("code") == "no_supported_files"
            for reason in reasons
        )
    )


def _merged_reasons(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for check in checks:
        reasons = check.get("reasons")
        if not isinstance(reasons, list):
            continue
        for reason in reasons:
            if not isinstance(reason, dict):
                continue
            code = reason.get("code")
            if isinstance(code, str) and code:
                counts[code] += max(1, int(reason.get("count") or 0))
    return [{"code": code, "count": count} for code, count in sorted(counts.items())]


def _malformed_check() -> dict[str, Any]:
    return {
        "id": "malformed_verification_check",
        "status": "skipped",
        "outcome": "incomplete",
        "scope": LOCAL_API_CAPABILITY,
        "languages": [],
        "applicable_files": 0,
        "raw_imports": 0,
        "references": 0,
        "checked_references": 0,
        "verified_references": 0,
        "skipped_references": 1,
        "finding_count": 0,
        "reasons": [{"code": "malformed_check_record", "count": 1}],
    }


def _append_reason(check: dict[str, Any], code: str) -> None:
    reasons = check.setdefault("reasons", [])
    if not isinstance(reasons, list):
        reasons = []
        check["reasons"] = reasons
    for reason in reasons:
        if isinstance(reason, dict) and reason.get("code") == code:
            reason["count"] = max(1, int(reason.get("count") or 0))
            return
    reasons.append({"code": code, "count": 1})
