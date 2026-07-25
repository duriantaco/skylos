from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.audit.freshness import latest_current_revalidation
from skylos.audit.processor import (
    agent_context_is_current,
    current_repository_catalog_digest,
)
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    STATUS_ANALYZED,
    STATUS_DELETED,
    STATUS_ERROR,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_SKIPPED,
    AuditCIGateSummary,
    AuditProcessSummary,
    AuditScanSummary,
    normalize_relative_path,
)

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def evaluate_deep_audit_ci_gate(
    *,
    store: AuditStore,
    fail_on: str,
    model: str | None = None,
    provider: str | None = None,
    allowed_files: list[str | Path] | None = None,
    scan_summary: AuditScanSummary | None = None,
    process_summary: AuditProcessSummary | None = None,
    finding_run_id: str | None = None,
) -> AuditCIGateSummary:
    threshold = _severity_value(fail_on)
    allowed = _normalized_allowed_files(store, allowed_files)
    repository_catalog_digest = (
        current_repository_catalog_digest(store) if model is not None else None
    )
    revalidation_catalog_cache: dict[tuple[Any, ...], bool] = {}
    counts = {
        "findings": 0,
        "pending": 0,
        "not_analyzed": 0,
        "skipped": 0,
        "error": 0,
        "locked": 0,
        "stale_analyzed": 0,
        "limited": 0,
        "rejected_source_files": 0,
    }
    if scan_summary is not None:
        counts["rejected_source_files"] = max(
            0,
            int(scan_summary.rejected_source_files),
        )

    for record in store.iter_file_records():
        if allowed is not None and record.file not in allowed:
            continue
        if record.status == STATUS_DELETED:
            continue
        model_review_unit = int(model is not None)
        if not record.candidates and not record.findings and not model_review_unit:
            continue

        high_risk_candidates = [
            candidate
            for candidate in record.candidates
            if _severity_value(candidate.severity_hint) >= threshold
        ]
        high_risk_candidate_count = max(
            len(high_risk_candidates),
            model_review_unit,
        )

        if record.status == STATUS_PENDING:
            counts["pending"] += high_risk_candidate_count
        elif record.status == STATUS_NOT_ANALYZED:
            counts["not_analyzed"] += high_risk_candidate_count
        elif record.status == STATUS_SKIPPED:
            counts["skipped"] += high_risk_candidate_count
        elif record.status == STATUS_ERROR:
            counts["error"] += high_risk_candidate_count
        elif record.status == STATUS_PROCESSING:
            counts["locked"] += high_risk_candidate_count
        elif (
            record.status == STATUS_ANALYZED
            and model is not None
            and not agent_context_is_current(
                record,
                model=model,
                provider=provider,
                repository_catalog_digest=repository_catalog_digest,
            )
        ):
            counts["stale_analyzed"] += high_risk_candidate_count

        for finding in record.findings:
            if not isinstance(finding, dict):
                continue
            if (
                finding_run_id is not None
                and finding.get("audit_produced_by_run_id") != finding_run_id
            ):
                continue
            if _finding_is_refuted(
                record,
                finding,
                catalog_cache=revalidation_catalog_cache,
            ):
                continue
            if _severity_value(finding.get("severity")) >= threshold:
                counts["findings"] += 1

    unresolved = sum(
        counts[key]
        for key in [
            "pending",
            "not_analyzed",
            "skipped",
            "error",
            "locked",
            "stale_analyzed",
        ]
    )
    if process_summary and process_summary.limited and unresolved:
        counts["limited"] = 1

    exit_code = 1 if any(counts.values()) else 0
    return AuditCIGateSummary(
        fail_on=fail_on,
        exit_code=exit_code,
        blocking_counts=counts,
        complete=exit_code == 0,
        reason=_gate_reason(counts),
    )


def _normalized_allowed_files(
    store: AuditStore,
    allowed_files: list[str | Path] | None,
) -> set[str] | None:
    if allowed_files is None:
        return None
    allowed: set[str] = set()
    for file_path in allowed_files:
        try:
            allowed.add(normalize_relative_path(store.project_root, file_path))
        except ValueError:
            continue
    return allowed


def _severity_value(value: Any) -> int:
    return SEVERITY_RANK.get(str(value or "info").lower(), 0)


def _finding_is_refuted(
    record,
    finding: dict[str, Any],
    *,
    catalog_cache: dict[tuple[Any, ...], bool],
) -> bool:
    item = latest_current_revalidation(
        record,
        finding,
        catalog_cache=catalog_cache,
    )
    verdict = str((item or {}).get("verdict") or "").lower()
    return verdict in {"false_positive", "fixed"}


def _gate_reason(counts: dict[str, int]) -> str:
    if counts["rejected_source_files"]:
        return "deep audit source files were rejected before analysis"
    if counts["findings"]:
        return "supported or unresolved findings meet the failure threshold"
    if counts["error"]:
        return "deep audit processing errors remain"
    if counts["pending"]:
        return "pending high-risk deep audit work remains"
    if counts["not_analyzed"]:
        return "unsupported high-risk deep audit work remains"
    if counts["skipped"]:
        return "skipped high-risk deep audit work remains"
    if counts["locked"]:
        return "locked high-risk deep audit work remains"
    if counts["stale_analyzed"]:
        return "stale analyzed high-risk deep audit work remains"
    if counts["limited"]:
        return "limited deep audit run left high-risk work unresolved"
    return "no blocking deep audit work at or above threshold"
