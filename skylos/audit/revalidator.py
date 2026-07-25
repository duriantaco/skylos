"""Orchestration for evidence-grounded Deep Audit finding revalidation.

The stable public entry point remains in this module. Evidence validation,
verifier adapters, and policy/provenance logic live in the ``revalidation``
package so each security boundary can be reviewed independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from skylos.audit.freshness import finding_fingerprint
from skylos.audit.redaction import sanitize_for_audit
from skylos.audit.revalidation.policy import (
    CatalogFreshnessCache,
    CatalogPolicy,
    base_provenance,
    catalog_policy,
    finding_id,
    has_current_verdict,
    has_secret_candidate,
    incomplete_verdict,
    latest_verdict,
    normalize_verdict,
    read_current_source,
)
from skylos.audit.revalidation.verifiers import verify_finding
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    STATUS_DELETED,
    AuditFileRecord,
    AuditRevalidationSummary,
    sha256_text,
    utc_now,
)


@dataclass
class _RunStats:
    considered: int = 0
    revalidated: int = 0
    challenged: int = 0
    skipped: int = 0
    errors: int = 0
    limited: bool = False
    verdict_counts: dict[str, int] = field(
        default_factory=lambda: {
            "true_positive": 0,
            "false_positive": 0,
            "fixed": 0,
            "uncertain": 0,
        }
    )

    def count_result(self, verdict: str, *, challenged: bool) -> None:
        self.verdict_counts[verdict] += 1
        self.revalidated += 1
        if challenged:
            self.challenged += 1


@dataclass
class _RevalidationRun:
    store: AuditStore
    verifier: Any
    model: str
    provider: str | None
    force: bool
    challenge: bool
    limit: int | None
    run_id: str
    policy: CatalogPolicy
    catalog_cache: CatalogFreshnessCache = field(default_factory=dict)
    stats: _RunStats = field(default_factory=_RunStats)

    @property
    def mode(self) -> str:
        return "challenge" if self.challenge else "revalidate"

    def process_records(self, records: list[AuditFileRecord]) -> None:
        for record in records:
            self._process_record(record)

    def _process_record(self, record: AuditFileRecord) -> None:
        current = self.store.read_file_record(record.file)
        if current is None:
            return
        if has_secret_candidate(current):
            self.stats.skipped += len(current.findings)
            return
        for finding in list(current.findings):
            if isinstance(finding, dict):
                self._process_finding(current, finding)

    def _process_finding(
        self,
        record: AuditFileRecord,
        finding: dict[str, Any],
    ) -> None:
        current_finding_id = finding_id(finding)
        self.stats.considered += 1
        if not self._finding_needs_work(record, finding, current_finding_id):
            return
        if self._limit_reached():
            self.stats.limited = True
            return
        verdict = self._run_verifier(
            record,
            finding,
            finding_id_value=current_finding_id,
        )
        normalized = normalize_verdict(verdict)
        if normalized["complete"] is not True:
            self.stats.errors += 1
        entry = self._build_entry(
            record,
            finding,
            finding_id_value=current_finding_id,
            normalized=normalized,
        )
        self._persist_result(record, finding, entry, normalized)

    def _finding_needs_work(
        self,
        record: AuditFileRecord,
        finding: dict[str, Any],
        finding_id_value: str,
    ) -> bool:
        if self.challenge and latest_verdict(record, finding_id_value) != "uncertain":
            return False
        return self.force or not has_current_verdict(
            record,
            finding,
            model=self.model,
            provider=self.provider,
            challenge=self.challenge,
            catalog_cache=self.catalog_cache,
        )

    def _limit_reached(self) -> bool:
        return (
            self.limit is not None
            and self.limit >= 0
            and self.stats.revalidated >= self.limit
        )

    def _run_verifier(
        self,
        record: AuditFileRecord,
        finding: dict[str, Any],
        *,
        finding_id_value: str,
    ) -> dict[str, Any]:
        try:
            source = read_current_source(self.store, record)
            return verify_finding(
                self.verifier,
                store=self.store,
                record=record,
                finding=finding,
                source=source,
                mode=self.mode,
                run_id=(
                    f"{self.run_id}-{sha256_text(finding_id_value)[:8]}"
                ),
                catalog_policy=self.policy,
            )
        except Exception as exc:
            return incomplete_verdict(f"Revalidation failed: {exc}")

    def _build_entry(
        self,
        record: AuditFileRecord,
        finding: dict[str, Any],
        *,
        finding_id_value: str,
        normalized: dict[str, Any],
    ) -> dict[str, Any]:
        payload = {
            "finding_id": finding_id_value,
            "verdict": normalized["verdict"],
            "reason": normalized["reason"],
            "evidence": normalized["evidence"],
            "evidence_validated": normalized["evidence_validated"],
            "refuting_invariant": normalized["refuting_invariant"],
            "complete": normalized["complete"],
            "model": self.model,
            "provider": self.provider,
            "run_id": self.run_id,
            "mode": self.mode,
            "revalidated_at": utc_now(),
            **base_provenance(record, finding, self.policy),
            **normalized["provenance"],
        }
        return sanitize_for_audit(payload)

    def _persist_result(
        self,
        record: AuditFileRecord,
        finding: dict[str, Any],
        entry: dict[str, Any],
        normalized: dict[str, Any],
    ) -> None:
        persisted = self.store.append_revalidation_entry(
            record.file,
            expected_source_hash=record.file_hash,
            expected_config_hash=record.config_hash,
            expected_finding_hash=finding_fingerprint(finding),
            entry=entry,
        )
        if not persisted:
            self._count_persist_failure(normalized)
            return
        record.revalidation.append(entry)
        self.stats.count_result(
            normalized["verdict"],
            challenged=self.challenge,
        )

    def _count_persist_failure(self, normalized: dict[str, Any]) -> None:
        if normalized["complete"] is True:
            self.stats.errors += 1
        self.stats.count_result("uncertain", challenged=self.challenge)

    def summary(self) -> AuditRevalidationSummary:
        counts = self.stats.verdict_counts
        return AuditRevalidationSummary(
            run_id=self.run_id,
            project_id=self.store.project_id,
            project_root=str(self.store.project_root),
            considered_findings=self.stats.considered,
            revalidated_findings=self.stats.revalidated,
            challenged_findings=self.stats.challenged,
            skipped_findings=self.stats.skipped,
            error_findings=self.stats.errors,
            true_positive=counts["true_positive"],
            false_positive=counts["false_positive"],
            fixed=counts["fixed"],
            uncertain=counts["uncertain"],
            forced=self.force,
            challenge=self.challenge,
            complete=(
                self.stats.skipped == 0
                and self.stats.errors == 0
                and not self.stats.limited
            ),
            limited=self.stats.limited,
        )


def revalidate_deep_audit_findings(
    *,
    store: AuditStore,
    verifier: Any,
    model: str,
    provider: str | None = None,
    force: bool = False,
    challenge: bool = False,
    allowed_files: list[str | Path] | None = None,
    limit: int | None = None,
    run_id: str | None = None,
) -> AuditRevalidationSummary:
    current_run_id = run_id or f"revalidate-{uuid4().hex[:12]}"
    allowed = store.processing_scope(allowed_files)
    all_records = store.iter_file_records()
    records = _eligible_records(all_records, allowed)
    run = _RevalidationRun(
        store=store,
        verifier=verifier,
        model=model,
        provider=provider,
        force=force,
        challenge=challenge,
        limit=limit,
        run_id=current_run_id,
        policy=catalog_policy(store, all_records),
    )
    run.process_records(records)
    summary = run.summary()
    store.write_run(
        current_run_id,
        {
            "mode": run.mode,
            "summary": summary.to_dict(),
        },
    )
    return summary


def _eligible_records(
    records: list[AuditFileRecord],
    allowed: set[str] | None,
) -> list[AuditFileRecord]:
    return [
        record
        for record in records
        if record.findings
        and record.status != STATUS_DELETED
        and (allowed is None or record.file in allowed)
    ]
