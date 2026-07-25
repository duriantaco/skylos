from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from skylos.audit.investigator_tools import (
    DEFAULT_EXCLUDED_FOLDERS,
    INVESTIGATOR_TOOL_SCHEMA_VERSION,
    AuditReadOnlyTools,
    AuditToolError,
)
from skylos.audit.redaction import redact_text, sanitize_for_audit
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    MAX_AUDIT_SOURCE_BYTES,
    SIGNAL_QUALITY_RANK,
    STATUS_ANALYZED,
    STATUS_DELETED,
    STATUS_ERROR,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_SKIPPED,
    AuditFileRecord,
    AuditCandidate,
    AuditProcessSummary,
    code_region_hash,
    normalize_relative_path,
    sha256_text,
    utc_now,
)
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.llm.investigator import (
    INVESTIGATOR_DEFINITION_HASH,
    INVESTIGATOR_PROTOCOL_VERSION,
    MAX_INVESTIGATOR_CANDIDATES,
    InvestigationIncompleteError,
)

SECURITY_AUDIT_ISSUE = "security_audit"
PYTHON_LANGUAGE = "python"
DEEP_AUDIT_ANALYSIS_VERSION = INVESTIGATOR_PROTOCOL_VERSION
DEFAULT_INVESTIGATOR_CANDIDATE_BATCH_SIZE = MAX_INVESTIGATOR_CANDIDATES
MAX_INVESTIGATOR_BATCH_ATTEMPTS = 32
INVESTIGATOR_USAGE_KEYS = frozenset(
    {
        "cached_tokens",
        "completion_tokens",
        "input_tokens",
        "output_tokens",
        "prompt_tokens",
        "reasoning_tokens",
        "total_tokens",
    }
)
INVESTIGATOR_OPERATIONAL_COUNTER_KEYS = (
    "turns",
    "llm_calls",
    "tool_calls",
    "source_observation_calls",
    "evidence_bytes",
    "unsafe_discovery_truncations",
    "sensitive_denials",
)


@dataclass(frozen=True)
class _InvestigationBatchResult:
    candidate_ids: tuple[str, ...]
    result: Any


@dataclass(frozen=True)
class _AggregatedInvestigationResult:
    findings: list[Any]
    status: str
    metadata: dict[str, Any]


@dataclass
class _InvestigationAttemptBudget:
    attempt_limit: int
    attempts_used: int = 0

    @property
    def attempts_remaining(self) -> int:
        return max(0, self.attempt_limit - self.attempts_used)

    def consume_attempt(self) -> bool:
        if self.attempts_remaining <= 0:
            return False
        self.attempts_used += 1
        return True


@dataclass(frozen=True)
class _InvestigationBatchRequest:
    investigate: Any
    redacted_source: str
    context: str | None
    store: AuditStore
    record: AuditFileRecord
    run_id: str
    sensitive_files: set[str]
    exclude_folders: tuple[str, ...]
    excluded_paths: set[str]
    repository_catalog_digest: str | None

    def run(self, candidates: list[dict[str, Any]], *, run_id: str) -> Any:
        return _run_investigation_batch(
            investigate=self.investigate,
            redacted_source=self.redacted_source,
            context=self.context,
            candidates=candidates,
            store=self.store,
            record=self.record,
            run_id=run_id,
            sensitive_files=self.sensitive_files,
            exclude_folders=self.exclude_folders,
            excluded_paths=self.excluded_paths,
            repository_catalog_digest=self.repository_catalog_digest,
        )


@dataclass
class _AdaptiveInvestigationState:
    request: _InvestigationBatchRequest
    budget: _InvestigationAttemptBudget
    completed: list[_InvestigationBatchResult] = field(default_factory=list)
    failed_attempt_metadata: list[dict[str, Any]] = field(default_factory=list)
    attempts: int = 0

    def run_once(
        self,
        batch: list[dict[str, Any]],
        *,
        run_id: str,
    ) -> Any:
        if not self.budget.consume_attempt():
            raise InvestigationIncompleteError(
                "investigator candidate-batch attempt budget exhausted"
            )
        self.attempts += 1
        return self.request.run(batch, run_id=run_id)

    def run_adaptive(
        self,
        batch: list[dict[str, Any]],
        *,
        run_id: str,
    ) -> None:
        try:
            result = self.run_once(batch, run_id=run_id)
        except InvestigationIncompleteError as exc:
            if len(batch) <= 1 or not _can_recover_by_splitting(exc):
                raise
            self.failed_attempt_metadata.append(
                _failed_attempt_operational_metadata(exc)
            )
            midpoint = len(batch) // 2
            self.run_adaptive(batch[:midpoint], run_id=f"{run_id}-a")
            self.run_adaptive(batch[midpoint:], run_id=f"{run_id}-b")
            return
        self.completed.append(
            _InvestigationBatchResult(
                candidate_ids=_candidate_ids(batch),
                result=result,
            )
        )

    def attach_terminal_metadata(self, exc: InvestigationIncompleteError) -> None:
        _attach_terminal_operational_metadata(
            exc,
            completed=self.completed,
            recoverable_failures=self.failed_attempt_metadata,
            attempt_count=self.attempts,
            attempt_limit=self.budget.attempt_limit,
        )


@dataclass
class _InvestigationAggregation:
    findings: list[Any] = field(default_factory=list)
    metadata_items: list[dict[str, Any]] = field(default_factory=list)
    related_hashes: dict[str, str] = field(default_factory=dict)
    inspected_ranges: dict[str, set[tuple[int, int]]] = field(default_factory=dict)
    visited_files: set[str] = field(default_factory=set)
    source_observed_files: set[str] = field(default_factory=set)
    clean_evidence: list[Any] = field(default_factory=list)
    batch_results: list[dict[str, Any]] = field(default_factory=list)


def process_deep_audit_records(
    *,
    store: AuditStore,
    analyzer: Any,
    model: str,
    provider: str | None = None,
    limit: int | None = None,
    force: bool = False,
    allowed_files: list[str | Path] | None = None,
    run_id: str | None = None,
) -> AuditProcessSummary:
    run_id = run_id or f"process-{uuid4().hex[:12]}"
    allowed = store.processing_scope(allowed_files)
    supports_investigator = _supports_repository_investigation(analyzer)
    holistic_scope = supports_investigator
    stored_exclude_folders, stored_exclude_paths = store.read_scan_excludes()
    investigator_exclude_folders = tuple(
        dict.fromkeys((*DEFAULT_EXCLUDED_FOLDERS, *stored_exclude_folders))
    )
    all_records = store.iter_file_records()
    sensitive_files = {
        record.file for record in all_records if _is_secret_bearing_record(record)
    }
    repository_catalog_digest: str | None = None
    if supports_investigator:
        repository_catalog_digest = current_repository_catalog_digest(
            store,
            records=all_records,
        )
    records = [
        record
        for record in all_records
        if (record.candidates or holistic_scope)
        and record.status != STATUS_DELETED
        and (allowed is None or record.file in allowed)
    ]
    locked_files = 0
    run_error_files = 0
    processed_files = 0
    findings_added = 0

    queue: list[AuditFileRecord] = []
    for record in sorted(records, key=_record_sort_key):
        if not supports_investigator and record.language != PYTHON_LANGUAGE:
            if _is_active_record(record, force=force):
                _mark_unsupported(store, record, run_id=run_id)
            continue

        if _is_secret_bearing_record(record):
            if _is_active_record(record, force=force):
                _mark_secret_skipped(store, record, run_id=run_id)
            continue

        if _should_process_record(
            record,
            force=force,
            model=model,
            provider=provider,
            holistic=holistic_scope,
            repository_catalog_digest=repository_catalog_digest,
        ):
            queue.append(record)

    total_queue = len(queue)
    if limit is not None and limit >= 0:
        queue = queue[:limit]
    limited = len(queue) < total_queue

    for queued in queue:
        lease_id = store.acquire_lease(
            queued.file,
            run_id=run_id,
            allow_inactive=queued.status
            in {
                STATUS_ANALYZED,
                STATUS_NOT_ANALYZED,
            },
        )
        if lease_id is None:
            locked_files += 1
            continue

        record = store.read_file_record(queued.file)
        if record is None or record.lock_lease_id != lease_id:
            locked_files += 1
            continue

        file_path = store.project_root / record.file
        try:
            source = _read_current_record_source(store, record)
            result = _analyze_file_with_redaction(
                analyzer,
                file_path,
                store=store,
                record=record,
                source=source,
                run_id=f"{run_id}-{sha256_text(record.file)[:8]}",
                sensitive_files=sensitive_files,
                exclude_folders=investigator_exclude_folders,
                excluded_paths=set(stored_exclude_paths),
                repository_catalog_digest=repository_catalog_digest,
            )
            if hasattr(result, "status") and result.status != "complete":
                raise InvestigationIncompleteError(
                    f"Investigator ended with status {result.status}"
                )
            findings = _normalize_findings(
                result,
                record=record,
                file_path=file_path,
                source=source,
            )
        except Exception as exc:
            failure_metadata = getattr(exc, "investigation_metadata", None)
            operational_metadata = (
                failure_metadata
                if isinstance(failure_metadata, dict)
                and failure_metadata.get("metadata_scope") == "operational_only"
                else None
            )
            failure_context: dict[str, Any] = {}
            if operational_metadata is not None:
                failure_context = {
                    "model": model,
                    "provider": provider,
                    "operational_metadata": operational_metadata,
                }
            if store.mark_error(
                record.file,
                f"Agent processing failed: {exc}",
                run_id=run_id,
                lease_id=lease_id,
                **failure_context,
            ):
                run_error_files += 1
            else:
                # A newer worker reclaimed the file. Its state is
                # authoritative, so this late worker must not overwrite it.
                locked_files += 1
            continue

        existing_ids = {
            str(item.get("audit_finding_id")): item
            for item in record.findings
            if isinstance(item, dict) and item.get("audit_finding_id")
        }
        new_finding_ids: list[str] = []
        record_findings_added = 0
        for finding in findings:
            finding_id = str(finding.get("audit_finding_id"))
            previous = existing_ids.get(finding_id)
            if previous is None:
                finding["audit_produced_by_run_id"] = run_id
                finding["audit_source_hash"] = record.file_hash
                record_findings_added += 1
                new_finding_ids.append(finding_id)
                continue

            # Discovery provenance is immutable. Re-investigation may refresh
            # the current finding text, but it must not make an old finding
            # look newly introduced by this run or erase the source snapshot
            # against which it was originally established.
            produced_by = previous.get("audit_produced_by_run_id")
            if produced_by:
                finding["audit_produced_by_run_id"] = produced_by
            source_hash = previous.get("audit_source_hash")
            if source_hash:
                finding["audit_source_hash"] = source_hash

        record.status = STATUS_ANALYZED
        record.locked_by_run_id = None
        record.lock_lease_id = None
        record.locked_at = None
        record.last_analyzed_at = utc_now()
        record.findings = sanitize_for_audit(findings)
        investigation_metadata = getattr(result, "metadata", None)
        history_entry = {
            "stage": "agent_process",
            "run_id": run_id,
            "model": model,
            "provider": provider,
            "analysis_version": DEEP_AUDIT_ANALYSIS_VERSION,
            "findings_count": len(findings),
            "finding_ids": [
                str(item.get("audit_finding_id"))
                for item in findings
                if item.get("audit_finding_id")
            ],
            "new_finding_ids": list(new_finding_ids),
            # Keep each analysis wave auditable even though record.findings is
            # the current materialized view and a later clean run may replace
            # it with an empty list.
            "finding_snapshot": sanitize_for_audit(findings),
            "candidate_count": len(record.candidates),
            "replaced_findings_count": len(existing_ids),
            "at": utc_now(),
        }
        if isinstance(investigation_metadata, dict):
            history_entry["investigation"] = investigation_metadata
            for key in (
                "protocol_version",
                "definition_hash",
                "tool_schema_version",
                "related_files",
                "catalog_digest",
            ):
                if key in investigation_metadata:
                    history_entry[key] = investigation_metadata[key]
        record.analysis_history.append(sanitize_for_audit(history_entry))
        if not store.commit_claimed_record(
            record,
            run_id=run_id,
            lease_id=lease_id,
        ):
            # The claim expired or was reclaimed while the model was
            # running. Drop this stale result rather than clobbering the
            # current owner's record.
            locked_files += 1
            continue
        findings_added += record_findings_added
        processed_files += 1

    state_counts = _audit_state_counts(
        store,
        model=model,
        provider=provider,
        allowed_files=allowed,
        repository_catalog_digest=repository_catalog_digest,
    )
    remaining = state_counts["unresolved"]
    summary = AuditProcessSummary(
        run_id=run_id,
        project_id=store.project_id,
        project_root=str(store.project_root),
        considered_files=len(records),
        processed_files=processed_files,
        findings_added=findings_added,
        skipped_secret_files=state_counts[STATUS_SKIPPED],
        unsupported_files=state_counts[STATUS_NOT_ANALYZED],
        locked_files=locked_files,
        error_files=state_counts[STATUS_ERROR],
        remaining_pending_files=remaining,
        limited=limited,
        complete=(
            remaining == 0
            and not limited
            and locked_files == 0
            and run_error_files == 0
        ),
        pending_files=state_counts[STATUS_PENDING],
        processing_files=state_counts[STATUS_PROCESSING],
        analyzed_files=(state_counts[STATUS_ANALYZED] - state_counts["stale_analyzed"]),
        stale_analyzed_files=state_counts["stale_analyzed"],
    )
    store.write_run(
        run_id,
        {
            "mode": "process",
            "summary": summary.to_dict(),
        },
    )
    return summary


def _record_sort_key(record: AuditFileRecord) -> tuple[int, int, str]:
    return (
        -max(
            (
                SIGNAL_QUALITY_RANK.get(candidate.signal_quality, 0)
                for candidate in record.candidates
            ),
            default=0,
        ),
        -max((candidate.priority for candidate in record.candidates), default=0),
        record.file,
    )


def current_repository_catalog_digest(
    store: AuditStore,
    *,
    records: list[AuditFileRecord] | None = None,
) -> str:
    """Build the repository catalog identity used by investigator freshness."""

    stored_folders, stored_paths = store.read_scan_excludes()
    exclude_folders = tuple(dict.fromkeys((*DEFAULT_EXCLUDED_FOLDERS, *stored_folders)))
    current_records = records if records is not None else store.iter_file_records()
    sensitive_files = {
        record.file for record in current_records if _is_secret_bearing_record(record)
    }
    catalog_probe = AuditReadOnlyTools(
        store.project_root,
        exclude_folders=exclude_folders,
        denied_paths=sensitive_files,
        excluded_paths=stored_paths,
    )
    return str(catalog_probe.metadata()["catalog_digest"])


def _supports_repository_investigation(analyzer: Any) -> bool:
    get_agent = getattr(analyzer, "_get_agent", None)
    if not callable(get_agent):
        return False
    try:
        agent = get_agent(SECURITY_AUDIT_ISSUE)
    except Exception:
        return False
    return callable(getattr(agent, "investigate", None))


def _read_current_record_source(
    store: AuditStore,
    record: AuditFileRecord,
) -> str:
    source = read_project_text_no_symlink(
        store.project_root,
        record.file,
        max_bytes=MAX_AUDIT_SOURCE_BYTES,
        encoding="utf-8",
        errors=None,
        newline="",
    )
    if source is None:
        raise InvestigationIncompleteError(
            f"source file could not be read safely: {record.file}"
        )
    if sha256_text(source) != record.file_hash:
        raise InvestigationIncompleteError(
            f"source changed after candidate discovery: {record.file}"
        )
    return source


def _related_context_is_current(
    record: AuditFileRecord,
    related_files: list[Any],
) -> bool:
    root = Path(record.project_root)
    for item in related_files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            return False
        path = item.get("path")
        expected_hash = item.get("sha256")
        if not isinstance(path, str) or not isinstance(expected_hash, str):
            return False
        source = read_project_text_no_symlink(
            root,
            path,
            max_bytes=MAX_AUDIT_SOURCE_BYTES,
            encoding="utf-8",
            errors=None,
            newline="",
        )
        if source is None or sha256_text(source) != expected_hash:
            return False
    return True


def _normalized_allowed_files(
    store: AuditStore,
    allowed_files: list[str | Path] | set[str] | None,
) -> set[str] | None:
    if isinstance(allowed_files, set):
        return set(allowed_files)
    if allowed_files is None:
        return None
    allowed: set[str] = set()
    for file_path in allowed_files:
        try:
            allowed.add(normalize_relative_path(store.project_root, file_path))
        except ValueError:
            continue
    return allowed


def _is_active_record(record: AuditFileRecord, *, force: bool) -> bool:
    if force:
        return record.status in {
            STATUS_PENDING,
            STATUS_PROCESSING,
            STATUS_ANALYZED,
            STATUS_ERROR,
            STATUS_NOT_ANALYZED,
            STATUS_SKIPPED,
        }
    return record.status in {STATUS_PENDING, STATUS_PROCESSING, STATUS_ERROR}


def _should_process_record(
    record: AuditFileRecord,
    *,
    force: bool,
    model: str,
    provider: str | None,
    holistic: bool = False,
    repository_catalog_digest: str | None = None,
) -> bool:
    if record.status == STATUS_ANALYZED:
        if force:
            return True
        return not agent_context_is_current(
            record,
            model=model,
            provider=provider,
            repository_catalog_digest=repository_catalog_digest,
        )
    if holistic and record.status == STATUS_NOT_ANALYZED:
        return True
    return record.status in {STATUS_PENDING, STATUS_PROCESSING, STATUS_ERROR}


def agent_context_is_current(
    record: AuditFileRecord,
    *,
    model: str,
    provider: str | None,
    repository_catalog_digest: str | None = None,
) -> bool:
    item = _latest_agent_process_entry(record)
    if item is None:
        return False
    if item.get("model") != model or item.get("provider") != provider:
        return False
    if item.get("analysis_version") != DEEP_AUDIT_ANALYSIS_VERSION:
        return False
    context, has_investigator_context = _merged_investigation_context(item)
    if not _investigator_provenance_is_current(
        context,
        required=has_investigator_context,
    ):
        return False
    return _repository_context_is_current(
        record,
        context,
        repository_catalog_digest=repository_catalog_digest,
    )


def _latest_agent_process_entry(record: AuditFileRecord) -> dict[str, Any] | None:
    for item in reversed(record.analysis_history):
        if isinstance(item, dict) and item.get("stage") == "agent_process":
            return item
    return None


def _merged_investigation_context(
    item: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    investigation = item.get("investigation")
    nested = investigation if isinstance(investigation, dict) else {}
    keys = (
        "protocol_version",
        "definition_hash",
        "tool_schema_version",
        "catalog_digest",
        "related_files",
    )
    context = {
        key: item[key] if key in item else nested.get(key)
        for key in keys
    }
    return context, bool(nested) or any(value is not None for value in context.values())


def _investigator_provenance_is_current(
    context: dict[str, Any],
    *,
    required: bool,
) -> bool:
    if not required:
        return True
    return (
        context.get("protocol_version") == INVESTIGATOR_PROTOCOL_VERSION
        and context.get("definition_hash") == INVESTIGATOR_DEFINITION_HASH
        and context.get("tool_schema_version") == INVESTIGATOR_TOOL_SCHEMA_VERSION
    )


def _repository_context_is_current(
    record: AuditFileRecord,
    context: dict[str, Any],
    *,
    repository_catalog_digest: str | None,
) -> bool:
    related_files = context.get("related_files")
    if repository_catalog_digest is not None:
        if context.get("catalog_digest") != repository_catalog_digest:
            return False
        if not isinstance(related_files, list):
            return False
    return not isinstance(related_files, list) or _related_context_is_current(
        record,
        related_files,
    )


def _is_unresolved_record(
    record: AuditFileRecord,
    *,
    model: str,
    provider: str | None,
    repository_catalog_digest: str | None = None,
    holistic: bool = False,
) -> bool:
    if not holistic and not record.candidates:
        return False
    if record.status in {
        STATUS_PENDING,
        STATUS_PROCESSING,
        STATUS_ERROR,
        STATUS_NOT_ANALYZED,
        STATUS_SKIPPED,
    }:
        return True
    if record.status == STATUS_ANALYZED:
        return not agent_context_is_current(
            record,
            model=model,
            provider=provider,
            repository_catalog_digest=repository_catalog_digest,
        )
    return False


def _has_secret_candidate(record: AuditFileRecord) -> bool:
    return any(
        candidate.redacted or candidate.rule_id.startswith("SKY-S")
        for candidate in record.candidates
    )


def _is_secret_bearing_record(record: AuditFileRecord) -> bool:
    name = Path(record.file).name.lower()
    return (
        record.language == "env"
        or name == ".env"
        or name.startswith(".env.")
        or _has_secret_candidate(record)
    )


def _mark_unsupported(
    store: AuditStore, record: AuditFileRecord, *, run_id: str
) -> None:
    current = store.read_file_record(record.file)
    if current is None:
        return
    current.status = STATUS_NOT_ANALYZED
    current.locked_by_run_id = None
    current.lock_lease_id = None
    current.locked_at = None
    if not _has_unsupported_language_history(current):
        current.analysis_history.append(
            sanitize_for_audit(
                {
                    "stage": "unsupported_agent_language",
                    "run_id": run_id,
                    "language": current.language,
                    "reason": (
                        "Deep Mode agent processing currently supports "
                        "Python files only."
                    ),
                    "at": utc_now(),
                }
            )
        )
    store.write_file_record(current)


def _has_unsupported_language_history(record: AuditFileRecord) -> bool:
    return any(
        isinstance(item, dict)
        and item.get("stage") == "unsupported_agent_language"
        and item.get("language") == record.language
        for item in record.analysis_history
    )


def _mark_secret_skipped(
    store: AuditStore, record: AuditFileRecord, *, run_id: str
) -> None:
    current = store.read_file_record(record.file)
    if current is None:
        return
    current.status = STATUS_SKIPPED
    current.locked_by_run_id = None
    current.lock_lease_id = None
    current.locked_at = None
    current.analysis_history.append(
        sanitize_for_audit(
            {
                "stage": "secret_context_skipped",
                "run_id": run_id,
                "reason": (
                    "Secret-bearing files are not sent to LLM processing in this phase."
                ),
                "at": utc_now(),
            }
        )
    )
    store.write_file_record(current)


def _normalize_findings(
    findings: Any,
    *,
    record: AuditFileRecord,
    file_path: Path,
    source: str | None = None,
) -> list[dict[str, Any]]:
    if hasattr(findings, "findings"):
        findings = findings.findings
    normalized = []
    seen_finding_ids: set[str] = set()
    source = source or ""

    for finding in findings or []:
        if hasattr(finding, "to_dict"):
            payload = finding.to_dict()
        elif isinstance(finding, dict):
            payload = dict(finding)
        else:
            continue
        payload = sanitize_for_audit(payload)
        # These fields are store-owned provenance, never model output. Strip
        # them before deriving identity so an analyzer cannot forge run or
        # source attribution.
        for key in (
            "audit_finding_id",
            "audit_produced_by_run_id",
            "audit_source_hash",
        ):
            payload.pop(key, None)
        _attach_candidate_threat_trace(payload, record=record)
        finding_id = _finding_id(payload, record=record, source=source)
        if finding_id in seen_finding_ids:
            continue
        seen_finding_ids.add(finding_id)
        payload["audit_finding_id"] = finding_id
        normalized.append(payload)
    return normalized


def _analyze_file_with_redaction(
    analyzer: Any,
    file_path: Path,
    *,
    store: AuditStore,
    record: AuditFileRecord,
    source: str,
    run_id: str,
    sensitive_files: set[str],
    exclude_folders: tuple[str, ...],
    excluded_paths: set[str],
    repository_catalog_digest: str | None,
) -> Any:
    redacted_source = redact_text(source)

    get_agent = getattr(analyzer, "_get_agent", None)
    if callable(get_agent):
        agent = get_agent(SECURITY_AUDIT_ISSUE)
        context = _build_redacted_context(
            analyzer,
            redacted_source,
            file_path,
            record=record,
        )
        context = redact_text(context) if context else None
        investigate = getattr(agent, "investigate", None)
        if callable(investigate):
            return _investigate_candidate_batches(
                agent=agent,
                investigate=investigate,
                redacted_source=redacted_source,
                context=context,
                store=store,
                record=record,
                run_id=run_id,
                sensitive_files=sensitive_files,
                exclude_folders=exclude_folders,
                excluded_paths=excluded_paths,
                repository_catalog_digest=repository_catalog_digest,
            )
        return agent.analyze(redacted_source, str(file_path), context=context)

    whole_file_analyzer = getattr(analyzer, "_analyze_whole_file", None)
    if callable(whole_file_analyzer):
        return whole_file_analyzer(
            redacted_source,
            str(file_path),
            issue_types=[SECURITY_AUDIT_ISSUE],
        )

    if redacted_source != source:
        raise RuntimeError(
            "Deep Mode refused to send unredacted source to an analyzer that does "
            "not support in-memory redacted review"
        )

    return analyzer.analyze_file(
        file_path,
        issue_types=[SECURITY_AUDIT_ISSUE],
    )


def _investigate_candidate_batches(
    redacted_source: str,
    *,
    agent: Any,
    investigate: Any,
    context: str | None,
    store: AuditStore,
    record: AuditFileRecord,
    run_id: str,
    sensitive_files: set[str],
    exclude_folders: tuple[str, ...],
    excluded_paths: set[str],
    repository_catalog_digest: str | None,
) -> Any:
    candidates = [candidate.to_dict() for candidate in record.candidates]
    candidate_limit = _investigator_candidate_limit(agent)
    request = _InvestigationBatchRequest(
        investigate=investigate,
        redacted_source=redacted_source,
        context=context,
        store=store,
        record=record,
        run_id=run_id,
        sensitive_files=sensitive_files,
        exclude_folders=exclude_folders,
        excluded_paths=excluded_paths,
        repository_catalog_digest=repository_catalog_digest,
    )
    state = _AdaptiveInvestigationState(
        request=request,
        budget=_InvestigationAttemptBudget(
            attempt_limit=max(0, MAX_INVESTIGATOR_BATCH_ATTEMPTS)
        ),
    )
    try:
        if not candidates:
            return state.run_once([], run_id=run_id)
        initial_batches = _candidate_batches(candidates, candidate_limit)
        _assert_batch_preflight_budget(state, len(initial_batches))
        _run_initial_candidate_batches(state, initial_batches)
        return _completed_candidate_batch_result(
            state,
            candidate_ids=_candidate_ids(candidates),
            candidate_limit=candidate_limit,
            initial_batch_count=len(initial_batches),
        )
    except InvestigationIncompleteError as exc:
        state.attach_terminal_metadata(exc)
        raise


def _candidate_batches(
    candidates: list[dict[str, Any]],
    candidate_limit: int,
) -> list[list[dict[str, Any]]]:
    return [
        candidates[start : start + candidate_limit]
        for start in range(0, len(candidates), candidate_limit)
    ]


def _assert_batch_preflight_budget(
    state: _AdaptiveInvestigationState,
    initial_batch_count: int,
) -> None:
    if initial_batch_count > state.budget.attempts_remaining:
        raise InvestigationIncompleteError(
            "investigator candidate-batch attempt budget exhausted during preflight"
        )


def _run_initial_candidate_batches(
    state: _AdaptiveInvestigationState,
    batches: list[list[dict[str, Any]]],
) -> None:
    multiple_batches = len(batches) > 1
    for index, batch in enumerate(batches, start=1):
        run_id = (
            f"{state.request.run_id}-b{index:03d}"
            if multiple_batches
            else state.request.run_id
        )
        state.run_adaptive(batch, run_id=run_id)


def _completed_candidate_batch_result(
    state: _AdaptiveInvestigationState,
    *,
    candidate_ids: tuple[str, ...],
    candidate_limit: int,
    initial_batch_count: int,
) -> Any:
    if len(state.completed) == 1:
        return state.completed[0].result
    return _aggregate_investigation_batches(
        state.completed,
        run_id=state.request.run_id,
        candidate_limit=candidate_limit,
        candidate_ids=candidate_ids,
        initial_batch_count=initial_batch_count,
        attempt_count=state.attempts,
        attempt_limit=state.budget.attempt_limit,
        failed_attempt_metadata=state.failed_attempt_metadata,
        repository_catalog_digest=state.request.repository_catalog_digest,
    )


def _run_investigation_batch(
    *,
    investigate: Any,
    redacted_source: str,
    context: str | None,
    candidates: list[dict[str, Any]],
    store: AuditStore,
    record: AuditFileRecord,
    run_id: str,
    sensitive_files: set[str],
    exclude_folders: tuple[str, ...],
    excluded_paths: set[str],
    repository_catalog_digest: str | None,
) -> Any:
    # Tool state and budgets are scoped to one model invocation. Reusing this
    # object across chunks would make later chunks inherit evidence and budget
    # consumption from earlier, unrelated candidate decisions.
    tools = AuditReadOnlyTools(
        store.project_root,
        exclude_folders=exclude_folders,
        denied_paths=sensitive_files,
        excluded_paths=excluded_paths,
    )
    authoritative_metadata = tools.metadata()
    if (
        repository_catalog_digest is not None
        and authoritative_metadata["catalog_digest"] != repository_catalog_digest
    ):
        raise InvestigationIncompleteError(
            "repository changed before investigation started"
        )
    tools.register_initial_file(record.file)
    if tools.related_file_hashes.get(record.file) != record.file_hash:
        raise InvestigationIncompleteError(
            f"source changed before investigation started: {record.file}"
        )
    try:
        result = investigate(
            redacted_source,
            record.file,
            context=context,
            candidates=candidates,
            tools=tools,
            run_id=run_id,
        )
    except InvestigationIncompleteError as exc:
        _merge_failed_attempt_tool_metadata(exc, tools)
        raise
    if getattr(result, "status", None) != "complete":
        exc = InvestigationIncompleteError(
            f"Investigator ended with status {getattr(result, 'status', None)}"
        )
        result_metadata = getattr(result, "metadata", None)
        if isinstance(result_metadata, dict):
            exc.investigation_metadata = dict(result_metadata)
        _merge_failed_attempt_tool_metadata(exc, tools)
        raise exc
    try:
        _assert_exact_candidate_coverage(result, candidates)
        _assert_current_investigator_provenance(result)
    except InvestigationIncompleteError as exc:
        result_metadata = getattr(result, "metadata", None)
        if isinstance(result_metadata, dict):
            exc.investigation_metadata = dict(result_metadata)
        _merge_failed_attempt_tool_metadata(exc, tools)
        raise
    try:
        tools.assert_completion_safe()
    except AuditToolError as tool_exc:
        exc = InvestigationIncompleteError(
            "investigator catalog completion safety check failed"
        )
        result_metadata = getattr(result, "metadata", None)
        if isinstance(result_metadata, dict):
            exc.investigation_metadata = dict(result_metadata)
        _merge_failed_attempt_tool_metadata(exc, tools)
        raise exc from tool_exc
    authoritative_metadata = tools.metadata()
    result_metadata = getattr(result, "metadata", None)
    if isinstance(result_metadata, dict):
        result_metadata.update(authoritative_metadata)
    else:
        try:
            result.metadata = authoritative_metadata
        except (AttributeError, TypeError):
            pass
    return result


def _investigator_candidate_limit(agent: Any) -> int:
    limits = getattr(agent, "limits", None)
    configured = getattr(limits, "max_candidates", None)
    if (
        isinstance(configured, int)
        and not isinstance(configured, bool)
        and configured > 0
    ):
        return min(configured, MAX_INVESTIGATOR_CANDIDATES)
    return min(
        DEFAULT_INVESTIGATOR_CANDIDATE_BATCH_SIZE,
        MAX_INVESTIGATOR_CANDIDATES,
    )


def _candidate_ids(candidates: list[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(str(candidate.get("candidate_id")) for candidate in candidates)


def _assert_exact_candidate_coverage(
    result: Any,
    candidates: list[dict[str, Any]],
) -> None:
    metadata = getattr(result, "metadata", None)
    covered = (
        metadata.get("covered_candidate_ids") if isinstance(metadata, dict) else None
    )
    expected = _candidate_ids(candidates)
    if not isinstance(covered, list) or any(
        not isinstance(item, str) for item in covered
    ):
        raise InvestigationIncompleteError(
            "investigator did not report exact candidate coverage"
        )
    if len(covered) != len(set(covered)) or set(covered) != set(expected):
        raise InvestigationIncompleteError(
            "investigator did not report exact candidate coverage"
        )


def _assert_current_investigator_provenance(result: Any) -> None:
    metadata = getattr(result, "metadata", None)
    expected = {
        "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
        "definition_hash": INVESTIGATOR_DEFINITION_HASH,
        "tool_schema_version": INVESTIGATOR_TOOL_SCHEMA_VERSION,
    }
    if not isinstance(metadata, dict) or any(
        metadata.get(key) != value for key, value in expected.items()
    ):
        raise InvestigationIncompleteError(
            "investigator provenance did not match the current protocol definition"
        )


def _can_recover_by_splitting(exc: InvestigationIncompleteError) -> bool:
    message = str(exc).lower()
    integrity_markers = (
        "adapter",
        "candidate coverage",
        "catalog",
        "denied",
        "exact candidate",
        "evidence",
        "malformed",
        "provenance",
        "repository changed",
        "source changed",
        "sensitive",
        "tool request failed",
        "unknown tool",
    )
    return not any(marker in message for marker in integrity_markers)


def _merge_failed_attempt_tool_metadata(
    exc: InvestigationIncompleteError,
    tools: AuditReadOnlyTools,
) -> None:
    metadata = getattr(exc, "investigation_metadata", None)
    merged = dict(metadata) if isinstance(metadata, dict) else {}
    # Tool counters come from the local read-only session, not exception text or
    # model output. Evidence fields are retained on the exception for diagnosis
    # but are deliberately not included in successful child aggregation.
    merged.update(tools.metadata())
    exc.investigation_metadata = merged


def _failed_attempt_operational_metadata(
    exc: InvestigationIncompleteError,
) -> dict[str, Any]:
    metadata = getattr(exc, "investigation_metadata", None)
    if not isinstance(metadata, dict):
        return {}
    operational = {
        key: _integer_metadata(metadata, key)
        for key in INVESTIGATOR_OPERATIONAL_COUNTER_KEYS
    }
    operational["usage"] = _usage_metadata(metadata)
    return operational


def _attach_terminal_operational_metadata(
    exc: InvestigationIncompleteError,
    *,
    completed: list[_InvestigationBatchResult],
    recoverable_failures: list[dict[str, Any]],
    attempt_count: int,
    attempt_limit: int,
) -> None:
    completed_metadata = [
        metadata
        for batch in completed
        if isinstance((metadata := getattr(batch.result, "metadata", None)), dict)
    ]
    terminal_metadata = _failed_attempt_operational_metadata(exc)
    operational_items = [
        *completed_metadata,
        *recoverable_failures,
        terminal_metadata,
    ]
    summary: dict[str, Any] = {
        "metadata_scope": "operational_only",
        "attempt_count": attempt_count,
        "attempt_limit": attempt_limit,
        "completed_attempt_count": len(completed),
        "failed_attempt_count": max(0, attempt_count - len(completed)),
        "recoverable_failed_attempt_count": len(recoverable_failures),
        "attempt_budget_exhausted": ("attempt budget exhausted" in str(exc).lower()),
        "usage": _sum_usage(operational_items),
    }
    for key in INVESTIGATOR_OPERATIONAL_COUNTER_KEYS:
        summary[key] = _sum_integer_metadata(operational_items, key)
    exc.investigation_metadata = sanitize_for_audit(summary)


def _aggregate_investigation_batches(
    completed: list[_InvestigationBatchResult],
    *,
    run_id: str,
    candidate_limit: int,
    candidate_ids: tuple[str, ...],
    initial_batch_count: int,
    attempt_count: int,
    attempt_limit: int,
    failed_attempt_metadata: list[dict[str, Any]],
    repository_catalog_digest: str | None,
) -> _AggregatedInvestigationResult:
    aggregate = _collect_investigation_batches(
        completed,
        repository_catalog_digest=repository_catalog_digest,
    )
    operational_items = [
        *aggregate.metadata_items,
        *failed_attempt_metadata,
    ]
    metadata = _build_aggregate_metadata(
        aggregate,
        operational_items=operational_items,
        run_id=run_id,
        candidate_ids=candidate_ids,
        candidate_limit=candidate_limit,
        initial_batch_count=initial_batch_count,
        attempt_count=attempt_count,
        attempt_limit=attempt_limit,
        repository_catalog_digest=repository_catalog_digest,
    )
    reviewer_guidance = _aggregate_reviewer_guidance(aggregate.metadata_items)
    if reviewer_guidance is not None:
        metadata["reviewer_guidance"] = reviewer_guidance
    return _AggregatedInvestigationResult(
        findings=aggregate.findings,
        status="complete",
        metadata=sanitize_for_audit(metadata),
    )


def _collect_investigation_batches(
    completed: list[_InvestigationBatchResult],
    *,
    repository_catalog_digest: str | None,
) -> _InvestigationAggregation:
    aggregate = _InvestigationAggregation()
    for batch in completed:
        _collect_investigation_batch(
            aggregate,
            batch,
            repository_catalog_digest=repository_catalog_digest,
        )
    return aggregate


def _collect_investigation_batch(
    aggregate: _InvestigationAggregation,
    batch: _InvestigationBatchResult,
    *,
    repository_catalog_digest: str | None,
) -> None:
    result_findings = list(getattr(batch.result, "findings", None) or [])
    metadata = _required_batch_metadata(batch.result)
    _assert_batch_catalog_current(
        metadata,
        repository_catalog_digest=repository_catalog_digest,
    )
    aggregate.findings.extend(result_findings)
    aggregate.metadata_items.append(metadata)
    aggregate.batch_results.append(
        {
            "candidate_ids": list(batch.candidate_ids),
            "findings_count": len(result_findings),
            "finish_reasoning_sha256": metadata.get("finish_reasoning_sha256"),
        }
    )
    _merge_related_file_hashes(aggregate.related_hashes, metadata)
    _merge_inspected_ranges(aggregate.inspected_ranges, metadata)
    aggregate.visited_files.update(_string_metadata_values(metadata, "visited_files"))
    aggregate.source_observed_files.update(
        _string_metadata_values(metadata, "source_observed_files")
    )
    clean_evidence = metadata.get("clean_evidence")
    if isinstance(clean_evidence, list):
        aggregate.clean_evidence.extend(clean_evidence)


def _required_batch_metadata(result: Any) -> dict[str, Any]:
    metadata = getattr(result, "metadata", None)
    if not isinstance(metadata, dict):
        raise InvestigationIncompleteError(
            "completed investigator batch omitted metadata"
        )
    return metadata


def _assert_batch_catalog_current(
    metadata: dict[str, Any],
    *,
    repository_catalog_digest: str | None,
) -> None:
    if (
        repository_catalog_digest is not None
        and metadata.get("catalog_digest") != repository_catalog_digest
    ):
        raise InvestigationIncompleteError(
            "repository changed between candidate batches"
        )


def _merge_related_file_hashes(
    related_hashes: dict[str, str],
    metadata: dict[str, Any],
) -> None:
    for item in metadata.get("related_files", []):
        path, file_hash = _related_file_identity(item)
        previous_hash = related_hashes.setdefault(path, file_hash)
        if previous_hash != file_hash:
            raise InvestigationIncompleteError(
                "repository evidence changed between candidate batches"
            )


def _related_file_identity(item: Any) -> tuple[str, str]:
    if not isinstance(item, dict):
        raise InvestigationIncompleteError(
            "investigator batch returned invalid related-file metadata"
        )
    path = item.get("path")
    file_hash = item.get("sha256")
    if not isinstance(path, str) or not isinstance(file_hash, str):
        raise InvestigationIncompleteError(
            "investigator batch returned invalid related-file metadata"
        )
    return path, file_hash


def _merge_inspected_ranges(
    inspected_ranges: dict[str, set[tuple[int, int]]],
    metadata: dict[str, Any],
) -> None:
    ranges_by_path = metadata.get("inspected_ranges") or {}
    if not isinstance(ranges_by_path, dict):
        return
    for path, ranges in ranges_by_path.items():
        if not isinstance(path, str) or not isinstance(ranges, list):
            continue
        destination = inspected_ranges.setdefault(path, set())
        destination.update(
            normalized
            for item in ranges
            if (normalized := _normalized_inspected_range(item)) is not None
        )


def _normalized_inspected_range(item: Any) -> tuple[int, int] | None:
    if (
        not isinstance(item, list)
        or len(item) != 2
        or not all(isinstance(value, int) for value in item)
    ):
        return None
    return item[0], item[1]


def _string_metadata_values(metadata: dict[str, Any], key: str) -> set[str]:
    values = metadata.get(key)
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str)}


def _build_aggregate_metadata(
    aggregate: _InvestigationAggregation,
    *,
    operational_items: list[dict[str, Any]],
    run_id: str,
    candidate_ids: tuple[str, ...],
    candidate_limit: int,
    initial_batch_count: int,
    attempt_count: int,
    attempt_limit: int,
    repository_catalog_digest: str | None,
) -> dict[str, Any]:
    metadata = _aggregate_execution_metadata(
        aggregate,
        operational_items=operational_items,
        run_id=run_id,
        candidate_ids=candidate_ids,
    )
    metadata.update(
        _aggregate_repository_metadata(
            aggregate,
            operational_items=operational_items,
            repository_catalog_digest=repository_catalog_digest,
        )
    )
    metadata["candidate_batching"] = {
        "strategy": "deterministic_adaptive_v1",
        "candidate_limit": candidate_limit,
        "attempt_limit": attempt_limit,
        "initial_batch_count": initial_batch_count,
        "completed_batch_count": len(aggregate.batch_results),
        "attempt_count": attempt_count,
        "batches": aggregate.batch_results,
    }
    return metadata


def _aggregate_execution_metadata(
    aggregate: _InvestigationAggregation,
    *,
    operational_items: list[dict[str, Any]],
    run_id: str,
    candidate_ids: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
        "definition_hash": INVESTIGATOR_DEFINITION_HASH,
        "tool_schema_version": INVESTIGATOR_TOOL_SCHEMA_VERSION,
        "run_id": run_id,
        "turns": _sum_integer_metadata(operational_items, "turns"),
        "llm_calls": _sum_integer_metadata(operational_items, "llm_calls"),
        "usage": _sum_usage(operational_items),
        "covered_candidate_ids": list(candidate_ids),
        "clean_evidence": aggregate.clean_evidence,
        "tool_calls": _sum_integer_metadata(operational_items, "tool_calls"),
        "source_observation_calls": _sum_integer_metadata(
            operational_items,
            "source_observation_calls",
        ),
        "source_observed_files": sorted(aggregate.source_observed_files),
        "evidence_bytes": _sum_integer_metadata(
            operational_items,
            "evidence_bytes",
        ),
        "visited_files": sorted(aggregate.visited_files),
    }


def _aggregate_repository_metadata(
    aggregate: _InvestigationAggregation,
    *,
    operational_items: list[dict[str, Any]],
    repository_catalog_digest: str | None,
) -> dict[str, Any]:
    metadata_items = aggregate.metadata_items
    return {
        "related_files": [
            {"path": path, "sha256": file_hash}
            for path, file_hash in sorted(aggregate.related_hashes.items())
        ],
        "inspected_ranges": {
            path: [[start, end] for start, end in sorted(ranges)]
            for path, ranges in sorted(aggregate.inspected_ranges.items())
        },
        "catalog_size": _maximum_integer_metadata(metadata_items, "catalog_size"),
        "catalog_truncated": any(
            bool(item.get("catalog_truncated")) for item in metadata_items
        ),
        "catalog_digest": repository_catalog_digest
        or str(metadata_items[0].get("catalog_digest") or ""),
        "excluded_sensitive_files": _maximum_integer_metadata(
            metadata_items,
            "excluded_sensitive_files",
        ),
        "redacted_source_files": _maximum_integer_metadata(
            metadata_items,
            "redacted_source_files",
        ),
        "unsafe_discovery_truncations": _sum_integer_metadata(
            operational_items,
            "unsafe_discovery_truncations",
        ),
        "configured_excluded_paths": _maximum_integer_metadata(
            metadata_items,
            "configured_excluded_paths",
        ),
        "sensitive_denials": _sum_integer_metadata(
            operational_items,
            "sensitive_denials",
        ),
    }


def _maximum_integer_metadata(metadata: list[dict[str, Any]], key: str) -> int:
    return max((_integer_metadata(item, key) for item in metadata), default=0)


def _integer_metadata(metadata: dict[str, Any], key: str) -> int:
    value = metadata.get(key)
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else 0
    )


def _sum_integer_metadata(metadata: list[dict[str, Any]], key: str) -> int:
    return sum(_integer_metadata(item, key) for item in metadata)


def _sum_usage(metadata: list[dict[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for item in metadata:
        for key, value in _usage_metadata(item).items():
            totals[key] = totals.get(key, 0) + value
    return dict(sorted(totals.items()))


def _usage_metadata(metadata: dict[str, Any]) -> dict[str, int]:
    usage = metadata.get("usage")
    if not isinstance(usage, dict):
        return {}
    return {
        key: value
        for key in INVESTIGATOR_USAGE_KEYS
        if isinstance((value := usage.get(key)), int)
        and not isinstance(value, bool)
        and value >= 0
    }


def _aggregate_reviewer_guidance(
    metadata: list[dict[str, Any]],
) -> dict[str, Any] | None:
    guidance_items = _reviewer_guidance_items(metadata)
    if guidance_items is None:
        return None
    registry_version = _single_guidance_provenance(
        guidance_items,
        "registry_version",
    )
    definition_hash = _single_guidance_provenance(
        guidance_items,
        "definition_hash",
    )
    selected_packs = _selected_reviewer_packs(guidance_items)
    return {
        "registry_version": registry_version,
        "definition_hash": definition_hash,
        "selected_packs": [selected_packs[key] for key in sorted(selected_packs)],
        "selection_truncated": any(
            bool(item.get("selection_truncated")) for item in guidance_items
        ),
    }


def _reviewer_guidance_items(
    metadata: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    guidance_items = [
        item["reviewer_guidance"]
        for item in metadata
        if isinstance(item.get("reviewer_guidance"), dict)
    ]
    if not guidance_items:
        return None
    if len(guidance_items) != len(metadata):
        raise InvestigationIncompleteError(
            "reviewer guidance metadata was missing from a candidate batch"
        )
    return guidance_items


def _single_guidance_provenance(
    guidance_items: list[dict[str, Any]],
    key: str,
) -> str:
    values = {
        item.get(key)
        for item in guidance_items
        if isinstance(item.get(key), str)
    }
    if len(values) != 1:
        raise InvestigationIncompleteError(
            "reviewer guidance provenance changed between candidate batches"
        )
    return next(iter(values))


def _selected_reviewer_packs(
    guidance_items: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, str]]:
    selected_packs: dict[tuple[str, str], dict[str, str]] = {}
    for item in guidance_items:
        packs = item.get("selected_packs")
        if not isinstance(packs, list):
            raise InvestigationIncompleteError(
                "investigator batch returned invalid reviewer guidance metadata"
            )
        for pack in packs:
            pack_id, version = _reviewer_pack_identity(pack)
            selected_packs[(pack_id, version)] = {
                "id": pack_id,
                "version": version,
            }
    return selected_packs


def _reviewer_pack_identity(pack: Any) -> tuple[str, str]:
    if not isinstance(pack, dict):
        raise InvestigationIncompleteError(
            "investigator batch returned invalid reviewer guidance metadata"
        )
    pack_id = pack.get("id")
    version = pack.get("version")
    if not isinstance(pack_id, str) or not isinstance(version, str):
        raise InvestigationIncompleteError(
            "investigator batch returned invalid reviewer guidance metadata"
        )
    return pack_id, version


def _build_redacted_context(
    analyzer: Any, source: str, file_path: Path, *, record: AuditFileRecord
) -> str | None:
    candidate_context = _candidate_context(record)
    context_builder = getattr(analyzer, "context_builder", None)
    if context_builder is None:
        return candidate_context

    config = getattr(analyzer, "config", None)
    repo_context_map = getattr(config, "repo_context_map", {}) or {}
    repo_metadata = (
        repo_context_map.get(str(file_path))
        or repo_context_map.get(file_path.as_posix())
        or repo_context_map.get(file_path.name)
    )
    if candidate_context:
        repo_metadata = (
            f"{repo_metadata}\n{candidate_context}"
            if repo_metadata
            else candidate_context
        )

    try:
        return context_builder.build_analysis_context(
            source,
            file_path=str(file_path),
            defs_map=None,
            include_review_hints=False,
            repo_metadata=repo_metadata,
        )
    except TypeError:
        return context_builder.build_analysis_context(
            source,
            file_path=str(file_path),
            defs_map=None,
            include_review_hints=False,
        )


def _candidate_context(record: AuditFileRecord) -> str | None:
    if not record.candidates:
        return None
    lines = ["[DEEP AUDIT CANDIDATES]"]
    for candidate in sorted(
        record.candidates,
        key=lambda item: (-item.priority, item.line, item.candidate_id),
    )[:8]:
        lines.append(
            f"- {candidate.kind} {candidate.rule_id} L{candidate.line}: "
            f"{candidate.reason}"
        )
        trace = _candidate_threat_trace(candidate)
        if trace is not None:
            source = (
                trace.get("source") if isinstance(trace.get("source"), dict) else {}
            )
            sink = trace.get("sink") if isinstance(trace.get("sink"), dict) else {}
            lines.append(
                "  threat trace: "
                f"{source.get('name')}@L{source.get('line')} -> "
                f"{sink.get('name')}@L{sink.get('line')} "
                f"({trace.get('validation')})"
            )
    return "\n".join(lines)


def _candidate_threat_trace(candidate: AuditCandidate) -> dict[str, Any] | None:
    data = candidate.data if isinstance(candidate.data, dict) else {}
    trace = data.get("threat_trace")
    return dict(trace) if isinstance(trace, dict) else None


def _candidate_threat_traces_by_line(
    record: AuditFileRecord,
) -> dict[int, dict[str, Any]]:
    by_line: dict[int, dict[str, Any]] = {}
    for candidate in record.candidates:
        trace = _candidate_threat_trace(candidate)
        if trace is not None:
            by_line.setdefault(candidate.line, trace)
    return by_line


def _attach_candidate_threat_trace(
    finding: dict[str, Any], *, record: AuditFileRecord
) -> None:
    location = (
        finding.get("location") if isinstance(finding.get("location"), dict) else {}
    )
    try:
        line = int(finding.get("line") or location.get("line") or 0)
    except (TypeError, ValueError):
        return
    trace = _candidate_threat_traces_by_line(record).get(line)
    if trace is None:
        return
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    metadata.setdefault("threat_trace", trace)
    finding["metadata"] = metadata


def _finding_id(
    finding: dict[str, Any],
    *,
    record: AuditFileRecord,
    source: str,
) -> str:
    location = (
        finding.get("location") if isinstance(finding.get("location"), dict) else {}
    )
    line = int(finding.get("line") or location.get("line") or 1)
    end_line = int(finding.get("end_line") or location.get("end_line") or line)
    metadata = finding.get("metadata")
    evidence = None
    if isinstance(metadata, dict):
        evidence = metadata.get("investigation_evidence") or metadata.get(
            "logic_evidence"
        )
    evidence_identity = ""
    if isinstance(evidence, dict):
        evidence_identity = sha256_text(
            "|".join(
                str(evidence.get(key) or "")
                for key in (
                    "category",
                    "actor",
                    "action",
                    "resource",
                    "trigger",
                    "invariant",
                    "actual_behavior",
                    "impact",
                )
            )
        )[:20]
    payload = {
        "path": normalize_relative_path(record.project_root, record.file),
        "rule_id": finding.get("rule_id"),
        "issue_type": finding.get("issue_type"),
        "symbol": finding.get("symbol"),
        "code_hash": code_region_hash(source, line),
        "end_line": end_line,
        "evidence_identity": evidence_identity,
    }
    return "finding-" + sha256_text(str(sorted(payload.items())))[:16]


def _audit_state_counts(
    store: AuditStore,
    *,
    model: str,
    provider: str | None,
    allowed_files: list[str | Path] | set[str] | None = None,
    repository_catalog_digest: str | None = None,
) -> dict[str, int]:
    allowed = _normalized_allowed_files(store, allowed_files)
    counts = {
        STATUS_PENDING: 0,
        STATUS_PROCESSING: 0,
        STATUS_ERROR: 0,
        STATUS_NOT_ANALYZED: 0,
        STATUS_SKIPPED: 0,
        STATUS_ANALYZED: 0,
        "stale_analyzed": 0,
        "unresolved": 0,
    }
    for record in store.iter_file_records():
        if allowed is not None and record.file not in allowed:
            continue
        if record.status == STATUS_DELETED:
            continue
        holistic = repository_catalog_digest is not None
        if not record.candidates and not holistic:
            continue
        if record.status in counts:
            counts[record.status] += 1
        if record.status == STATUS_ANALYZED and not agent_context_is_current(
            record,
            model=model,
            provider=provider,
            repository_catalog_digest=repository_catalog_digest,
        ):
            counts["stale_analyzed"] += 1
        if _is_unresolved_record(
            record,
            model=model,
            provider=provider,
            repository_catalog_digest=repository_catalog_digest,
            holistic=holistic,
        ):
            counts["unresolved"] += 1
    return counts
