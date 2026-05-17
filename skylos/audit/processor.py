from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from skylos.audit.redaction import redact_text, sanitize_for_audit
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    STATUS_ANALYZED,
    STATUS_DELETED,
    STATUS_ERROR,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_SKIPPED,
    AuditFileRecord,
    AuditProcessSummary,
    code_region_hash,
    normalize_relative_path,
    sha256_text,
    utc_now,
)

SECURITY_AUDIT_ISSUE = "security_audit"
PYTHON_LANGUAGE = "python"


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
    records = [
        record
        for record in store.iter_file_records()
        if record.candidates
        and record.status != STATUS_DELETED
        and (allowed is None or record.file in allowed)
    ]
    locked_files = 0
    run_error_files = 0
    processed_files = 0
    findings_added = 0

    queue: list[AuditFileRecord] = []
    for record in sorted(records, key=_record_sort_key):
        if record.language != PYTHON_LANGUAGE:
            if _is_active_record(record, force=force):
                _mark_unsupported(store, record, run_id=run_id)
            continue

        if _has_secret_candidate(record):
            if _is_active_record(record, force=force):
                _mark_secret_skipped(store, record, run_id=run_id)
            continue

        if _should_process_record(
            record,
            force=force,
            model=model,
            provider=provider,
        ):
            queue.append(record)

    total_queue = len(queue)
    if limit is not None and limit >= 0:
        queue = queue[:limit]
    limited = len(queue) < total_queue

    for queued in queue:
        if queued.status == STATUS_ANALYZED:
            queued.status = STATUS_PENDING
            store.write_file_record(queued)

        if not store.acquire_lock(queued.file, run_id=run_id):
            locked_files += 1
            continue

        record = store.read_file_record(queued.file)
        if record is None:
            locked_files += 1
            continue

        file_path = store.project_root / record.file
        try:
            result = _analyze_file_with_redaction(analyzer, file_path)
            findings = _normalize_findings(result, record=record, file_path=file_path)
        except Exception as exc:
            store.mark_error(record.file, f"Agent processing failed: {exc}")
            run_error_files += 1
            continue

        existing_by_id = {
            str(item.get("audit_finding_id")): item
            for item in record.findings
            if isinstance(item, dict) and item.get("audit_finding_id")
        }
        merged = [
            item
            for item in record.findings
            if not (
                isinstance(item, dict)
                and item.get("audit_finding_id") in existing_by_id
            )
        ]
        for finding in findings:
            finding_id = str(finding.get("audit_finding_id"))
            if finding_id not in existing_by_id:
                findings_added += 1
            existing_by_id[finding_id] = finding
        merged.extend(existing_by_id.values())

        record.status = STATUS_ANALYZED
        record.locked_by_run_id = None
        record.locked_at = None
        record.last_analyzed_at = utc_now()
        record.findings = sanitize_for_audit(merged)
        record.analysis_history.append(
            sanitize_for_audit(
                {
                    "stage": "agent_process",
                    "run_id": run_id,
                    "model": model,
                    "provider": provider,
                    "findings_count": len(findings),
                    "candidate_count": len(record.candidates),
                    "at": utc_now(),
                }
            )
        )
        store.write_file_record(record)
        processed_files += 1

    state_counts = _audit_state_counts(
        store,
        model=model,
        provider=provider,
        allowed_files=allowed,
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


def _record_sort_key(record: AuditFileRecord) -> tuple[int, str]:
    return (
        -max((candidate.priority for candidate in record.candidates), default=0),
        record.file,
    )


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
) -> bool:
    if record.status == STATUS_ANALYZED:
        if force:
            return True
        return not _agent_context_matches(record, model=model, provider=provider)
    return record.status in {STATUS_PENDING, STATUS_PROCESSING, STATUS_ERROR}


def _agent_context_matches(
    record: AuditFileRecord,
    *,
    model: str,
    provider: str | None,
) -> bool:
    for item in reversed(record.analysis_history):
        if not isinstance(item, dict) or item.get("stage") != "agent_process":
            continue
        return item.get("model") == model and item.get("provider") == provider
    return False


def _is_unresolved_record(
    record: AuditFileRecord,
    *,
    model: str,
    provider: str | None,
) -> bool:
    if not record.candidates:
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
        return not _agent_context_matches(record, model=model, provider=provider)
    return False


def _has_secret_candidate(record: AuditFileRecord) -> bool:
    return any(
        candidate.redacted or candidate.rule_id.startswith("SKY-S")
        for candidate in record.candidates
    )


def _mark_unsupported(
    store: AuditStore, record: AuditFileRecord, *, run_id: str
) -> None:
    current = store.read_file_record(record.file)
    if current is None:
        return
    current.status = STATUS_NOT_ANALYZED
    current.locked_by_run_id = None
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
) -> list[dict[str, Any]]:
    if hasattr(findings, "findings"):
        findings = findings.findings
    normalized = []
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        source = ""

    for finding in findings or []:
        if hasattr(finding, "to_dict"):
            payload = finding.to_dict()
        elif isinstance(finding, dict):
            payload = dict(finding)
        else:
            continue
        payload = sanitize_for_audit(payload)
        payload["audit_finding_id"] = _finding_id(payload, record=record, source=source)
        normalized.append(payload)
    return normalized


def _analyze_file_with_redaction(analyzer: Any, file_path: Path) -> Any:
    source = file_path.read_text(encoding="utf-8", errors="ignore")
    redacted_source = redact_text(source)

    get_agent = getattr(analyzer, "_get_agent", None)
    if callable(get_agent):
        agent = get_agent(SECURITY_AUDIT_ISSUE)
        context = _build_redacted_context(analyzer, redacted_source, file_path)
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


def _build_redacted_context(analyzer: Any, source: str, file_path: Path) -> str | None:
    context_builder = getattr(analyzer, "context_builder", None)
    if context_builder is None:
        return None

    config = getattr(analyzer, "config", None)
    repo_context_map = getattr(config, "repo_context_map", {}) or {}
    repo_metadata = (
        repo_context_map.get(str(file_path))
        or repo_context_map.get(file_path.as_posix())
        or repo_context_map.get(file_path.name)
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
    payload = {
        "path": normalize_relative_path(record.project_root, record.file),
        "rule_id": finding.get("rule_id"),
        "issue_type": finding.get("issue_type"),
        "symbol": finding.get("symbol"),
        "code_hash": code_region_hash(source, line),
    }
    return "finding-" + sha256_text(str(sorted(payload.items())))[:16]


def _audit_state_counts(
    store: AuditStore,
    *,
    model: str,
    provider: str | None,
    allowed_files: list[str | Path] | set[str] | None = None,
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
        if not record.candidates:
            continue
        if record.status in counts:
            counts[record.status] += 1
        if record.status == STATUS_ANALYZED and not _agent_context_matches(
            record, model=model, provider=provider
        ):
            counts["stale_analyzed"] += 1
        if _is_unresolved_record(record, model=model, provider=provider):
            counts["unresolved"] += 1
    return counts
