from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from skylos.audit.investigator_tools import (
    DEFAULT_EXCLUDED_FOLDERS,
    AuditReadOnlyTools,
)
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
    InvestigationIncompleteError,
)

SECURITY_AUDIT_ISSUE = "security_audit"
PYTHON_LANGUAGE = "python"
DEEP_AUDIT_ANALYSIS_VERSION = INVESTIGATOR_PROTOCOL_VERSION
MAX_DEEP_AUDIT_SOURCE_BYTES = 1_000_000


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
        catalog_probe = AuditReadOnlyTools(
            store.project_root,
            exclude_folders=investigator_exclude_folders,
            denied_paths=sensitive_files,
            excluded_paths=stored_exclude_paths,
        )
        repository_catalog_digest = str(
            catalog_probe.metadata()["catalog_digest"]
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
        if queued.status in {STATUS_ANALYZED, STATUS_NOT_ANALYZED}:
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
            store.mark_error(record.file, f"Agent processing failed: {exc}")
            run_error_files += 1
            continue

        existing_ids = {
            str(item.get("audit_finding_id")): item
            for item in record.findings
            if isinstance(item, dict) and item.get("audit_finding_id")
        }
        for finding in findings:
            finding_id = str(finding.get("audit_finding_id"))
            if finding_id not in existing_ids:
                findings_added += 1

        record.status = STATUS_ANALYZED
        record.locked_by_run_id = None
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
        record.analysis_history.append(
            sanitize_for_audit(history_entry)
        )
        store.write_file_record(record)
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


def _record_sort_key(record: AuditFileRecord) -> tuple[int, str]:
    return (
        -max((candidate.priority for candidate in record.candidates), default=0),
        record.file,
    )


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
        max_bytes=MAX_DEEP_AUDIT_SOURCE_BYTES,
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
            max_bytes=MAX_DEEP_AUDIT_SOURCE_BYTES,
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
        return not _agent_context_matches(
            record,
            model=model,
            provider=provider,
            repository_catalog_digest=repository_catalog_digest,
        )
    if holistic and record.status == STATUS_NOT_ANALYZED:
        return True
    return record.status in {STATUS_PENDING, STATUS_PROCESSING, STATUS_ERROR}


def _agent_context_matches(
    record: AuditFileRecord,
    *,
    model: str,
    provider: str | None,
    repository_catalog_digest: str | None = None,
) -> bool:
    for item in reversed(record.analysis_history):
        if not isinstance(item, dict) or item.get("stage") != "agent_process":
            continue
        if item.get("model") != model or item.get("provider") != provider:
            return False
        if item.get("analysis_version") != DEEP_AUDIT_ANALYSIS_VERSION:
            return False
        if item.get("protocol_version") == INVESTIGATOR_PROTOCOL_VERSION:
            if item.get("definition_hash") != INVESTIGATOR_DEFINITION_HASH:
                return False
        if (
            repository_catalog_digest is not None
            and item.get("catalog_digest") != repository_catalog_digest
        ):
            return False
        related_files = item.get("related_files")
        if repository_catalog_digest is not None and not isinstance(
            related_files, list
        ):
            return False
        if isinstance(related_files, list) and not _related_context_is_current(
            record, related_files
        ):
            return False
        return True
    return False


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
        return not _agent_context_matches(
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
    source: str | None = None,
) -> list[dict[str, Any]]:
    if hasattr(findings, "findings"):
        findings = findings.findings
    normalized = []
    source = source or ""

    for finding in findings or []:
        if hasattr(finding, "to_dict"):
            payload = finding.to_dict()
        elif isinstance(finding, dict):
            payload = dict(finding)
        else:
            continue
        payload = sanitize_for_audit(payload)
        _attach_candidate_threat_trace(payload, record=record)
        payload["audit_finding_id"] = _finding_id(payload, record=record, source=source)
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
            tools = AuditReadOnlyTools(
                store.project_root,
                exclude_folders=exclude_folders,
                denied_paths=sensitive_files,
                excluded_paths=excluded_paths,
            )
            if (
                repository_catalog_digest is not None
                and tools.metadata()["catalog_digest"]
                != repository_catalog_digest
            ):
                raise InvestigationIncompleteError(
                    "repository changed before investigation started"
                )
            tools.register_initial_file(record.file)
            if tools.related_file_hashes.get(record.file) != record.file_hash:
                raise InvestigationIncompleteError(
                    f"source changed before investigation started: {record.file}"
                )
            result = investigate(
                redacted_source,
                record.file,
                context=context,
                candidates=[candidate.to_dict() for candidate in record.candidates],
                tools=tools,
                run_id=run_id,
            )
            tools.assert_completion_safe()
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
            f"{repo_metadata}\n{candidate_context}" if repo_metadata else candidate_context
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
            source = trace.get("source") if isinstance(trace.get("source"), dict) else {}
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
    location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
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
        if record.status == STATUS_ANALYZED and not _agent_context_matches(
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
