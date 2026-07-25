from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import skylos
from skylos.audit.freshness import latest_current_revalidation
from skylos.audit.redaction import sanitize_for_audit
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    SIGNAL_QUALITY_EXPLORATORY,
    SIGNAL_QUALITY_PROVEN,
    SIGNAL_QUALITY_STRONG,
    STATUS_ANALYZED,
    STATUS_DELETED,
    STATUS_ERROR,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_SKIPPED,
    AuditFileRecord,
    normalize_signal_quality,
    normalize_relative_path,
    sha256_text,
)
from skylos.reporting.sarif import SarifExporter

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

EXPORT_VERDICTS = {
    "true_positive",
    "false_positive",
    "fixed",
    "uncertain",
    "pending",
    "not_analyzed",
    "error",
    "skipped",
    "deleted",
}

MARKDOWN_FORMATS = {"md", "markdown"}
SUPPORTED_EXPORT_FORMATS = {"json", "sarif", "md", "markdown", "md-dir"}
MARKDOWN_MANIFEST_NAME = ".skylos-deep-audit-manifest.json"
MAX_COVERAGE_RULE_BUCKETS = 128
MAX_ANALYSIS_DIMENSION_ROWS = 64
_COVERAGE_LANGUAGES = {
    "config",
    "csharp",
    "dart",
    "env",
    "go",
    "ini",
    "java",
    "javascript",
    "json",
    "kotlin",
    "php",
    "python",
    "rust",
    "toml",
    "typescript",
    "yaml",
}
_CANDIDATE_COVERAGE_SOURCES = {
    "static",
    "static_unvalidated",
    "stored_finding",
    "unknown",
}
_AUDIT_COVERAGE_RULE_IDS = {
    "SKY-AUDIT",
    "SKY-AUDIT-ENTRYPOINT",
    "SKY-AUDIT-LOGIC",
    "SKY-AUDIT-PATH",
    "SKY-AUDIT-SECURITY",
    "SKY-AUDIT-TRACE",
}
_ANALYSIS_USAGE_KEYS = {
    "cached_tokens",
    "completion_tokens",
    "input_tokens",
    "output_tokens",
    "prompt_tokens",
    "reasoning_tokens",
    "total_tokens",
}


@dataclass
class _AnalysisTelemetryState:
    by_model_provider: dict[tuple[str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    reviewer_pack_runs: dict[str, int] = field(default_factory=dict)
    usage: dict[str, int] = field(default_factory=dict)
    completed_usage: dict[str, int] = field(default_factory=dict)
    failed_usage: dict[str, int] = field(default_factory=dict)
    completed_runs: int = 0
    failed_runs_with_telemetry: int = 0
    error_events: int = 0
    llm_calls: int = 0
    completed_llm_calls: int = 0
    failed_llm_calls: int = 0


def build_deep_audit_export(
    *,
    store: AuditStore,
    min_severity: str | None = None,
    verdicts: list[str] | tuple[str, ...] | set[str] | str | None = None,
    allowed_files: list[str | Path] | None = None,
    include_deleted: bool = False,
) -> dict[str, Any]:
    allowed = _normalized_allowed_files(store, allowed_files)
    all_records = [
        record
        for record in store.iter_file_records()
        if allowed is None or record.file in allowed
    ]
    deleted_records = [
        record for record in all_records if record.status == STATUS_DELETED
    ]
    records = [
        record
        for record in all_records
        if include_deleted or record.status != STATUS_DELETED
    ]
    entries = _build_entries(records)
    severity_filter = _normalize_severity(min_severity) if min_severity else None
    verdict_filter = _normalize_verdict_filter(verdicts)
    filtered_entries = [
        entry
        for entry in entries
        if _entry_matches(entry, severity_filter, verdict_filter)
    ]
    file_scope = "repository" if allowed is None else "allowed_files"

    return sanitize_for_audit(
        {
            "schema_version": 1,
            "tool": "Skylos Deep Audit",
            "skylos_version": skylos.__version__,
            "project_id": store.project_id,
            "project_root": str(store.project_root),
            "filters": {
                "min_severity": severity_filter,
                "verdicts": sorted(verdict_filter) if verdict_filter else [],
                "file_scope": file_scope,
                "allowed_file_count": len(allowed) if allowed is not None else None,
            },
            "completion": _completion(
                records,
                deleted_file_count=0 if include_deleted else len(deleted_records),
            ),
            "coverage": _coverage(records, entries, scope=file_scope),
            "entry_count": len(filtered_entries),
            "entries": filtered_entries,
            "records": [record.to_dict() for record in records],
        }
    )


def render_deep_audit_export(
    export: dict[str, Any],
    export_format: str,
) -> str:
    normalized = _normalize_export_format(export_format)
    if normalized == "json":
        return json.dumps(export, indent=2, sort_keys=True) + "\n"
    if normalized == "sarif":
        return json.dumps(_export_to_sarif(export), indent=2, sort_keys=True) + "\n"
    if normalized in MARKDOWN_FORMATS:
        return _export_to_markdown(export) + "\n"
    raise ValueError(f"Unsupported Deep Mode export format: {export_format}")


def write_deep_audit_export(
    export: dict[str, Any],
    output: str | Path,
    export_format: str,
) -> list[Path]:
    normalized = _normalize_export_format(export_format)
    output_path = _resolve_deep_audit_export_path(
        output,
        directory=normalized == "md-dir",
    )
    if normalized == "md-dir":
        return _write_markdown_directory(export, output_path)
    rendered = render_deep_audit_export(export, normalized)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_export_text(output_path, rendered)
    return [output_path]


def _resolve_deep_audit_export_path(
    output: str | Path,
    *,
    directory: bool = False,
) -> Path:
    output_path = Path(output).expanduser()
    if not output_path.name:
        raise ValueError("Deep audit export output path must include a file name")
    _reject_symlink_components(output_path)
    if output_path.is_symlink():
        raise ValueError(
            f"Deep audit export output must not be a symlink: {output_path}"
        )
    if directory and output_path.exists() and not output_path.is_dir():
        raise ValueError(f"Markdown directory output is not a directory: {output_path}")
    if not directory and output_path.exists() and output_path.is_dir():
        raise ValueError(f"Deep audit export output is a directory: {output_path}")
    return output_path


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


def _build_entries(records: list[AuditFileRecord]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    catalog_cache: dict[tuple[Any, ...], bool] = {}
    for record in records:
        for finding in record.findings:
            if isinstance(finding, dict):
                entries.append(
                    _finding_entry(
                        record,
                        finding,
                        catalog_cache=catalog_cache,
                    )
                )

        if record.status in {
            STATUS_PENDING,
            STATUS_PROCESSING,
            STATUS_NOT_ANALYZED,
            STATUS_ERROR,
            STATUS_SKIPPED,
            STATUS_DELETED,
        }:
            entries.extend(_candidate_entries(record))

    return sorted(entries, key=_entry_sort_key)


def _finding_entry(
    record: AuditFileRecord,
    finding: dict[str, Any],
    *,
    catalog_cache: dict[tuple[Any, ...], bool],
) -> dict[str, Any]:
    finding_id = _finding_id(finding)
    if record.status == STATUS_DELETED:
        latest = None
        verdict = "deleted"
    else:
        latest = latest_current_revalidation(
            record,
            finding,
            catalog_cache=catalog_cache,
        )
        verdict = str((latest or {}).get("verdict") or "uncertain").lower()
    if verdict not in EXPORT_VERDICTS:
        verdict = "uncertain"
    severity = _normalize_severity(
        finding.get("severity") or finding.get("issue_severity") or "medium"
    )
    location = finding.get("location")
    location_line = location.get("line") if isinstance(location, dict) else None
    line = _int_or_default(
        finding.get("line_number")
        or finding.get("line")
        or finding.get("lineno")
        or location_line,
        1,
    )
    rule_id = str(finding.get("rule_id") or finding.get("rule") or "SKY-AUDIT")
    message = str(finding.get("message") or finding.get("title") or rule_id)
    entry = {
        "type": "finding",
        "id": finding_id,
        "file": record.file,
        "line": line,
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "status": record.status,
        "verdict": verdict,
        "verdict_reason": (latest or {}).get("reason"),
        "redacted": False,
        "source": "agent",
        "finding": finding,
    }
    threat_trace = _finding_threat_trace(finding)
    if threat_trace is not None:
        entry["threat_trace"] = threat_trace
    return sanitize_for_audit(entry)


def _candidate_entries(record: AuditFileRecord) -> list[dict[str, Any]]:
    verdict = _record_status_verdict(record.status)
    entries = []
    for candidate in record.candidates:
        entry = {
            "type": "candidate",
            "id": candidate.candidate_id,
            "file": record.file,
            "line": candidate.line,
            "rule_id": candidate.rule_id,
            "severity": _normalize_severity(candidate.severity_hint),
            "message": candidate.reason,
            "status": record.status,
            "verdict": verdict,
            "redacted": candidate.redacted,
            "source": candidate.evidence,
            "signal_quality": candidate.signal_quality,
            "priority": candidate.priority,
            "kind": candidate.kind,
            "symbol": candidate.symbol,
        }
        threat_trace = _candidate_threat_trace(candidate)
        if threat_trace is not None:
            entry["threat_trace"] = threat_trace
        entries.append(sanitize_for_audit(entry))
    return entries


def _record_status_verdict(status: str) -> str:
    if status in {STATUS_PENDING, STATUS_PROCESSING}:
        return "pending"
    if status == STATUS_NOT_ANALYZED:
        return "not_analyzed"
    if status == STATUS_ERROR:
        return "error"
    if status == STATUS_SKIPPED:
        return "skipped"
    if status == STATUS_DELETED:
        return "deleted"
    return "uncertain"


def _completion(
    records: list[AuditFileRecord],
    *,
    deleted_file_count: int = 0,
) -> dict[str, Any]:
    status_counts = {
        STATUS_PENDING: 0,
        STATUS_PROCESSING: 0,
        STATUS_ANALYZED: 0,
        STATUS_NOT_ANALYZED: 0,
        STATUS_ERROR: 0,
        STATUS_SKIPPED: 0,
        STATUS_DELETED: 0,
    }
    candidate_count = 0
    finding_count = 0
    redacted_candidates = 0
    skipped_candidates = 0
    no_candidate_files = 0
    for record in records:
        has_audit_work = bool(record.candidates or record.findings)
        if record.status == STATUS_NOT_ANALYZED and not has_audit_work:
            no_candidate_files += 1
        elif record.status in status_counts:
            status_counts[record.status] += 1
        candidate_count += len(record.candidates)
        finding_count += len(record.findings)
        redacted_candidates += sum(1 for item in record.candidates if item.redacted)
        if record.status == STATUS_SKIPPED:
            skipped_candidates += len(record.candidates)

    unresolved_files = (
        status_counts[STATUS_PENDING]
        + status_counts[STATUS_PROCESSING]
        + status_counts[STATUS_NOT_ANALYZED]
        + status_counts[STATUS_ERROR]
        + status_counts[STATUS_SKIPPED]
    )
    return {
        "complete": unresolved_files == 0,
        "total_files": len(records),
        "files_with_candidates": sum(1 for record in records if record.candidates),
        "candidate_count": candidate_count,
        "finding_count": finding_count,
        "redacted_candidates": redacted_candidates,
        "skipped_candidates": skipped_candidates,
        "pending_files": status_counts[STATUS_PENDING],
        "processing_files": status_counts[STATUS_PROCESSING],
        "analyzed_files": status_counts[STATUS_ANALYZED],
        "not_analyzed_files": status_counts[STATUS_NOT_ANALYZED],
        "error_files": status_counts[STATUS_ERROR],
        "skipped_files": status_counts[STATUS_SKIPPED],
        "deleted_files": status_counts[STATUS_DELETED] + deleted_file_count,
        "no_candidate_files": no_candidate_files,
    }


def _coverage(
    records: list[AuditFileRecord],
    entries: list[dict[str, Any]],
    *,
    scope: str,
) -> dict[str, Any]:
    """Report observed Deep Audit work without presenting it as measured recall."""

    dimensions = _coverage_dimensions(records)
    candidate_count = sum(len(record.candidates) for record in records)
    finding_count = sum(len(record.findings) for record in records)
    return {
        "schema_version": 1,
        "metric": "candidate_observation_coverage",
        "scope": scope,
        "interpretation": (
            "Observed candidates and investigator findings; labeled benchmark "
            "metrics are required to measure recall."
        ),
        "files": len(records),
        "files_with_candidates": sum(1 for record in records if record.candidates),
        "candidate_count": candidate_count,
        "finding_count": finding_count,
        "by_language": dict(sorted(dimensions["by_language"].items())),
        "by_rule": _bounded_export_rule_buckets(dimensions["by_rule"]),
        "by_signal_quality": dict(
            sorted(dimensions["by_signal_quality"].items())
        ),
        "by_candidate_source": dict(
            sorted(dimensions["by_candidate_source"].items())
        ),
        "observed_finding_verdicts": _observed_finding_verdicts(entries),
        "analysis": _analysis_telemetry(records),
    }


def _coverage_dimensions(
    records: list[AuditFileRecord],
) -> dict[str, dict[Any, Any]]:
    by_language: dict[str, dict[str, int]] = {}
    by_rule: dict[str, dict[str, int]] = {}
    by_signal_quality = {
        SIGNAL_QUALITY_PROVEN: 0,
        SIGNAL_QUALITY_STRONG: 0,
        SIGNAL_QUALITY_EXPLORATORY: 0,
    }
    by_candidate_source: dict[str, int] = {}

    for record in records:
        _add_record_coverage(
            record,
            by_language=by_language,
            by_rule=by_rule,
            by_signal_quality=by_signal_quality,
            by_candidate_source=by_candidate_source,
        )
    return {
        "by_language": by_language,
        "by_rule": by_rule,
        "by_signal_quality": by_signal_quality,
        "by_candidate_source": by_candidate_source,
    }


def _add_record_coverage(
    record: AuditFileRecord,
    *,
    by_language: dict[str, dict[str, int]],
    by_rule: dict[str, dict[str, int]],
    by_signal_quality: dict[str, int],
    by_candidate_source: dict[str, int],
) -> None:
    language = record.language if record.language in _COVERAGE_LANGUAGES else "other"
    language_bucket = by_language.setdefault(
        language,
        {
            "files": 0,
            "files_with_candidates": 0,
            "candidates": 0,
            "findings": 0,
        },
    )
    language_bucket["files"] += 1
    language_bucket["files_with_candidates"] += int(bool(record.candidates))
    language_bucket["candidates"] += len(record.candidates)
    language_bucket["findings"] += len(record.findings)
    for candidate in record.candidates:
        _add_candidate_coverage(
            candidate,
            by_rule=by_rule,
            by_signal_quality=by_signal_quality,
            by_candidate_source=by_candidate_source,
        )
    for finding in record.findings:
        _add_finding_coverage(finding, by_rule=by_rule)


def _add_candidate_coverage(
    candidate: Any,
    *,
    by_rule: dict[str, dict[str, int]],
    by_signal_quality: dict[str, int],
    by_candidate_source: dict[str, int],
) -> None:
    quality = normalize_signal_quality(candidate.signal_quality)
    by_signal_quality[quality] += 1
    raw_source = str(candidate.evidence or "unknown")
    source = raw_source if raw_source in _CANDIDATE_COVERAGE_SOURCES else "other"
    by_candidate_source[source] = by_candidate_source.get(source, 0) + 1
    rule_id = _coverage_rule_id(candidate.rule_id)
    rule_bucket = by_rule.setdefault(
        rule_id,
        {"candidates": 0, "findings": 0},
    )
    rule_bucket["candidates"] += 1


def _add_finding_coverage(
    finding: Any,
    *,
    by_rule: dict[str, dict[str, int]],
) -> None:
    if not isinstance(finding, dict):
        return
    rule_id = _coverage_rule_id(
        finding.get("rule_id") or finding.get("rule") or "SKY-AUDIT"
    )
    rule_bucket = by_rule.setdefault(
        rule_id,
        {"candidates": 0, "findings": 0},
    )
    rule_bucket["findings"] += 1


def _observed_finding_verdicts(
    entries: list[dict[str, Any]],
) -> dict[str, int]:
    observed_finding_verdicts: dict[str, int] = {}
    for entry in entries:
        if entry.get("type") != "finding":
            continue
        verdict = str(entry.get("verdict") or "uncertain")
        observed_finding_verdicts[verdict] = (
            observed_finding_verdicts.get(verdict, 0) + 1
        )
    return dict(sorted(observed_finding_verdicts.items()))


def _coverage_rule_id(value: Any) -> str:
    rule_id = str(value or "").strip().upper()
    if rule_id in _AUDIT_COVERAGE_RULE_IDS:
        return rule_id
    if not rule_id.startswith("SKY-"):
        return "other"
    suffix = rule_id[4:]
    prefix = suffix[:-3]
    digits = suffix[-3:]
    if 1 <= len(prefix) <= 3 and prefix.isalpha() and digits.isdigit():
        return rule_id
    return "other"


def _bounded_export_rule_buckets(
    buckets: dict[str, dict[str, int]],
) -> dict[str, dict[str, int]]:
    if len(buckets) <= MAX_COVERAGE_RULE_BUCKETS:
        return dict(sorted(buckets.items()))

    ordered = sorted(
        buckets.items(),
        key=lambda item: (
            -(item[1]["candidates"] + item[1]["findings"]),
            item[0],
        ),
    )
    visible = dict(ordered[: MAX_COVERAGE_RULE_BUCKETS - 1])
    overflow = {"candidates": 0, "findings": 0}
    for _rule_id, metrics in ordered[MAX_COVERAGE_RULE_BUCKETS - 1 :]:
        for key in overflow:
            overflow[key] += metrics[key]
    if "other" in visible:
        for key in overflow:
            visible["other"][key] += overflow[key]
    else:
        visible["other"] = overflow
    return dict(sorted(visible.items()))


def _analysis_telemetry(records: list[AuditFileRecord]) -> dict[str, Any]:
    state = _AnalysisTelemetryState()
    for record in records:
        for history in record.analysis_history:
            _record_analysis_history(state, history)
    return _analysis_telemetry_payload(state)


def _record_analysis_history(
    state: _AnalysisTelemetryState,
    history: Any,
) -> None:
    if not isinstance(history, dict):
        return
    stage = history.get("stage")
    if stage == "error":
        _record_failed_analysis(state, history)
    elif stage == "agent_process":
        _record_completed_analysis(state, history)


def _record_failed_analysis(
    state: _AnalysisTelemetryState,
    history: dict[str, Any],
) -> None:
    state.error_events += 1
    investigation = history.get("investigation")
    if (
        not isinstance(investigation, dict)
        or investigation.get("metadata_scope") != "operational_only"
    ):
        return
    state.failed_runs_with_telemetry += 1
    bucket = _analysis_model_bucket(state, history)
    bucket["failed_runs"] += 1
    calls = _nonnegative_metadata_int(investigation, "llm_calls")
    if calls is not None:
        _add_analysis_calls(state, bucket, calls, failed=True)
    _add_analysis_usage(
        state,
        investigation,
        destination=state.failed_usage,
        bucket_total=bucket["usage"],
        bucket_destination=bucket["failed_usage"],
    )


def _record_completed_analysis(
    state: _AnalysisTelemetryState,
    history: dict[str, Any],
) -> None:
    state.completed_runs += 1
    bucket = _analysis_model_bucket(state, history)
    bucket["completed_runs"] += 1
    investigation = history.get("investigation")
    if not isinstance(investigation, dict):
        return
    calls = _nonnegative_metadata_int(investigation, "llm_calls")
    if calls is not None:
        _add_analysis_calls(state, bucket, calls, failed=False)
    _add_analysis_usage(
        state,
        investigation,
        destination=state.completed_usage,
        bucket_total=bucket["usage"],
        bucket_destination=bucket["completed_usage"],
    )
    _record_reviewer_pack_runs(state, investigation)


def _analysis_model_bucket(
    state: _AnalysisTelemetryState,
    history: dict[str, Any],
) -> dict[str, Any]:
    model = str(history.get("model") or "unknown")
    provider = str(history.get("provider") or "default")
    return state.by_model_provider.setdefault(
        (provider, model),
        {
            "provider": provider,
            "model": model,
            "completed_runs": 0,
            "failed_runs": 0,
            "llm_calls": 0,
            "completed_llm_calls": 0,
            "failed_llm_calls": 0,
            "usage": {},
            "completed_usage": {},
            "failed_usage": {},
        },
    )


def _nonnegative_metadata_int(
    metadata: dict[str, Any],
    key: str,
) -> int | None:
    value = metadata.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _add_analysis_calls(
    state: _AnalysisTelemetryState,
    bucket: dict[str, Any],
    calls: int,
    *,
    failed: bool,
) -> None:
    state.llm_calls += calls
    bucket["llm_calls"] += calls
    if failed:
        state.failed_llm_calls += calls
        bucket["failed_llm_calls"] += calls
    else:
        state.completed_llm_calls += calls
        bucket["completed_llm_calls"] += calls


def _add_analysis_usage(
    state: _AnalysisTelemetryState,
    investigation: dict[str, Any],
    *,
    destination: dict[str, int],
    bucket_total: dict[str, int],
    bucket_destination: dict[str, int],
) -> None:
    investigation_usage = investigation.get("usage")
    if not isinstance(investigation_usage, dict):
        return
    for usage_key in _ANALYSIS_USAGE_KEYS:
        value = _nonnegative_metadata_int(investigation_usage, usage_key)
        if value is None:
            continue
        _increment_metric(state.usage, usage_key, value)
        _increment_metric(destination, usage_key, value)
        _increment_metric(bucket_total, usage_key, value)
        _increment_metric(bucket_destination, usage_key, value)


def _increment_metric(metrics: dict[str, int], key: str, value: int) -> None:
    metrics[key] = metrics.get(key, 0) + value


def _record_reviewer_pack_runs(
    state: _AnalysisTelemetryState,
    investigation: dict[str, Any],
) -> None:
    reviewer_guidance = investigation.get("reviewer_guidance")
    if not isinstance(reviewer_guidance, dict):
        return
    selected_packs = reviewer_guidance.get("selected_packs")
    if not isinstance(selected_packs, list):
        return
    for pack_id in _reviewer_pack_ids(selected_packs):
        _increment_metric(state.reviewer_pack_runs, pack_id, 1)


def _reviewer_pack_ids(selected_packs: list[Any]) -> set[str]:
    pack_ids: set[str] = set()
    for pack in selected_packs:
        if not isinstance(pack, dict):
            continue
        pack_id = pack.get("id")
        if isinstance(pack_id, str) and pack_id:
            pack_ids.add(pack_id)
    return pack_ids


def _analysis_model_rows(
    state: _AnalysisTelemetryState,
) -> tuple[list[dict[str, Any]], bool]:
    ordered_model_keys = sorted(
        state.by_model_provider,
        key=lambda key: (
            -(
                state.by_model_provider[key]["completed_runs"]
                + state.by_model_provider[key]["failed_runs"]
            ),
            key,
        ),
    )
    model_rows: list[dict[str, Any]] = []
    for key in ordered_model_keys[:MAX_ANALYSIS_DIMENSION_ROWS]:
        bucket = dict(state.by_model_provider[key])
        for usage_key in ("usage", "completed_usage", "failed_usage"):
            bucket[usage_key] = dict(sorted(bucket[usage_key].items()))
        model_rows.append(bucket)
    return model_rows, len(ordered_model_keys) > MAX_ANALYSIS_DIMENSION_ROWS


def _analysis_telemetry_payload(
    state: _AnalysisTelemetryState,
) -> dict[str, Any]:
    model_rows, model_rows_truncated = _analysis_model_rows(state)
    ordered_pack_runs = sorted(
        state.reviewer_pack_runs.items(),
        key=lambda item: (-item[1], item[0]),
    )
    return {
        "completed_runs": state.completed_runs,
        "failed_runs_with_telemetry": state.failed_runs_with_telemetry,
        "error_events": state.error_events,
        "llm_calls": state.llm_calls,
        "completed_llm_calls": state.completed_llm_calls,
        "failed_llm_calls": state.failed_llm_calls,
        "usage": dict(sorted(state.usage.items())),
        "completed_usage": dict(sorted(state.completed_usage.items())),
        "failed_usage": dict(sorted(state.failed_usage.items())),
        "by_model_provider": model_rows,
        "model_provider_rows_truncated": model_rows_truncated,
        "reviewer_pack_runs": [
            {"pack_id": pack_id, "completed_runs": runs}
            for pack_id, runs in ordered_pack_runs[:MAX_ANALYSIS_DIMENSION_ROWS]
        ],
        "reviewer_pack_rows_truncated": (
            len(ordered_pack_runs) > MAX_ANALYSIS_DIMENSION_ROWS
        ),
    }


def _finding_id(finding: dict[str, Any]) -> str:
    existing = finding.get("audit_finding_id")
    if existing:
        return str(existing)
    payload = json.dumps(finding, sort_keys=True, default=str)
    return "finding-" + sha256_text(payload)[:16]


def _finding_threat_trace(finding: dict[str, Any]) -> dict[str, Any] | None:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        return None
    trace = metadata.get("threat_trace")
    return dict(trace) if isinstance(trace, dict) else None


def _candidate_threat_trace(candidate: Any) -> dict[str, Any] | None:
    data = getattr(candidate, "data", None)
    if not isinstance(data, dict):
        return None
    trace = data.get("threat_trace")
    return dict(trace) if isinstance(trace, dict) else None


def _entry_threat_trace(entry: dict[str, Any]) -> dict[str, Any] | None:
    trace = entry.get("threat_trace")
    if isinstance(trace, dict):
        return dict(trace)

    finding = entry.get("finding")
    if isinstance(finding, dict):
        return _finding_threat_trace(finding)
    return None


def _threat_trace_summary(trace: dict[str, Any] | None) -> str:
    if not isinstance(trace, dict):
        return ""
    source = _threat_trace_point_summary(trace.get("source"))
    sink = _threat_trace_point_summary(trace.get("sink"))
    validation = str(trace.get("validation") or "").strip()
    parts: list[str] = []
    if source or sink:
        parts.append(f"{source or 'source'} -> {sink or 'sink'}")
    if validation:
        parts.append(f"({validation})")
    if parts:
        return " ".join(parts)
    return str(trace.get("trace_id") or "").strip()


def _threat_trace_point_summary(point: Any) -> str:
    if not isinstance(point, dict):
        return ""
    name = str(point.get("name") or point.get("kind") or "").strip()
    line = point.get("line")
    if name and line:
        return f"{name}@L{line}"
    if name:
        return name
    if line:
        return f"L{line}"
    return ""


def _entry_matches(
    entry: dict[str, Any],
    severity_filter: str | None,
    verdict_filter: set[str] | None,
) -> bool:
    if severity_filter and _severity_value(entry.get("severity")) < _severity_value(
        severity_filter
    ):
        return False
    if verdict_filter and str(entry.get("verdict") or "").lower() not in verdict_filter:
        return False
    return True


def _normalize_verdict_filter(
    verdicts: list[str] | tuple[str, ...] | set[str] | str | None,
) -> set[str] | None:
    if verdicts is None:
        return None
    raw_items: list[str]
    if isinstance(verdicts, str):
        raw_items = [verdicts]
    else:
        raw_items = [str(item) for item in verdicts]
    normalized: set[str] = set()
    for item in raw_items:
        for part in item.split(","):
            verdict = part.strip().lower()
            if verdict:
                normalized.add(verdict)
    return normalized or None


def _normalize_severity(value: Any) -> str:
    severity = str(value or "info").strip().lower()
    return severity if severity in SEVERITY_RANK else "info"


def _severity_value(value: Any) -> int:
    return SEVERITY_RANK.get(str(value or "info").lower(), 0)


def _entry_sort_key(entry: dict[str, Any]) -> tuple[int, str, int, str, str]:
    return (
        -_severity_value(entry.get("severity")),
        str(entry.get("file") or ""),
        _int_or_default(entry.get("line"), 1),
        str(entry.get("rule_id") or ""),
        str(entry.get("id") or ""),
    )


def _int_or_default(value: Any, default: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return result if result > 0 else default


def _normalize_export_format(export_format: str) -> str:
    normalized = str(export_format or "json").lower()
    if normalized not in SUPPORTED_EXPORT_FORMATS:
        raise ValueError(f"Unsupported Deep Mode export format: {export_format}")
    return normalized


def _export_to_sarif(export: dict[str, Any]) -> dict[str, Any]:
    findings = [_entry_to_sarif_finding(entry) for entry in export.get("entries", [])]
    sarif = SarifExporter(
        findings,
        tool_name="Skylos Deep Audit",
        version=skylos.__version__,
    ).generate()
    run = sarif["runs"][0]
    run.setdefault("properties", {})["deep_audit"] = {
        "project_id": export.get("project_id"),
        "completion": export.get("completion", {}),
        "coverage": export.get("coverage", {}),
        "filters": export.get("filters", {}),
        "entry_count": export.get("entry_count", 0),
    }
    return sarif


def _entry_to_sarif_finding(entry: dict[str, Any]) -> dict[str, Any]:
    message = str(entry.get("message") or entry.get("rule_id") or "Deep audit entry")
    verdict = str(entry.get("verdict") or "uncertain")
    metadata = {
        "deep_audit_id": entry.get("id"),
        "verdict": verdict,
        "status": entry.get("status"),
        "redacted": entry.get("redacted", False),
        "source": entry.get("source"),
    }
    if entry.get("signal_quality") is not None:
        metadata["signal_quality"] = entry["signal_quality"]
    if entry.get("priority") is not None:
        metadata["priority"] = entry["priority"]
    threat_trace = _entry_threat_trace(entry)
    if threat_trace is not None:
        metadata["threat_trace"] = threat_trace
        summary = _threat_trace_summary(threat_trace)
        if summary:
            metadata["threat_trace_summary"] = summary
    return {
        "rule_id": entry.get("rule_id") or "SKY-AUDIT",
        "severity": str(entry.get("severity") or "info").upper(),
        "message": f"[{verdict}] {message}",
        "file": entry.get("file"),
        "line": entry.get("line") or 1,
        "category": "SECURITY",
        "kind": entry.get("type"),
        "metadata": metadata,
    }


def _export_to_markdown(export: dict[str, Any]) -> str:
    completion = export.get("completion") or {}
    lines = [
        "# Skylos Deep Audit Report",
        "",
        f"- Project: `{_md_inline(export.get('project_root'))}`",
        f"- Complete: `{str(completion.get('complete', False)).lower()}`",
        f"- Entries: `{export.get('entry_count', 0)}`",
        f"- Files: `{completion.get('total_files', 0)}`",
        f"- Pending files: `{completion.get('pending_files', 0)}`",
        f"- Not analyzed files: `{completion.get('not_analyzed_files', 0)}`",
        f"- Error files: `{completion.get('error_files', 0)}`",
        f"- Skipped files: `{completion.get('skipped_files', 0)}`",
        f"- Deleted files: `{completion.get('deleted_files', 0)}`",
        f"- No-candidate files: `{completion.get('no_candidate_files', 0)}`",
        "",
    ]
    filters = export.get("filters") or {}
    if filters.get("min_severity") or filters.get("verdicts"):
        lines.extend(
            [
                "## Filters",
                "",
                f"- Minimum severity: `{filters.get('min_severity') or 'none'}`",
                f"- Verdicts: `{', '.join(filters.get('verdicts') or []) or 'none'}`",
                "",
            ]
        )

    entries = list(export.get("entries") or [])
    if not entries:
        lines.extend(["## Entries", "", "No Deep Mode entries matched the filters."])
        return "\n".join(lines)

    has_threat_traces = any(_entry_threat_trace(entry) for entry in entries)
    lines.extend(["## Entries", ""])
    if has_threat_traces:
        lines.extend(
            [
                "| Severity | Verdict | Status | Rule | Location | Threat Trace | Message |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
    else:
        lines.extend(
            [
                "| Severity | Verdict | Status | Rule | Location | Message |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
    for entry in entries:
        location = f"{entry.get('file')}:{entry.get('line') or 1}"
        row = [
            _md_cell(entry.get("severity")),
            _md_cell(entry.get("verdict")),
            _md_cell(entry.get("status")),
            _md_cell(entry.get("rule_id")),
            _md_cell(location),
        ]
        if has_threat_traces:
            row.append(_md_cell(_threat_trace_summary(_entry_threat_trace(entry))))
        row.append(_md_cell(entry.get("message")))
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def _write_markdown_directory(
    export: dict[str, Any],
    output_dir: Path,
) -> list[Path]:
    if output_dir.is_symlink():
        raise ValueError(
            f"Markdown directory output must not be a symlink: {output_dir}"
        )
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError(f"Markdown directory output is not a directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    entry_paths = [
        output_dir / _entry_markdown_filename(entry, index)
        for index, entry in enumerate(export.get("entries") or [], start=1)
    ]
    current_names = {"index.md", *(path.name for path in entry_paths)}

    written: list[Path] = []
    index_path = output_dir / "index.md"
    _write_export_text(index_path, _export_to_markdown(export) + "\n")
    written.append(index_path)

    for entry_path, entry in zip(entry_paths, export.get("entries") or []):
        _write_export_text(entry_path, _entry_to_markdown(entry) + "\n")
        written.append(entry_path)
    _write_export_text(
        output_dir / MARKDOWN_MANIFEST_NAME,
        json.dumps(
            {"schema_version": 1, "files": sorted(current_names)},
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    return written


def _write_export_text(path: Path, content: str) -> None:
    """Atomically replace one export file without following a target symlink."""

    _reject_symlink_components(path.parent)
    try:
        if path.is_symlink():
            raise ValueError(f"Deep audit export file must not be a symlink: {path}")
    except OSError as exc:
        raise ValueError(
            f"Deep audit export path could not be inspected: {path}"
        ) from exc

    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(  # skylos: ignore[SKY-D215] exclusive no-follow temporary
            temporary, flags, 0o600
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _reject_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for component in reversed((absolute, *absolute.parents)):
        try:
            if component.is_symlink():
                raise ValueError(
                    f"Deep audit export path must not contain symlinks: {path}"
                )
        except OSError as exc:
            raise ValueError(
                f"Deep audit export path could not be inspected: {path}"
            ) from exc


def _entry_markdown_filename(entry: dict[str, Any], index: int) -> str:
    rule = _slug(entry.get("rule_id") or "audit")
    file_slug = _slug(str(entry.get("file") or "unknown").replace("/", "-"))
    severity = _slug(entry.get("severity") or "info")
    return f"{index:03d}-{severity}-{rule}-{file_slug}.md"


def _entry_to_markdown(entry: dict[str, Any]) -> str:
    lines = [
        f"# {_md_inline(entry.get('rule_id') or 'Deep Audit Entry')}",
        "",
        f"- Severity: `{_md_inline(entry.get('severity'))}`",
        f"- Verdict: `{_md_inline(entry.get('verdict'))}`",
        f"- Status: `{_md_inline(entry.get('status'))}`",
        f"- Location: `{_md_inline(entry.get('file'))}:{entry.get('line') or 1}`",
        f"- Type: `{_md_inline(entry.get('type'))}`",
        "",
        "## Message",
        "",
        str(entry.get("message") or "").strip() or "(no message)",
    ]
    reason = entry.get("verdict_reason")
    if reason:
        lines.extend(["", "## Verdict Reason", "", str(reason)])
    threat_trace = _entry_threat_trace(entry)
    if threat_trace is not None:
        lines.extend(["", "## Threat Trace", ""])
        summary = _threat_trace_summary(threat_trace)
        if summary:
            lines.append(summary)
        entrypoint = str(threat_trace.get("entrypoint") or "").strip()
        if entrypoint:
            lines.append(f"- Entrypoint: `{_md_inline(entrypoint)}`")
        source = _threat_trace_point_markdown("Source", threat_trace.get("source"))
        if source:
            lines.append(source)
        sink = _threat_trace_point_markdown("Sink", threat_trace.get("sink"))
        if sink:
            lines.append(sink)
        validation = str(threat_trace.get("validation") or "").strip()
        if validation:
            lines.append(f"- Validation: `{_md_inline(validation)}`")
    return "\n".join(lines)


def _threat_trace_point_markdown(label: str, point: Any) -> str:
    if not isinstance(point, dict):
        return ""
    name = str(point.get("name") or point.get("kind") or "").strip()
    line = point.get("line")
    file_path = str(point.get("file") or "").strip()
    if not any([name, line, file_path]):
        return ""
    details = []
    if name:
        details.append(f"`{_md_inline(name)}`")
    if file_path:
        details.append(f"`{_md_inline(file_path)}`")
    if line:
        details.append(f"line `{_md_inline(line)}`")
    return f"- {label}: " + " at ".join(details)


def _slug(value: Any) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip().lower())
    slug = slug.strip("-._")
    return slug[:80] or "entry"


def _md_cell(value: Any) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\n", " ").replace("|", "\\|")
    return text.strip()


def _md_inline(value: Any) -> str:
    return str(value if value is not None else "").replace("`", "\\`")
