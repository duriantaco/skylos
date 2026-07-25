from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any
from uuid import uuid4

from skylos.audit.redaction import sanitize_for_audit
from skylos.audit.polyglot import build_polyglot_signal_candidates
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    DEFAULT_PROJECT_ID,
    MAX_AUDIT_SOURCE_BYTES,
    SIGNAL_QUALITY_EXPLORATORY,
    SIGNAL_QUALITY_PROVEN,
    SIGNAL_QUALITY_RANK,
    SIGNAL_QUALITY_STRONG,
    STATUS_ERROR,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    AuditCandidate,
    AuditScanSummary,
    code_region_hash,
    language_for_path,
    normalize_relative_path,
    read_audit_source_text,
    sha256_text,
    stable_json_hash,
)
from skylos.config import load_config
from skylos.constants import parse_exclude_folders
from skylos.core.file_discovery import discover_source_files, should_exclude_path
from skylos.llm.threat_trace import build_static_threat_traces
from skylos.llm.repo_activation import build_repo_activation_index
from skylos.pipeline import run_static_on_files
from skylos.rules.secrets import scan_ctx as scan_secrets_ctx

DEEP_AUDIT_EXTENSIONS = (
    ".py",
    ".pyi",
    ".pyw",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".java",
    ".php",
    ".rs",
    ".dart",
    ".cs",
    ".kt",
    ".kts",
    ".env",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
)

SEVERITY_PRIORITY = {
    "critical": 1000,
    "high": 800,
    "medium": 500,
    "low": 200,
    "info": 100,
}

SECURITY_PATH_TOKENS = (
    "admin",
    "auth",
    "billing",
    "crypto",
    "login",
    "oauth",
    "password",
    "payment",
    "query",
    "secret",
    "session",
    "sql",
    "token",
    "upload",
)
THREAT_TRACE_KIND = "threat_trace"
THREAT_TRACE_RULE_ID = "SKY-AUDIT-TRACE"
MAX_COVERAGE_RULE_BUCKETS = 128
_AUDIT_COVERAGE_RULE_IDS = {
    "SKY-AUDIT",
    "SKY-AUDIT-ENTRYPOINT",
    "SKY-AUDIT-LOGIC",
    "SKY-AUDIT-PATH",
    "SKY-AUDIT-SECURITY",
    "SKY-AUDIT-TRACE",
}
_CANDIDATE_COVERAGE_KINDS = {
    "entrypoint",
    "finding_revalidation",
    "path_signal",
    "polyglot_static_signal",
    "static_finding",
    "threat_trace",
}


def scan_deep_audit_candidates(
    path: str | Path,
    *,
    project_id: str = DEFAULT_PROJECT_ID,
    changed_files: list[str | Path] | None = None,
    exclude_folders: list[str] | None = None,
    exclude_paths: list[str | Path] | None = None,
    audit_root: str | Path | None = None,
) -> tuple[AuditScanSummary, AuditStore]:
    project_root = _project_root(path)
    project_cfg = load_config(project_root)
    parsed_excludes = list(
        exclude_folders
        or parse_exclude_folders(
            use_defaults=True,
            config_exclude_folders=project_cfg.get("exclude"),
        )
    )
    if ".skylos" not in parsed_excludes:
        parsed_excludes.append(".skylos")
    config_hash = stable_json_hash(
        {
            "config": project_cfg,
            "exclude": parsed_excludes,
            "extensions": DEEP_AUDIT_EXTENSIONS,
        }
    )

    files, rejected_sources = _discover_audit_files(
        path,
        project_root=project_root,
        changed_files=changed_files,
        exclude_folders=parsed_excludes,
        exclude_paths=exclude_paths,
    )
    source_cache = _source_cache(files, project_root=project_root)
    safe_files: list[Path] = []
    for file_path in files:
        rel_path = normalize_relative_path(project_root, file_path)
        if rel_path in source_cache:
            safe_files.append(file_path)
        else:
            _record_rejected_source(rejected_sources, project_root, file_path)
    files = safe_files
    rejected_source_files = len(rejected_sources)
    static_result = run_static_on_files(
        files,
        project_root=project_root,
        conf=10,
        enable_secrets=True,
        enable_danger=True,
        enable_quality=False,
        exclude_folders=parsed_excludes,
    )
    _merge_direct_secret_findings(
        static_result,
        files,
        project_root=project_root,
        source_cache=source_cache,
    )
    candidates_by_file = _build_static_candidates(
        files,
        project_root=project_root,
        static_result=static_result,
        source_cache=source_cache,
    )
    _add_polyglot_signal_candidates(
        candidates_by_file,
        files,
        project_root=project_root,
    )
    _add_threat_trace_candidates(
        candidates_by_file,
        files,
        project_root=project_root,
    )
    _add_repo_activation_candidates(
        candidates_by_file,
        files,
        project_root=project_root,
        static_result=static_result,
    )
    _add_path_signal_candidates(candidates_by_file, files, project_root=project_root)

    store = AuditStore(project_root, project_id=project_id, audit_root=audit_root)
    store.init_project(
        config_hash=config_hash,
        exclude_folders=parsed_excludes,
        exclude_paths=exclude_paths,
    )
    store.set_current_scan_files(files)
    deleted_records = store.mark_deleted_records(allowed_files=changed_files)

    records_written = 0
    candidate_count = 0
    redacted_candidates = 0
    pending_files = 0
    not_analyzed_files = 0
    processing_files = 0
    error_files = 0

    for file_path in files:
        rel_path = normalize_relative_path(project_root, file_path)
        candidate_map = {
            candidate.candidate_id: candidate
            for candidate in candidates_by_file.get(rel_path, [])
        }
        candidates = sorted(
            candidate_map.values(),
            key=_candidate_sort_key,
        )
        file_hash = sha256_text(source_cache[rel_path])
        record = store.upsert_scan_record(
            file_path=file_path,
            file_hash=file_hash,
            language=language_for_path(file_path),
            candidates=candidates,
            config_hash=config_hash,
        )
        records_written += 1
        candidate_count += len(candidates)
        redacted_candidates += sum(1 for candidate in candidates if candidate.redacted)
        if record.status == STATUS_PENDING:
            pending_files += 1
        elif record.status == STATUS_NOT_ANALYZED:
            not_analyzed_files += 1
        elif record.status == STATUS_PROCESSING:
            processing_files += 1
        elif record.status == STATUS_ERROR:
            error_files += 1

    summary = AuditScanSummary(
        project_id=project_id,
        project_root=str(project_root),
        files_scanned=len(files),
        records_written=records_written,
        candidate_count=candidate_count,
        redacted_candidates=redacted_candidates,
        pending_files=pending_files,
        processing_files=processing_files,
        not_analyzed_files=not_analyzed_files,
        error_files=error_files,
        deleted_files=len(deleted_records),
        complete=(
            pending_files == 0
            and processing_files == 0
            and error_files == 0
            and rejected_source_files == 0
        ),
        coverage=_candidate_coverage(
            files,
            project_root=project_root,
            candidates_by_file=candidates_by_file,
            scope="changed_files" if changed_files is not None else "repository",
            rejected_source_files=rejected_source_files,
        ),
        rejected_source_files=rejected_source_files,
    )
    run_id = f"scan-{uuid4().hex[:12]}"
    store.write_run(
        run_id,
        {
            "mode": "scan_only",
            "summary": summary.to_dict(),
        },
    )
    return summary, store


def _project_root(path: str | Path) -> Path:
    target = Path(path).resolve()
    return target.parent if target.is_file() else target


def _resolve_audit_file(
    path: Path,
    project_root: Path,
    *,
    rejected_sources: set[str] | None = None,
    report_rejection: bool = False,
) -> Path | None:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if not _is_audit_file(candidate):
        return None
    try:
        file_stat = candidate.lstat()
    except OSError:
        # Changed-file lists include deleted files; absence is not a read failure.
        return None
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_size > MAX_AUDIT_SOURCE_BYTES
    ):
        return _report_rejected_source(
            rejected_sources,
            project_root,
            candidate,
            enabled=report_rejection,
        )
    if (
        read_audit_source_text(
            project_root,
            candidate,
            max_bytes=MAX_AUDIT_SOURCE_BYTES,
        )
        is None
    ):
        return _report_rejected_source(
            rejected_sources,
            project_root,
            candidate,
            enabled=report_rejection,
        )
    resolved = _resolve_contained_file(candidate, project_root)
    if resolved is None:
        return _report_rejected_source(
            rejected_sources,
            project_root,
            candidate,
            enabled=report_rejection,
        )
    return resolved


def _resolve_contained_file(candidate: Path, project_root: Path) -> Path | None:
    try:
        root = project_root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None


def _report_rejected_source(
    rejected_sources: set[str] | None,
    project_root: Path,
    candidate: Path,
    *,
    enabled: bool,
) -> None:
    if enabled and rejected_sources is not None:
        _record_rejected_source(rejected_sources, project_root, candidate)


def _record_rejected_source(
    rejected_sources: set[str],
    project_root: Path,
    candidate: Path,
) -> None:
    try:
        key = candidate.relative_to(project_root).as_posix()
    except ValueError:
        key = str(candidate)
    rejected_sources.add(key)


def _discover_audit_files(
    path: str | Path,
    *,
    project_root: Path,
    changed_files: list[str | Path] | None,
    exclude_folders: list[str],
    exclude_paths: list[str | Path] | None,
) -> tuple[list[Path], set[str]]:
    excluded_paths = _normalized_exclude_paths(project_root, exclude_paths)
    rejected_sources: set[str] = set()
    if changed_files is not None:
        files = []
        for item in changed_files:
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = project_root / candidate
            if should_exclude_path(candidate, project_root, exclude_folders):
                continue
            if _is_excluded_output_path(candidate, project_root, excluded_paths):
                continue
            resolved = _resolve_audit_file(
                candidate,
                project_root,
                rejected_sources=rejected_sources,
                report_rejection=True,
            )
            if resolved is None:
                continue
            files.append(resolved)
        return sorted(set(files)), rejected_sources

    discovered = discover_source_files(
        path,
        [ext for ext in DEEP_AUDIT_EXTENSIONS if ext != ".env"],
        exclude_folders=exclude_folders,
    )
    raw_target = Path(path)
    target = raw_target.resolve()
    root = target.parent if target.is_file() else target
    if target.is_file():
        resolved_target = _resolve_audit_file(
            raw_target,
            project_root,
            rejected_sources=rejected_sources,
            report_rejection=True,
        )
        if (
            resolved_target is not None
            and not should_exclude_path(target, root, exclude_folders)
            and not _is_excluded_output_path(target, project_root, excluded_paths)
        ):
            discovered.append(resolved_target)
    else:
        for env_file in target.rglob(".env*"):
            if should_exclude_path(env_file, target, exclude_folders):
                continue
            if _is_excluded_output_path(env_file, project_root, excluded_paths):
                continue
            resolved_env = _resolve_audit_file(
                env_file,
                project_root,
                rejected_sources=rejected_sources,
                report_rejection=not env_file.is_symlink(),
            )
            if resolved_env is not None:
                discovered.append(resolved_env)
    resolved_files: set[Path] = set()
    for file_path in discovered:
        if _is_excluded_output_path(file_path, project_root, excluded_paths):
            continue
        resolved = _resolve_audit_file(
            file_path,
            project_root,
            rejected_sources=rejected_sources,
            report_rejection=True,
        )
        if resolved is not None:
            resolved_files.add(resolved)
    return sorted(resolved_files), rejected_sources


def _is_audit_file(path: Path) -> bool:
    if path.name == ".env" or path.name.startswith(".env."):
        return True
    return path.suffix.lower() in DEEP_AUDIT_EXTENSIONS


def _normalized_exclude_paths(
    project_root: Path,
    exclude_paths: list[str | Path] | None,
) -> set[str]:
    excluded: set[str] = set()
    for item in exclude_paths or []:
        try:
            excluded.add(normalize_relative_path(project_root, item))
        except ValueError:
            continue
    return excluded


def _is_excluded_output_path(
    path: Path,
    project_root: Path,
    excluded_paths: set[str],
) -> bool:
    if not excluded_paths:
        return False
    try:
        rel_path = normalize_relative_path(project_root, path)
    except ValueError:
        return False
    return any(
        rel_path == excluded or rel_path.startswith(f"{excluded}/")
        for excluded in excluded_paths
    )


def _build_static_candidates(
    files: list[Path],
    *,
    project_root: Path,
    static_result: dict[str, Any],
    source_cache: dict[str, str],
) -> dict[str, list[AuditCandidate]]:
    candidates_by_file: dict[str, list[AuditCandidate]] = {
        normalize_relative_path(project_root, file_path): [] for file_path in files
    }

    for finding in static_result.get("danger", []) or []:
        try:
            rel_path = _finding_rel_path(finding, project_root)
        except ValueError:
            continue
        if rel_path not in candidates_by_file:
            continue
        candidates_by_file[rel_path].append(
            _candidate_from_finding(
                finding,
                rel_path=rel_path,
                source=source_cache.get(rel_path, ""),
                kind="static_finding",
                redacted=False,
            )
        )

    for finding in static_result.get("secrets", []) or []:
        try:
            rel_path = _finding_rel_path(finding, project_root)
        except ValueError:
            continue
        if rel_path not in candidates_by_file:
            continue
        candidates_by_file[rel_path].append(
            _candidate_from_finding(
                finding,
                rel_path=rel_path,
                source=source_cache.get(rel_path, ""),
                kind="static_finding",
                redacted=True,
                reason_prefix="Secret candidate redacted before persistence",
            )
        )

    return candidates_by_file


def _merge_direct_secret_findings(
    static_result: dict[str, Any],
    files: list[Path],
    *,
    project_root: Path,
    source_cache: dict[str, str],
) -> None:
    seen = {
        (
            str(item.get("file") or ""),
            int(item.get("line") or 1),
            str(item.get("rule_id") or ""),
            str(item.get("provider") or ""),
        )
        for item in static_result.get("secrets", []) or []
        if isinstance(item, dict)
    }
    secrets = list(static_result.get("secrets", []) or [])
    for file_path in files:
        rel_path = normalize_relative_path(project_root, file_path)
        source = source_cache.get(rel_path)
        if source is None:
            continue
        findings = scan_secrets_ctx(
            {
                "relpath": rel_path,
                "lines": source.splitlines(True),
                "tree": None,
            }
        )
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            key = (
                str(finding.get("file") or ""),
                int(finding.get("line") or 1),
                str(finding.get("rule_id") or ""),
                str(finding.get("provider") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            secrets.append(finding)
    static_result["secrets"] = secrets


def _add_repo_activation_candidates(
    candidates_by_file: dict[str, list[AuditCandidate]],
    files: list[Path],
    *,
    project_root: Path,
    static_result: dict[str, Any],
) -> None:
    static_findings = {
        "security": list(static_result.get("danger", []) or []),
        "secrets": list(static_result.get("secrets", []) or []),
        "quality": [],
    }
    python_files = [
        file_path for file_path in files if file_path.suffix.lower() == ".py"
    ]
    index = build_repo_activation_index(
        python_files,
        project_root=project_root,
        static_findings=static_findings,
    )
    for meta in index.by_path.values():
        try:
            rel_path = normalize_relative_path(project_root, meta.path)
        except ValueError:
            continue
        if rel_path not in candidates_by_file:
            continue
        reasons = list(
            meta.entrypoint_reasons + meta.registration_hints + meta.security_hints
        )
        if not reasons:
            continue
        reason = "; ".join(reasons[:3])
        candidate_id = _candidate_id(
            rel_path=rel_path,
            kind="entrypoint",
            rule_id="SKY-AUDIT-ENTRYPOINT",
            line=1,
            symbol=meta.module,
            code_hash=sha256_text(reason)[:16],
        )
        candidates_by_file[rel_path].append(
            AuditCandidate(
                candidate_id=candidate_id,
                kind="entrypoint",
                rule_id="SKY-AUDIT-ENTRYPOINT",
                line=1,
                severity_hint="medium",
                reason=reason,
                signal_quality=SIGNAL_QUALITY_EXPLORATORY,
                priority=450 + min(meta.review_score, 250),
                symbol=meta.module,
                code_hash=sha256_text(reason)[:16],
                data={
                    "review_score": meta.review_score,
                    "prefer_full_file_review": meta.prefer_full_file_review,
                },
            )
        )


def _add_polyglot_signal_candidates(
    candidates_by_file: dict[str, list[AuditCandidate]],
    files: list[Path],
    *,
    project_root: Path,
) -> None:
    for file_path in files:
        rel_path = normalize_relative_path(project_root, file_path)
        existing = candidates_by_file.setdefault(rel_path, [])
        existing_locations = {
            (candidate.rule_id, candidate.line) for candidate in existing
        }
        for candidate in build_polyglot_signal_candidates(
            file_path,
            project_root=project_root,
        ):
            if (candidate.rule_id, candidate.line) in existing_locations:
                continue
            existing.append(candidate)
            existing_locations.add((candidate.rule_id, candidate.line))


def _add_threat_trace_candidates(
    candidates_by_file: dict[str, list[AuditCandidate]],
    files: list[Path],
    *,
    project_root: Path,
) -> None:
    for trace in build_static_threat_traces(project_root, files):
        rel_path = normalize_relative_path(project_root, trace.file)
        if rel_path not in candidates_by_file:
            continue
        reason = (
            "Static threat trace: "
            f"{trace.source.name} reaches {trace.sink.name} in {trace.entrypoint}"
        )
        candidate_id = _candidate_id(
            rel_path=rel_path,
            kind=THREAT_TRACE_KIND,
            rule_id=THREAT_TRACE_RULE_ID,
            line=trace.sink.line,
            source_kind=trace.source.name,
            sink_kind=trace.sink.name,
            code_hash=trace.trace_id,
        )
        candidates_by_file.setdefault(rel_path, []).append(
            AuditCandidate(
                candidate_id=candidate_id,
                kind=THREAT_TRACE_KIND,
                rule_id=THREAT_TRACE_RULE_ID,
                line=trace.sink.line,
                severity_hint="high",
                reason=reason,
                evidence=trace.validation,
                # This is a concrete static path, but exploitability and
                # runtime reachability remain explicitly unvalidated.
                signal_quality=SIGNAL_QUALITY_STRONG,
                redacted=False,
                priority=875,
                symbol=trace.entrypoint,
                source_kind=trace.source.name,
                sink_kind=trace.sink.name,
                code_hash=trace.trace_id,
                data={"threat_trace": trace.to_dict()},
            )
        )


def _add_path_signal_candidates(
    candidates_by_file: dict[str, list[AuditCandidate]],
    files: list[Path],
    *,
    project_root: Path,
) -> None:
    for file_path in files:
        rel_path = normalize_relative_path(project_root, file_path)
        lowered = rel_path.lower()
        matched = [token for token in SECURITY_PATH_TOKENS if token in lowered]
        if not matched:
            continue
        reason = "Path suggests security-sensitive surface: " + ", ".join(matched[:4])
        candidate_id = _candidate_id(
            rel_path=rel_path,
            kind="path_signal",
            rule_id="SKY-AUDIT-PATH",
            line=1,
            code_hash=sha256_text(reason)[:16],
        )
        candidates_by_file.setdefault(rel_path, []).append(
            AuditCandidate(
                candidate_id=candidate_id,
                kind="path_signal",
                rule_id="SKY-AUDIT-PATH",
                line=1,
                severity_hint="medium",
                reason=reason,
                signal_quality=SIGNAL_QUALITY_EXPLORATORY,
                priority=350,
                code_hash=sha256_text(reason)[:16],
                data={"matched_tokens": matched},
            )
        )


def _candidate_from_finding(
    finding: dict[str, Any],
    *,
    rel_path: str,
    source: str,
    kind: str,
    redacted: bool,
    reason_prefix: str | None = None,
) -> AuditCandidate:
    line = int(finding.get("line") or finding.get("lineno") or 1)
    rule_id = str(finding.get("rule_id") or "SKY-AUDIT")
    severity = str(finding.get("severity") or "medium").lower()
    message = str(finding.get("message") or rule_id)
    safe_finding = sanitize_for_audit(finding)
    code_hash = code_region_hash(source, line)
    reason = sanitize_for_audit(message)
    if reason_prefix:
        reason = f"{reason_prefix}: {reason}"
    symbol = finding.get("symbol") or finding.get("name")
    candidate_id = _candidate_id(
        rel_path=rel_path,
        kind=kind,
        rule_id=rule_id,
        line=line,
        symbol=str(symbol) if symbol else None,
        source_kind=str(finding.get("source")) if finding.get("source") else None,
        sink_kind=str(finding.get("sink")) if finding.get("sink") else None,
        code_hash=code_hash,
    )
    return AuditCandidate(
        candidate_id=candidate_id,
        kind=kind,
        rule_id=rule_id,
        line=line,
        severity_hint=severity,
        reason=str(reason),
        evidence="static",
        signal_quality=SIGNAL_QUALITY_STRONG,
        redacted=redacted,
        priority=SEVERITY_PRIORITY.get(severity, 400),
        symbol=str(symbol) if symbol else None,
        source_kind=str(finding.get("source")) if finding.get("source") else None,
        sink_kind=str(finding.get("sink")) if finding.get("sink") else None,
        code_hash=code_hash,
        data=safe_finding if isinstance(safe_finding, dict) else {},
    )


def _candidate_sort_key(candidate: AuditCandidate) -> tuple[int, int, str]:
    """Order evidence quality independently from severity-derived priority."""

    quality_rank = SIGNAL_QUALITY_RANK.get(candidate.signal_quality, 0)
    return (-quality_rank, -candidate.priority, candidate.candidate_id)


def _candidate_coverage(
    files: list[Path],
    *,
    project_root: Path,
    candidates_by_file: dict[str, list[AuditCandidate]],
    scope: str,
    rejected_source_files: int,
) -> dict[str, Any]:
    """Summarize observed candidate coverage without claiming measured recall."""

    by_language: dict[str, dict[str, int]] = {}
    by_rule: dict[str, dict[str, int]] = {}
    by_signal_quality = {
        SIGNAL_QUALITY_PROVEN: 0,
        SIGNAL_QUALITY_STRONG: 0,
        SIGNAL_QUALITY_EXPLORATORY: 0,
    }
    by_kind: dict[str, int] = {}
    files_with_candidates = 0
    candidate_count = 0

    for file_path in files:
        rel_path = normalize_relative_path(project_root, file_path)
        language = language_for_path(file_path)
        candidate_map = {
            candidate.candidate_id: candidate
            for candidate in candidates_by_file.get(rel_path, [])
        }
        candidates = list(candidate_map.values())
        language_bucket = by_language.setdefault(
            language,
            {
                "files_scanned": 0,
                "files_with_candidates": 0,
                "candidate_count": 0,
            },
        )
        language_bucket["files_scanned"] += 1
        if candidates:
            files_with_candidates += 1
            language_bucket["files_with_candidates"] += 1
        language_bucket["candidate_count"] += len(candidates)
        candidate_count += len(candidates)

        rules_seen: set[str] = set()
        for candidate in candidates:
            by_signal_quality[candidate.signal_quality] = (
                by_signal_quality.get(candidate.signal_quality, 0) + 1
            )
            kind = (
                candidate.kind
                if candidate.kind in _CANDIDATE_COVERAGE_KINDS
                else "other"
            )
            by_kind[kind] = by_kind.get(kind, 0) + 1
            rule_id = _coverage_rule_id(candidate.rule_id)
            rule_bucket = by_rule.setdefault(
                rule_id,
                {"candidate_count": 0, "files_with_candidates": 0},
            )
            rule_bucket["candidate_count"] += 1
            rules_seen.add(rule_id)
        for rule_id in rules_seen:
            by_rule[rule_id]["files_with_candidates"] += 1

    return {
        "schema_version": 1,
        "metric": "candidate_observation_coverage",
        "scope": scope,
        "interpretation": (
            "Observed scanner candidates only; this is not labeled recall."
        ),
        "files_scanned": len(files),
        "rejected_source_files": rejected_source_files,
        "files_with_candidates": files_with_candidates,
        "files_without_candidates": len(files) - files_with_candidates,
        "candidate_count": candidate_count,
        "by_language": dict(sorted(by_language.items())),
        "by_rule": _bounded_rule_buckets(by_rule),
        "by_signal_quality": dict(sorted(by_signal_quality.items())),
        "by_kind": dict(sorted(by_kind.items())),
    }


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


def _bounded_rule_buckets(
    buckets: dict[str, dict[str, int]],
) -> dict[str, dict[str, int]]:
    if len(buckets) <= MAX_COVERAGE_RULE_BUCKETS:
        return dict(sorted(buckets.items()))

    ordered = sorted(
        buckets.items(),
        key=lambda item: (-item[1]["candidate_count"], item[0]),
    )
    visible = dict(ordered[: MAX_COVERAGE_RULE_BUCKETS - 1])
    overflow = {"candidate_count": 0, "files_with_candidates": 0}
    for _rule_id, metrics in ordered[MAX_COVERAGE_RULE_BUCKETS - 1 :]:
        for key in overflow:
            overflow[key] += metrics[key]
    if "other" in visible:
        for key in overflow:
            visible["other"][key] += overflow[key]
    else:
        visible["other"] = overflow
    return dict(sorted(visible.items()))


def _candidate_id(
    *,
    rel_path: str,
    kind: str,
    rule_id: str,
    line: int,
    symbol: str | None = None,
    source_kind: str | None = None,
    sink_kind: str | None = None,
    code_hash: str | None = None,
) -> str:
    payload = json.dumps(
        {
            "path": rel_path,
            "kind": kind,
            "rule_id": rule_id,
            "line": line if not code_hash else None,
            "symbol": symbol,
            "source_kind": source_kind,
            "sink_kind": sink_kind,
            "code_hash": code_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "cand-" + sha256_text(payload)[:16]


def _finding_rel_path(finding: dict[str, Any], project_root: Path) -> str:
    file_value = finding.get("file") or finding.get("path") or ""
    return normalize_relative_path(project_root, file_value)


def _source_cache(files: list[Path], *, project_root: Path) -> dict[str, str]:
    cache: dict[str, str] = {}
    for file_path in files:
        rel_path = normalize_relative_path(project_root, file_path)
        source = read_audit_source_text(
            project_root,
            file_path,
            max_bytes=MAX_AUDIT_SOURCE_BYTES,
        )
        if source is not None:
            cache[rel_path] = source
    return cache
