from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from skylos.audit.redaction import sanitize_for_audit
from skylos.audit.polyglot import build_polyglot_signal_candidates
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    DEFAULT_PROJECT_ID,
    STATUS_ERROR,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    AuditCandidate,
    AuditScanSummary,
    code_region_hash,
    language_for_path,
    normalize_relative_path,
    sha256_file,
    sha256_text,
    stable_json_hash,
)
from skylos.config import load_config
from skylos.constants import parse_exclude_folders
from skylos.core.file_discovery import discover_source_files, should_exclude_path
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

    files = _discover_audit_files(
        path,
        project_root=project_root,
        changed_files=changed_files,
        exclude_folders=parsed_excludes,
        exclude_paths=exclude_paths,
    )
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
    )
    candidates_by_file = _build_static_candidates(
        files,
        project_root=project_root,
        static_result=static_result,
    )
    _add_polyglot_signal_candidates(
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
    store.init_project(config_hash=config_hash)
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
            key=lambda item: (-item.priority, item.candidate_id),
        )
        file_hash = sha256_file(Path(file_path))
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
        complete=(pending_files == 0 and processing_files == 0 and error_files == 0),
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


def _resolve_audit_file(path: Path, project_root: Path) -> Path | None:
    candidate = Path(path)
    if candidate.is_symlink():
        return None
    if not _is_audit_file(candidate):
        return None
    try:
        root = project_root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    if not resolved.is_file():
        return None
    return resolved


def _discover_audit_files(
    path: str | Path,
    *,
    project_root: Path,
    changed_files: list[str | Path] | None,
    exclude_folders: list[str],
    exclude_paths: list[str | Path] | None,
) -> list[Path]:
    excluded_paths = _normalized_exclude_paths(project_root, exclude_paths)
    if changed_files is not None:
        files = []
        for item in changed_files:
            try:
                rel = normalize_relative_path(project_root, item)
            except ValueError:
                continue
            candidate = project_root / rel
            if should_exclude_path(candidate, project_root, exclude_folders):
                continue
            if _is_excluded_output_path(candidate, project_root, excluded_paths):
                continue
            resolved = _resolve_audit_file(candidate, project_root)
            if resolved is not None:
                files.append(resolved)
        return sorted(set(files))

    discovered = discover_source_files(
        path,
        [ext for ext in DEEP_AUDIT_EXTENSIONS if ext != ".env"],
        exclude_folders=exclude_folders,
    )
    target = Path(path).resolve()
    root = target.parent if target.is_file() else target
    if target.is_file():
        resolved_target = _resolve_audit_file(target, project_root)
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
            resolved_env = _resolve_audit_file(env_file, project_root)
            if resolved_env is not None:
                discovered.append(resolved_env)
    return sorted(
        {
            resolved
            for file_path in discovered
            if (resolved := _resolve_audit_file(file_path, project_root)) is not None
            if not _is_excluded_output_path(file_path, project_root, excluded_paths)
        }
    )


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
) -> dict[str, list[AuditCandidate]]:
    source_cache = _source_cache(files, project_root=project_root)
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
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
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
            file_path, project_root=project_root
        ):
            if (candidate.rule_id, candidate.line) in existing_locations:
                continue
            existing.append(candidate)
            existing_locations.add((candidate.rule_id, candidate.line))


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
        redacted=redacted,
        priority=SEVERITY_PRIORITY.get(severity, 400),
        symbol=str(symbol) if symbol else None,
        source_kind=str(finding.get("source")) if finding.get("source") else None,
        sink_kind=str(finding.get("sink")) if finding.get("sink") else None,
        code_hash=code_hash,
        data=safe_finding if isinstance(safe_finding, dict) else {},
    )


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
        try:
            cache[rel_path] = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            cache[rel_path] = ""
    return cache
