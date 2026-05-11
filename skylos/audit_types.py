from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import skylos

SCHEMA_VERSION = 1
CANDIDATE_ENGINE_VERSION = "deep-audit-v1"
DEFAULT_PROJECT_ID = "default"

STATUS_PENDING = "pending"
STATUS_PROCESSING = "processing"
STATUS_ANALYZED = "analyzed"
STATUS_ERROR = "error"
STATUS_NOT_ANALYZED = "not_analyzed"
STATUS_SKIPPED = "skipped"
STATUS_DELETED = "deleted"

VALID_STATUSES = {
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_ANALYZED,
    STATUS_ERROR,
    STATUS_NOT_ANALYZED,
    STATUS_SKIPPED,
    STATUS_DELETED,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_json_hash(value: Any) -> str:
    try:
        payload = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    except TypeError:
        payload = repr(value)
    return sha256_text(payload)


def normalize_relative_path(project_root: str | Path, file_path: str | Path) -> str:
    root = Path(project_root).resolve()
    candidate = Path(file_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        rel = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Audit path escapes project root: {file_path}") from exc
    return rel.as_posix()


def language_for_path(path: str | Path) -> str:
    path_obj = Path(path)
    if path_obj.name == ".env" or path_obj.name.startswith(".env."):
        return "env"
    suffix = path_obj.suffix.lower()
    return {
        ".py": "python",
        ".pyi": "python",
        ".pyw": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".go": "go",
        ".java": "java",
        ".php": "php",
        ".rs": "rust",
        ".dart": "dart",
        ".env": "env",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".toml": "toml",
        ".ini": "ini",
        ".cfg": "config",
        ".conf": "config",
    }.get(suffix, suffix.lstrip(".") or "unknown")


def code_region_hash(source: str, line: int | None, *, radius: int = 2) -> str:
    lines = source.splitlines()
    if not lines:
        return sha256_text("")
    if not line or line < 1:
        region = "\n".join(lines[: min(len(lines), radius * 2 + 1)])
    else:
        start = max(0, line - 1 - radius)
        end = min(len(lines), line + radius)
        region = "\n".join(lines[start:end])
    normalized = "\n".join(part.strip() for part in region.splitlines() if part.strip())
    return sha256_text(normalized)[:16]


@dataclass
class AuditCandidate:
    candidate_id: str
    kind: str
    rule_id: str
    line: int
    severity_hint: str
    reason: str
    evidence: str = "static"
    redacted: bool = False
    priority: int = 0
    symbol: str | None = None
    source_kind: str | None = None
    sink_kind: str | None = None
    code_hash: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "candidate_id": self.candidate_id,
            "kind": self.kind,
            "rule_id": self.rule_id,
            "line": self.line,
            "severity_hint": self.severity_hint,
            "reason": self.reason,
            "evidence": self.evidence,
            "redacted": self.redacted,
            "priority": self.priority,
            "symbol": self.symbol,
            "source_kind": self.source_kind,
            "sink_kind": self.sink_kind,
            "code_hash": self.code_hash,
            "data": dict(self.data),
        }
        return {key: value for key, value in payload.items() if value is not None}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditCandidate":
        return cls(
            candidate_id=str(payload["candidate_id"]),
            kind=str(payload["kind"]),
            rule_id=str(payload.get("rule_id") or "SKY-AUDIT"),
            line=int(payload.get("line") or 1),
            severity_hint=str(payload.get("severity_hint") or "medium").lower(),
            reason=str(payload.get("reason") or ""),
            evidence=str(payload.get("evidence") or "static"),
            redacted=bool(payload.get("redacted", False)),
            priority=int(payload.get("priority") or 0),
            symbol=str(payload["symbol"]) if payload.get("symbol") else None,
            source_kind=(
                str(payload["source_kind"]) if payload.get("source_kind") else None
            ),
            sink_kind=str(payload["sink_kind"]) if payload.get("sink_kind") else None,
            code_hash=str(payload["code_hash"]) if payload.get("code_hash") else None,
            data=dict(payload.get("data") or {}),
        )


@dataclass
class AuditFileRecord:
    project_id: str
    project_root: str
    file: str
    file_hash: str
    language: str
    status: str
    candidates: list[AuditCandidate] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    analysis_history: list[dict[str, Any]] = field(default_factory=list)
    revalidation: list[dict[str, Any]] = field(default_factory=list)
    locked_by_run_id: str | None = None
    locked_at: str | None = None
    last_scanned_at: str | None = None
    last_analyzed_at: str | None = None
    skylos_version: str = skylos.__version__
    config_hash: str = ""
    candidate_engine_version: str = CANDIDATE_ENGINE_VERSION
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "project_root": self.project_root,
            "file": self.file,
            "file_hash": self.file_hash,
            "language": self.language,
            "status": self.status,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "findings": list(self.findings),
            "analysis_history": list(self.analysis_history),
            "revalidation": list(self.revalidation),
            "locked_by_run_id": self.locked_by_run_id,
            "locked_at": self.locked_at,
            "last_scanned_at": self.last_scanned_at,
            "last_analyzed_at": self.last_analyzed_at,
            "skylos_version": self.skylos_version,
            "config_hash": self.config_hash,
            "candidate_engine_version": self.candidate_engine_version,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditFileRecord":
        schema_version = int(payload.get("schema_version") or 0)
        if schema_version != SCHEMA_VERSION:
            raise ValueError(f"Unsupported audit schema version: {schema_version}")

        status = str(payload.get("status") or "")
        if status not in VALID_STATUSES:
            raise ValueError(f"Unsupported audit file status: {status}")

        return cls(
            schema_version=schema_version,
            project_id=str(payload["project_id"]),
            project_root=str(payload["project_root"]),
            file=str(payload["file"]),
            file_hash=str(payload["file_hash"]),
            language=str(payload.get("language") or "unknown"),
            status=status,
            candidates=[
                AuditCandidate.from_dict(item)
                for item in payload.get("candidates") or []
                if isinstance(item, dict)
            ],
            findings=[
                dict(item)
                for item in payload.get("findings") or []
                if isinstance(item, dict)
            ],
            analysis_history=[
                dict(item)
                for item in payload.get("analysis_history") or []
                if isinstance(item, dict)
            ],
            revalidation=[
                dict(item)
                for item in payload.get("revalidation") or []
                if isinstance(item, dict)
            ],
            locked_by_run_id=(
                str(payload["locked_by_run_id"])
                if payload.get("locked_by_run_id")
                else None
            ),
            locked_at=str(payload["locked_at"]) if payload.get("locked_at") else None,
            last_scanned_at=(
                str(payload["last_scanned_at"])
                if payload.get("last_scanned_at")
                else None
            ),
            last_analyzed_at=(
                str(payload["last_analyzed_at"])
                if payload.get("last_analyzed_at")
                else None
            ),
            skylos_version=str(payload.get("skylos_version") or skylos.__version__),
            config_hash=str(payload.get("config_hash") or ""),
            candidate_engine_version=str(payload.get("candidate_engine_version") or ""),
        )


@dataclass
class AuditScanSummary:
    project_id: str
    project_root: str
    files_scanned: int
    records_written: int
    candidate_count: int
    redacted_candidates: int
    pending_files: int
    not_analyzed_files: int
    processing_files: int = 0
    error_files: int = 0
    deleted_files: int = 0
    complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "project_root": self.project_root,
            "files_scanned": self.files_scanned,
            "records_written": self.records_written,
            "candidate_count": self.candidate_count,
            "redacted_candidates": self.redacted_candidates,
            "pending_files": self.pending_files,
            "processing_files": self.processing_files,
            "not_analyzed_files": self.not_analyzed_files,
            "error_files": self.error_files,
            "deleted_files": self.deleted_files,
            "complete": self.complete,
        }


@dataclass
class AuditProcessSummary:
    run_id: str
    project_id: str
    project_root: str
    considered_files: int
    processed_files: int
    findings_added: int
    skipped_secret_files: int
    unsupported_files: int
    locked_files: int
    error_files: int
    remaining_pending_files: int
    limited: bool
    complete: bool
    pending_files: int = 0
    processing_files: int = 0
    analyzed_files: int = 0
    stale_analyzed_files: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "project_id": self.project_id,
            "project_root": self.project_root,
            "considered_files": self.considered_files,
            "processed_files": self.processed_files,
            "findings_added": self.findings_added,
            "skipped_secret_files": self.skipped_secret_files,
            "unsupported_files": self.unsupported_files,
            "locked_files": self.locked_files,
            "error_files": self.error_files,
            "remaining_pending_files": self.remaining_pending_files,
            "limited": self.limited,
            "complete": self.complete,
            "pending_files": self.pending_files,
            "processing_files": self.processing_files,
            "analyzed_files": self.analyzed_files,
            "stale_analyzed_files": self.stale_analyzed_files,
        }


@dataclass
class AuditCIGateSummary:
    fail_on: str
    exit_code: int
    blocking_counts: dict[str, int]
    complete: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on": self.fail_on,
            "exit_code": self.exit_code,
            "blocking_counts": dict(self.blocking_counts),
            "complete": self.complete,
            "reason": self.reason,
        }


@dataclass
class AuditRevalidationSummary:
    run_id: str
    project_id: str
    project_root: str
    considered_findings: int
    revalidated_findings: int
    challenged_findings: int
    skipped_findings: int
    error_findings: int
    true_positive: int
    false_positive: int
    fixed: int
    uncertain: int
    forced: bool
    challenge: bool
    complete: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "project_id": self.project_id,
            "project_root": self.project_root,
            "considered_findings": self.considered_findings,
            "revalidated_findings": self.revalidated_findings,
            "challenged_findings": self.challenged_findings,
            "skipped_findings": self.skipped_findings,
            "error_findings": self.error_findings,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "fixed": self.fixed,
            "uncertain": self.uncertain,
            "forced": self.forced,
            "challenge": self.challenge,
            "complete": self.complete,
        }
