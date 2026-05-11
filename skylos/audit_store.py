from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import skylos
from skylos.audit_redaction import sanitize_for_audit
from skylos.audit_types import (
    CANDIDATE_ENGINE_VERSION,
    DEFAULT_PROJECT_ID,
    SCHEMA_VERSION,
    STATUS_ANALYZED,
    STATUS_ERROR,
    STATUS_DELETED,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_SKIPPED,
    AuditCandidate,
    AuditFileRecord,
    normalize_relative_path,
    utc_now,
)


class AuditStore:
    def __init__(
        self,
        project_root: str | Path,
        *,
        project_id: str = DEFAULT_PROJECT_ID,
        audit_root: str | Path | None = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.project_id = project_id
        base = (
            Path(audit_root).resolve()
            if audit_root
            else self.project_root / ".skylos" / "audit"
        )
        self.project_dir = base / "projects" / project_id
        self.files_dir = self.project_dir / "files"
        self.runs_dir = self.project_dir / "runs"
        self.exports_dir = self.project_dir / "exports"

    def init_project(self, *, config_hash: str) -> None:
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(
            self.project_dir / "project.json",
            {
                "schema_version": SCHEMA_VERSION,
                "project_id": self.project_id,
                "project_root": str(self.project_root),
                "skylos_version": skylos.__version__,
                "candidate_engine_version": CANDIDATE_ENGINE_VERSION,
                "updated_at": utc_now(),
            },
        )
        self._write_json_atomic(
            self.project_dir / "config.json",
            {
                "schema_version": SCHEMA_VERSION,
                "config_hash": config_hash,
                "updated_at": utc_now(),
            },
        )

    def encoded_record_name(self, rel_path: str) -> str:
        normalized = rel_path.replace("\\", "/")
        encoded = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii")
        return encoded.rstrip("=") + ".json"

    def decoded_record_name(self, filename: str) -> str | None:
        if not filename.endswith(".json"):
            return None
        stem = filename[:-5]
        padding = "=" * (-len(stem) % 4)
        try:
            return base64.urlsafe_b64decode(stem + padding).decode("utf-8")
        except Exception:
            return None

    def record_path(self, file_path: str | Path) -> Path:
        rel_path = normalize_relative_path(self.project_root, file_path)
        return self.files_dir / self.encoded_record_name(rel_path)

    def read_file_record(self, file_path: str | Path) -> AuditFileRecord | None:
        requested_rel_path = normalize_relative_path(self.project_root, file_path)
        record_path = self.record_path(file_path)
        try:
            payload = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        try:
            record = AuditFileRecord.from_dict(payload)
        except (KeyError, TypeError, ValueError):
            return None
        if record.project_id != self.project_id:
            return None
        if Path(record.project_root).resolve() != self.project_root:
            return None
        try:
            record_rel_path = normalize_relative_path(self.project_root, record.file)
        except ValueError:
            return None
        if record_rel_path != requested_rel_path:
            return None
        return record

    def iter_file_records(self) -> list[AuditFileRecord]:
        records: list[AuditFileRecord] = []
        if not self.files_dir.exists():
            return records
        for record_file in sorted(self.files_dir.glob("*.json")):
            rel_path = self.decoded_record_name(record_file.name)
            if not rel_path:
                continue
            record = self.read_file_record(rel_path)
            if record is not None:
                records.append(record)
        return records

    def write_file_record(self, record: AuditFileRecord) -> None:
        if record.project_id != self.project_id:
            raise ValueError("Audit record project_id mismatch")
        if Path(record.project_root).resolve() != self.project_root:
            raise ValueError("Audit record project_root mismatch")
        normalize_relative_path(self.project_root, record.file)
        self.files_dir.mkdir(parents=True, exist_ok=True)
        payload = sanitize_for_audit(record.to_dict())
        self._write_json_atomic(self.record_path(record.file), payload)

    def mark_deleted_records(
        self,
        *,
        allowed_files: list[str | Path] | None = None,
        now: str | None = None,
    ) -> list[AuditFileRecord]:
        allowed = self._normalized_allowed_files(allowed_files)
        marked: list[AuditFileRecord] = []
        timestamp = now or utc_now()
        for record in self.iter_file_records():
            if allowed is not None and record.file not in allowed:
                continue
            source_path = self.project_root / record.file
            if source_path.exists():
                continue
            if record.status == STATUS_DELETED:
                marked.append(record)
                continue
            record.status = STATUS_DELETED
            record.locked_by_run_id = None
            record.locked_at = None
            record.last_scanned_at = timestamp
            record.analysis_history.append(
                sanitize_for_audit(
                    {
                        "stage": "file_deleted",
                        "reason": (
                            "Source file no longer exists; record retained as "
                            "audit history."
                        ),
                        "at": timestamp,
                    }
                )
            )
            self.write_file_record(record)
            marked.append(record)
        return marked

    def upsert_scan_record(
        self,
        *,
        file_path: str | Path,
        file_hash: str,
        language: str,
        candidates: list[AuditCandidate],
        config_hash: str,
        now: str | None = None,
    ) -> AuditFileRecord:
        rel_path = normalize_relative_path(self.project_root, file_path)
        now = now or utc_now()
        existing = self.read_file_record(rel_path)
        candidate_map = {candidate.candidate_id: candidate for candidate in candidates}
        ordered_candidates = sorted(
            candidate_map.values(), key=lambda item: (-item.priority, item.candidate_id)
        )

        status = STATUS_PENDING if ordered_candidates else STATUS_NOT_ANALYZED
        preserve_history = existing is not None
        current_scan_matches = existing and self._record_matches_current_scan(
            existing,
            file_hash=file_hash,
            config_hash=config_hash,
        )
        if existing and current_scan_matches:
            existing_ids = {candidate.candidate_id for candidate in existing.candidates}
            new_ids = set(candidate_map)
            if existing.status == STATUS_ANALYZED and existing_ids == new_ids:
                status = STATUS_ANALYZED
            elif existing.status == STATUS_PROCESSING:
                status = STATUS_PROCESSING
            elif existing.status == STATUS_ERROR and existing_ids == new_ids:
                status = STATUS_ERROR

        record = AuditFileRecord(
            project_id=self.project_id,
            project_root=str(self.project_root),
            file=rel_path,
            file_hash=file_hash,
            language=language,
            status=status,
            candidates=ordered_candidates,
            findings=(
                sanitize_for_audit(list(existing.findings)) if preserve_history else []
            ),
            analysis_history=(
                sanitize_for_audit(list(existing.analysis_history))
                if preserve_history
                else []
            ),
            revalidation=(
                sanitize_for_audit(list(existing.revalidation))
                if preserve_history
                else []
            ),
            locked_by_run_id=(
                existing.locked_by_run_id
                if existing and preserve_history and status == STATUS_PROCESSING
                else None
            ),
            locked_at=(
                existing.locked_at
                if existing and preserve_history and status == STATUS_PROCESSING
                else None
            ),
            last_scanned_at=now,
            last_analyzed_at=(existing.last_analyzed_at if preserve_history else None),
            skylos_version=skylos.__version__,
            config_hash=config_hash,
            candidate_engine_version=CANDIDATE_ENGINE_VERSION,
        )
        self.write_file_record(record)
        return record

    def acquire_lock(
        self,
        file_path: str | Path,
        *,
        run_id: str,
        stale_after_seconds: int = 3600,
        now: str | None = None,
    ) -> bool:
        record = self.read_file_record(file_path)
        if record is None:
            return False
        if record.status == STATUS_ANALYZED:
            return False
        if record.status in {STATUS_NOT_ANALYZED, STATUS_SKIPPED}:
            return False
        now = now or utc_now()
        if (
            record.status == STATUS_PROCESSING
            and record.locked_by_run_id
            and record.locked_by_run_id != run_id
            and not self._lock_is_stale(record.locked_at, stale_after_seconds)
        ):
            return False
        record.status = STATUS_PROCESSING
        record.locked_by_run_id = run_id
        record.locked_at = now
        self.write_file_record(record)
        return True

    def mark_error(self, file_path: str | Path, message: str) -> None:
        record = self.read_file_record(file_path)
        if record is None:
            return
        record.status = STATUS_ERROR
        record.locked_by_run_id = None
        record.locked_at = None
        record.analysis_history.append(
            {
                "stage": "error",
                "message": sanitize_for_audit(message),
                "at": utc_now(),
            }
        )
        self.write_file_record(record)

    def write_run(self, run_id: str, payload: dict[str, Any]) -> Path:
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        run_path = self.runs_dir / f"{run_id}.json"
        merged = {
            "schema_version": SCHEMA_VERSION,
            "project_id": self.project_id,
            "project_root": str(self.project_root),
            "run_id": run_id,
            "created_at": utc_now(),
            **sanitize_for_audit(payload),
        }
        self._write_json_atomic(run_path, merged)
        return run_path

    def _record_matches_current_scan(
        self,
        record: AuditFileRecord,
        *,
        file_hash: str,
        config_hash: str,
    ) -> bool:
        return (
            record.schema_version == SCHEMA_VERSION
            and record.file_hash == file_hash
            and record.config_hash == config_hash
            and record.candidate_engine_version == CANDIDATE_ENGINE_VERSION
            and record.skylos_version == skylos.__version__
        )

    def _lock_is_stale(self, locked_at: str | None, stale_after_seconds: int) -> bool:
        if not locked_at:
            return True
        try:
            locked = datetime.fromisoformat(locked_at)
        except ValueError:
            return True
        if locked.tzinfo is None:
            locked = locked.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - locked
        return age.total_seconds() >= stale_after_seconds

    def _normalized_allowed_files(
        self,
        allowed_files: list[str | Path] | None,
    ) -> set[str] | None:
        if allowed_files is None:
            return None
        allowed: set[str] = set()
        for file_path in allowed_files:
            try:
                allowed.add(normalize_relative_path(self.project_root, file_path))
            except ValueError:
                continue
        return allowed

    def _write_json_atomic(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, path)
