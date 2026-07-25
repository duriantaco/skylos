from __future__ import annotations

import base64
import binascii
import json
import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import skylos
from skylos.audit.redaction import sanitize_for_audit
from skylos.audit.types import (
    CANDIDATE_ENGINE_VERSION,
    DEFAULT_PROJECT_ID,
    SCHEMA_VERSION,
    SIGNAL_QUALITY_RANK,
    STATUS_ANALYZED,
    STATUS_ERROR,
    STATUS_DELETED,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_PROCESSING,
    AuditCandidate,
    AuditFileRecord,
    normalize_relative_path,
    stable_json_hash,
    utc_now,
)
from skylos.core.safe_cache_io import read_text_no_symlink


MUTATION_LOCK_TIMEOUT_SECONDS = 5.0
MUTATION_LOCK_POLL_SECONDS = 0.01
MUTATION_LOCK_STALE_SECONDS = 3600.0
MUTATION_LOCK_DIR_NAME = ".mutation.lock"
MAX_AUDIT_RECORD_BYTES = 16_000_000
_FAILURE_OPERATIONAL_INTEGER_KEYS = (
    "attempt_count",
    "attempt_limit",
    "completed_attempt_count",
    "failed_attempt_count",
    "recoverable_failed_attempt_count",
    "turns",
    "llm_calls",
    "tool_calls",
    "source_observation_calls",
    "evidence_bytes",
    "unsafe_discovery_truncations",
    "sensitive_denials",
)
_FAILURE_USAGE_KEYS = frozenset(
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


def _failure_operational_metadata(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("metadata_scope") != "operational_only":
        return None
    metadata: dict[str, Any] = {"metadata_scope": "operational_only"}
    for key in _FAILURE_OPERATIONAL_INTEGER_KEYS:
        observed = value.get(key)
        metadata[key] = (
            observed
            if isinstance(observed, int)
            and not isinstance(observed, bool)
            and observed >= 0
            else 0
        )
    metadata["attempt_budget_exhausted"] = bool(
        value.get("attempt_budget_exhausted") is True
    )
    usage = value.get("usage")
    metadata["usage"] = {
        key: observed
        for key in _FAILURE_USAGE_KEYS
        if isinstance(usage, dict)
        and isinstance((observed := usage.get(key)), int)
        and not isinstance(observed, bool)
        and observed >= 0
    }
    return metadata


class AuditStore:
    def __init__(
        self,
        project_root: str | Path,
        *,
        project_id: str = DEFAULT_PROJECT_ID,
        audit_root: str | Path | None = None,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        if (
            not project_id
            or len(project_id) > 200
            or Path(project_id).name != project_id
            or "/" in project_id
            or "\\" in project_id
            or project_id in {".", ".."}
        ):
            raise ValueError("Audit project_id must be a safe path segment")
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
        self.current_scan_files: set[str] | None = None

    def init_project(
        self,
        *,
        config_hash: str,
        exclude_folders: list[str] | None = None,
        exclude_paths: list[str | Path] | None = None,
    ) -> None:
        self._ensure_directory_no_symlink(self.files_dir)
        self._ensure_directory_no_symlink(self.runs_dir)
        self._ensure_directory_no_symlink(self.exports_dir)
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
                "exclude_folders": sorted(
                    {
                        str(value)
                        for value in (exclude_folders or ())
                        if str(value).strip()
                    }
                ),
                "exclude_paths": sorted(
                    {
                        normalized
                        for value in (exclude_paths or ())
                        if (normalized := self._normalize_optional_project_path(value))
                    }
                ),
                "updated_at": utc_now(),
            },
        )

    def read_scan_excludes(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        text = read_text_no_symlink(
            self.project_dir / "config.json",
            max_bytes=1_000_000,
            encoding="utf-8",
            errors=None,
        )
        if text is None:
            return (), ()
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return (), ()
        if not isinstance(payload, dict):
            return (), ()

        def strings(key: str) -> tuple[str, ...]:
            values = payload.get(key)
            if not isinstance(values, list):
                return ()
            return tuple(
                value
                for value in values
                if isinstance(value, str) and 0 < len(value) <= 1_000
            )

        return strings("exclude_folders"), strings("exclude_paths")

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
        except (binascii.Error, UnicodeError, ValueError):
            return None

    def record_path(self, file_path: str | Path) -> Path:
        rel_path = normalize_relative_path(self.project_root, file_path)
        return self.files_dir / self.encoded_record_name(rel_path)

    def read_file_record(self, file_path: str | Path) -> AuditFileRecord | None:
        requested_rel_path = normalize_relative_path(self.project_root, file_path)
        record_path = self.record_path(file_path)
        text = read_text_no_symlink(  # skylos: ignore[SKY-D325] bounded O_NOFOLLOW state read
            record_path,
            max_bytes=MAX_AUDIT_RECORD_BYTES,
            encoding="utf-8",
            errors=None,
        )
        if text is None:
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
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

    def set_current_scan_files(self, files: list[str | Path]) -> None:
        current: set[str] = set()
        for file_path in files:
            try:
                current.add(normalize_relative_path(self.project_root, file_path))
            except ValueError:
                continue
        self.current_scan_files = current

    def processing_scope(
        self,
        allowed_files: list[str | Path] | set[str] | None = None,
    ) -> set[str] | None:
        requested = self._normalized_allowed_files(allowed_files)
        if self.current_scan_files is None:
            return requested if requested is not None else set()
        if requested is None:
            return set(self.current_scan_files)
        return requested & self.current_scan_files

    def write_file_record(self, record: AuditFileRecord) -> None:
        with self._mutation_guard():
            self._write_file_record_unlocked(record)

    def _write_file_record_unlocked(self, record: AuditFileRecord) -> None:
        if record.project_id != self.project_id:
            raise ValueError("Audit record project_id mismatch")
        if Path(record.project_root).resolve() != self.project_root:
            raise ValueError("Audit record project_root mismatch")
        normalize_relative_path(self.project_root, record.file)
        self._ensure_directory_no_symlink(self.files_dir)
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
        for snapshot in self.iter_file_records():
            if allowed is not None and snapshot.file not in allowed:
                continue
            with self._mutation_guard():
                record = self.read_file_record(snapshot.file)
                if record is None:
                    continue
                source_path = self.project_root / record.file
                if source_path.exists():
                    continue
                if record.status == STATUS_DELETED:
                    marked.append(record)
                    continue
                record.status = STATUS_DELETED
                record.locked_by_run_id = None
                record.lock_lease_id = None
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
                self._write_file_record_unlocked(record)
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
        with self._mutation_guard():
            return self._upsert_scan_record_unlocked(
                file_path=file_path,
                file_hash=file_hash,
                language=language,
                candidates=candidates,
                config_hash=config_hash,
                now=now,
            )

    def _upsert_scan_record_unlocked(
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
        ordered_candidates = self._ordered_scan_candidates(candidates)
        status = self._scan_record_status(
            existing,
            ordered_candidates,
            file_hash=file_hash,
            config_hash=config_hash,
        )
        findings, analysis_history, revalidation = self._preserved_record_lists(
            existing
        )
        locked_by_run_id, lock_lease_id, locked_at = self._preserved_processing_lock(
            existing,
            status=status,
        )

        record = AuditFileRecord(
            project_id=self.project_id,
            project_root=str(self.project_root),
            file=rel_path,
            file_hash=file_hash,
            language=language,
            status=status,
            candidates=ordered_candidates,
            findings=findings,
            analysis_history=analysis_history,
            revalidation=revalidation,
            locked_by_run_id=locked_by_run_id,
            lock_lease_id=lock_lease_id,
            locked_at=locked_at,
            last_scanned_at=now,
            last_analyzed_at=getattr(existing, "last_analyzed_at", None),
            skylos_version=skylos.__version__,
            config_hash=config_hash,
            candidate_engine_version=CANDIDATE_ENGINE_VERSION,
        )
        self._write_file_record_unlocked(record)
        return record

    @staticmethod
    def _ordered_scan_candidates(
        candidates: list[AuditCandidate],
    ) -> list[AuditCandidate]:
        candidate_map = {candidate.candidate_id: candidate for candidate in candidates}
        return sorted(
            candidate_map.values(),
            key=lambda item: (
                -SIGNAL_QUALITY_RANK.get(item.signal_quality, 0),
                -item.priority,
                item.candidate_id,
            ),
        )

    def _scan_record_status(
        self,
        existing: AuditFileRecord | None,
        candidates: list[AuditCandidate],
        *,
        file_hash: str,
        config_hash: str,
    ) -> str:
        status = STATUS_PENDING if candidates else STATUS_NOT_ANALYZED
        if existing is None or not self._record_matches_current_scan(
            existing,
            file_hash=file_hash,
            config_hash=config_hash,
        ):
            return status

        existing_ids = {candidate.candidate_id for candidate in existing.candidates}
        new_ids = {candidate.candidate_id for candidate in candidates}
        if existing.status == STATUS_PROCESSING:
            return STATUS_PROCESSING
        if existing_ids == new_ids and existing.status in {
            STATUS_ANALYZED,
            STATUS_ERROR,
        }:
            return existing.status
        return status

    @staticmethod
    def _preserved_record_lists(
        existing: AuditFileRecord | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        if existing is None:
            return [], [], []
        return (
            sanitize_for_audit(list(existing.findings)),
            sanitize_for_audit(list(existing.analysis_history)),
            sanitize_for_audit(list(existing.revalidation)),
        )

    @staticmethod
    def _preserved_processing_lock(
        existing: AuditFileRecord | None,
        *,
        status: str,
    ) -> tuple[str | None, str | None, str | None]:
        if existing is None or status != STATUS_PROCESSING:
            return None, None, None
        return existing.locked_by_run_id, existing.lock_lease_id, existing.locked_at

    def acquire_lock(
        self,
        file_path: str | Path,
        *,
        run_id: str,
        stale_after_seconds: int = 3600,
        now: str | None = None,
        allow_inactive: bool = False,
    ) -> bool:
        """Acquire a processing claim using the legacy boolean return contract."""

        return (
            self.acquire_lease(
                file_path,
                run_id=run_id,
                stale_after_seconds=stale_after_seconds,
                now=now,
                allow_inactive=allow_inactive,
            )
            is not None
        )

    def acquire_lease(
        self,
        file_path: str | Path,
        *,
        run_id: str,
        stale_after_seconds: int = 3600,
        now: str | None = None,
        allow_inactive: bool = False,
    ) -> str | None:
        """Acquire a fenced processing claim and return its unique lease ID."""

        with self._mutation_guard():
            record = self.read_file_record(file_path)
            if record is None:
                return None

            claimable_statuses = {STATUS_PENDING, STATUS_PROCESSING, STATUS_ERROR}
            if allow_inactive:
                claimable_statuses.update({STATUS_ANALYZED, STATUS_NOT_ANALYZED})
            if record.status not in claimable_statuses:
                return None

            claim_time = now or utc_now()
            if (
                record.status == STATUS_PROCESSING
                and record.locked_by_run_id
                and record.locked_by_run_id != run_id
                and not self._lock_is_stale(record.locked_at, stale_after_seconds)
            ):
                return None
            lease_id = uuid4().hex
            record.status = STATUS_PROCESSING
            record.locked_by_run_id = run_id
            record.lock_lease_id = lease_id
            record.locked_at = claim_time
            self._write_file_record_unlocked(record)
            return lease_id

    def commit_claimed_record(
        self,
        record: AuditFileRecord,
        *,
        run_id: str,
        lease_id: str,
    ) -> bool:
        """Persist a worker result only while its exact lease is still current."""

        with self._mutation_guard():
            current = self.read_file_record(record.file)
            if (
                current is None
                or current.status != STATUS_PROCESSING
                or current.locked_by_run_id != run_id
                or current.lock_lease_id != lease_id
            ):
                return False
            if record.locked_by_run_id not in {None, run_id}:
                raise ValueError("Committed audit record lock owner mismatch")
            self._write_file_record_unlocked(record)
            return True

    def mark_error(
        self,
        file_path: str | Path,
        message: str,
        *,
        run_id: str | None = None,
        lease_id: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        operational_metadata: dict[str, Any] | None = None,
    ) -> bool:
        with self._mutation_guard():
            record = self.read_file_record(file_path)
            if record is None:
                return False
            if run_id is not None and (
                record.status != STATUS_PROCESSING
                or record.locked_by_run_id != run_id
                or not lease_id
                or record.lock_lease_id != lease_id
            ):
                return False
            record.status = STATUS_ERROR
            record.locked_by_run_id = None
            record.lock_lease_id = None
            record.locked_at = None
            history_entry = {
                "stage": "error",
                "message": sanitize_for_audit(message),
                "at": utc_now(),
            }
            if run_id is not None:
                history_entry["run_id"] = run_id
            failure_telemetry = _failure_operational_metadata(operational_metadata)
            if failure_telemetry is not None:
                history_entry["model"] = model or "unknown"
                history_entry["provider"] = provider
                history_entry["investigation"] = failure_telemetry
            record.analysis_history.append(sanitize_for_audit(history_entry))
            self._write_file_record_unlocked(record)
            return True

    def append_revalidation_entry(
        self,
        file_path: str | Path,
        *,
        expected_source_hash: str,
        expected_config_hash: str,
        expected_finding_hash: str,
        entry: dict[str, Any],
    ) -> bool:
        """Append a verdict only if the finding and scan inputs are unchanged."""

        with self._mutation_guard():
            record = self.read_file_record(file_path)
            if (
                record is None
                or record.status in {STATUS_DELETED, STATUS_PROCESSING}
                or record.file_hash != expected_source_hash
                or record.config_hash != expected_config_hash
                or not any(
                    stable_json_hash(finding) == expected_finding_hash
                    for finding in record.findings
                    if isinstance(finding, dict)
                )
            ):
                return False
            record.revalidation.append(sanitize_for_audit(entry))
            self._write_file_record_unlocked(record)
            return True

    def write_run(self, run_id: str, payload: dict[str, Any]) -> Path:
        if (
            not run_id
            or len(run_id) > 240
            or Path(run_id).name != run_id
            or "/" in run_id
            or "\\" in run_id
            or run_id in {".", ".."}
        ):
            raise ValueError("Audit run_id must be a safe path segment")
        self._ensure_directory_no_symlink(self.runs_dir)
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

    def _normalize_optional_project_path(self, value: str | Path) -> str | None:
        try:
            return normalize_relative_path(self.project_root, value)
        except ValueError:
            return None

    @staticmethod
    def _try_create_mutation_guard(lock_path: Path) -> os.stat_result | None:
        try:
            os.mkdir(  # skylos: ignore[SKY-D215] validated project-local lock path
                lock_path, mode=0o700
            )
        except FileExistsError:
            return None
        created = os.lstat(lock_path)
        if stat.S_ISLNK(created.st_mode) or not stat.S_ISDIR(created.st_mode):
            raise RuntimeError(
                f"Audit mutation lock changed during acquisition: {lock_path}"
            )
        return created

    @staticmethod
    def _existing_mutation_guard(lock_path: Path) -> os.stat_result | None:
        try:
            existing = os.lstat(lock_path)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(existing.st_mode):
            raise RuntimeError(f"Refusing symlinked audit mutation lock: {lock_path}")
        if not stat.S_ISDIR(existing.st_mode):
            raise RuntimeError(f"Audit mutation lock is not a directory: {lock_path}")
        return existing

    @staticmethod
    def _remove_stale_mutation_guard(
        lock_path: Path,
        existing: os.stat_result,
    ) -> bool:
        if time.time() - existing.st_mtime < MUTATION_LOCK_STALE_SECONDS:
            return False
        try:
            current = os.lstat(lock_path)
            same_directory = (
                stat.S_ISDIR(current.st_mode)
                and not stat.S_ISLNK(current.st_mode)
                and current.st_dev == existing.st_dev
                and current.st_ino == existing.st_ino
            )
            if not same_directory:
                return False
            # The guard directory is deliberately empty, so rmdir cannot
            # traverse or remove attacker-chosen contents. A non-empty or
            # replaced lock fails closed and falls through to the bounded wait.
            os.rmdir(  # skylos: ignore[SKY-D215] inode-verified lock directory
                lock_path
            )
        except (FileNotFoundError, OSError):
            return False
        return True

    @staticmethod
    def _wait_for_mutation_guard(lock_path: Path, *, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"Timed out waiting for audit mutation lock: {lock_path}")
        time.sleep(min(MUTATION_LOCK_POLL_SECONDS, remaining))

    def _acquire_mutation_guard(
        self,
        lock_path: Path,
        *,
        deadline: float,
    ) -> os.stat_result:
        while True:
            created = self._try_create_mutation_guard(lock_path)
            if created is not None:
                return created
            existing = self._existing_mutation_guard(lock_path)
            if existing is None:
                continue
            if self._remove_stale_mutation_guard(lock_path, existing):
                continue
            self._wait_for_mutation_guard(lock_path, deadline=deadline)

    @contextmanager
    def _mutation_guard(
        self,
        *,
        timeout_seconds: float = MUTATION_LOCK_TIMEOUT_SECONDS,
    ) -> Iterator[None]:
        """Serialize short record mutations across processes for this project."""

        if timeout_seconds < 0:
            raise ValueError("Audit mutation lock timeout must be non-negative")
        self._ensure_directory_no_symlink(self.project_dir)
        lock_path = self.project_dir / MUTATION_LOCK_DIR_NAME
        deadline = time.monotonic() + timeout_seconds
        owned_stat = self._acquire_mutation_guard(lock_path, deadline=deadline)

        try:
            yield  # skylos: ignore[SKY-D215] validated project-local lock directory
        finally:
            self._release_mutation_guard(lock_path, owned_stat)

    def _release_mutation_guard(
        self,
        lock_path: Path,
        owned_stat: os.stat_result,
    ) -> None:
        try:
            current = (
                os.lstat(  # skylos: ignore[SKY-D215] validated project-local lock path
                    lock_path
                )
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Audit mutation lock disappeared while held: {lock_path}"
            ) from exc
        if (
            not stat.S_ISDIR(current.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or current.st_dev != owned_stat.st_dev
            or current.st_ino != owned_stat.st_ino
        ):
            raise RuntimeError(
                f"Audit mutation lock ownership changed while held: {lock_path}"
            )
        os.rmdir(  # skylos: ignore[SKY-D215] inode-verified project-local lock
            lock_path
        )

    def _write_json_atomic(self, path: Path, payload: dict[str, Any]) -> None:
        self._ensure_directory_no_symlink(path.parent)
        tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = (
                os.open(  # skylos: ignore[SKY-D215] exclusive no-follow state temp
                    tmp_path, flags, 0o600
                )
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = None
                handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass

    def _ensure_directory_no_symlink(self, path: Path) -> None:
        absolute = Path(os.path.abspath(path))
        for component in reversed((absolute, *absolute.parents)):
            try:
                value = os.lstat(component)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700)
                except FileExistsError:
                    value = os.lstat(component)
                else:
                    value = os.lstat(component)
            if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
                raise RuntimeError(
                    f"Audit state path contains a symlink or non-directory: {component}"
                )
