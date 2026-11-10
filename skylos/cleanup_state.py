"""Local cleanup work history. Absence is an observation, never a test receipt."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import time
from contextlib import contextmanager
from uuid import uuid4

from skylos.core.safe_cache_io import (
    PROJECT_CACHE_LOCK_TIMEOUT_SECONDS,
    PROJECT_CACHE_LOCK_POLL_SECONDS,
    PROJECT_CACHE_LOCK_STALE_SECONDS,
)

STATE_PATH = ".skylos/cache/cleanup.json"
LOCK_PATH = ".skylos/cache/cleanup.lock"


def scope_identity(scope: dict) -> str:
    return sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()


def load_cleanup_state(root: Path) -> dict:
    state, _snapshot = _read_snapshot(root)
    return state


def _decode_state(data: bytes | None) -> dict:
    if data is None:
        return {"version": 1, "scopes": {}}
    try:
        state = json.loads(data.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("Cleanup history is malformed; it was not replaced") from exc
    if (
        not isinstance(state, dict)
        or state.get("version") != 1
        or not isinstance(state.get("scopes"), dict)
    ):
        raise ValueError("Unsupported cleanup history; it was not replaced")
    return state


@contextmanager
def _state_directory(root: Path, *, create=False):
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Guarded cleanup history is unavailable on this platform")
    root = Path(root)
    if root.is_symlink():
        raise ValueError("Cleanup history root is unsafe")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Cleanup history root must be a directory")
    # The caller-selected canonical project directory is the authorized base,
    # never a task/report path. Only fixed children are opened beneath its fd.
    directory = os.open(  # skylos: ignore[SKY-D215] authorized project root
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        for component in (".skylos", "cache"):
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory)
                except FileExistsError:
                    pass
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = child
        yield directory
    finally:
        os.close(directory)


def _directory_identity(directory):
    metadata = os.fstat(directory)
    return metadata.st_dev, metadata.st_ino


def _read_bytes(directory):
    try:
        source = os.open(
            "cleanup.json",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
    except FileNotFoundError:
        return None, None, 0o600
    try:
        metadata = os.fstat(source)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 8_000_000
        ):
            raise ValueError(
                "Cleanup history is unsafe or oversized; it was not replaced"
            )
        result = bytearray()
        while len(result) <= 8_000_000:
            part = os.read(source, min(65536, 8_000_001 - len(result)))
            if not part:
                break
            result.extend(part)
        if len(result) > 8_000_000:
            raise ValueError("Cleanup history is oversized; it was not replaced")
        token = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        return bytes(result), token, stat.S_IMODE(metadata.st_mode) & 0o777
    finally:
        os.close(source)


def _read_snapshot(root):
    try:
        with _state_directory(root) as directory:
            return _snapshot_from_directory(directory)
    except FileNotFoundError:
        return _decode_state(None), None
    except OSError as exc:
        raise ValueError(
            "Cleanup history path is unreadable or unsafe; it was not replaced"
        ) from exc


def _snapshot_from_directory(directory):
    data, token, mode = _read_bytes(directory)
    return _decode_state(data), (_directory_identity(directory), data, token, mode)


@contextmanager
def _history_lock(root):
    """Use the existing lock name, with all operations pinned to one directory."""
    with _state_directory(root, create=True) as directory:
        name = Path(LOCK_PATH).name
        deadline = time.monotonic() + PROJECT_CACHE_LOCK_TIMEOUT_SECONDS
        owned = None
        while owned is None:
            try:
                os.mkdir(name, mode=0o700, dir_fd=directory)
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ValueError("Cleanup history lock path is unsafe")
                owned = (metadata.st_dev, metadata.st_ino)
            except FileExistsError:
                try:
                    metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ValueError("Cleanup history lock path is unsafe")
                if time.time() - metadata.st_mtime >= PROJECT_CACHE_LOCK_STALE_SECONDS:
                    try:
                        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if (current.st_dev, current.st_ino) == (
                        metadata.st_dev,
                        metadata.st_ino,
                    ):
                        try:
                            os.rmdir(name, dir_fd=directory)
                            continue
                        except OSError:
                            pass
                if time.monotonic() >= deadline:
                    raise ValueError("Cleanup history is locked or its path is unsafe")
                time.sleep(PROJECT_CACHE_LOCK_POLL_SECONDS)
        try:
            yield directory
        finally:
            try:
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (
                    stat.S_ISDIR(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == owned
                ):
                    os.rmdir(name, dir_fd=directory)
            except OSError:
                pass


def _atomic_write_state(root, snapshot, text):
    payload = text.encode("utf-8")
    if len(payload) > 8_000_000:
        raise ValueError("Cleanup history exceeds its storage limit")
    temporary = f".cleanup.{uuid4().hex}.tmp"
    try:
        with _state_directory(root) as directory:
            if snapshot is None or _directory_identity(directory) != snapshot[0]:
                raise ValueError(
                    "Cleanup history directory changed; it was not replaced"
                )
            output = None
            try:
                output = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                os.fchmod(output, snapshot[3])
                position = 0
                while position < len(payload):
                    written = os.write(output, payload[position:])
                    if written < 1:
                        raise OSError("Cleanup history write did not make progress")
                    position += written
                os.fsync(output)
                os.close(output)
                output = None
                current, token, _mode = _read_bytes(directory)
                if current != snapshot[1] or token != snapshot[2]:
                    raise ValueError(
                        "Cleanup history changed during this update; it was not replaced"
                    )
                with _state_directory(root) as current_directory:
                    if _directory_identity(current_directory) != snapshot[0]:
                        raise ValueError(
                            "Cleanup history directory changed; it was not replaced"
                        )
                os.replace(
                    temporary,
                    "cleanup.json",
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                )
                os.fsync(directory)
            finally:
                if output is not None:
                    os.close(output)
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
    except OSError as exc:
        raise ValueError(
            "Cleanup history could not be atomically published; existing complete data was not truncated"
        ) from exc


def mutate_cleanup_workspace(root: Path, scope: dict, callback):
    """Atomically update one scoped workspace using trusted local code.

    The callback receives the current bucket, not serialized code or source.
    Exceptions leave the last complete state untouched; returned data is detached.
    """
    if not isinstance(scope, dict) or not callable(callback):
        raise ValueError("Cleanup workspace requires a scope and a local callback")
    expected_scope = deepcopy(scope)
    key = scope_identity(expected_scope)
    with _history_lock(root) as directory:
        state, snapshot = _snapshot_from_directory(directory)
        bucket = state["scopes"].setdefault(
            key, {"scope": deepcopy(expected_scope), "tasks": {}}
        )

        def validate():
            if (
                not isinstance(bucket, dict)
                or bucket.get("scope") != expected_scope
                or not isinstance(bucket.get("tasks"), dict)
            ):
                raise ValueError("Cleanup workspace scope or task history is malformed")

        validate()
        result = deepcopy(callback(bucket))
        validate()
        _atomic_write_state(
            root, snapshot, json.dumps(state, sort_keys=True, indent=2) + "\n"
        )
        return result


def update_cleanup_state(
    root: Path,
    scope: dict,
    plan: dict,
    *,
    disposition=None,
    receipt=None,
    inventory=None,
) -> dict:
    """Reconcile only an identical scan scope and config, preserving uncertainty."""
    if inventory is None:
        inventory = plan.get("_inventory")
    if inventory is None:
        inventory = plan.get("tasks", []) + plan.get("advisories", [])
    if not isinstance(inventory, list) or any(
        not isinstance(task, dict)
        or any(
            not isinstance(task.get(key), str) or not task[key]
            for key in ("id", "rule_id", "file")
        )
        for task in inventory
    ):
        raise ValueError("Cleanup reconciliation inventory is malformed")
    with _history_lock(root) as directory:
        state, snapshot = _snapshot_from_directory(directory)
        key = scope_identity(scope)
        bucket = state["scopes"].setdefault(key, {"scope": scope, "tasks": {}})
        records = bucket["tasks"]
        if not isinstance(records, dict):
            raise ValueError("Cleanup task history is malformed")
        now = datetime.now(timezone.utc).isoformat()
        current = {task["id"]: task for task in inventory}
        for task_id, task in current.items():
            record = records.setdefault(
                task_id,
                {
                    "id": task_id,
                    "rule_id": task["rule_id"],
                    "file": task["file"],
                    "name": task.get("name", ""),
                    "first_seen": now,
                    "status": "open",
                    "history": [],
                },
            )
            if record["status"] in {
                "not_reported",
                "verified",
                "applied_unverified",
                "failed",
                "incomplete",
            }:
                _event(record, "reopened", now)
                record["status"] = "open"
            record["last_seen"] = now
            record["source_sha256"] = task.get("source_sha256")
        if plan.get("status") != "incomplete":
            for task_id, record in records.items():
                if task_id not in current and record["status"] == "open":
                    record["status"] = "not_reported"
                    _event(
                        record,
                        "not_reported",
                        now,
                        reason="Absent in a complete comparable scan; behavior is not verified",
                    )
        if disposition:
            task_id = _match(records, disposition["id"])
            record = records[task_id]
            record["status"] = disposition["status"]
            _event(
                record, disposition["status"], now, reason=disposition.get("reason", "")
            )
        if receipt:
            task_id = _match(records, receipt["task_id"])
            record = records[task_id]
            record["status"] = receipt["status"]
            record["verification"] = deepcopy(receipt)
            _event(record, receipt["status"], now)
        bucket["last_scan"] = {
            "at": now,
            "status": plan.get("status"),
            "complete": plan.get("status") != "incomplete",
        }
        _atomic_write_state(
            root, snapshot, json.dumps(state, sort_keys=True, indent=2) + "\n"
        )
        return deepcopy(bucket)


def _match(records, prefix):
    matches = [key for key in records if key.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(
            "Task ID is unknown or ambiguous; use the full ID from cleanup JSON"
        )
    return matches[0]


def _event(record, status, at, **details):
    record.setdefault("history", []).append({"at": at, "status": status, **details})
    record["history"] = record["history"][-30:]
