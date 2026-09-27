"""Scans whose upload failed for a reason worth retrying.

A failed upload is written to ``<project>/.skylos/pending-uploads/`` as
``<idempotency-key>.json.gz`` (mode 0600, directory 0700, git-ignored) so
``skylos upload --retry`` can send it again with the same idempotency key.

Per the upload contract (``transport.client_resend_rule``) the record keeps
the exact request bytes that were sent, never a body to be re-serialised, and
a scan is only resent within ``transport.client_resend_window_days``. Older
scans move to ``failed/`` with the reason. No token or request header is
stored.
"""

from __future__ import annotations

import base64
import contextlib
import gzip
import io
import json
import logging
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.api._upload_contract import client_resend_window_days

logger = logging.getLogger(__name__)

__all__ = [
    "PENDING_DIR_ENV",
    "PendingUpload",
    "TOO_OLD_REASON",
    "count_pending_uploads",
    "decode_request_body",
    "delete_pending_upload",
    "expire_pending_uploads",
    "list_pending_uploads",
    "mark_pending_upload_failed",
    "pending_uploads_dir",
    "save_pending_upload",
]

RECORD_FORMAT = "skylos-pending-upload"
RECORD_VERSION = 2
PENDING_DIR_ENV = "SKYLOS_PENDING_UPLOAD_DIR"
PENDING_RELATIVE_DIR = Path(".skylos") / "pending-uploads"
FAILED_DIRNAME = "failed"
TOO_OLD_REASON = "too old to resend safely; rerun the scan"

MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_COUNT = 20
# Records of failed resends are kept for reference, then pruned.
FAILED_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
# A saved record is at most MAX_TOTAL_BYTES compressed; refuse to inflate a
# file past this so a crafted gzip cannot exhaust memory.
MAX_DECOMPRESSED_BYTES = 1024 * 1024 * 1024

_KEY_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SUFFIX = ".json.gz"
_GITIGNORE_BODY = "# Written by Skylos: scans waiting for 'skylos upload --retry'.\n*\n"


def resend_window_seconds() -> int:
    return client_resend_window_days() * 24 * 60 * 60


@dataclass
class PendingUpload:
    path: Path
    record: dict[str, Any]

    @property
    def idempotency_key(self) -> str:
        return str(self.record.get("idempotency_key") or "")

    @property
    def created_at(self) -> float:
        value = self.record.get("created_at")
        return float(value) if isinstance(value, (int, float)) else 0.0

    @property
    def finding_count(self) -> int | None:
        value = self.record.get("finding_count")
        return value if isinstance(value, int) else None


def is_valid_key(key: Any) -> bool:
    return isinstance(key, str) and bool(_KEY_RE.match(key))


def pending_uploads_dir(project_root: str | os.PathLike | None) -> Path | None:
    override = os.getenv(PENDING_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    if project_root is None:
        return None
    return Path(project_root) / PENDING_RELATIVE_DIR


def _is_safe_dir(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode)


def _ensure_dir(directory: Path) -> bool:
    """Create the pending directory without following symlinks."""
    if os.getenv(PENDING_DIR_ENV, "").strip():
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            return False
        return _is_safe_dir(directory)
    for current in (directory.parent, directory):
        if current.is_symlink():
            return False
        if not current.exists():
            try:
                current.mkdir(mode=0o700)  # skylos: ignore[SKY-D215] project-local upload queue
            except FileExistsError:
                pass
            except OSError:
                return False
        if not _is_safe_dir(current):
            return False
    return True


def _ensure_gitignore(directory: Path) -> None:
    gitignore = directory / ".gitignore"
    if gitignore.is_symlink() or gitignore.exists():
        return
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] fixed name inside the no-symlink pending folder
            gitignore,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
    except OSError:
        return
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(_GITIGNORE_BODY)


def encode_request_body(body: bytes) -> dict[str, str]:
    """Keep the request bytes exactly; JSON bodies are stored as UTF-8 text."""
    try:
        return {"request_body": body.decode("utf-8"), "request_body_encoding": "utf-8"}
    except UnicodeDecodeError:
        return {
            "request_body": base64.b64encode(body).decode("ascii"),
            "request_body_encoding": "base64",
        }


def decode_request_body(record: dict[str, Any]) -> bytes:
    body = record.get("request_body")
    if not isinstance(body, str):
        raise ValueError("saved upload has no request body")
    if record.get("request_body_encoding") == "base64":
        return base64.b64decode(body.encode("ascii"), validate=True)
    return body.encode("utf-8")


def _gzip_record(record: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as handle:
        with io.TextIOWrapper(handle, encoding="utf-8") as text:
            json.dump(record, text, separators=(",", ":"))
    return buffer.getvalue()


def _write_private_file(path: Path, data: bytes) -> bool:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(tmp, flags, 0o600)  # skylos: ignore[SKY-D215] UUID-named file, no-follow exclusive create
    except OSError:
        return False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            with contextlib.suppress(OSError):
                os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return True
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp)  # skylos: ignore[SKY-D215] temp file this function created
        return False


def _entries(directory: Path) -> list[Path]:
    try:
        return sorted(
            p
            for p in directory.iterdir()
            if p.name.endswith(_SUFFIX) and is_valid_key(p.name[: -len(_SUFFIX)])
        )
    except OSError:
        return []


def _file_info(path: Path) -> os.stat_result | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info


def _move_to_failed(path: Path, key: str, reason: dict[str, Any]) -> Path | None:
    failed_dir = path.parent / FAILED_DIRNAME
    if failed_dir.is_symlink():
        return None
    try:
        failed_dir.mkdir(mode=0o700, exist_ok=True)
    except OSError:
        return None
    if not _is_safe_dir(failed_dir):
        return None
    target = failed_dir / path.name
    try:
        os.replace(path, target)
    except OSError:
        return None
    body = json.dumps({"failed_at": time.time(), **reason}, indent=2, sort_keys=True)
    _write_private_file(failed_dir / f"{key}.reason.json", body.encode("utf-8"))
    return target


def _prune_failed(directory: Path, now: float) -> None:
    failed_dir = directory / FAILED_DIRNAME
    if not _is_safe_dir(failed_dir):
        return
    try:
        entries = list(failed_dir.iterdir())
    except OSError:
        return
    for path in entries:
        info = _file_info(path)
        if info is not None and now - info.st_mtime > FAILED_MAX_AGE_SECONDS:
            with contextlib.suppress(OSError):
                path.unlink()


def expire_pending_uploads(directory: Path, *, now: float | None = None) -> int:
    """Move scans past the resend window to ``failed/``; never send them.

    The file time is when the scan was first sent (the file is written once).
    """
    current = time.time() if now is None else now
    window = resend_window_seconds()
    moved = 0
    for path in _entries(directory):
        info = _file_info(path)
        if info is None or current - info.st_mtime <= window:
            continue
        key = path.name[: -len(_SUFFIX)]
        if _move_to_failed(path, key, {"reason": TOO_OLD_REASON, "code": "TOO_OLD"}):
            moved += 1
    _prune_failed(directory, current)
    return moved


def _make_room(directory: Path, incoming_bytes: int) -> None:
    """Drop the oldest saved uploads until the new one fits the caps."""
    entries = []
    for path in _entries(directory):
        info = _file_info(path)
        if info is not None:
            entries.append((info.st_mtime, path, info.st_size))
    entries.sort()
    total = sum(size for _, _, size in entries)
    while entries and (
        len(entries) + 1 > MAX_COUNT or total + incoming_bytes > MAX_TOTAL_BYTES
    ):
        _, path, size = entries.pop(0)
        with contextlib.suppress(OSError):
            path.unlink()
            logger.debug("Dropped oldest pending upload %s to stay under caps", path)
        total -= size


def save_pending_upload(
    directory: Path | None,
    *,
    idempotency_key: str,
    kind: str,
    mode: str,
    endpoint: str,
    api_base: str,
    project_id: str | None,
    cli_version: str | None,
    request_body: bytes,
    artifacts: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    finding_count: int | None = None,
    last_error: dict[str, Any] | None = None,
    now: float | None = None,
) -> Path | None:
    """Write one pending upload. Returns its path, or None if it was not saved.

    ``request_body`` is stored byte for byte; nothing here edits it.
    """
    if directory is None or not is_valid_key(idempotency_key):
        return None
    if not isinstance(request_body, (bytes, bytearray)):
        return None
    if not _ensure_dir(directory):
        return None
    _ensure_gitignore(directory)
    expire_pending_uploads(directory, now=now)

    record = {
        "format": RECORD_FORMAT,
        "version": RECORD_VERSION,
        "idempotency_key": idempotency_key,
        "kind": kind,
        "mode": mode,
        "endpoint": endpoint,
        "api_base": api_base,
        "project_id": project_id,
        "created_at": time.time() if now is None else now,
        "cli_version": cli_version,
        "finding_count": finding_count,
        "last_error": last_error or {},
        **encode_request_body(bytes(request_body)),
        "artifacts": artifacts or {},
        "context": context or {},
    }
    try:
        data = _gzip_record(record)
    except (TypeError, ValueError) as exc:
        logger.debug("Could not serialize pending upload: %s", exc)
        return None
    if len(data) > MAX_TOTAL_BYTES:
        return None
    _make_room(directory, len(data))
    path = directory / f"{idempotency_key}{_SUFFIX}"
    if not _write_private_file(path, data):
        return None
    if now is not None:
        with contextlib.suppress(OSError):
            os.utime(path, (now, now))
    return path


def _read_record(path: Path) -> dict[str, Any] | None:
    info = _file_info(path)
    if info is None:
        return None
    if os.name == "posix":
        # Only read files this user wrote privately; a copy planted in the
        # repository (for example a committed file) is ignored.
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))  # skylos: ignore[SKY-D215] UUID-named regular file, no-follow read
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as raw, gzip.GzipFile(fileobj=raw) as handle:
            data = handle.read(MAX_DECOMPRESSED_BYTES + 1)
    except (OSError, EOFError):
        return None
    if len(data) > MAX_DECOMPRESSED_BYTES:
        return None
    try:
        record = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    if record.get("format") != RECORD_FORMAT or record.get("version") != RECORD_VERSION:
        return None
    if record.get("idempotency_key") != path.name[: -len(_SUFFIX)]:
        return None
    if not isinstance(record.get("request_body"), str):
        return None
    return record


def list_pending_uploads(directory: Path | None) -> tuple[list[PendingUpload], int]:
    """Saved uploads inside the resend window, oldest first, and how many
    unreadable files were skipped."""
    if directory is None or not _is_safe_dir(directory):
        return [], 0
    now = time.time()
    expire_pending_uploads(directory, now=now)
    window = resend_window_seconds()
    pending = []
    skipped = 0
    for path in _entries(directory):
        record = _read_record(path)
        if record is None:
            skipped += 1
            continue
        item = PendingUpload(path=path, record=record)
        if now - item.created_at > window:
            _move_to_failed(
                path, item.idempotency_key, {"reason": TOO_OLD_REASON, "code": "TOO_OLD"}
            )
            continue
        pending.append(item)
    pending.sort(key=lambda item: item.created_at)
    return pending, skipped


def count_pending_uploads(directory: Path | None) -> int:
    """Cheap count for the reminder line; does not read the files."""
    if directory is None or not _is_safe_dir(directory):
        return 0
    now = time.time()
    window = resend_window_seconds()
    count = 0
    for path in _entries(directory):
        info = _file_info(path)
        if info is not None and now - info.st_mtime <= window:
            count += 1
    return count


def is_within_resend_window(pending: PendingUpload, *, now: float | None = None) -> bool:
    current = time.time() if now is None else now
    return current - pending.created_at <= resend_window_seconds()


def delete_pending_upload(pending: PendingUpload) -> None:
    with contextlib.suppress(OSError):
        pending.path.unlink()


def mark_pending_upload_failed(
    pending: PendingUpload, reason: dict[str, Any]
) -> Path | None:
    """Move a saved upload that cannot be sent into ``failed/`` with the reason."""
    return _move_to_failed(pending.path, pending.idempotency_key, reason)
