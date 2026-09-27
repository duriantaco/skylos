"""Scans whose upload failed for a reason worth retrying.

A failed upload is saved outside the repository, in a per-user state folder:
``~/.skylos/pending-uploads/<repo-id>/<idempotency-key>.json.gz`` (files
0600, folders 0700), where ``<repo-id>`` is derived from the repository's
path. ``skylos upload --retry`` sends it again with the same idempotency key.

Each record is signed with HMAC-SHA256 using a per-user key kept 0600 in the
state folder, so a file written by anyone else (for example one committed to
a repository) is never sent under the user's token.

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
import hashlib
import hmac
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
    "legacy_pending_uploads",
    "delete_pending_upload",
    "expire_pending_uploads",
    "list_pending_uploads",
    "mark_pending_upload_failed",
    "pending_uploads_dir",
    "save_pending_upload",
]

RECORD_FORMAT = "skylos-pending-upload"
RECORD_VERSION = 3
# Root of the per-user queue; one sub-folder per repository.
PENDING_DIR_ENV = "SKYLOS_PENDING_UPLOAD_DIR"
# Where Skylos versions before the per-user queue saved uploads. Those files
# are never sent; the user is told where they are.
LEGACY_RELATIVE_DIR = Path(".skylos") / "pending-uploads"
KEY_FILENAME = ".record-key"
_KEY_BYTES = 32
_MAGIC = b"SKYLOS-PENDING-UPLOAD 3 "
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


def home_pending_root() -> Path:
    """``~/.skylos/pending-uploads``: the queue root when nothing overrides it."""
    return Path.home() / ".skylos" / "pending-uploads"


# The default root, looked up at call time; the test suite points it at a
# temporary folder so no test can ever write to the real home directory.
default_pending_root = home_pending_root


def pending_root() -> Path:
    """The per-user queue root (``SKYLOS_PENDING_UPLOAD_DIR`` overrides it)."""
    override = os.getenv(PENDING_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return default_pending_root()


def repository_queue_id(project_root: str | os.PathLike) -> str:
    try:
        resolved = os.path.realpath(os.fspath(project_root))
    except (OSError, ValueError):
        resolved = os.path.abspath(os.fspath(project_root))
    return hashlib.sha256(resolved.encode("utf-8", "surrogatepass")).hexdigest()[:24]


def pending_uploads_dir(project_root: str | os.PathLike | None) -> Path | None:
    """This repository's queue folder in the per-user state folder."""
    if project_root is None:
        return None
    return pending_root() / repository_queue_id(project_root)


def legacy_pending_uploads(
    project_root: str | os.PathLike | None,
) -> tuple[Path | None, int]:
    """Uploads an older Skylos saved inside the repository; never sent."""
    if project_root is None:
        return None, 0
    directory = Path(project_root) / LEGACY_RELATIVE_DIR
    if not _is_safe_dir(directory):
        return None, 0
    try:
        count = sum(
            1
            for path in directory.iterdir()
            if path.name.endswith(_SUFFIX) and _file_info(path) is not None
        )
    except OSError:
        return None, 0
    return (directory, count) if count else (None, 0)


def _is_safe_dir(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode)


def _is_private_dir(path: Path) -> bool:
    """The queue must be a real directory owned and accessible only by us."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        return False
    return os.name != "posix" or (
        info.st_uid == os.getuid() and not info.st_mode & 0o077
    )


def _is_private_queue_dir(directory: Path) -> bool:
    return _is_private_dir(directory.parent) and _is_private_dir(directory)


def _private_dir(path: Path) -> bool:
    """Create ``path`` (0700) if needed; refuse a symlink or a non-folder."""
    if path.is_symlink():
        return False
    try:
        path.mkdir(
            mode=0o700, exist_ok=True
        )  # skylos: ignore[SKY-D215] per-user upload queue
    except OSError:
        return False
    return _is_private_dir(path)


def _ensure_dir(directory: Path) -> bool:
    """Create the queue root and this repository's folder."""
    root = directory.parent
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        return False
    if not _is_private_dir(root):
        return False
    return _private_dir(directory)


def _owned_private_file(info: os.stat_result) -> bool:
    if os.name != "posix":
        return True
    return info.st_uid == os.getuid() and not info.st_mode & 0o077


def _same_private_file(before: os.stat_result, opened: os.stat_result) -> bool:
    return (
        stat.S_ISREG(opened.st_mode)
        and _owned_private_file(opened)
        and (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)
    )


def _record_key(root: Path, *, create: bool) -> bytes | None:
    """The per-user HMAC key (32 random bytes, 0600) in the queue root."""
    if not _is_private_dir(root):
        return None
    path = root / KEY_FILENAME
    info = _file_info(path)
    if info is None:
        if not create or path.is_symlink():
            return None
        key = os.urandom(_KEY_BYTES)
        try:
            fd = os.open(  # skylos: ignore[SKY-D215] fixed name in the per-user queue root
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            return _record_key(root, create=False)
        except OSError:
            return None
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
        return key
    if not _owned_private_file(info) or info.st_size != _KEY_BYTES:
        return None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] fixed name in the private queue root
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not _same_private_file(info, opened) or opened.st_size != _KEY_BYTES:
                return None
            key = handle.read(_KEY_BYTES + 1)
    except OSError:
        return None
    return key if len(key) == _KEY_BYTES else None


def _record_mac(key: bytes, directory: Path, body: bytes) -> str:
    # Bound to the repository folder, so a record moved to another
    # repository's queue does not verify there.
    message = (
        b"skylos-pending-upload/3\n" + directory.name.encode("utf-8") + b"\n" + body
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


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


def _signed_record(record: dict[str, Any], key: bytes, directory: Path) -> bytes:
    body = json.dumps(record, separators=(",", ":")).encode("utf-8")
    header = _MAGIC + _record_mac(key, directory, body).encode("ascii") + b"\n"
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as handle:
        handle.write(header)
        handle.write(body)
    return buffer.getvalue()


def _write_private_file(path: Path, data: bytes) -> bool:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] private queue, no-follow exclusive create
            tmp, flags, 0o600
        )
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
    if not _is_private_queue_dir(path.parent):
        return None
    failed_dir = path.parent / FAILED_DIRNAME
    if failed_dir.is_symlink():
        return None
    try:
        failed_dir.mkdir(mode=0o700, exist_ok=True)
    except OSError:
        return None
    if not _is_private_dir(failed_dir):
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
    if not _is_private_queue_dir(directory) or not _is_private_dir(failed_dir):
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
    if not _is_private_queue_dir(directory):
        return 0
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
    key = _record_key(directory.parent, create=True)
    if key is None:
        return None
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
        data = _signed_record(record, key, directory)
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


def _read_record(path: Path, key: bytes | None) -> dict[str, Any] | None:
    """A verified record, or None for anything unreadable or not signed with
    this user's key."""
    if key is None:
        return None
    info = _file_info(path)
    if info is None or not _owned_private_file(info):
        return None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] signed record in private queue, no-follow read
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as raw:
            if not _same_private_file(info, os.fstat(raw.fileno())):
                return None
            with gzip.GzipFile(fileobj=raw) as handle:
                data = handle.read(MAX_DECOMPRESSED_BYTES + 1)
    except (OSError, EOFError):
        return None
    if len(data) > MAX_DECOMPRESSED_BYTES or not data.startswith(_MAGIC):
        return None
    header, _, body = data.partition(b"\n")
    mac = header[len(_MAGIC) :].decode("ascii", "replace")
    if not hmac.compare_digest(mac, _record_mac(key, path.parent, body)):
        return None
    try:
        record = json.loads(body.decode("utf-8"))
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
    if directory is None or not _is_private_queue_dir(directory):
        return [], 0
    now = time.time()
    expire_pending_uploads(directory, now=now)
    window = resend_window_seconds()
    key = _record_key(directory.parent, create=False)
    pending = []
    skipped = 0
    for path in _entries(directory):
        record = _read_record(path, key)
        if record is None:
            skipped += 1
            continue
        item = PendingUpload(path=path, record=record)
        if now - item.created_at > window:
            _move_to_failed(
                path,
                item.idempotency_key,
                {"reason": TOO_OLD_REASON, "code": "TOO_OLD"},
            )
            continue
        pending.append(item)
    pending.sort(key=lambda item: item.created_at)
    return pending, skipped


def count_pending_uploads(directory: Path | None) -> int:
    """Cheap count for the reminder line; does not read the files."""
    if directory is None or not _is_private_queue_dir(directory):
        return 0
    now = time.time()
    window = resend_window_seconds()
    count = 0
    for path in _entries(directory):
        info = _file_info(path)
        if info is not None and now - info.st_mtime <= window:
            count += 1
    return count


def is_within_resend_window(
    pending: PendingUpload, *, now: float | None = None
) -> bool:
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
