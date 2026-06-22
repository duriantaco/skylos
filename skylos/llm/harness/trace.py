from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .types import sanitize_run_id

SKYLOS_DIRNAME = ".skylos"
RUNS_DIRNAME = "runs"
EVENTS_FILENAME = "events.jsonl"
STATE_FILENAME = "state.json"
SUMMARY_FILENAME = "summary.json"


def default_trace_root(project_root: str | Path) -> Path:
    resolved = Path(project_root).resolve()
    root = resolved.parent if resolved.is_file() else resolved
    return root / SKYLOS_DIRNAME / RUNS_DIRNAME


def write_jsonl_trace(
    trace_root: str | Path,
    run_id: str,
    events: list[dict[str, Any]],
) -> Path | None:
    run_dir_fd, run_dir_path = _open_run_dir(trace_root, run_id)
    if run_dir_fd is None or run_dir_path is None:
        return None

    try:
        path = _write_artifact_in_dir(
            run_dir_fd,
            run_dir_path,
            EVENTS_FILENAME,
            lambda handle: _write_jsonl(handle, events),
        )
        return path
    finally:
        _close_fd(run_dir_fd)


def write_json_artifact(
    trace_root: str | Path,
    run_id: str,
    filename: str,
    payload: dict[str, Any],
) -> Path | None:
    run_dir_fd, run_dir_path = _open_run_dir(trace_root, run_id)
    if run_dir_fd is None or run_dir_path is None:
        return None

    try:
        return _write_artifact_in_dir(
            run_dir_fd,
            run_dir_path,
            filename,
            lambda handle: _write_json(handle, payload),
        )
    finally:
        _close_fd(run_dir_fd)


def _write_artifact_in_dir(
    dir_fd: int,
    run_dir_path: Path,
    filename: str,
    writer: Any,
) -> Path | None:
    final_name = _safe_artifact_name(filename)
    if final_name is None:
        return None
    if _unsafe_existing_name(dir_fd, final_name):
        return None

    temp_name = f".{final_name}.{os.getpid()}.tmp"
    fd = _open_temp_file(dir_fd, temp_name)
    if fd is None:
        return None

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        if _unsafe_existing_name(dir_fd, final_name):
            return None
        os.replace(temp_name, final_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return run_dir_path / final_name
    except (OSError, TypeError, ValueError):
        return None
    finally:
        _close_fd(fd)
        _unlink_name(dir_fd, temp_name)


def _write_jsonl(handle: Any, events: list[dict[str, Any]]) -> None:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True, default=str))
        handle.write("\n")


def _write_json(handle: Any, payload: dict[str, Any]) -> None:
    json.dump(payload, handle, indent=2, sort_keys=True, default=str)
    handle.write("\n")


def _open_temp_file(dir_fd: int, temp_name: str) -> int | None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(  # skylos: ignore[SKY-D215] dir_fd temp name from _safe_artifact_name
            temp_name, flags, 0o600, dir_fd=dir_fd
        )
    except OSError:
        return None


def _open_run_dir(trace_root: str | Path, run_id: str) -> tuple[int | None, Path | None]:
    safe_run_id = sanitize_run_id(run_id)
    root_path = _absolute_lexical_path(trace_root)
    if root_path is None:
        return None, None
    run_dir_path = root_path / safe_run_id
    run_fd = _open_or_create_directory(run_dir_path)
    if run_fd is None:
        return None, None
    return run_fd, run_dir_path


def _absolute_lexical_path(path: str | Path) -> Path | None:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if any(part in {"", ".", ".."} for part in candidate.parts[1:]):
        return None
    return candidate


def _open_or_create_directory(path: Path) -> int | None:
    parts = path.parts
    if not parts:
        return None

    current_fd: int | None = None
    try:
        current_fd = os.open(os.sep, _directory_flags(follow_symlinks=True))
        for part in parts[1:]:
            if part in {"", ".", ".."}:
                _close_fd(current_fd)
                return None
            _mkdirat(current_fd, part)
            next_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
            _close_fd(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError:
        _close_fd(current_fd)
        return None


def _directory_flags(*, follow_symlinks: bool = False) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if not follow_symlinks and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _mkdirat(dir_fd: int, name: str) -> None:
    try:
        os.mkdir(  # skylos: ignore[SKY-D215] dir_fd path component rejects separators/dotdot
            name, mode=0o700, dir_fd=dir_fd
        )
    except FileExistsError:
        pass


def _safe_artifact_name(filename: str) -> str | None:
    candidate_name = Path(filename).name
    if not candidate_name or candidate_name != filename:
        return None
    return candidate_name


def _unsafe_existing_name(dir_fd: int, name: str) -> bool:
    try:
        metadata = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return not stat.S_ISREG(metadata.st_mode)


def _unlink_name(dir_fd: int, name: str) -> None:
    try:
        os.unlink(  # skylos: ignore[SKY-D215] dir_fd temp cleanup does not follow symlinks
            name, dir_fd=dir_fd
        )
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _close_fd(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass
