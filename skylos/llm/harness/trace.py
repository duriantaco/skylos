from __future__ import annotations

import json
import os
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
    run_dir = _safe_run_dir(trace_root, run_id)
    if run_dir is None:
        return None
    if not _ensure_trace_dir(run_dir):
        return None

    path = run_dir / EVENTS_FILENAME
    if _unsafe_existing_path(path):
        return None

    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] guarded project-local trace temp path
            temp_path, flags, 0o600
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            for event in events:
                handle.write(json.dumps(event, sort_keys=True, default=str))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if _unsafe_existing_path(path):
            return None
        os.replace(temp_path, path)
        return path
    except (OSError, TypeError, ValueError):
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            if temp_path.exists() and not temp_path.is_symlink():
                temp_path.unlink()
        except OSError:
            pass


def write_json_artifact(
    trace_root: str | Path,
    run_id: str,
    filename: str,
    payload: dict[str, Any],
) -> Path | None:
    run_dir = _safe_run_dir(trace_root, run_id)
    if run_dir is None:
        return None
    if not _ensure_trace_dir(run_dir):
        return None

    path = _safe_artifact_path(run_dir, filename)
    if path is None:
        return None
    if _unsafe_existing_path(path):
        return None

    return _write_json_file(path, payload)


def _write_json_file(path: Path, payload: dict[str, Any]) -> Path | None:
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] guarded project-local artifact temp path
            temp_path, flags, 0o600
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            json.dump(payload, handle, indent=2, sort_keys=True, default=str)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if _unsafe_existing_path(path):
            return None
        os.replace(temp_path, path)
        return path
    except (OSError, TypeError, ValueError):
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            if temp_path.exists() and not temp_path.is_symlink():
                temp_path.unlink()
        except OSError:
            pass


def _safe_run_dir(trace_root: str | Path, run_id: str) -> Path | None:
    try:
        root = Path(trace_root).resolve()
        run_dir = root / sanitize_run_id(run_id)
        run_dir.resolve(strict=False).relative_to(root)
    except (OSError, ValueError):
        return None
    return run_dir


def _safe_artifact_path(run_dir: Path, filename: str) -> Path | None:
    candidate_name = Path(filename).name
    if not candidate_name or candidate_name != filename:
        return None
    try:
        path = run_dir / candidate_name
        path.resolve(strict=False).relative_to(run_dir.resolve(strict=False))
    except (OSError, ValueError):
        return None
    return path


def _ensure_trace_dir(path: Path) -> bool:
    current = Path(path.anchor) if path.is_absolute() else Path(".")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        try:
            if current.is_symlink():
                return False
            if current.exists():
                if not current.is_dir():
                    return False
                continue
            current.mkdir(mode=0o700)
        except OSError:
            return False
    return True


def _unsafe_existing_path(path: Path) -> bool:
    try:
        return path.exists() and (path.is_symlink() or not path.is_file())
    except OSError:
        return True
