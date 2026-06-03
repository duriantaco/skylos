from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path
from typing import Any


INDEX_SCHEMA_VERSION = 1
INDEX_KIND = "reference_graph"
INDEX_CACHE_PATH = Path(".skylos") / "index" / "v1" / "reference_graph.json"
MAX_INDEXED_SOURCE_BYTES = 10_000_000


def build_empty_index(project_root: str | Path) -> dict[str, Any]:
    root = _resolve_root(project_root)
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "index_kind": INDEX_KIND,
        "generated_at": _utc_timestamp(),
        "project_root": str(root),
        "files": {},
        "definitions": {},
        "references": [],
        "imports": {},
        "reverse_dependencies": {},
    }


def build_index_payload(
    project_root: str | Path,
    *,
    files: dict[str, dict[str, Any]] | None = None,
    definitions: dict[str, Any] | None = None,
    references: list[dict[str, Any]] | None = None,
    imports: dict[str, Any] | None = None,
    reverse_dependencies: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    payload = build_empty_index(project_root)
    payload["files"] = _dict_copy(files)
    payload["definitions"] = _dict_copy(definitions)
    payload["references"] = _list_copy(references)
    payload["imports"] = _dict_copy(imports)
    payload["reverse_dependencies"] = _normalize_reverse_dependencies(
        reverse_dependencies
    )
    return payload


def file_signature(
    project_root: str | Path,
    file_path: str | Path,
    *,
    max_bytes: int = MAX_INDEXED_SOURCE_BYTES,
) -> dict[str, Any] | None:
    root = _resolve_root(project_root)
    path = Path(file_path)
    if not path.is_absolute():
        path = root / path

    try:
        if path.is_symlink():
            return None
        stat_result = path.stat()
    except OSError:
        return None

    if not stat.S_ISREG(stat_result.st_mode):
        return None
    if stat_result.st_size > max_bytes:
        return None

    digest = _sha256_file_no_symlink(path, max_bytes=max_bytes)
    if digest is None:
        return None

    try:
        relpath = path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return None

    return {
        "path": relpath,
        "sha256": digest,
        "size": int(stat_result.st_size),
        "mtime_ns": int(stat_result.st_mtime_ns),
    }


def validate_index_payload(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("schema_version") != INDEX_SCHEMA_VERSION:
        return False
    if payload.get("index_kind") != INDEX_KIND:
        return False
    required = {
        "generated_at",
        "project_root",
        "files",
        "definitions",
        "references",
        "imports",
        "reverse_dependencies",
    }
    if not required.issubset(payload):
        return False
    if not isinstance(payload["files"], dict):
        return False
    if not isinstance(payload["definitions"], dict):
        return False
    if not isinstance(payload["references"], list):
        return False
    if not isinstance(payload["imports"], dict):
        return False
    if not isinstance(payload["reverse_dependencies"], dict):
        return False
    return True


def _sha256_file_no_symlink(path: Path, *, max_bytes: int) -> str | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(path, flags)  # skylos: ignore[SKY-D215] guarded index source path
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            return None
        if stat_result.st_size > max_bytes:
            return None

        digest = hashlib.sha256()
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining <= 0:
            return None
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _resolve_root(project_root: str | Path) -> Path:
    try:
        return Path(project_root).resolve()
    except OSError:
        return Path(project_root)


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _dict_copy(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    return dict(value)


def _list_copy(value: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if value is None:
        return []
    return list(value)


def _normalize_reverse_dependencies(
    reverse_dependencies: dict[str, list[str]] | None,
) -> dict[str, list[str]]:
    if reverse_dependencies is None:
        return {}

    normalized: dict[str, list[str]] = {}
    for path, dependencies in reverse_dependencies.items():
        unique_dependencies = set()
        for dependency in dependencies:
            unique_dependencies.add(str(dependency))
        normalized[str(path)] = sorted(unique_dependencies)
    return normalized
