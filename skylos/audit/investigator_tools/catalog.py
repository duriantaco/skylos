"""Immutable repository catalog and root-confined source reads."""

from __future__ import annotations

import hashlib
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.core.file_discovery import discover_source_files
from skylos.core.safe_cache_io import read_project_text_no_symlink

from .models import AuditToolError, AuditToolFileChanged
from .validation import _validated_relative_path_text


FileSignature = tuple[int, int, int, int, int]


@dataclass(frozen=True)
class CatalogSnapshot:
    paths: dict[str, Path]
    signatures: dict[str, FileSignature]
    discovered_count: int
    truncated: bool
    digest: str


def build_catalog_snapshot(
    project_root: Path,
    extensions: tuple[str, ...],
    exclude_folders: tuple[str, ...],
    excluded_paths: frozenset[str],
    *,
    max_catalog_files: int,
) -> CatalogSnapshot:
    discovered = discover_source_files(
        project_root,
        extensions,
        exclude_folders=exclude_folders,
        respect_gitignore=True,
    )
    allowed = [
        path
        for path in discovered
        if (rel_path := path.relative_to(project_root).as_posix())
        and not _path_is_excluded(rel_path, excluded_paths)
    ]
    truncated = len(allowed) > max_catalog_files
    paths: dict[str, Path] = {}
    signatures: dict[str, FileSignature] = {}
    for path in allowed[:max_catalog_files]:
        rel_path = path.relative_to(project_root).as_posix()
        signature = _regular_file_signature(path)
        if signature is None:
            continue
        paths[rel_path] = path
        signatures[rel_path] = signature
    digest = _catalog_digest(
        signatures,
        discovered_count=len(allowed),
        catalog_truncated=truncated,
    )
    return CatalogSnapshot(
        paths=paths,
        signatures=signatures,
        discovered_count=len(allowed),
        truncated=truncated,
        digest=digest,
    )


class CatalogMixin:
    def _catalog_path(self, raw_path: Any) -> str:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise AuditToolError(
                "tool path must be a non-empty project-relative string"
            )
        cleaned = _validated_relative_path_text(raw_path, name="tool path")
        path = Path(cleaned)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise AuditToolError("tool path must stay inside the project root")
        rel_path = path.as_posix()
        if rel_path not in self._catalog:
            raise AuditToolError(f"tool path is not an allowed source file: {rel_path}")
        return rel_path

    def _path_prefix(self, raw_prefix: Any) -> str:
        if raw_prefix is None or raw_prefix == "":
            return ""
        if not isinstance(raw_prefix, str):
            raise AuditToolError("path_prefix must be a project-relative string")
        cleaned = _validated_relative_path_text(raw_prefix, name="path_prefix")
        path = Path(cleaned)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise AuditToolError("path_prefix must stay inside the project root")
        return path.as_posix().rstrip("/")

    def _catalog_items(self, prefix: str) -> list[tuple[str, Path]]:
        if not prefix:
            return sorted(self._catalog.items())
        return [
            (rel_path, path)
            for rel_path, path in sorted(self._catalog.items())
            if rel_path == prefix or rel_path.startswith(prefix + "/")
        ]

    def _is_excluded_path(self, rel_path: str) -> bool:
        return _path_is_excluded(rel_path, self._excluded_paths)

    def _current_catalog_digest(self) -> str:
        snapshot = build_catalog_snapshot(
            self.project_root,
            self._extensions,
            self._exclude_folders,
            self._excluded_paths,
            max_catalog_files=self.limits.max_catalog_files,
        )
        return snapshot.digest

    def _read_source(self, rel_path: str) -> str:
        path = self._catalog[rel_path]
        if _regular_file_signature(path) != self._catalog_signatures[rel_path]:
            raise AuditToolFileChanged(
                f"source file changed during investigation: {rel_path}"
            )
        source = read_project_text_no_symlink(
            self.project_root,
            rel_path,
            max_bytes=self.limits.max_file_bytes,
            encoding="utf-8",
            errors=None,
            newline="",
        )
        if source is None:
            raise AuditToolError(f"source file could not be read safely: {rel_path}")
        if _regular_file_signature(path) != self._catalog_signatures[rel_path]:
            raise AuditToolFileChanged(
                f"source file changed during investigation: {rel_path}"
            )
        return source


def _path_is_excluded(rel_path: str, excluded_paths: frozenset[str]) -> bool:
    return any(
        rel_path == excluded or rel_path.startswith(excluded + "/")
        for excluded in excluded_paths
    )


def _regular_file_signature(path: Path) -> FileSignature | None:
    try:
        value = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        return None
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _catalog_digest(
    signatures: dict[str, FileSignature],
    *,
    discovered_count: int,
    catalog_truncated: bool,
) -> str:
    digest = hashlib.sha256()
    digest.update(f"{discovered_count}:{int(catalog_truncated)}\n".encode("ascii"))
    for rel_path, signature in sorted(signatures.items()):
        digest.update(rel_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(":".join(str(value) for value in signature).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()
