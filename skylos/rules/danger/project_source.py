"""Bounded source snapshots used by proofs that require project context.

An incomplete snapshot never supplies a safety proof. The cache is keyed by
the complete file inventory and file metadata, including ctime, so additions,
removals and same-size rewrites invalidate it. Returned trees are read-only.
"""

from __future__ import annotations

import ast
from functools import lru_cache
import os
from pathlib import Path

from .danger_fs.closed_world import _SKIP_DIRS

_MAX_FILES = 2048
_MAX_FILE_BYTES = 2_000_000
_MAX_TOTAL_BYTES = 32_000_000
_MAX_NODES = 1_000_000


@lru_cache(maxsize=16)
def _parse_snapshot(root, inventory, limits):
    max_file_bytes, max_nodes = limits
    trees = {}
    count = 0
    for relative, *_metadata in inventory:
        path = Path(root) / relative
        try:
            source = path.read_bytes()
            if len(source) > max_file_bytes:
                return {}, False
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, ValueError, RecursionError):
            return {}, False
        count += sum(1 for _node in ast.walk(tree))
        if count > max_nodes:
            return {}, False
        stat = path.stat()
        if (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino) != tuple(
            _metadata
        ):
            return {}, False
        trees[path] = tree
    return trees, True


def project_source_snapshot(project_root):
    """Return ``(file -> AST, complete)`` without importing project code."""
    if not project_root:
        return {}, False
    try:
        root = Path(project_root).resolve()
        exists = root.is_dir()
    except (OSError, RuntimeError, ValueError):
        return {}, False
    if not exists:
        return {}, False
    inventory = []
    total = 0
    failed = []
    try:
        for directory, dirs, files in os.walk(root, onerror=failed.append):
            kept = []
            for name in sorted(dirs):
                if name in _SKIP_DIRS:
                    continue
                if (Path(directory) / name).is_symlink():
                    return {}, False
                kept.append(name)
            dirs[:] = kept
            for name in sorted(files):
                if not name.endswith((".py", ".pyw", ".pyi")):
                    continue
                path = Path(directory) / name
                if path.is_symlink():
                    return {}, False
                stat = path.stat()
                total += stat.st_size
                if (
                    stat.st_size > _MAX_FILE_BYTES
                    or total > _MAX_TOTAL_BYTES
                    or len(inventory) >= _MAX_FILES
                ):
                    return {}, False
                inventory.append(
                    (
                        str(path.relative_to(root)),
                        stat.st_mtime_ns,
                        stat.st_ctime_ns,
                        stat.st_size,
                        stat.st_ino,
                    )
                )
    except (OSError, ValueError):
        return {}, False
    if failed:
        return {}, False
    try:
        return _parse_snapshot(
            str(root), tuple(inventory), (_MAX_FILE_BYTES, _MAX_NODES)
        )
    except (OSError, RecursionError):
        return {}, False
