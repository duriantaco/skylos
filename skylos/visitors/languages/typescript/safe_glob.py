from __future__ import annotations

import glob
import os
from pathlib import Path

MAX_TYPESCRIPT_GLOB_MATCHES = 512


def _is_inside_root(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), root]) == root
    except ValueError:
        return False


def _absolute_pattern(base_dir: str, pattern: str) -> str:
    if os.path.isabs(pattern):
        return os.path.normpath(pattern)
    return os.path.normpath(os.path.join(os.path.abspath(base_dir), pattern))


def _static_glob_prefix(pattern: str) -> str:
    normalized = os.path.abspath(os.path.normpath(pattern))
    drive, tail = os.path.splitdrive(normalized)
    prefix_parts: list[str] = []

    for part in tail.split(os.sep):
        if not part:
            continue
        if glob.has_magic(part):
            break
        prefix_parts.append(part)

    if drive:
        root = drive + os.sep
    elif normalized.startswith(os.sep):
        root = os.sep
    else:
        root = os.curdir

    if not prefix_parts:
        return root
    return os.path.join(root, *prefix_parts)


def resolve_bounded_base(base_dir: str, candidate: str) -> str | None:
    root = os.path.realpath(base_dir)
    resolved = _absolute_pattern(root, candidate)
    if not _is_inside_root(resolved, root):
        return None
    return os.path.normpath(resolved)


def safe_glob_paths(
    base_dir: str,
    pattern: str,
    *,
    allowed_suffixes: frozenset[str] | set[str] | None = None,
    max_matches: int = MAX_TYPESCRIPT_GLOB_MATCHES,
) -> list[str]:
    root = os.path.realpath(base_dir)
    full_pattern = _absolute_pattern(root, pattern)
    search_base = _static_glob_prefix(full_pattern)

    if not _is_inside_root(search_base, root):
        return []

    matches: list[str] = []
    for candidate in glob.iglob(full_pattern, recursive=True):
        real_path = os.path.realpath(candidate)
        if not _is_inside_root(real_path, root):
            continue
        if not os.path.isfile(real_path):
            continue
        if allowed_suffixes and Path(real_path).suffix.lower() not in allowed_suffixes:
            continue

        matches.append(real_path)
        if len(matches) >= max_matches:
            break

    return matches
