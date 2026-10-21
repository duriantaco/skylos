"""Ruff rules a project turned off, read from its own configuration.

When maintainers ignore a ruff rule that makes the same suggestion as a Skylos
check, they have already decided against that rewrite. The nearest ruff
configuration between the file and the project root is used, as ruff finds
it: ``.ruff.toml``, ``ruff.toml``, or a ``pyproject.toml`` with a
``[tool.ruff]`` table. ``ignore`` and ``extend-ignore`` (top level or under
``lint``) count, and so do ``per-file-ignores`` whose pattern matches the file.
Codes match by prefix, the way ruff selects them. Reads are bounded and refuse
symlinks; nothing is executed.
"""

from __future__ import annotations

import os
import stat
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from skylos.core.safe_cache_io import read_project_text_no_symlink

_MAX_CONFIG_BYTES = 1_000_000
_CONFIG_NAMES = (".ruff.toml", "ruff.toml", "pyproject.toml")


def _codes(value) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        item.strip().upper() for item in value if isinstance(item, str) and item.strip()
    )


def _ignores(table: dict):
    lint = table.get("lint")
    if not isinstance(lint, dict):
        lint = {}
    codes = []
    per_file = []
    for section in (table, lint):
        for key in ("ignore", "extend-ignore"):
            codes.extend(_codes(section.get(key)))
        for key in ("per-file-ignores", "extend-per-file-ignores"):
            patterns = section.get(key)
            if not isinstance(patterns, dict):
                continue
            for pattern, values in patterns.items():
                if isinstance(pattern, str):
                    per_file.append((pattern, _codes(values)))
    return tuple(codes), tuple(per_file)


@lru_cache(maxsize=256)
def _ruff_settings(root: str, path: str, size: int, mtime_ns: int):
    try:
        source = read_project_text_no_symlink(
            root, path, max_bytes=_MAX_CONFIG_BYTES, errors="replace"
        )
        if source is None:
            return None
        document = tomllib.loads(source)
    except (OSError, ValueError, RuntimeError, TypeError):
        return None
    if Path(path).name != "pyproject.toml":
        return _ignores(document)
    tool = document.get("tool")
    if not isinstance(tool, dict) or not isinstance(tool.get("ruff"), dict):
        return None
    return _ignores(tool["ruff"])


def _nearest_settings(filename, project_root):
    root = Path(os.path.abspath(project_root))
    directory = Path(os.path.abspath(filename)).parent
    try:
        directory.relative_to(root)
    except ValueError:
        return None
    while True:
        for name in _CONFIG_NAMES:
            candidate = directory / name
            try:
                info = candidate.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            settings = _ruff_settings(
                str(root), str(candidate), info.st_size, info.st_mtime_ns
            )
            if settings is not None:
                return directory, settings
        if directory == root or directory.parent == directory:
            return None
        directory = directory.parent


def ruff_ignores(filename, project_root, codes) -> bool:
    """Whether the project's ruff configuration ignores one of ``codes`` here."""
    if not filename or project_root is None or not codes:
        return False
    found = _nearest_settings(filename, project_root)
    if found is None:
        return False
    directory, (ignored, per_file) = found
    relative = PurePosixPath(
        Path(os.path.abspath(filename)).relative_to(directory).as_posix()
    )
    active = list(ignored)
    for pattern, values in per_file:
        if fnmatchcase(str(relative), pattern) or fnmatchcase(relative.name, pattern):
            active.extend(values)
    return any(
        prefix == "ALL" or code.upper().startswith(prefix)
        for prefix in active
        for code in codes
    )
