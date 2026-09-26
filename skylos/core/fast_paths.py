"""Cheaper equivalents of hot ``pathlib`` calls for whole-project passes.

``Path.resolve()`` walks every path component with ``lstat`` and
``Path.relative_to()`` re-parses both paths; over a few thousand files per
run (discovery, then each repo-wide rule pass) that was a measurable share
of an agent-hook edit check. These helpers return the same results.
"""

from __future__ import annotations

import os
from pathlib import Path

_POSIX = os.name == "posix"


class ParentResolver:
    """``Path.resolve(strict=...)`` that reuses resolved parent directories.

    ``realpath(dir/name) == realpath(dir)/name`` whenever ``name`` is a
    plain component that is not itself a symlink, so each directory is
    resolved once instead of once per file in it. Anything else falls back
    to ``Path.resolve``.
    """

    __slots__ = ("_parents",)

    def __init__(self) -> None:
        self._parents: dict[Path, Path] = {}

    def resolve(self, path: Path, *, strict: bool = False) -> Path:
        name = path.name
        if name in {"", ".", ".."} or os.path.islink(path):
            return path.resolve(strict=strict)
        parent = path.parent
        resolved_parent = self._parents.get(parent)
        if resolved_parent is None:
            resolved_parent = parent.resolve()
            self._parents[parent] = resolved_parent
        resolved = resolved_parent / name
        if strict and not os.path.lexists(resolved):
            # Same failure Path.resolve(strict=True) reports.
            raise FileNotFoundError(str(path))
        return resolved


def _string_fast_path(path: Path, root: Path) -> bool:
    # Lexical string comparison equals pathlib's only for absolute POSIX
    # paths; relative ones ("." roots, "a/../b") go through pathlib.
    return _POSIX and path.is_absolute() and root.is_absolute()


def is_within(path: Path, root: Path) -> bool:
    """``path.relative_to(root)`` succeeds (POSIX string fast path)."""
    if not _string_fast_path(path, root):
        try:
            path.relative_to(root)
        except ValueError:
            return False
        return True
    path_text = str(path)
    root_text = str(root)
    if path_text == root_text:
        return True
    if not root_text.endswith("/"):
        root_text += "/"
    return path_text.startswith(root_text)


def relative_parts(path: Path, root: Path) -> tuple[str, ...]:
    """``path.relative_to(root).parts``; raises ValueError like it."""
    if not _string_fast_path(path, root):
        return path.relative_to(root).parts
    path_text = str(path)
    root_text = str(root)
    if path_text == root_text:
        return ()
    prefix = root_text if root_text.endswith("/") else root_text + "/"
    if not path_text.startswith(prefix):
        raise ValueError(f"{path_text!r} is not in the subpath of {root_text!r}")
    return tuple(part for part in path_text[len(prefix) :].split("/") if part)
