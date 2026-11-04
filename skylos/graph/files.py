from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skylos.changemap.languages import is_mapped
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.core.git_context import GitContext
from skylos.graph.other_languages import LANGUAGE_NAMES, grammar_ready, other_language

NOT_MAPPED_LANGUAGES = {
    ".kt": "Kotlin",
    ".dart": "Dart",
    ".rb": "Ruby",
    ".cs": "C#",
    ".swift": "Swift",
}


@dataclass
class RepoFiles:
    root: Path
    paths: list[str]
    is_git: bool
    head: str | None = None
    dirty: bool = False
    not_mapped: dict[str, int] = field(default_factory=dict)


def _excluded(path: str) -> bool:
    for part in PurePosixPath(path).parts[:-1]:
        if part in DEFAULT_EXCLUDE_FOLDERS or part.endswith(".egg-info"):
            return True
        if part.startswith(".") and part not in {".", ".."}:
            return True
    return False


def _resolves_inside(root: Path, full: Path) -> bool:
    base = root.resolve()
    target = full.resolve()
    return target != base and base in target.parents


def _split_z(text: str) -> list[str]:
    return [item for item in text.split("\0") if item]


def _git_listing(context: GitContext) -> tuple[list[str], str | None, bool] | None:
    tracked = context.run("ls-files", "-z")
    if tracked.returncode:
        return None
    untracked = context.run("ls-files", "--others", "--exclude-standard", "-z")
    paths = _split_z(tracked.stdout)
    if not untracked.returncode:
        paths += _split_z(untracked.stdout)
    head_result = context.run("rev-parse", "HEAD")
    head = None
    if not head_result.returncode:
        head = head_result.stdout.strip() or None
    status = context.run("status", "--porcelain", "--untracked-files=no")
    dirty = bool(status.returncode == 0 and status.stdout.strip())
    return paths, head, dirty


def _walk(root: Path) -> list[str]:
    found = []
    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in DEFAULT_EXCLUDE_FOLDERS and not d.startswith(".") and not d.endswith(".egg-info")
        )
        for name in filenames:
            full = Path(directory) / name
            found.append(full.relative_to(root).as_posix())
    return found


def _within(path: str, scope: str) -> bool:
    if not scope:
        return True
    return path == scope or path.startswith(scope.rstrip("/") + "/")


def list_repo_files(target: str | Path) -> RepoFiles:
    target = Path(target).resolve()
    context = GitContext.from_path(target)
    root = Path(context.root).resolve()
    listing = None
    if (root / ".git").exists() or os.environ.get("GIT_DIR"):
        listing = _git_listing(context)
    if listing is None:
        root = target
        candidates, head, dirty, is_git = _walk(root), None, False, False
    else:
        candidates, head, dirty = listing
        is_git = True
    scope = ""
    if target != root:
        scope = target.relative_to(root).as_posix()
    paths = []
    not_mapped: Counter[str] = Counter()
    for path in sorted(set(candidates)):
        if not _within(path, scope) or _excluded(path):
            continue
        full = root / path
        if not full.is_file():
            continue
        if not _resolves_inside(root, full):
            continue
        if is_mapped(path):
            paths.append(path)
            continue
        other = other_language(path)
        if other and grammar_ready(other):
            paths.append(path)
            continue
        if other:
            not_mapped[LANGUAGE_NAMES[other]] += 1
            continue
        language = NOT_MAPPED_LANGUAGES.get(PurePosixPath(path).suffix.lower())
        if language:
            not_mapped[language] += 1
    return RepoFiles(
        root=root,
        paths=paths,
        is_git=is_git,
        head=head,
        dirty=dirty,
        not_mapped=dict(sorted(not_mapped.items())),
    )
