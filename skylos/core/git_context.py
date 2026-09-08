from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from skylos.core.file_discovery import find_git_root


_REPOSITORY_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
)


def _absolute_env_path(value: str, cwd: Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else cwd / path).resolve()


def _git_paths(root: Path, env: dict[str, str]) -> tuple[Path, Path] | None:
    """Ask Git how this invocation resolves its repository and index."""
    try:
        result = subprocess.run(
            [
                "git",
                "rev-parse",
                "--path-format=absolute",
                "--absolute-git-dir",
                "--git-path",
                "index",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(root),
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    lines = result.stdout.splitlines()
    if result.returncode != 0 or len(lines) != 2:
        return None
    return tuple(_absolute_env_path(line, root) for line in lines)


@dataclass(frozen=True)
class GitContext:
    """Git reads anchored to the requested worktree, including inside hooks."""

    root: Path
    env: dict[str, str]

    @classmethod
    def from_path(cls, path: str | Path) -> GitContext:
        original_cwd = Path.cwd()
        inherited = dict(os.environ)
        target = Path(path).resolve()
        start = target.parent if target.is_file() else target
        root = find_git_root(start)
        explicit_git_dir = None

        # Separate Git directories normally have a .git file. Also support an
        # explicitly declared worktree with no marker, but never guess its root
        # from GIT_DIR alone: in a hook Git can mistake a subdirectory for it.
        if root is None and inherited.get("GIT_WORK_TREE") and inherited.get("GIT_DIR"):
            worktree = _absolute_env_path(inherited["GIT_WORK_TREE"], original_cwd)
            if worktree.is_dir() and start.is_relative_to(worktree):
                root = worktree
                explicit_git_dir = _absolute_env_path(
                    inherited["GIT_DIR"], original_cwd
                )

        env = dict(inherited)
        for key in (*_REPOSITORY_ENV, "GIT_INDEX_FILE"):
            env.pop(key, None)
        if root is not None:
            env["GIT_WORK_TREE"] = str(root)
        if explicit_git_dir is not None:
            env["GIT_DIR"] = str(explicit_git_dir)
            if inherited.get("GIT_COMMON_DIR"):
                env["GIT_COMMON_DIR"] = str(
                    _absolute_env_path(inherited["GIT_COMMON_DIR"], original_cwd)
                )

        root = root or start
        if inherited.get("GIT_INDEX_FILE"):
            original_paths = _git_paths(original_cwd, inherited)
            target_paths = _git_paths(root, env)
            if original_paths and target_paths and original_paths[0] == target_paths[0]:
                # Relative index paths follow Git's setup semantics, which
                # differ between repository discovery and an explicit GIT_DIR.
                env["GIT_INDEX_FILE"] = str(original_paths[1])
        return cls(root=root, env=env)

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(self.root),
            env=self.env,
        )

    def relative_path(self, path: str | Path) -> str | None:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        try:
            return candidate.resolve().relative_to(self.root).as_posix()
        except (OSError, ValueError):
            return None
