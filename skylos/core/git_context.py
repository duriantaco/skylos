from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from skylos.core.file_discovery import find_git_root
from skylos.core.git_safety import (
    read_only_git_command,
    read_only_git_environment,
)


_REPOSITORY_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
)
_FILTER_CONFIG_KEY_RE = re.compile(
    r"^filter\.(?P<driver>.+)\.(?:clean|smudge|process|required)$",
    re.IGNORECASE,
)
_DIFF_CONFIG_KEY_RE = re.compile(
    r"^diff\.(?P<driver>.+)\.(?:command|textconv|cachetextconv|trustExitCode)$",
    re.IGNORECASE,
)
_SAFE_FILTER_DRIVER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_MAX_FILTER_DRIVERS = 128
_MAX_FILTER_DRIVER_LENGTH = 128
_MAX_FILTER_CONFIG_OUTPUT = 128_000


def _absolute_env_path(value: str, cwd: Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else cwd / path).resolve()


def _git_paths(root: Path, env: dict[str, str]) -> tuple[Path, Path] | None:
    """Ask Git how this invocation resolves its repository and index."""
    try:
        result = subprocess.run(
            read_only_git_command(
                [
                    "rev-parse",
                    "--path-format=absolute",
                    "--absolute-git-dir",
                    "--git-path",
                    "index",
                ]
            ),
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


def _filter_config_overrides(
    root: Path,
    env: dict[str, str],
) -> tuple[str, ...] | None:
    """Neutralize clean/process filters selected by repository attributes."""

    try:
        result = subprocess.run(
            read_only_git_command(
                [
                    "config",
                    "--includes",
                    "--null",
                    "--name-only",
                    "--get-regexp",
                    (
                        r"^(filter\..*\.(clean|smudge|process|required)"
                        r"|diff\..*\.(command|textconv|cachetextconv|trustExitCode))$"
                    ),
                ]
            ),
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(root),
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 1:
        return ()
    if result.returncode != 0:
        return None
    if len(result.stdout.encode("utf-8")) > _MAX_FILTER_CONFIG_OUTPUT:
        return None

    filter_drivers: set[str] = set()
    diff_drivers: set[str] = set()
    for key in result.stdout.split("\0"):
        if not key:
            continue
        match = _FILTER_CONFIG_KEY_RE.fullmatch(key)
        drivers = filter_drivers
        if match is None:
            match = _DIFF_CONFIG_KEY_RE.fullmatch(key)
            drivers = diff_drivers
        if match is None:
            return None
        driver = match.group("driver")
        if (
            not driver
            or len(driver) > _MAX_FILTER_DRIVER_LENGTH
            or _SAFE_FILTER_DRIVER_RE.fullmatch(driver) is None
        ):
            return None
        drivers.add(driver)
        if len(filter_drivers) + len(diff_drivers) > _MAX_FILTER_DRIVERS:
            return None

    overrides = []
    for driver in sorted(filter_drivers):
        overrides.extend(
            (
                f"filter.{driver}.clean=",
                f"filter.{driver}.smudge=",
                f"filter.{driver}.process=",
                f"filter.{driver}.required=false",
            )
        )
    for driver in sorted(diff_drivers):
        overrides.extend(
            (
                f"diff.{driver}.command=",
                f"diff.{driver}.textconv=",
                f"diff.{driver}.cachetextconv=false",
                f"diff.{driver}.trustExitCode=false",
            )
        )
    return tuple(overrides)


@dataclass(frozen=True)
class GitContext:
    """Git reads anchored to the requested worktree, including inside hooks."""

    root: Path
    env: dict[str, str]
    filter_config_overrides: tuple[str, ...] | None

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

        env = read_only_git_environment(inherited)
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
            original_env = read_only_git_environment(inherited)
            for key in (*_REPOSITORY_ENV, "GIT_INDEX_FILE"):
                if inherited.get(key):
                    original_env[key] = inherited[key]
            original_paths = _git_paths(original_cwd, original_env)
            target_paths = _git_paths(root, env)
            if original_paths and target_paths and original_paths[0] == target_paths[0]:
                # Relative index paths follow Git's setup semantics, which
                # differ between repository discovery and an explicit GIT_DIR.
                env["GIT_INDEX_FILE"] = str(original_paths[1])
        return cls(
            root=root,
            env=env,
            filter_config_overrides=_filter_config_overrides(root, env),
        )

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        safe_args = list(args)
        config_overrides: tuple[str, ...] = ()
        if safe_args and safe_args[0] in {"blame", "diff"}:
            if self.filter_config_overrides is None:
                return subprocess.CompletedProcess(
                    args=list(args),
                    returncode=2,
                    stdout="",
                    stderr="Could not safely inspect repository Git filters",
                )
            config_overrides = self.filter_config_overrides
        if safe_args and safe_args[0] == "diff":
            if "--no-ext-diff" not in safe_args:
                safe_args.insert(1, "--no-ext-diff")
            if "--no-textconv" not in safe_args:
                safe_args.insert(1, "--no-textconv")
        return subprocess.run(
            read_only_git_command(
                safe_args,
                config_overrides=config_overrides,
            ),
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
