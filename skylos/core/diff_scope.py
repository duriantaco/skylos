"""Select changed source files without walking automatically excluded trees."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

from skylos.config import ConfigError
from skylos.core.file_discovery import should_exclude_path
from skylos.core.git_context import GitContext
from skylos.core.git_safety import (
    needs_content_guard,
    read_only_git_command,
    with_diff_guards,
)
from skylos.security.regression_diff import _lexical_repository_path


class DiffBaseUnavailable(ConfigError):
    """The requested comparison base could not be resolved."""


def _git_inventory(context: GitContext, *args):
    """Preserve filename bytes while retaining GitContext's execution guards."""
    safe_args = with_diff_guards(args)
    overrides = context.filter_config_overrides
    if overrides is None:
        if needs_content_guard(safe_args):
            raise ConfigError("Could not inspect changed source files safely")
        overrides = ()
    try:
        return subprocess.run(
            read_only_git_command(safe_args, config_overrides=overrides),
            capture_output=True,
            text=False,
            timeout=10,
            cwd=str(context.root),
            env=context.env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigError("Could not inspect changed source files") from exc


def _git_changed_files(project_root: Path, diff_base: str | None) -> list[Path]:
    if not diff_base:
        raise ConfigError("Changed-file inclusion requires a comparison base")
    context = GitContext.from_path(project_root)
    merge_base = context.run("merge-base", diff_base, "HEAD")
    if merge_base.returncode or not merge_base.stdout.strip():
        raise DiffBaseUnavailable("Could not resolve the changed-file comparison base")
    changed = _git_inventory(
        context,
        "diff",
        "--name-only",
        "--no-relative",
        "--no-ext-diff",
        "--no-textconv",
        "-z",
        "--diff-filter=ACMRTUXB",
        merge_base.stdout.strip(),
        "--",
    )
    untracked = _git_inventory(
        context, "ls-files", "--others", "--exclude-standard", "--full-name", "-z"
    )
    if changed.returncode or untracked.returncode:
        raise ConfigError("Could not inspect changed source files")
    return [
        context.root / os.fsdecode(name)
        for output in (changed.stdout, untracked.stdout)
        for name in output.split(b"\0")
        if name
    ]


def _scan_targets(scan_paths, project_root: Path):
    paths = scan_paths if isinstance(scan_paths, (list, tuple)) else [scan_paths]
    targets = []
    for value in paths:
        target = _lexical_repository_path(
            project_root, Path(os.path.abspath(Path(value).expanduser()))
        )
        if not target.is_relative_to(project_root) or target.is_symlink():
            continue
        try:
            resolved = target.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_relative_to(project_root):
            continue
        if target.is_dir():
            targets.append((target, resolved, True))
        elif target.is_file():
            targets.append((target, resolved, False))
    return targets


def changed_source_files(
    scan_paths,
    project_root,
    *,
    changed_files,
    explicit_exclude_folders,
    diff_base,
    include_unsafe_secret_text=False,
) -> list[Path]:
    """Return existing, contained changed files allowed by explicit policy.

    Automatic defaults are deliberately absent here: ordinary discovery still
    uses them for unchanged files. Candidates are literal file names, never
    directory patterns or recursive scan requests. A supplied empty change set
    is authoritative; Git is read only when ``changed_files`` is ``None``.
    """
    # Import at invocation time: the analyzer owns its supported language list
    # and imports this helper while constructing an analysis run.
    from skylos.analyzer import (
        ANALYZED_SOURCE_SUFFIXES,
        _is_provider_only_secret_text,
        _is_secret_config_candidate,
    )

    root = Path(project_root).expanduser().resolve()
    targets = _scan_targets(scan_paths, root)
    if not targets:
        return []
    candidates = (
        changed_files
        if changed_files is not None
        else _git_changed_files(root, diff_base)
    )
    selected = set()
    for value in candidates:
        candidate = _lexical_repository_path(root, value)
        if _is_provider_only_secret_text(candidate):
            if not include_unsafe_secret_text:
                continue
            if not candidate.is_relative_to(root):
                continue
            for target, _, directory in targets:
                within_target = (
                    candidate.is_relative_to(target)
                    if directory
                    else candidate == target
                )
                scope_root = target if directory else target.parent
                if within_target and not should_exclude_path(
                    candidate, scope_root, explicit_exclude_folders
                ):
                    # Selection is lexical. The secret collector rejects unsafe
                    # ancestors/leafs before reading and emits an incomplete scan.
                    selected.add(candidate)
                    break
            continue
        if (
            not (
                candidate.suffix.lower() in ANALYZED_SOURCE_SUFFIXES
                or _is_secret_config_candidate(candidate)
            )
            or not candidate.is_relative_to(root)
            or candidate.is_symlink()
        ):
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_relative_to(root) or not resolved.is_file():
            continue
        for target, resolved_target, directory in targets:
            within_target = (
                candidate.is_relative_to(target)
                and resolved.is_relative_to(resolved_target)
                if directory
                else candidate == target and resolved == resolved_target
            )
            if not within_target:
                continue
            scope_root = target if directory else target.parent
            resolved_scope_root = (
                resolved_target if directory else resolved_target.parent
            )
            if should_exclude_path(
                candidate, scope_root, explicit_exclude_folders
            ) or should_exclude_path(
                resolved, resolved_scope_root, explicit_exclude_folders
            ):
                continue
            selected.add(resolved)
            break
    return sorted(selected)
