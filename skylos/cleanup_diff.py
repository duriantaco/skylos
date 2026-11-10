"""Pin cleanup comparison evidence while keeping selection separate from analysis."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path

from skylos.core.diff_scope import _git_changed_files, changed_source_files
from skylos.core.git_context import GitContext
from skylos.security.regression_diff import changed_sources


def _git_text(context, *args):
    result = context.run(*args)
    if result.returncode or not result.stdout.strip():
        raise ValueError(
            "Cleanup diff requires an available Git repository and comparison base"
        )
    return result.stdout.strip()


def _inside_target(path, target):
    return path.is_relative_to(target) if target.is_dir() else path == target


def _has_symlink(root, path):
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


@dataclass(frozen=True)
class CleanupDiff:
    context: GitContext
    target: Path
    requested_base: str
    base_sha: str
    merge_base_sha: str
    head_sha: str
    dirty: bool
    changed_files: tuple[str, ...]
    deleted_files: tuple[str, ...]

    def assert_head_unchanged(self):
        current = _git_text(self.context, "rev-parse", "--verify", "HEAD^{commit}")
        if current != self.head_sha:
            raise ValueError(
                "Git HEAD changed during cleanup; the scan is not comparable"
            )

    def scope_binding(self):
        return {
            "diff_base_sha": self.base_sha,
            "diff_merge_base_sha": self.merge_base_sha,
        }

    def baseline(self):
        return {
            "base_sha": self.base_sha,
            "merge_base_sha": self.merge_base_sha,
            "head_sha": self.head_sha,
            "worktree_dirty": self.dirty,
        }

    def includes(self, file):
        path = Path(file)
        if path.is_absolute():
            try:
                path = path.relative_to(self.context.root)
            except ValueError:
                return False
        return ".." not in path.parts and path.as_posix() in self.changed_files


def resolve_cleanup_diff(target: Path, base: str) -> CleanupDiff:
    """Compare a pinned merge base with current committed and local changes."""
    if not base or base.startswith("-") or not all(char.isprintable() for char in base):
        raise ValueError("Cleanup --diff requires a valid Git comparison ref")
    context = GitContext.from_path(target)
    top = context.root.resolve()
    if _git_text(
        context, "rev-parse", "--is-inside-work-tree"
    ) != "true" or not target.is_relative_to(top):
        raise ValueError("Cleanup diff target must remain inside its Git worktree")
    base_sha = _git_text(
        context, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}"
    )
    head_sha = _git_text(context, "rev-parse", "--verify", "HEAD^{commit}")
    merge_base_sha = _git_text(context, "merge-base", base_sha, head_sha)
    status = context.run("status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status.returncode:
        raise ValueError("Cleanup diff could not inspect working-tree changes safely")

    from skylos.config import load_config, resolve_config_file_path
    from skylos.constants import parse_exclude_folders
    from skylos.core.file_discovery import should_exclude_path

    config = load_config(top, config_file=resolve_config_file_path())
    excluded = sorted(
        parse_exclude_folders(
            use_defaults=True, config_exclude_folders=config.get("exclude")
        )
    )
    candidates = _git_changed_files(top, merge_base_sha)
    if len(candidates) > 50_000:
        raise ValueError("Cleanup changed-file inventory exceeded its limit")
    candidates = [
        path
        for path in candidates
        if path.is_relative_to(top) and not _has_symlink(top, path)
    ]
    selected = changed_source_files(
        target,
        top,
        changed_files=candidates,
        explicit_exclude_folders=excluded,
        diff_base=merge_base_sha,
    )
    changed = tuple(
        path.relative_to(top).as_posix()
        for path in selected
        if not _has_symlink(top, path)
    )
    deleted = tuple(
        sorted(
            change.path
            for change in changed_sources(context, merge_base_sha).values()
            if change.deleted
            and _inside_target(top / change.path, target)
            and not _has_symlink(top, top / change.path)
            and not should_exclude_path(top / change.path, top, excluded)
        )
    )
    selection = CleanupDiff(
        context,
        target,
        base,
        base_sha,
        merge_base_sha,
        head_sha,
        bool(status.stdout),
        changed,
        deleted,
    )
    selection.assert_head_unchanged()
    return selection


@contextmanager
def cleanup_diff_environment(selection: CleanupDiff | None):
    """Feed existing native diff providers a pinned base; restore caller state."""
    if selection is None:
        yield
        return
    previous = os.environ.get("SKYLOS_DIFF_BASE")
    os.environ["SKYLOS_DIFF_BASE"] = selection.merge_base_sha
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("SKYLOS_DIFF_BASE", None)
        else:
            os.environ["SKYLOS_DIFF_BASE"] = previous


def select_cleanup_diff(report, selection: CleanupDiff, inventory):
    """Narrow display and task selection after full inventory reconciliation."""
    original = {section: report[section] for section in ("tasks", "advisories")}
    all_visible = {task["id"] for rows in original.values() for task in rows}
    for section, rows in original.items():
        report[section] = [task for task in rows if selection.includes(task["file"])]
        for task in report[section]:
            task["change_relation"] = "changed_file"
        report["counts"][section] = len(report[section])
        report["counts"]["shown_" + section] = len(report[section])
    report["counts"]["optional_advice"] = sum(
        task["id"] not in all_visible and selection.includes(task["file"])
        for task in inventory or []
    )
    selected = {task["id"]: task for section in original for task in report[section]}
    groups = []
    for group in report.get("groups", []):
        ids = [task_id for task_id in group["task_ids"] if task_id in selected]
        if ids:
            groups.append(
                {
                    **group,
                    "task_ids": ids,
                    "count": len(ids),
                    "files": sorted({selected[task_id]["file"] for task_id in ids}),
                }
            )
    report["groups"] = groups
    report["selection"] = {
        "kind": "changed_files",
        "path": str(selection.target),
        "base": selection.requested_base,
        **selection.baseline(),
        "changed_files": list(selection.changed_files),
        "deleted_files": list(selection.deleted_files),
        "analysis_scope": "full_project",
        "finding_newness": "not_assessed",
        "excluded_tasks": len(original["tasks"]) - len(report["tasks"]),
        "excluded_advisories": len(original["advisories"]) - len(report["advisories"]),
    }
    if report["status"] != "incomplete":
        report["status"] = "ready" if selected else "clear"
    report["next_step"] = (
        "Review the changed-file task and its evidence, make a focused change, run authorized "
        "checks, then rerun skylos cleanup with the same PATH and --diff base. Findings in "
        "changed files may predate this change."
    )
