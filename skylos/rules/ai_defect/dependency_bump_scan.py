"""Read consistent Git snapshots for the dependency bump advisory."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path, PurePosixPath

from skylos.core.file_discovery import should_exclude_path
from skylos.core.git_context import GitContext
from skylos.core.safe_cache_io import read_project_text_no_symlink

from .dependency_version_bump import (
    MAX_MANIFEST_BYTES,
    PROJECT_MANIFEST_NAMES,
    detect_mirrored_dependency_bumps,
    is_supported_path,
)


_MAX_FILES = 256
_MAX_TOTAL_BYTES = 32_000_000


def scan_mirrored_dependency_bumps(
    repo_root: str | Path,
    *,
    scan_paths=None,
    changed_files=None,
    exclude_folders=(),
    diff_base: str | None = None,
    staged: bool = False,
) -> list[dict]:
    """Compare merge-base to HEAD for PRs, or HEAD to local working files.

    A PR comparison never mixes committed metadata with uncommitted dependency
    edits. Only selected changed files receive findings; ancestor manifests are
    read as evidence so an explicit single-file scan keeps package ownership.
    Commit hooks use staged=True to compare HEAD with index blobs, regardless
    of worktree edits or the PR base. No Git tree or target file is written.
    """
    try:
        started = time.monotonic()
        project_root = Path(repo_root).resolve()
        context = GitContext.from_path(repo_root)
        revisions = _revisions(context, None if staged else diff_base)
        if revisions is None:
            return []
        before_ref, after_ref = revisions
        revision_args = (before_ref, after_ref) if after_ref else (before_ref,)
        changes = context.run(
            "diff",
            "--name-only",
            "--no-relative",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--diff-filter=M",
            "-z",
            *(["--cached"] if staged else []),
            *revision_args,
            "--",
        )
        if changes.returncode != 0:
            return []
        selected = _selected_paths(
            context,
            project_root,
            changes.stdout.split("\0"),
            scan_paths,
            changed_files,
            exclude_folders,
            staged=staged,
        )
        if not selected or len(selected) > _MAX_FILES:
            return []

        candidates = set(selected)
        for name in selected:
            for parent in PurePosixPath(name).parents:
                candidates.update(
                    str(parent / basename) for basename in PROJECT_MANIFEST_NAMES
                )
        if len(candidates) > _MAX_FILES:
            return []

        # Read all selected index object IDs together, then use those immutable
        # blobs even if another process changes the index during this scan.
        index_entries = _index_entries(context, candidates) if staged else {}
        if index_entries is None:
            return []
        before_files, after_files = {}, {}
        total_bytes = 0
        for name in sorted(candidates):
            if time.monotonic() - started > 20:
                return []
            before = _read_at_ref(context, before_ref, name)
            if staged:
                after = _read_index_entry(context, index_entries.get(name))
            elif after_ref:
                after = _read_at_ref(context, after_ref, name)
            else:
                after = _read_current(context, name)
            for target, source in ((before_files, before), (after_files, after)):
                if source is not None:
                    total_bytes += len(source.encode("utf-8"))
                    if total_bytes > _MAX_TOTAL_BYTES:
                        return []
                    target[name] = source

        findings = detect_mirrored_dependency_bumps(before_files, after_files)
        selected_findings = []
        for finding in findings:
            if finding.get("file") not in selected:
                continue
            finding["file"] = str(context.root / finding["file"])
            for location in finding.get("related_locations", []):
                location["file"] = str(context.root / location["file"])
            selected_findings.append(finding)
        return selected_findings
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return []


def _revisions(context: GitContext, diff_base: str | None):
    head = context.run("rev-parse", "--verify", "--end-of-options", "HEAD^{commit}")
    if head.returncode != 0:
        return None
    head_ref = head.stdout.strip()
    if not diff_base:
        return head_ref, None
    base = context.run(
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{diff_base}^{{commit}}",
    )
    if base.returncode != 0:
        return None
    merge_base = context.run("merge-base", base.stdout.strip(), head_ref)
    if merge_base.returncode != 0:
        return None
    return merge_base.stdout.strip(), head_ref


def _selected_paths(
    context,
    project_root,
    names,
    scan_paths,
    changed_files,
    exclude_folders,
    *,
    staged=False,
):
    requested = None
    if changed_files is not None:
        requested = {
            context.relative_path(
                Path(name) if Path(name).is_absolute() else project_root / name
            )
            for name in changed_files
        }
    targets = (
        scan_paths
        if isinstance(scan_paths, (list, tuple))
        else [scan_paths or project_root]
    )
    targets = [Path(target).resolve() for target in targets]
    selected = set()
    for name in names:
        relative = PurePosixPath(name)
        if not name or relative.is_absolute() or ".." in relative.parts:
            continue
        if not is_supported_path(name) or (
            requested is not None and name not in requested
        ):
            continue
        candidate = context.root / name
        if not any(
            candidate == target
            or ((staged or target.is_dir()) and candidate.is_relative_to(target))
            for target in targets
        ):
            continue
        if should_exclude_path(candidate, project_root, exclude_folders or []):
            continue
        selected.add(name)
    return selected


def _read_current(context: GitContext, name: str) -> str | None:
    source = read_project_text_no_symlink(
        context.root, name, max_bytes=MAX_MANIFEST_BYTES, encoding="utf-8"
    )
    if source is not None:
        return source
    try:
        (context.root / name).lstat()
    except OSError:
        return None
    # An unreadable or unsupported manifest still establishes a project
    # boundary; do not use the outer project's version in its place.
    return ""


def _read_at_ref(context: GitContext, ref: str, name: str) -> str | None:
    entry = context.run("ls-tree", "-l", "-z", ref, "--", f":(literal){name}")
    if entry.returncode != 0:
        return None
    records = [record for record in entry.stdout.split("\0") if record]
    if len(records) != 1:
        return None
    metadata, separator, path = records[0].partition("\t")
    fields = metadata.split()
    if not separator or path != name or len(fields) != 4:
        return None
    mode, kind, object_id, size = fields
    if mode not in {"100644", "100755"} or kind != "blob":
        return ""
    if not size.isdigit() or int(size) > MAX_MANIFEST_BYTES:
        return ""
    return _read_blob(context, object_id)


def _index_entries(context: GitContext, names: set[str]):
    result = context.run(
        "ls-files",
        "--stage",
        "--full-name",
        "-z",
        "--",
        *(f":(literal){name}" for name in sorted(names)),
    )
    if result.returncode != 0:
        return None
    entries = {}
    for record in result.stdout.split("\0"):
        metadata, separator, name = record.partition("\t")
        if not separator or name not in names:
            continue
        fields = metadata.split()
        if len(fields) != 3:
            return None
        mode, object_id, stage = fields
        if name in entries or stage != "0" or mode not in {"100644", "100755"}:
            # Preserve a manifest boundary without treating unmerged or
            # nonregular entries as usable project metadata.
            entries[name] = ""
        else:
            entries[name] = object_id
    return entries


def _read_index_entry(context: GitContext, object_id: str | None) -> str | None:
    if not object_id:
        return object_id
    size = context.run("cat-file", "-s", object_id)
    if size.returncode != 0:
        return None
    if (
        not size.stdout.strip().isdigit()
        or int(size.stdout.strip()) > MAX_MANIFEST_BYTES
    ):
        return ""
    return _read_blob(context, object_id)


def _read_blob(context: GitContext, object_id: str) -> str | None:
    blob = context.run("cat-file", "blob", object_id)
    if blob.returncode != 0 or len(blob.stdout.encode("utf-8")) > MAX_MANIFEST_BYTES:
        return None
    return blob.stdout
