from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skylos.config import ConfigError
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.core.git_context import GitContext
from skylos.core.pr_impact import ImpactUnavailable, _read_blobs


def is_mapped(path: str) -> bool:
    from skylos.changemap.languages import is_mapped as mapped

    return mapped(path)

STATUS_ADDED = "A"
STATUS_DELETED = "D"
STATUS_MODIFIED = "M"
_REGULAR_MODES = frozenset({"100644", "100755"})
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


@dataclass
class FileChange:
    path: str
    status: str
    old_lines: set[int] = field(default_factory=set)
    new_lines: set[int] = field(default_factory=set)
    base_source: str | None = None
    head_source: str | None = None


@dataclass
class ChangeInputs:
    root: Path
    base_commit: str
    files: dict[str, FileChange]
    project_python_files: list[str]
    not_mapped: list[str]


def _excluded(path: str) -> bool:
    for part in PurePosixPath(path).parts[:-1]:
        if part in DEFAULT_EXCLUDE_FOLDERS or part.endswith(".egg-info"):
            return True
    return False


def _split_z(text: str) -> list[str]:
    return [item for item in text.split("\0") if item]


def _resolve_base(root: Path, base_ref: str) -> str:
    from skylos.cicd.policy import resolve_policy_base

    try:
        return resolve_policy_base(root, base_ref)
    except ConfigError as exc:
        raise ValueError(f"Could not resolve the base ref {base_ref!r}: {exc}") from exc


def _run(context: GitContext, *args: str) -> str:
    result = context.run(*args)
    if result.returncode:
        raise ValueError(f"git {args[0]} failed: {result.stderr.strip() or result.returncode}")
    return result.stdout


def _line_range(start: str, length: str | None) -> range:
    count = 1
    if length is not None:
        count = int(length)
    return range(int(start), int(start) + count)


def _hunk_path(old_path: str | None, new_path: str) -> str:
    if new_path == "/dev/null" and old_path:
        return old_path[2:]
    return new_path[2:]


def _parse_hunks(diff_text: str, files: dict[str, FileChange]) -> None:
    current = None
    old_path = None
    for line in diff_text.splitlines():
        if line.startswith("--- "):
            old_path = line[4:]
        elif line.startswith("+++ "):
            current = files.get(_hunk_path(old_path, line[4:]))
        elif line.startswith("@@") and current is not None:
            match = _HUNK.match(line)
            if match is not None:
                old_start, old_len, new_start, new_len = match.groups()
                current.old_lines.update(_line_range(old_start, old_len))
                current.new_lines.update(_line_range(new_start, new_len))


def _blob_entry(record: str) -> tuple[str, str, int] | None:
    header, _, name = record.partition("\t")
    fields = header.split()
    if len(fields) != 4 or fields[1] != "blob" or fields[0] not in _REGULAR_MODES:
        return None
    if not _OBJECT_ID.fullmatch(fields[2]) or not fields[3].isdigit():
        return None
    return name, fields[2], int(fields[3])


def _base_sources(context: GitContext, commit: str, paths: list[str]) -> dict[str, str]:
    if not paths:
        return {}
    records = _split_z(_run(context, "ls-tree", "-l", "-z", commit, "--", *paths))
    entries = [entry for entry in map(_blob_entry, records) if entry is not None]
    try:
        contents = _read_blobs(context, entries)
    except ImpactUnavailable as exc:
        raise ValueError(f"Could not read base sources: {exc}") from exc
    return {name: content.decode("utf-8", errors="replace") for (name, _, _), content in zip(entries, contents)}


def _head_source(root: Path, path: str) -> str | None:
    target = root / path
    if target.is_symlink() or not target.is_file():
        return None
    try:
        return target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _classify(paths_with_status, files: dict[str, FileChange], not_mapped: list[str]) -> None:
    for status, path in paths_with_status:
        if _excluded(path) or path in files:
            continue
        if is_mapped(path):
            files[path] = FileChange(path=path, status=status)
        else:
            not_mapped.append(path)


def _tracked_changes(context: GitContext, commit: str) -> list[tuple[str, str]]:
    records = _split_z(_run(context, "diff", "--name-status", "--no-renames", "-z", commit, "--"))
    return [(records[i][:1], records[i + 1]) for i in range(0, len(records) - 1, 2)]


def _all_lines(source: str | None) -> set[int]:
    if source is None:
        return set()
    return set(range(1, source.count("\n") + 2))


def _fill_sources(context: GitContext, commit: str, files: dict[str, FileChange]) -> None:
    base = _base_sources(context, commit, sorted(p for p, f in files.items() if f.status != STATUS_ADDED))
    for path, change in files.items():
        change.base_source = base.get(path)
        if change.status != STATUS_DELETED:
            change.head_source = _head_source(context.root, path)
        if change.status == STATUS_ADDED:
            change.new_lines = _all_lines(change.head_source)
        elif change.status == STATUS_DELETED:
            change.old_lines = _all_lines(change.base_source)


def collect_inputs(root: str | Path, base_ref: str) -> ChangeInputs:
    root = Path(root).resolve()
    commit = _resolve_base(root, base_ref)
    context = GitContext.from_path(root)
    files: dict[str, FileChange] = {}
    not_mapped: list[str] = []
    _classify(_tracked_changes(context, commit), files, not_mapped)
    untracked = _split_z(_run(context, "ls-files", "--others", "--exclude-standard", "-z"))
    _classify([(STATUS_ADDED, path) for path in untracked], files, not_mapped)
    modified = sorted(p for p, f in files.items() if f.status == STATUS_MODIFIED)
    if modified:
        _parse_hunks(_run(context, "diff", "-U0", "--no-color", "--no-renames", commit, "--", *modified), files)
    _fill_sources(context, commit, files)
    tracked = _split_z(_run(context, "ls-files", "-z"))
    project = {
        path for path in tracked + untracked
        if is_mapped(path) and not _excluded(path) and (context.root / path).is_file()
    }
    return ChangeInputs(
        root=context.root,
        base_commit=commit,
        files=dict(sorted(files.items())),
        project_python_files=sorted(project),
        not_mapped=sorted(set(not_mapped)),
    )
