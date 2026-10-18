"""Compare dead-code findings with raw Git objects without executing the target."""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
from typing import NamedTuple
import unicodedata

from skylos.core.git_context import GitContext
from skylos.core.git_safety import read_only_git_command


DEAD_CODE_CATEGORIES = (
    "unused_functions", "unused_imports", "unused_classes", "unused_variables",
    "unused_parameters", "unused_files", "unused_exports",
)
_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MAX_SNAPSHOT_FILES = 20_000
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_BLOB_BYTES = 2 * 1024 * 1024
MAX_SYMLINK_BYTES = 4096
MAX_SYMLINK_HOPS = 40  # Linux SYMLOOP_MAX
MAX_LINK_WORK = 50_000_000  # path characters walked for one snapshot
MAX_LINK_PATH = 4096  # Linux PATH_MAX
_REGULAR_MODES = frozenset({"100644", "100755"})
_SYMLINK_MODE = "120000"
_SUBMODULE_MODE = "160000"


class ImpactUnavailable(ValueError):
    pass


class _Snapshot(NamedTuple):
    files: list  # (path, object id, size) of regular blobs to write
    links: list  # (path, object id, size) of symlink blobs
    omitted: dict  # path -> why the base snapshot does not hold it


def _snapshot_entries(context: GitContext, commit: str, source_suffixes) -> _Snapshot:
    """What the base snapshot holds. An entry it cannot hold is omitted only
    when omission cannot add a definition the head has and the base lacks:
    omitting anything else only removes references from the base, which can
    hide a newly unused finding but never invent one."""
    listing = context.run("ls-tree", "-r", "-l", "-z", commit)
    if listing.returncode:
        raise ImpactUnavailable("base_tree_unavailable")
    files, links, omitted, total = [], [], {}, 0
    for record in listing.stdout.split("\0"):
        if not record:
            continue
        header, separator, name = record.partition("\t")
        fields = header.split()
        path = PurePosixPath(name)
        if (
            not separator or len(fields) != 4 or path.is_absolute()
            or any(part in {"..", ".git"} for part in path.parts)
            or "\\" in name or ":" in name
        ):
            raise ImpactUnavailable("invalid_base_tree_entry")
        mode, kind, object_id, size = fields
        if mode == _SUBMODULE_MODE:
            # The parent repository holds no source for a submodule. One the
            # head checkout did not initialize is an empty folder there too;
            # an initialized one gives the head definitions the base lacks.
            if _has_entries(context.root / name):
                raise ImpactUnavailable("base_submodule_unavailable")
            omitted[name] = "submodule_not_checked_out"
            continue
        if mode not in _REGULAR_MODES and mode != _SYMLINK_MODE or kind != "blob":
            raise ImpactUnavailable("nonregular_base_source")
        if not _OBJECT_ID.fullmatch(object_id) or not size.isdigit():
            raise ImpactUnavailable("invalid_base_blob")
        size = int(size)
        if mode == _SYMLINK_MODE:
            if size > MAX_SYMLINK_BYTES:
                raise ImpactUnavailable("invalid_base_symlink")
            links.append((name, object_id, size))
        elif size > MAX_BLOB_BYTES and path.suffix.lower() not in source_suffixes:
            # Images, archives, model weights, data: no definitions in them.
            # Analyzed source is kept at any size; the head read it in full.
            omitted[name] = "oversize_non_source"
            continue
        else:
            files.append((name, object_id, size))
        total += size
        if len(files) + len(links) > MAX_SNAPSHOT_FILES or total > MAX_SNAPSHOT_BYTES:
            raise ImpactUnavailable("base_snapshot_too_large")
    return _Snapshot(files, links, omitted)


def _has_entries(directory: Path) -> bool:
    try:
        with os.scandir(directory) as entries:
            return any(True for _ in entries)
    except (FileNotFoundError, NotADirectoryError):
        return False


_OUTSIDE = (None, "symlink_outside_repository")


class _LinkTable:
    """Where the base tree's symlinks point, resolved the way the kernel
    does: one component at a time, following links as they are reached, so
    ``s/..`` is the parent of where ``s`` points, not the folder holding
    ``s`` (a ``..`` normalized away as text can still climb out through a
    chain). Only the tree's own link table (path -> target text) is
    consulted, so nothing on disk is read. Each link is resolved once.

    The snapshot may sit on a case-insensitive file system (macOS, Windows),
    where ``d/S`` reaches ``d/s``. So a link is omitted on every system when
    its path goes through a component the tree holds only under another
    spelling (case or Unicode form, against every file, folder and link), a
    non-ASCII component (no Unicode table is trusted to match the disk's), or
    a component the tree does not hold at all (it points at nothing in the
    snapshot, and the disk must never get to choose what it reaches)."""

    def __init__(self, targets: dict, files=()):
        self.targets = targets
        self.folded: dict[str, set] = {}
        for name in (*targets, *files):
            parts = PurePosixPath(name).parts
            for end in range(1, len(parts) + 1):
                path = "/".join(parts[:end])
                self.folded.setdefault(_fold(path), set()).add(path)
        self.memo: dict[str, tuple] = {}
        self.active: set[str] = set()
        self.budget = MAX_LINK_WORK

    def resolve(self, name: str, depth: int = 0) -> tuple:
        """(where ``name`` points, "") inside the repository, else (None,
        why the snapshot omits it). The repository root itself and ``.git``
        are outside."""
        if name in self.memo:
            return self.memo[name]
        if name in self.active or depth >= MAX_SYMLINK_HOPS:
            return None, "symlink_loop"
        self.active.add(name)
        try:
            result = self._walk(name, depth)
        finally:
            self.active.discard(name)
        self.memo[name] = result
        return result

    def _walk(self, name: str, depth: int) -> tuple:
        target = self.targets[name]
        if not _relative_link_target(target):
            return _OUTSIDE
        resolved = list(PurePosixPath(name).parent.parts)
        for part in target.split("/"):
            self.budget -= 1
            if part in ("", "."):
                continue
            if part == "..":
                if not resolved:
                    return _OUTSIDE
                resolved.pop()
                continue
            if _fold(part) == ".git":
                return _OUTSIDE
            if not part.isascii():
                return None, "symlink_ambiguous_name"
            resolved.append(part)
            path = "/".join(resolved)
            if len(path) > MAX_LINK_PATH:
                return None, "symlink_too_long"
            self.budget -= len(path)
            if self.budget < 0:
                raise ImpactUnavailable("base_symlinks_too_complex")
            spellings = self.folded.get(_fold(path))
            if not spellings:
                return None, "symlink_dangling"
            if spellings != {path}:
                return None, "symlink_ambiguous_name"
            if path not in self.targets:
                continue
            destination, why = self.resolve(path, depth + 1)
            if destination is None:
                return None, why
            resolved = destination.split("/")
        return ("/".join(resolved), "") if resolved else _OUTSIDE


def _resolve_link(name: str, targets: dict, files=()) -> tuple:
    return _LinkTable(targets, files).resolve(name)


def _fold(text: str) -> str:
    """``text`` as a case- and normalization-insensitive file system compares it."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFD", text).casefold())


def _relative_link_target(target: str) -> bool:
    return bool(target) and "\0" not in target and "\\" not in target and not target.startswith("/")


def _read_blobs(context: GitContext, entries) -> list[bytes]:
    """Raw contents of (path, object id, size) entries, in order; the whole
    batch is validated before anything is written."""
    if not entries:
        return []
    # Use object IDs, never checkout, archive, smudge filters or executable
    # package scripts. Sizes from ls-tree bound the captured raw object batch.
    batch = subprocess.run(
        read_only_git_command(["cat-file", "--batch"]),
        input="".join(f"{object_id}\n" for _, object_id, _ in entries).encode(),
        capture_output=True, cwd=context.root, env=context.env, timeout=60,
    )
    if batch.returncode:
        raise ImpactUnavailable("base_blobs_unavailable")
    data, offset = batch.stdout, 0
    expected_size = sum(size + len(object_id) + 32 for _, object_id, size in entries)
    if len(data) > expected_size:
        raise ImpactUnavailable("invalid_base_blob_batch")
    contents = []
    for _, object_id, size in entries:
        end = data.find(b"\n", offset)
        header = data[offset:end].decode("ascii") if end >= offset else ""
        if header != f"{object_id} blob {size}":
            raise ImpactUnavailable("invalid_base_blob_batch")
        offset = end + 1
        content = data[offset:offset + size]
        offset += size
        if len(content) != size or data[offset:offset + 1] != b"\n":
            raise ImpactUnavailable("invalid_base_blob_batch")
        offset += 1
        contents.append(content)
    if offset != len(data):
        raise ImpactUnavailable("invalid_base_blob_batch")
    return contents


def _write_snapshot(context: GitContext, entries, destination: Path):
    """Write regular files, given as (path, object id, size), under destination."""
    for (name, _, _), content in zip(entries, _read_blobs(context, entries)):
        target = destination.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)  # skylos: ignore[SKY-D324] validated Git entry under a fresh private TemporaryDirectory; no checkout or target-code execution


def _write_links(context: GitContext, snapshot: _Snapshot, destination: Path):
    """Recreate the symlinks that resolve inside the repository, after every
    file is written so nothing is written through one; the head scan treats
    the two trees alike (source discovery never follows a symlinked file).
    Others are recorded in ``snapshot.omitted``."""
    targets = {}
    for (name, _, _), content in zip(snapshot.links, _read_blobs(context, snapshot.links)):
        try:
            targets[name] = content.decode("utf-8")
        except UnicodeDecodeError:
            targets[name] = ""
    table = _LinkTable(targets, [name for name, _, _ in snapshot.files])
    for name, target_text in targets.items():
        resolved, why = table.resolve(name)
        link = destination.joinpath(*PurePosixPath(name).parts)
        if resolved is None or _crosses_link(destination, link):
            snapshot.omitted[name] = why or "symlink_outside_repository"
            continue
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(target_text, link)
        except OSError:
            snapshot.omitted[name] = "symlink_unavailable"


def _crosses_link(root: Path, path: Path) -> bool:
    current = path.parent
    while current != root and root in current.parents:
        if current.is_symlink():
            return True
        current = current.parent
    return False


def _in_omitted(relative: str, omitted) -> bool:
    return any(relative == path or relative.startswith(path + "/") for path in omitted)


@contextmanager
def _snapshot_environment():
    from skylos.config import POLICY_BASE_ENV_VAR

    keys = (POLICY_BASE_ENV_VAR, "SKYLOS_DIFF_BASE", "GIT_DIR", "GIT_WORK_TREE",
            "GIT_COMMON_DIR", "GIT_INDEX_FILE")
    saved = {key: os.environ.pop(key, None) for key in keys}
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value


def _identity(item: dict, category: str, root: Path):
    file = Path(str(item.get("file", "")))
    try:
        relative = (file if file.is_absolute() else root / file).relative_to(root)
    except ValueError:
        return None
    name = item.get("full_name") or item.get("name")
    if category == "unused_files":
        # File-level findings such as SKY-E003 have no declaration name.
        name = relative.as_posix()
    if not isinstance(name, str) or not name:
        return None
    # Some file-level reports use absolute paths as their names.
    if name.startswith(str(root) + os.sep):
        name = name[len(str(root)) + 1:]
    return category, relative.as_posix(), name, str(item.get("type", category))


def annotate_dead_code_impact(
    result: dict, paths, *, project_root: Path, base_ref: str,
    config: dict, confidence: int = 60, exclude_folders=None, grep_verify=True,
    config_file=None,
):
    """Mark newly unused findings; missing baselines produce incomplete analysis."""
    from skylos.analyzer import ANALYZED_SOURCE_SUFFIXES, Skylos
    from skylos.cicd.policy import resolve_policy_base

    receipt = {"mode": "impact", "status": "incomplete", "introduced_count": 0}
    try:
        if result.get("analysis_errors"):
            raise ImpactUnavailable("head_analysis_incomplete")
        context = GitContext.from_path(project_root)
        commit = resolve_policy_base(project_root, base_ref)
        receipt["base_commit"] = commit
        entries = _snapshot_entries(context, commit, ANALYZED_SOURCE_SUFFIXES)
        with tempfile.TemporaryDirectory(prefix="skylos-pr-impact-") as directory:
            snapshot = Path(directory).resolve()
            _write_snapshot(context, entries.files, snapshot)
            _write_links(context, entries, snapshot)
            requested = paths if isinstance(paths, (list, tuple)) else [paths]
            targets = []
            for requested_path in requested:
                relative = Path(requested_path).resolve().relative_to(context.root)
                target = snapshot / relative
                # A new file/directory has no baseline. Materialize only an
                # empty directory so the analyzer never reads the worktree.
                if not target.exists():
                    if Path(requested_path).is_file():
                        continue
                    target.mkdir(parents=True, exist_ok=True)  # skylos: ignore[SKY-D215] resolved scope is relative to the Git root, mapped into the private snapshot
                targets.append(str(target))
            baseline = {}
            if targets:
                with _snapshot_environment():
                    baseline_paths = (
                        targets if isinstance(paths, (list, tuple)) else targets[0]
                    )
                    baseline = json.loads(Skylos().analyze(
                        baseline_paths, thr=confidence,
                        exclude_folders=sorted(exclude_folders) if exclude_folders else None,
                        grep_verify=grep_verify, grep_cache=False,
                        trace_file=False,
                        config_file=config_file,
                        project_config_overrides=config,
                    ))
            if baseline.get("analysis_errors"):
                raise ImpactUnavailable("base_analysis_incomplete")
            baseline_ids = set()
            for category in DEAD_CODE_CATEGORIES:
                for item in baseline.get(category, []) or []:
                    if not isinstance(item, dict):
                        raise ImpactUnavailable("base_finding_identity_unavailable")
                    identity = _identity(item, category, snapshot)
                    if identity is None:
                        raise ImpactUnavailable("base_finding_identity_unavailable")
                    baseline_ids.add(identity)
            introduced = []
            for category in DEAD_CODE_CATEGORIES:
                for item in result.get(category, []) or []:
                    if not isinstance(item, dict):
                        continue
                    identity = _identity(item, category, context.root)
                    if identity is None:
                        raise ImpactUnavailable("finding_identity_unavailable")
                    # The base has no copy of an omitted path to compare with.
                    if identity not in baseline_ids and not _in_omitted(
                        identity[1], entries.omitted
                    ):
                        introduced.append(item)
            # Do not mutate findings until the entire comparison succeeds.
            for item in introduced:
                item["change_status"] = "introduced"
                item["report_scope"] = "dependency_impact"
            receipt.update(status="complete", introduced_count=len(introduced),
                           snapshot_file_count=len(entries.files) + len(entries.links))
            if entries.omitted:
                receipt["omitted"] = dict(Counter(entries.omitted.values()))
    except Exception as exc:
        logging.getLogger("Skylos").debug("PR impact comparison failed", exc_info=True)
        receipt["error_type"] = type(exc).__name__
        receipt["reason"] = str(exc) if isinstance(exc, ImpactUnavailable) else "base_comparison_failed"
        result.setdefault("analysis_errors", []).append({
            "kind": "pr_impact_incomplete", "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "severity": "HIGH", "file": str(project_root), "line": 1,
            "message": "PR impact could not be checked against the base revision.",
            "reason": receipt["reason"],
        })
        result.setdefault("analysis_summary", {})["analysis_error_count"] = len(result["analysis_errors"])
    result.setdefault("analysis_summary", {})["pr_impact"] = receipt
    return receipt
