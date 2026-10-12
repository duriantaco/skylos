"""Compare dead-code findings with raw Git objects without executing the target."""

from __future__ import annotations

from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

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


class ImpactUnavailable(ValueError):
    pass


def _snapshot_entries(context: GitContext, commit: str):
    listing = context.run("ls-tree", "-r", "-l", "-z", commit)
    if listing.returncode:
        raise ImpactUnavailable("base_tree_unavailable")
    entries, total = [], 0
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
        # Submodules cannot be treated as empty directories in a complete
        # static baseline; their source is not present in the parent objects.
        if fields[0] == "160000":
            raise ImpactUnavailable("base_submodule_unavailable")
        # Static liveness also reads templates, documentation, project metadata
        # and literal configured filenames with arbitrary extensions. Retain
        # every bounded regular blob rather than pretending a suffix allowlist
        # contains all evidence that the head analyzer may have read.
        mode, kind, object_id, size = fields
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ImpactUnavailable("nonregular_base_source")
        if not _OBJECT_ID.fullmatch(object_id) or not size.isdigit():
            raise ImpactUnavailable("invalid_base_blob")
        size = int(size)
        if size > MAX_BLOB_BYTES:
            raise ImpactUnavailable("base_blob_too_large")
        total += size
        entries.append((name, object_id, size))
        if len(entries) > MAX_SNAPSHOT_FILES or total > MAX_SNAPSHOT_BYTES:
            raise ImpactUnavailable("base_snapshot_too_large")
    return entries


def _write_snapshot(context: GitContext, entries, destination: Path):
    if not entries:
        return
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
    for name, object_id, size in entries:
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
        target = destination.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)  # skylos: ignore[SKY-D324] validated Git entry under a fresh private TemporaryDirectory; no checkout or target-code execution
    if offset != len(data):
        raise ImpactUnavailable("invalid_base_blob_batch")


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
    from skylos.analyzer import Skylos
    from skylos.cicd.policy import resolve_policy_base

    receipt = {"mode": "impact", "status": "incomplete", "introduced_count": 0}
    try:
        if result.get("analysis_errors"):
            raise ImpactUnavailable("head_analysis_incomplete")
        context = GitContext.from_path(project_root)
        commit = resolve_policy_base(project_root, base_ref)
        receipt["base_commit"] = commit
        entries = _snapshot_entries(context, commit)
        with tempfile.TemporaryDirectory(prefix="skylos-pr-impact-") as directory:
            snapshot = Path(directory).resolve()
            _write_snapshot(context, entries, snapshot)
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
                    if identity not in baseline_ids:
                        introduced.append(item)
            # Do not mutate findings until the entire comparison succeeds.
            for item in introduced:
                item["change_status"] = "introduced"
                item["report_scope"] = "dependency_impact"
            receipt.update(status="complete", introduced_count=len(introduced),
                           snapshot_file_count=len(entries))
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
