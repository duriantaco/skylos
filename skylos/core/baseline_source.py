"""Read dependency baselines without trusting a CI checkout's suppression file."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from skylos.core.git_context import GitContext
from skylos.core.review_decisions import is_ci_environment
from skylos.core.safe_cache_io import read_project_text_no_symlink


MAX_DEPENDENCY_BASELINE_BYTES = 2_000_000
_BASELINE_RELATIVE_PATH = Path(".skylos") / "baseline.json"
_OBJECT_ID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_REF_LENGTH = 512
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 100_000


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_baseline(text: str) -> dict | None:
    try:
        baseline = json.loads(text, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError, MemoryError):
        return None
    if not isinstance(baseline, dict):
        return None
    if "dependency_baseline" in baseline and not isinstance(
        baseline["dependency_baseline"], dict
    ):
        return None
    remaining = [(baseline, 0)]
    node_count = 0
    while remaining:
        value, depth = remaining.pop()
        node_count += 1
        if depth > _MAX_JSON_DEPTH or node_count > _MAX_JSON_NODES:
            return None
        if isinstance(value, dict):
            remaining.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            remaining.extend((child, depth + 1) for child in value)
    return baseline


def _failure(receipt: dict, error: str) -> tuple[None, dict]:
    return None, {**receipt, "status": "unavailable", "error": error}


def _read_git_baseline(root: Path, ref: str, receipt: dict) -> tuple[dict | None, dict]:
    if (
        not isinstance(ref, str)
        or not ref
        or len(ref) > _MAX_REF_LENGTH
        or ref.startswith("-")
        or any(ord(char) <= 32 or ord(char) == 127 for char in ref)
    ):
        return _failure(receipt, "invalid_ref")

    context = GitContext.from_path(root)
    # Resolve only the requested revision, never HEAD or a local-file fallback.
    revision = context.run(
        "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"
    )
    commit = revision.stdout.strip()
    if revision.returncode != 0 or _OBJECT_ID_RE.fullmatch(commit) is None:
        return _failure(receipt, "ref_unavailable")
    receipt = {**receipt, "commit": commit}

    # Do not resolve the working-tree baseline path: it may be a symlink even
    # though the operator-selected commit contains a regular baseline file.
    try:
        relative = (root.relative_to(context.root) / _BASELINE_RELATIVE_PATH).as_posix()
    except ValueError:
        return _failure(receipt, "invalid_root")
    entry = context.run("ls-tree", "-l", "-z", commit, "--", f":(literal){relative}")
    if entry.returncode != 0:
        return _failure(receipt, "baseline_unavailable")
    records = [record for record in entry.stdout.split("\0") if record]
    if len(records) != 1:
        return _failure(receipt, "baseline_unavailable")
    metadata, separator, name = records[0].partition("\t")
    fields = metadata.split()
    if not separator or name != relative or len(fields) != 4:
        return _failure(receipt, "invalid_git_entry")
    mode, kind, object_id, size = fields
    if (
        mode not in {"100644", "100755"}
        or kind != "blob"
        or _OBJECT_ID_RE.fullmatch(object_id) is None
    ):
        return _failure(receipt, "nonregular_baseline")
    if not size.isdigit() or int(size) > MAX_DEPENDENCY_BASELINE_BYTES:
        return _failure(receipt, "baseline_too_large")

    # cat-file reads the immutable raw object, without checkout filters,
    # attributes, external diffs, or path traversal through working-tree links.
    blob = context.run("cat-file", "blob", object_id)
    if blob.returncode != 0:
        return _failure(receipt, "baseline_unavailable")
    if len(blob.stdout.encode("utf-8")) > MAX_DEPENDENCY_BASELINE_BYTES:
        return _failure(receipt, "baseline_too_large")
    baseline = _parse_baseline(blob.stdout)
    if baseline is None:
        return _failure(receipt, "invalid_baseline")
    return baseline, {**receipt, "status": "loaded"}


def load_dependency_baseline(
    project_root: str | Path,
    *,
    ref: str | None = None,
    environ: dict | None = None,
) -> tuple[dict | None, dict]:
    """Return a baseline and a small receipt, retaining findings on any failure.

    CI needs an explicit operator-selected base revision. Ref selection is never
    inferred from the scanned project's files. Callers must obtain the ref from
    trusted CI configuration, preferably the base commit SHA supplied by CI.
    ``environ`` controls CI detection; GitContext independently guards Git reads.
    """
    receipt = {"source": "git_ref" if ref is not None else "working_tree"}
    if ref is None and is_ci_environment(environ):
        return None, {**receipt, "status": "ci_ref_required"}

    try:
        requested_root = Path(project_root).expanduser()
        if requested_root.is_symlink():
            return _failure(receipt, "invalid_root")
        root = requested_root.resolve(strict=True)
        if not root.is_dir():
            return _failure(receipt, "invalid_root")
        if ref is not None:
            return _read_git_baseline(root, ref, receipt)

        text = read_project_text_no_symlink(
            root,
            _BASELINE_RELATIVE_PATH,
            max_bytes=MAX_DEPENDENCY_BASELINE_BYTES,
            encoding="utf-8",
        )
        if text is None:
            return _failure(receipt, "baseline_unavailable")
        baseline = _parse_baseline(text)
        if baseline is None:
            return _failure(receipt, "invalid_baseline")
        return baseline, {**receipt, "status": "loaded"}
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        # Neither Git stderr nor filesystem errors belong in reports: they may
        # contain credentials, user paths, or attacker-controlled ref strings.
        return _failure(receipt, "source_unavailable")
