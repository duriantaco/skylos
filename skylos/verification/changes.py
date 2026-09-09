"""Load Git snapshots for the shared source-comparison service."""

from __future__ import annotations

import os
from pathlib import Path

from skylos.core.verify_change_schema import parse_line_range
from skylos.verification.comparison import (
    ComparisonScope,
    SourceSnapshot,
    _new_result,
    compare_source_changes,
)
from skylos.verification.refactor import (
    _base_sources,
    _current_sources,
    _git,
    _selected_file,
)

_GIT_ASSUMPTIONS = [
    "Tracked and unignored Python sources are compared; ignored dependencies and the external environment are assumed stable.",
    "Unchanged Git submodules are treated as external dependencies; their source is not analyzed.",
    "Snapshot hashes identify the bytes read; working-tree reads are not an atomic filesystem transaction.",
]


def _scope(path, file):
    target = Path(path).expanduser().absolute()
    if target.is_symlink():
        raise ValueError("Verification path must not be a symlink")
    directory = target.is_dir()
    if file is not None and (Path(file).is_absolute() or ".." in Path(file).parts):
        raise ValueError("--file must be a relative path within the selected directory")
    if file is not None and not directory:
        raise ValueError("--file cannot be combined with a file path target")
    anchor = target if directory else target.parent
    try:
        root = Path(
            os.fsdecode(_git(anchor, "rev-parse", "--show-toplevel")).removesuffix("\n")
        ).resolve()
        commit = _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    except ValueError:
        return None
    selected = target / file if file is not None else target
    if not selected.resolve().is_relative_to(root):
        raise ValueError("Verification scope must stay within the Git repository")
    if not directory or file is not None:
        if selected.suffix != ".py":
            return root, commit, selected.resolve().relative_to(root).as_posix(), False
        _, relative = _selected_file(target, file)
        return root, commit, relative, False
    return root, commit, target.resolve().relative_to(root).as_posix(), True


def compare_working_changes(
    path, *, file=None, line_range=None, exclude_folders=None
) -> dict:
    """Infer affected existing functions; differences require intent review.

    This is an automatic companion to normal verification, not an implicit
    assertion that every code change must preserve behavior.
    """
    result = _new_result("unavailable")
    result["base"] = {"ref": "HEAD", "commit": None}
    result["assumptions"].extend(_GIT_ASSUMPTIONS)
    scope = _scope(path, file)
    if scope is None:
        result["reasons"] = ["No local Git HEAD is available for behavior comparison"]
        return result
    root, commit, selected, directory = scope
    result["base"]["commit"] = commit
    if not directory and not selected.endswith(".py"):
        result["reasons"] = [
            "Automatic behavior comparison currently applies to Python files"
        ]
        return result
    excluded = set(exclude_folders or [])
    bounds = (
        line_range if isinstance(line_range, tuple) else parse_line_range(line_range)
    )
    if bounds is not None and (
        len(bounds) != 2 or bounds[0] < 1 or bounds[1] < bounds[0]
    ):
        raise ValueError("Invalid line range")

    comparison_scope = ComparisonScope(
        selected=selected,
        directory=directory,
        line_range=bounds,
        exclude_folders=excluded,
    )

    try:
        before, before_hashes = _base_sources(root, commit, allow_submodules=True)
        after, after_hashes = _current_sources(
            root, None if directory else selected, allow_submodules=True
        )
        changes = _git(
            root,
            "diff",
            "--raw",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            commit,
            "--",
        )
        if any(
            b"160000" in row.split(b"\t", 1)[0].split() or row.startswith(b":160000 ")
            for row in changes.splitlines()
        ):
            raise ValueError(
                "Git submodule dependencies changed; behavior comparison is incomplete"
            )
    except ValueError as exc:
        result.update(status="unknown", reasons=[str(exc)])
        return result
    result["base"]["source_hashes"] = before_hashes
    result["current"] = {"source_hashes": after_hashes}
    result.update(
        compare_source_changes(
            SourceSnapshot(before, before_hashes),
            SourceSnapshot(after, after_hashes),
            scope=comparison_scope,
        )
    )
    result["assumptions"] = [*result["assumptions"], *_GIT_ASSUMPTIONS]
    return result
