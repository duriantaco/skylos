"""Compare local or committed Git changes through the shared source service."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from skylos.verification.comparison import _new_result, compare_source_changes
from skylos.verification.context import (
    ComparisonContext,
    ComparisonTarget as ComparisonTarget,
    resolve_comparison_contexts,
)

_SHARED_ASSUMPTIONS = [
    "Unchanged Git submodules are treated as external dependencies; their source is not analyzed.",
]
_WORKING_ASSUMPTIONS = [
    "Tracked and unignored Python sources are compared; ignored dependencies and the external environment are assumed stable.",
    *_SHARED_ASSUMPTIONS,
    "Snapshot hashes identify the bytes read; working-tree reads are not an atomic filesystem transaction.",
]
_COMMITTED_ASSUMPTIONS = [
    "Both source snapshots come from the recorded immutable commits; staged, working and untracked files do not participate.",
    *_SHARED_ASSUMPTIONS,
    "The external Python environment is assumed stable; it is not captured by Git source snapshots.",
]


def _compare_context(context: ComparisonContext) -> dict:
    result = _new_result(context.status)
    if context.status == "ready":
        if len(context.scopes) == 1:
            result.update(
                compare_source_changes(
                    context.before, context.after, scope=context.scopes[0]
                )
            )
        else:
            result.update(
                compare_source_changes(
                    context.before, context.after, scopes=context.scopes
                )
            )
    else:
        result["reasons"] = list(context.reasons)
    result["base"] = {"ref": context.base_ref, "commit": context.base_commit}
    result["current"] = {
        "kind": context.current_kind,
        "commit": context.current_commit,
        "source_hashes": dict(context.after.hashes) if context.after else {},
    }
    if context.before is not None:
        result["base"]["source_hashes"] = dict(context.before.hashes)
    result["context"] = context.metadata()
    assumptions = (
        _COMMITTED_ASSUMPTIONS
        if context.current_kind == "commit"
        else _WORKING_ASSUMPTIONS
    )
    result["assumptions"] = [*result["assumptions"], *assumptions]
    return result


def compare_target_changes(
    paths: Sequence[str | Path | ComparisonTarget],
    *,
    base_ref: str | None = None,
    exclude_folders: Sequence[str] | None = None,
) -> list[dict]:
    """Return one behavior report per repository selected by the requested paths.

    Without a base reference compare HEAD to working sources. With a reference,
    compare its merge base with HEAD to committed HEAD. This API prepares branch
    review for existing diff workflows; it does not activate ordinary CLI scans.
    """
    return [
        _compare_context(context)
        for context in resolve_comparison_contexts(
            paths, base_ref=base_ref, exclude_folders=exclude_folders
        )
    ]


def compare_working_changes(
    path, *, file=None, line_range=None, exclude_folders=None
) -> dict:
    """Keep focused verification's HEAD-to-working-tree comparison compatible."""
    return compare_target_changes(
        [ComparisonTarget(path, file=file, line_range=line_range)],
        exclude_folders=exclude_folders,
    )[0]
