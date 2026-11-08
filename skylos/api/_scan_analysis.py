"""Bounded public analysis metadata, shared by every Cloud upload transport."""

from __future__ import annotations

import math

_SCALAR = object()
_DIAGNOSTIC = {
    key: _SCALAR
    for key in (
        "file",
        "line",
        "column",
        "code",
        "message",
        "severity",
        "origin",
        "scope",
        "source",
    )
}
_TYPE_CHECK = {
    key: _SCALAR
    for key in (
        "status",
        "complete",
        "checker",
        "summary",
        "reason",
        "error_count",
        "warning_count",
        "project_error_count",
        "out_of_scope_count",
        "seconds",
    )
}
_TYPE_CHECK.update(
    {
        "counts": {
            key: _SCALAR for key in ("introduced", "preexisting", "unclassified")
        },
        "diagnostics": (_DIAGNOSTIC, 500),
        "comparison": {
            key: _SCALAR for key in ("status", "base", "reason", "base_run")
        },
        "escape_guard": {key: _SCALAR for key in ("status", "added")},
        "truncated": _SCALAR,
    }
)
_FUNCTION = {
    key: _SCALAR
    for key in (
        "file",
        "line",
        "function",
        "calls",
        "primitive_calls",
        "self_seconds",
        "cumulative_seconds",
    )
}
_PROFILE = {
    "schema_version": _SCALAR,
    "kind": _SCALAR,
    "completed": _SCALAR,
    "wall_seconds": _SCALAR,
    "phases": ({key: _SCALAR for key in ("name", "seconds", "visits")}, 100),
    "functions": {"by_cumulative": (_FUNCTION, 100), "by_self": (_FUNCTION, 100)},
    "notes": (_SCALAR, 20),
}


def _project(value, schema):
    """Copy only display fields; the server validates their claimed semantics.

    Malformed supplied fields stay explicit as null so they cannot turn into
    absent/passing checks. Commands, interpreter paths, setup output and local
    configuration fingerprints are never included.
    """
    if schema is _SCALAR:
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value[:4000]
        if isinstance(value, int):
            return value if -(2**53 - 1) <= value <= 2**53 - 1 else None
        if isinstance(value, float) and math.isfinite(value):
            return value
        return None
    if isinstance(schema, tuple):
        if not isinstance(value, list):
            return None
        item_schema, limit = schema
        return [_project(item, item_schema) for item in value[:limit]]
    if not isinstance(value, dict):
        return None
    return {
        key: _project(value[key], child)
        for key, child in schema.items()
        if key in value
    }


def scan_analysis_metadata(result, *, done_receipt=None) -> dict:
    """Project optional CLI analysis onto native SARIF/legacy upload metadata.

    A validated, commit-bound attached Done receipt supplies a type result only
    when the scan itself has none. The caller owns that receipt validation.
    Older scans retain their exact metadata shape.
    """
    if not isinstance(result, dict):
        return {}
    metadata = {}
    if "type_check" in result:
        raw = result["type_check"]
    elif isinstance(done_receipt, dict) and "type_check" in done_receipt:
        raw = done_receipt["type_check"]
    else:
        raw = None
    if (
        "type_check" in result
        or isinstance(done_receipt, dict)
        and "type_check" in done_receipt
    ):
        projected = _project(raw, _TYPE_CHECK)
        if isinstance(raw, dict) and isinstance(projected, dict):
            diagnostics = raw.get("diagnostics")
            previous = raw.get("truncated", 0)
            previous = (
                previous if type(previous) is int and 0 <= previous <= 2**31 - 1 else 0
            )
            removed = (
                max(0, len(diagnostics) - 500) if isinstance(diagnostics, list) else 0
            )
            if previous or removed:
                projected["truncated"] = min(2**31 - 1, previous + removed)
        metadata["type_check"] = projected
    if "profiling" in result:
        metadata["profiling"] = _project(result["profiling"], _PROFILE)
    return metadata
