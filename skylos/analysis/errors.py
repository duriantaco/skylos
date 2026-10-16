from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any


def dedupe_source_analysis_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep one diagnostic when both source passes report the same failure.

    Credential analysis runs before file workers and must report its own
    failures. Its source diagnostic is redundant only after a worker reports
    the identical read or syntax failure. Resolver failures and failures not
    independently reported by a worker remain visible.
    """
    fields = ("file", "error_type", "message", "line", "column")
    worker_failures = {
        tuple(error.get(field) for field in fields)
        for error in errors
        if error.get("kind") in {"syntax_error", "source_read_error"}
    }
    return [
        error
        for error in errors
        if not (
            error.get("kind") == "credential_source_analysis"
            and tuple(error.get(field) for field in fields) in worker_failures
        )
    ]


def analysis_result_incomplete(result: object) -> bool:
    """Return whether a serialized analyzer result is unsafe to trust as complete."""
    if not isinstance(result, Mapping):
        return True
    if result.get("analysis_errors"):
        return True
    summary = result.get("analysis_summary")
    if not isinstance(summary, Mapping):
        return False
    grep_verify = summary.get("grep_verify")
    return bool(
        summary.get("incomplete_languages")
        or summary.get("grade_unavailable_reason") == "analysis_incomplete"
        or (
            isinstance(grep_verify, Mapping)
            and grep_verify.get("complete") is False
        )
    )


def analysis_error_payload(
    file: object,
    error: BaseException,
    *,
    kind: str | None = None,
) -> dict[str, Any]:
    """Build the stable payload used when static analysis cannot complete."""
    is_syntax_error = isinstance(error, SyntaxError)
    message = getattr(error, "msg", None) if is_syntax_error else None
    message = str(message or error or type(error).__name__)
    message = " ".join(message.splitlines())[:500]

    line = getattr(error, "lineno", None) or 1
    column = getattr(error, "offset", None) or 1
    try:
        line = max(1, int(line))
    except (TypeError, ValueError):
        line = 1
    try:
        column = max(1, int(column))
    except (TypeError, ValueError):
        column = 1

    payload = {
        "rule_id": "SKY-ANALYSIS-INCOMPLETE",
        "severity": "HIGH",
        "kind": kind or ("syntax_error" if is_syntax_error else "processing_error"),
        "error_type": type(error).__name__,
        "message": message,
        "file": str(file),
        "line": line,
        "column": column,
        "python_version": (
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
    }
    if is_syntax_error:
        payload["suggestion"] = (
            "Fix the reported syntax, or use a Python runtime that supports the "
            "project's syntax; official container images provide matching "
            "-pythonX.Y tags."
        )
    return payload
