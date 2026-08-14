from __future__ import annotations

import sys
from typing import Any


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
