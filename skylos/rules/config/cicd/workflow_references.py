"""Literal local reusable-workflow references resolved at the caller's commit."""

from __future__ import annotations

import unicodedata


def local_workflow_reference(value: object) -> str | None:
    """Return a valid ``./`` or ``$/`` workflow path without its prefix.

    This describes a job-level reusable-workflow reference, not a local action.
    The new ``$/`` form cannot carry a ref or expressions, and workflow files
    must be directly inside ``.github/workflows``. No target file is read.
    """
    if not isinstance(value, str) or any(
        unicodedata.category(char) in {"Cc", "Zl", "Zp"} for char in value
    ):
        return None
    text = value.strip()
    if not text.startswith(("./.github/workflows/", "$/.github/workflows/")):
        return None
    path = text[2:]
    filename = path.removeprefix(".github/workflows/")
    if (
        not filename
        or not filename.endswith((".yml", ".yaml"))
        or any(char in filename for char in ("/", "\\", "@"))
        or "${{" in filename
    ):
        return None
    return path
