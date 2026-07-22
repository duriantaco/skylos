"""Validation helpers for model-supplied tool arguments."""

from __future__ import annotations

import re
from typing import Any

from .models import AuditToolError


def _validated_relative_path_text(value: str, *, name: str) -> str:
    cleaned = value.strip()
    parts = cleaned.split("/")
    if (
        cleaned != value
        or "\x00" in cleaned
        or "\\" in cleaned
        or cleaned.startswith("//")
        or re.match(r"^[A-Za-z]:", cleaned)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise AuditToolError(f"{name} must stay inside the project root")
    return cleaned


def _reject_unknown_arguments(arguments: dict[str, Any], allowed: set[str]) -> None:
    if not isinstance(arguments, dict):
        raise AuditToolError("tool arguments must be an object")
    unknown = set(arguments) - allowed
    if unknown:
        raise AuditToolError(
            "unsupported tool argument(s): " + ", ".join(sorted(unknown))
        )


def _positive_int(value: Any, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AuditToolError(f"{name} must be a positive integer")
    return value


def _optional_positive_int(value: Any, *, default: int) -> int:
    if value is None:
        return default
    return _positive_int(value, name="line")


def _symbol_matcher(query: str) -> re.Pattern[str]:
    escaped = re.escape(query)
    return re.compile(rf"(?<![A-Za-z0-9_$]){escaped}(?![A-Za-z0-9_$])")
