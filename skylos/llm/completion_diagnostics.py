from __future__ import annotations

from typing import Any


MAX_FINISH_REASON_CHARS = 64
OUTPUT_BUDGET_FINISH_REASON = "length"
OUTPUT_BUDGET_SIGNAL = "output_budget_exhausted"
PERSISTED_FINISH_REASONS = frozenset(
    {
        "content_filter",
        "error",
        "length",
        "stop",
        "tool_calls",
    }
)

_FINISH_REASON_ALIASES = {
    "blocked": "content_filter",
    "completed": "stop",
    "content_filter": "content_filter",
    "end_turn": "stop",
    "eos": "stop",
    "eos_token": "stop",
    "error": "error",
    "function_call": "tool_calls",
    "length": "length",
    "max_output_tokens": "length",
    "max_token": "length",
    "max_tokens": "length",
    "max_tokens_exceeded": "length",
    "model_length": "length",
    "safety": "content_filter",
    "stop": "stop",
    "token_limit": "length",
    "tool_call": "tool_calls",
    "tool_calls": "tool_calls",
}


def normalize_finish_reason(value: Any) -> str | None:
    """Return a bounded canonical finish reason, or ``None`` if unknown."""

    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or len(stripped) > MAX_FINISH_REASON_CHARS:
        return None
    key = "_".join(stripped.casefold().replace("-", "_").split())
    normalized = _FINISH_REASON_ALIASES.get(key)
    if normalized not in PERSISTED_FINISH_REASONS:
        return None
    return normalized
