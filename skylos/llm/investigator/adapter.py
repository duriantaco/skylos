"""Model-adapter calls constrained by the investigator budget."""

from __future__ import annotations

import time
from typing import Any

from skylos.llm.harness import HarnessRunner
from skylos.llm.completion_diagnostics import (
    OUTPUT_BUDGET_FINISH_REASON,
    OUTPUT_BUDGET_SIGNAL,
    normalize_finish_reason,
)

from .models import InvestigationIncompleteError, InvestigationLimits
from .protocol import INVESTIGATOR_SYSTEM_PROMPT, INVESTIGATOR_TURN_FORMAT


MAX_MODEL_CALL_DIAGNOSTICS = 32
MAX_DIAGNOSTIC_COUNT = 1_000_000_000


def record_adapter_usage(adapter: Any, runner: HarnessRunner) -> None:
    usage = getattr(adapter, "last_usage", None)
    if not isinstance(usage, dict):
        return
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = usage.get(key)
        if isinstance(value, int | float) and value >= 0:
            runner.update_usage(**{key: value})


def read_adapter_completion_diagnostic(
    adapter: Any,
    *,
    call_index: int,
) -> dict[str, Any] | None:
    """Copy only bounded scalar transport metadata from the last model call."""
    raw = getattr(adapter, "last_completion_diagnostic", None)
    if not isinstance(raw, dict):
        return None

    finish_reason = normalize_finish_reason(raw.get("finish_reason"))

    content_chars = _bounded_diagnostic_count(raw.get("content_chars"))
    completion_tokens = _bounded_diagnostic_count(raw.get("completion_tokens"))
    reasoning_tokens = _bounded_diagnostic_count(raw.get("reasoning_tokens"))
    signal = (
        OUTPUT_BUDGET_SIGNAL if finish_reason == OUTPUT_BUDGET_FINISH_REASON else None
    )

    return {
        "call_index": call_index,
        "finish_reason": finish_reason,
        "content_chars": content_chars,
        "completion_tokens": completion_tokens,
        "reasoning_tokens": reasoning_tokens,
        "signal": signal,
    }


def _bounded_diagnostic_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        normalized = int(value)
    except (OverflowError, ValueError):
        return None
    if normalized < 0 or normalized > MAX_DIAGNOSTIC_COUNT:
        return None
    return normalized


def complete_with_remaining_budget(
    adapter: Any,
    user_prompt: str,
    *,
    started: float,
    limits: InvestigationLimits,
) -> Any:
    remaining = limits.max_seconds - (time.monotonic() - started)
    if remaining <= 0:
        raise InvestigationIncompleteError("investigator elapsed-time budget exhausted")
    original_timeout = getattr(adapter, "timeout", None)
    original_retries = getattr(adapter, "retry_attempts", None)
    if hasattr(adapter, "timeout"):
        bounded_timeout = remaining
        if isinstance(original_timeout, int | float) and original_timeout > 0:
            bounded_timeout = min(float(original_timeout), remaining)
        adapter.timeout = max(0.001, bounded_timeout)
    if hasattr(adapter, "retry_attempts"):
        adapter.retry_attempts = 1
    try:
        return adapter.complete(
            INVESTIGATOR_SYSTEM_PROMPT,
            user_prompt,
            response_format=INVESTIGATOR_TURN_FORMAT,
        )
    finally:
        if hasattr(adapter, "timeout"):
            adapter.timeout = original_timeout
        if hasattr(adapter, "retry_attempts"):
            adapter.retry_attempts = original_retries
