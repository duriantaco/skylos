"""Model-adapter calls constrained by the investigator budget."""

from __future__ import annotations

import time
from typing import Any

from skylos.llm.harness import HarnessRunner

from .models import InvestigationIncompleteError, InvestigationLimits
from .protocol import INVESTIGATOR_SYSTEM_PROMPT, INVESTIGATOR_TURN_FORMAT


def record_adapter_usage(adapter: Any, runner: HarnessRunner) -> None:
    usage = getattr(adapter, "last_usage", None)
    if not isinstance(usage, dict):
        return
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = usage.get(key)
        if isinstance(value, int | float) and value >= 0:
            runner.update_usage(**{key: value})


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
