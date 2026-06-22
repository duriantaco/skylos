from __future__ import annotations

import time
from typing import Sized

from .types import HarnessBudget, HarnessBudgetExceeded


def enforce_step_budget(steps_started: int, budget: HarnessBudget) -> None:
    if budget.max_steps is not None and steps_started >= budget.max_steps:
        raise HarnessBudgetExceeded(
            f"harness step budget exceeded: {steps_started + 1}>{budget.max_steps}"
        )


def enforce_elapsed_budget(started_monotonic: float, budget: HarnessBudget) -> None:
    if budget.max_seconds is None:
        return
    elapsed = time.monotonic() - started_monotonic
    if elapsed > budget.max_seconds:
        raise HarnessBudgetExceeded(
            f"harness time budget exceeded: {elapsed:.3f}s>{budget.max_seconds:.3f}s"
        )


def enforce_findings_budget(findings: Sized, budget: HarnessBudget) -> None:
    if budget.max_findings is None:
        return
    count = len(findings)
    if count > budget.max_findings:
        raise HarnessBudgetExceeded(
            f"harness findings budget exceeded: {count}>{budget.max_findings}"
        )


def enforce_llm_call_budget(llm_calls: int | None, budget: HarnessBudget) -> None:
    if budget.max_llm_calls is None or llm_calls is None:
        return
    if llm_calls > budget.max_llm_calls:
        raise HarnessBudgetExceeded(
            f"harness LLM call budget exceeded: {llm_calls}>{budget.max_llm_calls}"
        )
