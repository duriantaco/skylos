from __future__ import annotations

from pathlib import Path
from typing import Any

from skylos.llm.verify_orchestrator import run_verification

from .guards import enforce_findings_budget, enforce_llm_call_budget
from .runner import HarnessRunner
from .trace import default_trace_root
from .tools import default_verification_tool_registry
from .types import HarnessBudget, HarnessResult


def run_verification_harness(
    *,
    findings: list[dict[str, Any]],
    defs_map: dict[str, Any],
    project_root: str | Path,
    harness_budget: HarnessBudget | None = None,
    harness_run_id: str | None = None,
    harness_trace_root: str | Path | None = None,
    model: str = "gpt-4.1",
    api_key: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    max_verify: int = 50,
    max_challenge: int = 20,
    confidence_range: tuple[int, int] = (40, 100),
    enable_entry_discovery: bool = True,
    enable_suppression_challenge: bool = True,
    enable_survivor_challenge: bool = True,
    batch_mode: bool = True,
    max_suppression_audit: int = 20,
    quiet: bool = False,
    verification_mode: str = "production",
    grep_workers: int = 4,
    parallel_grep: bool = False,
) -> HarnessResult:
    budget = harness_budget or HarnessBudget()
    runner = HarnessRunner(
        kind="verification",
        project_root=project_root,
        budget=budget,
        run_id=harness_run_id,
        trace_root=(
            harness_trace_root
            if harness_trace_root is not None
            else default_trace_root(project_root)
        ),
        metadata={
            "verification_mode": verification_mode,
            "batch_mode": batch_mode,
        },
        tool_registry=default_verification_tool_registry(),
    )

    try:
        runner.update_usage(findings=len(findings))
        enforce_findings_budget(findings, budget)
        output = run_verification(
            findings=findings,
            defs_map=defs_map,
            project_root=project_root,
            model=model,
            api_key=api_key,
            provider=provider,
            base_url=base_url,
            max_verify=max_verify,
            max_challenge=max_challenge,
            confidence_range=confidence_range,
            enable_entry_discovery=enable_entry_discovery,
            enable_suppression_challenge=enable_suppression_challenge,
            enable_survivor_challenge=enable_survivor_challenge,
            batch_mode=batch_mode,
            max_suppression_audit=max_suppression_audit,
            quiet=quiet,
            verification_mode=verification_mode,
            grep_workers=grep_workers,
            parallel_grep=parallel_grep,
            harness_runner=runner,
            harness_budget=budget,
        )
        llm_calls = _llm_calls(output)
        enforce_llm_call_budget(llm_calls, budget)
    except Exception as exc:
        if runner.run.ended_at is None:
            runner.finish(status="failed", error=f"{type(exc).__name__}: {exc}")
        raise

    runner.finish()
    return HarnessResult(output=output, run=runner.run)


def _llm_calls(result: dict[str, Any]) -> int | None:
    stats = result.get("stats") if isinstance(result, dict) else None
    if not isinstance(stats, dict):
        return None
    value = stats.get("llm_calls")
    return value if isinstance(value, int) else None
