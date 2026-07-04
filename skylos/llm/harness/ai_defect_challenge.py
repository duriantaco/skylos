from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from skylos.llm.agents import AgentConfig, create_llm_adapter

from .ai_defect_challenge_decisions import (
    AIDefectChallengeDecision,
    AIDefectChallengeOutcome,
    ACCEPTED_OUTCOME,
    REFUTED_OUTCOME,
    UNCERTAIN_OUTCOME,
    UNCERTAIN_VERDICT,
    apply_ai_defect_challenge_decisions,
    build_ai_defect_challenge_metadata,
    challenge_outcome_counts,
    normalize_ai_defect_challenge_decisions,
)
from .ai_defect_challenge_probes import (
    AIDefectChallengeProbe,
    HighImpactFindingDetector,
    is_high_impact_ai_finding,
)
from .ai_defect_challenge_prompt import build_ai_defect_challenge_prompt
from .ai_defect_challenge_proof import StaticProofDetector
from .guards import enforce_findings_budget, enforce_llm_call_budget
from .runner import HarnessRunner
from .trace import default_trace_root
from .tools import HarnessToolRegistry
from .types import HarnessBudget, HarnessResult

ChallengeFunc = Callable[[list[AIDefectChallengeProbe], str], Any]


def default_ai_defect_challenge_tool_registry() -> HarnessToolRegistry:
    registry = HarnessToolRegistry()
    registry.register(
        "high_impact_probe_selection",
        category="deterministic",
        description="Select high-impact AI-code findings for challenge.",
    )
    registry.register(
        "chain_of_verification_prompt",
        category="deterministic",
        description="Build grounded challenge prompts from static finding evidence.",
    )
    registry.register(
        "llm_challenge",
        category="llm",
        description="Ask the verifier to accept, refute, or keep uncertainty.",
    )
    registry.register(
        "static_refutation_proof",
        category="deterministic",
        description="Validate that refutations include code-level static proof.",
    )
    return registry


def run_ai_defect_challenge_harness(
    *,
    findings: list[dict[str, Any]],
    project_root: str | Path,
    challenge_func: ChallengeFunc | None = None,
    harness_budget: HarnessBudget | None = None,
    harness_run_id: str | None = None,
    harness_trace_root: str | Path | None = None,
    max_challenge: int = 20,
    model: str = "gpt-4.1",
    api_key: str | None = None,
    provider: str | None = None,
    base_url: str | None = None,
    write_traces: bool = True,
) -> HarnessResult:
    budget = harness_budget or HarnessBudget()
    runner = _create_challenge_runner(
        project_root=project_root,
        budget=budget,
        harness_run_id=harness_run_id,
        harness_trace_root=harness_trace_root,
        max_challenge=max_challenge,
        model=model,
        write_traces=write_traces,
    )
    proof_detector = StaticProofDetector()

    try:
        runner.update_usage(findings=len(findings))
        enforce_findings_budget(findings, budget)
        probes = _select_challenge_probes(
            runner,
            findings,
            project_root=project_root,
            max_challenge=max_challenge,
        )
        prompt = _build_challenge_prompt(runner, probes)
        challenge = _configured_challenge_func(
            challenge_func,
            model=model,
            api_key=api_key,
            provider=provider,
            base_url=base_url,
        )
        decisions, llm_calls = _challenge_findings(
            runner,
            probes,
            prompt,
            challenge,
        )
        outcomes = _apply_static_refutation_proof(
            runner,
            probes,
            decisions,
            proof_detector=proof_detector,
            project_root=project_root,
        )
        enforce_llm_call_budget(llm_calls, budget)
    except Exception as exc:
        if runner.run.ended_at is None:
            runner.finish(status="failed", error=f"{type(exc).__name__}: {exc}")
        raise

    output = build_ai_defect_challenge_metadata(
        findings=findings,
        outcomes=outcomes,
        skipped_count=max(0, len(findings) - len(probes)),
    )
    runner.finish()
    return HarnessResult(output=output, run=runner.run)


def _create_challenge_runner(
    *,
    project_root: str | Path,
    budget: HarnessBudget,
    harness_run_id: str | None,
    harness_trace_root: str | Path | None,
    max_challenge: int,
    model: str,
    write_traces: bool,
) -> HarnessRunner:
    return HarnessRunner(
        kind="ai_defect_challenge",
        project_root=project_root,
        budget=budget,
        run_id=harness_run_id,
        trace_root=_challenge_trace_root(
            project_root,
            harness_trace_root=harness_trace_root,
            write_traces=write_traces,
        ),
        metadata={
            "model": model,
            "max_challenge": max_challenge,
        },
        tool_registry=default_ai_defect_challenge_tool_registry(),
    )


def _select_challenge_probes(
    runner: HarnessRunner,
    findings: list[dict[str, Any]],
    *,
    project_root: str | Path,
    max_challenge: int,
) -> list[AIDefectChallengeProbe]:
    detector = HighImpactFindingDetector()
    with runner.step(
        "probe_selection",
        input_summary={
            "finding_count": len(findings),
            "max_challenge": max_challenge,
        },
    ) as step:
        probes = runner.run_tool(
            "high_impact_probe_selection",
            lambda: detector.select(
                findings,
                project_root=project_root,
                max_challenge=max_challenge,
            ),
            output_summary=lambda selected: {"probe_count": len(selected)},
        )
        step.set_output_summary(probe_count=len(probes))
        return probes


def _build_challenge_prompt(
    runner: HarnessRunner,
    probes: list[AIDefectChallengeProbe],
) -> str:
    with runner.step(
        "challenge_prompt",
        input_summary={"probe_count": len(probes)},
    ) as step:
        prompt = runner.run_tool(
            "chain_of_verification_prompt",
            lambda: build_ai_defect_challenge_prompt(probes),
            output_summary=lambda value: {"prompt_chars": len(value)},
        )
        step.set_output_summary(prompt_chars=len(prompt))
        return prompt


def _configured_challenge_func(
    challenge_func: ChallengeFunc | None,
    *,
    model: str,
    api_key: str | None,
    provider: str | None,
    base_url: str | None,
) -> ChallengeFunc | None:
    if challenge_func is not None:
        return challenge_func
    if not api_key:
        return None
    return _adapter_challenge_func(
        model=model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
    )


def _challenge_findings(
    runner: HarnessRunner,
    probes: list[AIDefectChallengeProbe],
    prompt: str,
    challenge: ChallengeFunc | None,
) -> tuple[list[AIDefectChallengeDecision], int]:
    if not probes or challenge is None:
        return _uncertain_decisions_without_llm(probes), 0

    with runner.step(
        "llm_challenge",
        input_summary={"probe_count": len(probes)},
    ) as step:
        response = runner.run_tool(
            "llm_challenge",
            lambda: challenge(probes, prompt),
            output_summary=lambda value: {"response_kind": type(value).__name__},
        )
        runner.update_usage(llm_calls=1)
        decisions = normalize_ai_defect_challenge_decisions(
            response,
            expected_count=len(probes),
        )
        step.set_output_summary(decision_count=len(decisions), llm_calls=1)
        return decisions, 1


def _uncertain_decisions_without_llm(
    probes: list[AIDefectChallengeProbe],
) -> list[AIDefectChallengeDecision]:
    return [
        AIDefectChallengeDecision(
            id=probe.id,
            verdict=UNCERTAIN_VERDICT,
            reason="No LLM challenge function configured.",
        )
        for probe in probes
    ]


def _apply_static_refutation_proof(
    runner: HarnessRunner,
    probes: list[AIDefectChallengeProbe],
    decisions: list[AIDefectChallengeDecision],
    *,
    proof_detector: StaticProofDetector,
    project_root: str | Path,
) -> list[AIDefectChallengeOutcome]:
    with runner.step(
        "static_refutation_proof",
        input_summary={"decision_count": len(decisions)},
    ) as step:
        outcomes = runner.run_tool(
            "static_refutation_proof",
            lambda: apply_ai_defect_challenge_decisions(
                probes,
                decisions,
                proof_detector=proof_detector,
                project_root=project_root,
            ),
            output_summary=lambda value: challenge_outcome_counts(value),
        )
        step.set_output_summary(**challenge_outcome_counts(outcomes))
        return outcomes


def _adapter_challenge_func(
    *,
    model: str,
    api_key: str,
    provider: str | None,
    base_url: str | None,
) -> ChallengeFunc:
    config = AgentConfig(model=model, api_key=api_key, stream=False)
    config.provider = provider
    config.base_url = base_url
    config.temperature = 0.0
    config.max_tokens = 4096
    adapter = create_llm_adapter(config)

    def _challenge(_probes: list[AIDefectChallengeProbe], prompt: str) -> Any:
        system = "You are Skylos AI-code Challenge Verifier. Respond with JSON only."
        return adapter.complete(system, prompt)

    return _challenge


def _challenge_trace_root(
    project_root: str | Path,
    *,
    harness_trace_root: str | Path | None,
    write_traces: bool,
) -> str | Path | None:
    if not write_traces:
        return None
    if harness_trace_root is not None:
        return harness_trace_root
    return default_trace_root(project_root)


__all__ = [
    "ACCEPTED_OUTCOME",
    "REFUTED_OUTCOME",
    "UNCERTAIN_OUTCOME",
    "AIDefectChallengeDecision",
    "AIDefectChallengeOutcome",
    "AIDefectChallengeProbe",
    "ChallengeFunc",
    "HighImpactFindingDetector",
    "StaticProofDetector",
    "build_ai_defect_challenge_metadata",
    "build_ai_defect_challenge_prompt",
    "default_ai_defect_challenge_tool_registry",
    "is_high_impact_ai_finding",
    "normalize_ai_defect_challenge_decisions",
    "run_ai_defect_challenge_harness",
]
