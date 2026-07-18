from __future__ import annotations

import math
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from skylos.llm.harness.runner import HarnessRunner
from skylos.llm.harness.tools import HarnessToolRegistry
from skylos.llm.harness.trace import default_trace_root, write_json_artifact
from skylos.llm.harness.types import HarnessBudget, HarnessBudgetExceeded, HarnessRun

from ._runner_evidence import (
    artifact_payload as _artifact_payload,
    enforce_result_size_budget as _enforce_result_size_budget,
    evaluation_payload as _evaluation_payload,
    evidence_provenance as _evidence_provenance,
    json_artifact_size as _json_artifact_size,
    missing_harness_artifacts as _missing_harness_artifacts,
    observation_summary as _observation_summary,
    record_artifact_issue as _record_artifact_issue,
    record_assertion_decisions as _record_assertion_decisions,
    result_payload as _result_payload,
    serialized_evaluation as _serialized_evaluation,
)
from .evidence import behavior_evidence_digest
from .evaluator import evaluate_behavior
from .openai_chat import (
    AgentAuthContext,
    AgentEndpointError,
    LiveAgentObservation,
    agent_endpoint_fingerprint,
    load_agent_auth_context,
    observe_openai_chat_evidence,
    validate_agent_endpoint,
)
from .schema import (
    AgentBehaviorContract,
    AgentBehaviorError,
    AgentObservation,
    AgentScenario,
    BehaviorEvaluation,
    MAX_BEHAVIOR_RESULT_BYTES,
)


BEHAVIOR_RESULTS_FILENAME = "behavior-results.json"
DEFAULT_MAX_SCENARIOS = 25
DEFAULT_MAX_SECONDS = 300.0
DEFAULT_MAX_TOKENS = 1024
MAX_RUN_SECONDS = 3_600.0
MAX_OUTPUT_TOKENS = 32_768


@dataclass(frozen=True)
class BehaviorRunResult:
    payload: dict[str, Any]
    harness_run: HarnessRun


@dataclass(frozen=True)
class _BehaviorRunContext:
    contract: AgentBehaviorContract
    mode: str
    auth_context: AgentAuthContext | None
    runtime_identity: dict[str, Any] | None
    selected_ids: frozenset[str]
    artifact_root: Path | None
    runner: HarnessRunner


def run_behavior_test(
    contract: AgentBehaviorContract,
    *,
    observations: Mapping[str, AgentObservation] | None = None,
    scenario_ids: tuple[str, ...] | None = None,
    endpoint_override: str | None = None,
    auth_env: str | None = None,
    allow_remote: bool = False,
    allow_contract_endpoint: bool = False,
    save_artifacts: bool = True,
    trace_root: str | Path | None = None,
    session: Any = None,
    max_scenarios: int = DEFAULT_MAX_SCENARIOS,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> BehaviorRunResult:
    _validate_run_options(
        observations=observations,
        endpoint_override=endpoint_override,
        auth_env=auth_env,
        allow_remote=allow_remote,
        allow_contract_endpoint=allow_contract_endpoint,
        max_scenarios=max_scenarios,
        max_seconds=max_seconds,
        max_tokens=max_tokens,
    )
    context = _prepare_run_context(
        contract,
        observations=observations,
        scenario_ids=scenario_ids,
        endpoint_override=endpoint_override,
        auth_env=auth_env,
        allow_remote=allow_remote,
        allow_contract_endpoint=allow_contract_endpoint,
        save_artifacts=save_artifacts,
        trace_root=trace_root,
        max_scenarios=max_scenarios,
        max_seconds=max_seconds,
    )
    evaluation_observations, persisted_observations = _collect_observations(
        context,
        observations=observations,
        endpoint_override=endpoint_override,
        allow_remote=allow_remote,
        allow_contract_endpoint=allow_contract_endpoint,
        session=session,
        max_tokens=max_tokens,
    )
    evaluation, core_payload, evidence_digest = _evaluate_run(
        context,
        observations=observations,
        evaluation_observations=evaluation_observations,
        persisted_observations=persisted_observations,
        max_scenarios=max_scenarios,
        max_seconds=max_seconds,
        max_tokens=max_tokens,
    )
    _finish_run(context.runner, evaluation)
    payload = _finalize_behavior_payload(context, core_payload, evidence_digest)
    return BehaviorRunResult(payload=payload, harness_run=context.runner.run)


def _prepare_run_context(
    contract: AgentBehaviorContract,
    *,
    observations: Mapping[str, AgentObservation] | None,
    scenario_ids: tuple[str, ...] | None,
    endpoint_override: str | None,
    auth_env: str | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
    save_artifacts: bool,
    trace_root: str | Path | None,
    max_scenarios: int,
    max_seconds: float,
) -> _BehaviorRunContext:
    selected_contract = _selected_contract(contract, scenario_ids)
    if len(selected_contract.scenarios) > max_scenarios:
        raise AgentBehaviorError(
            f"selected scenarios exceed --max-scenarios ({max_scenarios})"
        )
    _validate_observation_ids(contract, observations)
    mode = "offline" if observations is not None else "live"
    auth_context = load_agent_auth_context(auth_env) if mode == "live" else None
    runtime_identity = None
    if mode == "live":
        runtime_identity = _runtime_endpoint_identity(
            selected_contract,
            endpoint_override=endpoint_override,
            allow_remote=allow_remote,
            allow_contract_endpoint=allow_contract_endpoint,
            authenticated=auth_context is not None,
        )
    selected_ids = frozenset(
        scenario.scenario_id for scenario in selected_contract.scenarios
    )
    artifact_root = _artifact_root(
        selected_contract,
        save_artifacts=save_artifacts,
        trace_root=trace_root,
    )
    return _BehaviorRunContext(
        contract=selected_contract,
        mode=mode,
        auth_context=auth_context,
        runtime_identity=runtime_identity,
        selected_ids=selected_ids,
        artifact_root=artifact_root,
        runner=_new_behavior_runner(
            selected_contract,
            mode=mode,
            selected_ids=selected_ids,
            artifact_root=artifact_root,
            max_scenarios=max_scenarios,
            max_seconds=max_seconds,
        ),
    )


def _validate_observation_ids(
    contract: AgentBehaviorContract,
    observations: Mapping[str, AgentObservation] | None,
) -> None:
    if observations is None:
        return
    contract_ids = {scenario.scenario_id for scenario in contract.scenarios}
    unknown = sorted(set(observations) - contract_ids)
    if unknown:
        raise AgentBehaviorError(
            f"observations contain scenarios not defined by the contract: {unknown}"
        )


def _new_behavior_runner(
    contract: AgentBehaviorContract,
    *,
    mode: str,
    selected_ids: frozenset[str],
    artifact_root: Path | None,
    max_scenarios: int,
    max_seconds: float,
) -> HarnessRunner:
    tool_registry = HarnessToolRegistry()
    if mode == "live":
        tool_registry.register("agent_endpoint", category="network")
    return HarnessRunner(
        kind="agent_behavior",
        project_root=contract.project_root,
        budget=HarnessBudget(max_steps=max_scenarios, max_seconds=max_seconds),
        trace_root=artifact_root,
        metadata={
            "contract_path": str(contract.path),
            "contract_digest": contract.source_digest,
            "contract_version": contract.version,
            "mode": mode,
            "scenario_ids": sorted(selected_ids),
            "evidence_trust": (
                "unverified_fixture" if mode == "offline" else "runtime_observed"
            ),
        },
        tool_registry=tool_registry,
    )


def _collect_observations(
    context: _BehaviorRunContext,
    *,
    observations: Mapping[str, AgentObservation] | None,
    endpoint_override: str | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
    session: Any,
    max_tokens: int,
) -> tuple[dict[str, AgentObservation], dict[str, AgentObservation]]:
    evaluation: dict[str, AgentObservation] = {}
    persisted: dict[str, AgentObservation] = {}
    try:
        for scenario in context.contract.scenarios:
            evidence = _collect_scenario_observation(
                context,
                scenario,
                observations=observations,
                endpoint_override=endpoint_override,
                allow_remote=allow_remote,
                allow_contract_endpoint=allow_contract_endpoint,
                session=session,
                max_tokens=max_tokens,
            )
            if evidence is not None:
                evaluation[scenario.scenario_id] = evidence.evaluation
                persisted[scenario.scenario_id] = evidence.persisted
        context.runner.enforce_budget()
    except HarnessBudgetExceeded as exc:
        _raise_budget_error(context.runner, exc)
    return evaluation, persisted


def _collect_scenario_observation(
    context: _BehaviorRunContext,
    scenario: AgentScenario,
    *,
    observations: Mapping[str, AgentObservation] | None,
    endpoint_override: str | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
    session: Any,
    max_tokens: int,
) -> LiveAgentObservation | None:
    with context.runner.step(
        f"scenario:{scenario.scenario_id}",
        input_summary={"scenario_id": scenario.scenario_id, "mode": context.mode},
    ) as step:
        evidence = _scenario_evidence(
            context,
            scenario,
            observations=observations,
            endpoint_override=endpoint_override,
            allow_remote=allow_remote,
            allow_contract_endpoint=allow_contract_endpoint,
            session=session,
            max_tokens=max_tokens,
        )
        persisted = None if evidence is None else evidence.persisted
        step.set_output_summary(**_observation_summary(persisted))
        return evidence


def _scenario_evidence(
    context: _BehaviorRunContext,
    scenario: AgentScenario,
    *,
    observations: Mapping[str, AgentObservation] | None,
    endpoint_override: str | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
    session: Any,
    max_tokens: int,
) -> LiveAgentObservation | None:
    if observations is not None:
        observation = observations.get(scenario.scenario_id)
        if observation is None:
            return None
        return LiveAgentObservation(evaluation=observation, persisted=observation)
    request_timeout = context.contract.agent.timeout_seconds
    remaining_seconds = context.runner.remaining_seconds()
    if remaining_seconds is not None:
        request_timeout = min(request_timeout, remaining_seconds)
    return context.runner.run_tool(
        "agent_endpoint",
        lambda: _live_observation(
            context.contract,
            scenario,
            endpoint_override=endpoint_override,
            auth_context=context.auth_context,
            allow_remote=allow_remote,
            allow_contract_endpoint=allow_contract_endpoint,
            session=session,
            request_timeout=max(request_timeout, 0.001),
            max_tokens=max_tokens,
        ),
        input_summary={"scenario_id": scenario.scenario_id},
        output_summary=lambda item: _observation_summary(
            None if item is None else item.persisted
        ),
    )


def _evaluate_run(
    context: _BehaviorRunContext,
    *,
    observations: Mapping[str, AgentObservation] | None,
    evaluation_observations: Mapping[str, AgentObservation],
    persisted_observations: Mapping[str, AgentObservation],
    max_scenarios: int,
    max_seconds: float,
    max_tokens: int,
) -> tuple[BehaviorEvaluation, dict[str, Any], str]:
    try:
        evaluation = evaluate_behavior(context.contract, evaluation_observations)
        serialized = _serialized_evaluation(
            evaluation,
            persisted_observations,
            auth_context=context.auth_context,
        )
        provenance = _evidence_provenance(
            observations,
            persisted_observations,
            selected_ids=set(context.selected_ids),
            runtime_identity=context.runtime_identity,
            contract=context.contract,
            max_scenarios=max_scenarios,
            max_seconds=max_seconds,
            max_tokens=max_tokens,
        )
        core_payload = _core_evaluation_payload(
            context,
            evaluation,
            serialized,
            provenance,
        )
        _enforce_result_size_budget(
            context.runner,
            core_payload,
            evidence_digest="0" * 64,
        )
        evidence_digest = behavior_evidence_digest(core_payload)
        _bind_evaluation_evidence(
            context.runner,
            provenance,
            serialized,
            evidence_digest,
        )
        _enforce_result_size_budget(
            context.runner,
            core_payload,
            evidence_digest=evidence_digest,
        )
        context.runner.enforce_budget()
        return evaluation, core_payload, evidence_digest
    except HarnessBudgetExceeded as exc:
        _raise_budget_error(context.runner, exc)


def _core_evaluation_payload(
    context: _BehaviorRunContext,
    evaluation: BehaviorEvaluation,
    serialized: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    behavior_artifact = None
    if context.artifact_root is not None:
        behavior_artifact = str(
            context.artifact_root
            / context.runner.run.run_id
            / BEHAVIOR_RESULTS_FILENAME
        )
    return _evaluation_payload(
        context.contract,
        serialized,
        status=evaluation.status,
        mode=context.mode,
        provenance=provenance,
        artifacts=_artifact_payload(
            context.runner.run,
            behavior_artifact=behavior_artifact,
        ),
    )


def _bind_evaluation_evidence(
    runner: HarnessRunner,
    provenance: dict[str, Any],
    serialized: dict[str, Any],
    evidence_digest: str,
) -> None:
    runner.run.metadata.update(
        {
            "behavior_evidence_digest": evidence_digest,
            "observation_evidence_digest": provenance["selected_digest"],
            "observation_source_digest": provenance.get("source_digest"),
            "behavior_provenance": provenance,
        }
    )
    _record_assertion_decisions(runner, serialized["scenarios"])


def _raise_budget_error(
    runner: HarnessRunner,
    error: HarnessBudgetExceeded,
) -> None:
    runner.finish(status="failed", error=str(error))
    raise AgentBehaviorError(
        f"agent behavior run exceeded its budget: {error}"
    ) from error


def _finish_run(runner: HarnessRunner, evaluation: BehaviorEvaluation) -> None:
    runner.finish(
        status="completed" if evaluation.status == "pass" else "failed",
        error=(
            None
            if evaluation.status == "pass"
            else f"agent behavior evaluation {evaluation.status}"
        ),
    )


def _finalize_behavior_payload(
    context: _BehaviorRunContext,
    core_payload: dict[str, Any],
    evidence_digest: str,
) -> dict[str, Any]:
    payload = _result_payload(
        core_payload,
        context.runner.run,
        evidence_digest=evidence_digest,
    )
    if _json_artifact_size(payload) > MAX_BEHAVIOR_RESULT_BYTES:
        raise AgentBehaviorError(
            f"agent behavior evidence exceeds {MAX_BEHAVIOR_RESULT_BYTES} bytes"
        )
    if context.artifact_root is not None:
        _write_behavior_artifact(context, payload)
    return payload


def _write_behavior_artifact(
    context: _BehaviorRunContext,
    payload: dict[str, Any],
) -> None:
    missing = _missing_harness_artifacts(context.runner.run)
    if missing:
        payload["artifacts"]["behavior_results"] = None
        _record_artifact_issue(
            payload,
            "harness_artifact_write_failed",
            f"required harness artifacts were not written: {missing}",
        )
        return
    behavior_path = write_json_artifact(
        context.artifact_root,
        context.runner.run.run_id,
        BEHAVIOR_RESULTS_FILENAME,
        payload,
    )
    if behavior_path is None:
        payload["artifacts"]["behavior_results"] = None
        _record_artifact_issue(
            payload,
            "behavior_artifact_write_failed",
            f"could not write {BEHAVIOR_RESULTS_FILENAME}",
        )


def _validate_run_options(
    *,
    observations: Mapping[str, AgentObservation] | None,
    endpoint_override: str | None,
    auth_env: str | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
    max_scenarios: int,
    max_seconds: float,
    max_tokens: int,
) -> None:
    _validate_endpoint_options(
        observations=observations,
        endpoint_override=endpoint_override,
        auth_env=auth_env,
        allow_remote=allow_remote,
        allow_contract_endpoint=allow_contract_endpoint,
    )
    _validate_scenario_limit(max_scenarios)
    _validate_time_limit(max_seconds)
    _validate_token_limit(max_tokens)


def _validate_endpoint_options(
    *,
    observations: Mapping[str, AgentObservation] | None,
    endpoint_override: str | None,
    auth_env: str | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
) -> None:
    if endpoint_override is not None and (
        not isinstance(endpoint_override, str)
        or not endpoint_override.strip()
        or endpoint_override != endpoint_override.strip()
    ):
        raise AgentBehaviorError(
            "--endpoint must be a non-empty URL without surrounding whitespace"
        )
    if observations is not None and (
        endpoint_override is not None
        or auth_env
        or allow_remote
        or allow_contract_endpoint
    ):
        raise AgentBehaviorError(
            "--observations cannot be combined with live endpoint options"
        )


def _validate_scenario_limit(max_scenarios: int) -> None:
    if isinstance(max_scenarios, bool) or not isinstance(max_scenarios, int):
        raise AgentBehaviorError("--max-scenarios must be an integer")
    if max_scenarios <= 0 or max_scenarios > 1_000:
        raise AgentBehaviorError("--max-scenarios must be between 1 and 1000")


def _validate_time_limit(max_seconds: float) -> None:
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, int | float):
        raise AgentBehaviorError("--max-seconds must be a number")
    if not math.isfinite(max_seconds):
        raise AgentBehaviorError("--max-seconds must be finite")
    if max_seconds <= 0 or max_seconds > MAX_RUN_SECONDS:
        raise AgentBehaviorError(
            f"--max-seconds must be between 0 and {int(MAX_RUN_SECONDS)}"
        )


def _validate_token_limit(max_tokens: int) -> None:
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
        raise AgentBehaviorError("--max-tokens must be an integer")
    if max_tokens <= 0 or max_tokens > MAX_OUTPUT_TOKENS:
        raise AgentBehaviorError(
            f"--max-tokens must be between 1 and {MAX_OUTPUT_TOKENS}"
        )


def _selected_contract(
    contract: AgentBehaviorContract,
    scenario_ids: tuple[str, ...] | None,
) -> AgentBehaviorContract:
    if not scenario_ids:
        return contract
    requested = set(scenario_ids)
    available = {scenario.scenario_id for scenario in contract.scenarios}
    unknown = sorted(requested - available)
    if unknown:
        raise AgentBehaviorError(f"unknown scenario ids: {unknown}")
    scenarios = tuple(
        scenario for scenario in contract.scenarios if scenario.scenario_id in requested
    )
    return replace(contract, scenarios=scenarios)


def _artifact_root(
    contract: AgentBehaviorContract,
    *,
    save_artifacts: bool,
    trace_root: str | Path | None,
) -> Path | None:
    if not save_artifacts:
        return None
    if trace_root is not None:
        return Path(trace_root).absolute()
    return default_trace_root(contract.project_root)


def _live_observation(
    contract: AgentBehaviorContract,
    scenario,
    *,
    endpoint_override: str | None,
    auth_context: AgentAuthContext | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
    session: Any,
    request_timeout: float,
    max_tokens: int,
) -> LiveAgentObservation:
    try:
        return observe_openai_chat_evidence(
            contract.agent,
            scenario,
            endpoint_override=endpoint_override,
            auth_context=auth_context,
            allow_remote=allow_remote,
            allow_contract_endpoint=allow_contract_endpoint,
            session=session,
            request_timeout=request_timeout,
            max_tokens=max_tokens,
        )
    except AgentEndpointError as exc:
        observation = AgentObservation(
            scenario_id=scenario.scenario_id,
            error=str(exc),
        )
        return LiveAgentObservation(evaluation=observation, persisted=observation)


def _runtime_endpoint_identity(
    contract: AgentBehaviorContract,
    *,
    endpoint_override: str | None,
    allow_remote: bool,
    allow_contract_endpoint: bool,
    authenticated: bool,
) -> dict[str, Any]:
    endpoint = (
        endpoint_override if endpoint_override is not None else contract.agent.endpoint
    )
    if endpoint is None:
        raise AgentBehaviorError(
            "agent.endpoint is required for live tests; use --observations for offline mode"
        )
    if contract.agent.model is None:
        raise AgentBehaviorError(
            "agent.model is required for live tests; use --observations for offline mode"
        )
    safe_endpoint = validate_agent_endpoint(
        endpoint,
        allow_remote=allow_remote,
        endpoint_is_override=endpoint_override is not None,
        authenticated=authenticated,
        allow_contract_endpoint=allow_contract_endpoint,
    )
    return {
        "endpoint_source": (
            "cli_override" if endpoint_override is not None else "contract_endpoint"
        ),
        "endpoint_fingerprint": agent_endpoint_fingerprint(safe_endpoint),
        "authenticated": authenticated,
        "contract_endpoint_consent": bool(
            endpoint_override is None and allow_contract_endpoint
        ),
    }
