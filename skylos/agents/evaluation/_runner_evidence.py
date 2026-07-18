from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from skylos.llm.harness.runner import HarnessRunner
from skylos.llm.harness.types import HarnessRun

from .evidence import observation_evidence_digest
from .openai_chat import MAX_ENDPOINT_RESPONSE_BYTES, AgentAuthContext
from .schema import (
    BEHAVIOR_RESULT_VERSION,
    MAX_BEHAVIOR_RESULT_BYTES,
    AgentBehaviorContract,
    AgentBehaviorError,
    AgentObservation,
    BehaviorEvaluation,
    BehaviorObservationSet,
)


BEHAVIOR_RESULT_SIZE_RESERVE_BYTES = 16 * 1024


def observation_summary(observation: AgentObservation | None) -> dict[str, Any]:
    return {
        "observed": observation is not None,
        "response_observed": bool(
            observation is not None and observation.response is not None
        ),
        "response_complete": (
            None if observation is None else observation.response_complete
        ),
        "finish_reason": None if observation is None else observation.finish_reason,
        "tool_calls_observed": bool(
            observation is not None and observation.tool_calls is not None
        ),
        "tool_calls_complete": (
            None if observation is None else observation.tool_calls_complete
        ),
        "tool_call_count": (
            0
            if observation is None or observation.tool_calls is None
            else len(observation.tool_calls)
        ),
        "refusal_observed": bool(
            observation is not None and observation.refusal is not None
        ),
        "sources_observed": bool(
            observation is not None and observation.sources is not None
        ),
        "source_count": (
            0
            if observation is None or observation.sources is None
            else len(observation.sources)
        ),
        "error": None if observation is None else observation.error,
    }


def serialized_evaluation(
    evaluation: BehaviorEvaluation,
    persisted_observations: Mapping[str, AgentObservation],
    *,
    auth_context: AgentAuthContext | None,
) -> dict[str, Any]:
    payload = evaluation.to_dict()
    for scenario in payload["scenarios"]:
        scenario_id = scenario["id"]
        observation = persisted_observations.get(scenario_id)
        scenario["observation"] = None if observation is None else observation.to_dict()
        if auth_context is None:
            continue
        for assertion in scenario["assertions"]:
            assertion["message"] = auth_context.redact_text(assertion["message"])
            assertion["observed"] = auth_context.redact_value(assertion["observed"])
    return payload


def record_assertion_decisions(
    runner: HarnessRunner,
    scenarios: list[dict[str, Any]],
) -> None:
    for scenario in scenarios:
        scenario_id = scenario["id"]
        phase = f"scenario:{scenario_id}"
        for assertion in scenario["assertions"]:
            runner.record_decision(
                phase=phase,
                code=f"behavior_assertion_{assertion['status']}",
                target={
                    "scenario_id": scenario_id,
                    "assertion": assertion["assertion"],
                    "kind": assertion["kind"],
                },
                details={
                    "message": assertion["message"],
                    "expected": assertion["expected"],
                    "observed": assertion["observed"],
                },
                persist=False,
            )


def evaluation_payload(
    contract: AgentBehaviorContract,
    evaluation: dict[str, Any],
    *,
    status: str,
    mode: str,
    provenance: dict[str, Any],
    artifacts: dict[str, str | None],
) -> dict[str, Any]:
    return {
        "schema_version": BEHAVIOR_RESULT_VERSION,
        "kind": "agent_behavior",
        "status": status,
        "mode": mode,
        "contract": {
            "version": contract.version,
            "path": str(contract.path),
            "digest": contract.source_digest,
        },
        "summary": evaluation["summary"],
        "coverage": evaluation["coverage"],
        "scenarios": evaluation["scenarios"],
        "provenance": provenance,
        "artifacts": artifacts,
    }


def result_payload(
    core_payload: dict[str, Any],
    harness_run: HarnessRun,
    *,
    evidence_digest: str,
) -> dict[str, Any]:
    return {
        **core_payload,
        "evidence_digest": evidence_digest,
        "harness": harness_run.summary_dict(),
    }


def artifact_payload(
    harness_run: HarnessRun,
    *,
    behavior_artifact: str | None,
) -> dict[str, str | None]:
    return {
        "run_dir": None if harness_run.state_path is None else ".",
        "events": (
            None
            if harness_run.trace_path is None
            else Path(harness_run.trace_path).name
        ),
        "state": (
            None
            if harness_run.state_path is None
            else Path(harness_run.state_path).name
        ),
        "summary": (
            None
            if harness_run.summary_path is None
            else Path(harness_run.summary_path).name
        ),
        "behavior_results": (
            None if behavior_artifact is None else Path(behavior_artifact).name
        ),
    }


def evidence_provenance(
    input_observations: Mapping[str, AgentObservation] | None,
    collected: Mapping[str, AgentObservation],
    *,
    selected_ids: set[str],
    runtime_identity: dict[str, Any] | None,
    contract: AgentBehaviorContract,
    max_scenarios: int,
    max_seconds: float,
    max_tokens: int,
) -> dict[str, Any]:
    selected_digest = observation_evidence_digest(collected, sorted(selected_ids))
    fixture = _fixture_provenance(input_observations, selected_digest)
    if fixture is not None:
        return fixture
    if runtime_identity is None:
        raise AgentBehaviorError("runtime endpoint identity is missing")
    return {
        "kind": "runtime_endpoint",
        "trust": "runtime_observed",
        **runtime_identity,
        "request_limits": {
            "max_scenarios": max_scenarios,
            "max_seconds": max_seconds,
            "max_tokens": max_tokens,
            "timeout_seconds": contract.agent.timeout_seconds,
            "max_response_bytes": MAX_ENDPOINT_RESPONSE_BYTES,
        },
        "source_digest": None,
        "selected_digest": selected_digest,
    }


def _fixture_provenance(
    observations: Mapping[str, AgentObservation] | None,
    selected_digest: str,
) -> dict[str, Any] | None:
    if isinstance(observations, BehaviorObservationSet):
        return {
            "kind": "observation_file",
            "trust": "unverified_fixture",
            "path": str(observations.path),
            "schema_version": observations.version,
            "source_digest": observations.source_digest,
            "selected_digest": selected_digest,
        }
    if observations is None:
        return None
    return {
        "kind": "in_memory_observations",
        "trust": "unverified_fixture",
        "path": None,
        "schema_version": None,
        "source_digest": None,
        "selected_digest": selected_digest,
    }


def missing_harness_artifacts(run: HarnessRun) -> list[str]:
    return [
        name
        for name, path in (
            ("events", run.trace_path),
            ("state", run.state_path),
            ("summary", run.summary_path),
        )
        if path is None
    ]


def record_artifact_issue(payload: dict[str, Any], code: str, message: str) -> None:
    payload.setdefault("issues", []).append({"code": code, "message": message})
    payload["evidence_digest"] = None
    if payload.get("status") != "fail":
        payload["status"] = "incomplete"


def enforce_result_size_budget(
    runner: HarnessRunner,
    core_payload: dict[str, Any],
    *,
    evidence_digest: str,
) -> None:
    payload = result_payload(
        core_payload,
        runner.run,
        evidence_digest=evidence_digest,
    )
    if (
        json_artifact_size(payload)
        <= MAX_BEHAVIOR_RESULT_BYTES - BEHAVIOR_RESULT_SIZE_RESERVE_BYTES
    ):
        return
    error = f"agent behavior evidence exceeds {MAX_BEHAVIOR_RESULT_BYTES} bytes"
    runner.finish(status="failed", error=error)
    raise AgentBehaviorError(error)


def json_artifact_size(payload: dict[str, Any]) -> int:
    try:
        encoded = json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AgentBehaviorError(
            "agent behavior evidence must contain JSON values"
        ) from exc
    return len(encoded) + 1
