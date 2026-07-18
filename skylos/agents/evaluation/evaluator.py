from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from ._assertion_helpers import checked as _checked
from ._assertion_helpers import incomplete as _incomplete
from ._tool_evaluator import (
    allowed_tools as _allowed_tools,
    exact_tool_sequence as _exact_tool_sequence,
    forbidden_tool as _forbidden_tool,
    match_required_tool_calls as _match_required_tool_calls,
    max_tool_calls as _max_tool_calls,
    required_tool as _required_tool,
)
from .schema import (
    AgentBehaviorContract,
    AgentObservation,
    AgentScenario,
    BehaviorAssertion,
    BehaviorEvaluation,
    ScenarioEvaluation,
)


def evaluate_behavior(
    contract: AgentBehaviorContract,
    observations: Mapping[str, AgentObservation],
) -> BehaviorEvaluation:
    scenario_results = tuple(
        _evaluate_scenario(scenario, observations.get(scenario.scenario_id))
        for scenario in contract.scenarios
    )
    status = _combined_status(result.status for result in scenario_results)
    assertions = [
        assertion
        for scenario_result in scenario_results
        for assertion in scenario_result.assertions
    ]
    summary = {
        "scenario_count": len(scenario_results),
        "passed_scenarios": sum(result.status == "pass" for result in scenario_results),
        "failed_scenarios": sum(result.status == "fail" for result in scenario_results),
        "incomplete_scenarios": sum(
            result.status == "incomplete" for result in scenario_results
        ),
        "assertion_count": len(assertions),
        "passed_assertions": sum(item.status == "pass" for item in assertions),
        "failed_assertions": sum(item.status == "fail" for item in assertions),
        "incomplete_assertions": sum(
            item.status == "incomplete" for item in assertions
        ),
    }
    return BehaviorEvaluation(
        status=status,
        scenarios=scenario_results,
        summary=summary,
        coverage=_coverage(assertions),
    )


def _evaluate_scenario(
    scenario: AgentScenario,
    observation: AgentObservation | None,
) -> ScenarioEvaluation:
    assertions: list[BehaviorAssertion] = []
    expectation = scenario.expectation
    unavailable = _observation_error(observation)
    response_unavailable = _final_response_error(observation, unavailable)
    tools_unavailable = _tool_calls_error(observation, unavailable)
    required_tool_matches = _match_required_tool_calls(
        expectation.tools.required,
        observation,
        tools_unavailable,
    )
    matched_tool_calls = set(required_tool_matches.values())

    for index, expected in enumerate(expectation.response.contains):
        assertions.append(
            _response_contains(index, expected, observation, response_unavailable)
        )
    for index, expected in enumerate(expectation.response.excludes):
        assertions.append(
            _response_excludes(index, expected, observation, response_unavailable)
        )
    for index, expected in enumerate(expectation.tools.required):
        assertions.append(
            _required_tool(
                index,
                expected,
                observation,
                tools_unavailable,
                required_tool_matches.get(index),
                matched_tool_calls,
            )
        )
    if expectation.tools.allowed is not None:
        assertions.append(
            _allowed_tools(expectation.tools.allowed, observation, tools_unavailable)
        )
    for index, expected in enumerate(expectation.tools.forbidden):
        assertions.append(
            _forbidden_tool(index, expected, observation, tools_unavailable)
        )
    if expectation.tools.exact_sequence is not None:
        assertions.append(
            _exact_tool_sequence(
                expectation.tools.exact_sequence,
                observation,
                tools_unavailable,
            )
        )
    if expectation.tools.max_calls is not None:
        assertions.append(
            _max_tool_calls(
                expectation.tools.max_calls,
                observation,
                tools_unavailable,
            )
        )
    if expectation.refusal is not None:
        assertions.append(
            _refusal(expectation.refusal, observation, response_unavailable)
        )
    for index, expected in enumerate(expectation.sources.required):
        assertions.append(
            _required_source(index, expected, observation, response_unavailable)
        )

    status = _combined_status(item.status for item in assertions)
    return ScenarioEvaluation(
        scenario_id=scenario.scenario_id,
        status=status,
        assertions=tuple(assertions),
        observation=observation,
    )


def _response_contains(
    index: int,
    expected: str,
    observation: AgentObservation | None,
    unavailable: str | None,
) -> BehaviorAssertion:
    assertion = f"response.contains[{index}]"
    if unavailable or observation is None or observation.response is None:
        return _incomplete(
            assertion,
            "response_contains",
            unavailable or "final response text was not observed",
            expected,
        )
    passed = expected in observation.response
    return _checked(
        assertion,
        "response_contains",
        passed,
        f"response contains {expected!r}",
        f"response does not contain {expected!r}",
        expected,
        {"response_length": len(observation.response)},
    )


def _response_excludes(
    index: int,
    expected: str,
    observation: AgentObservation | None,
    unavailable: str | None,
) -> BehaviorAssertion:
    assertion = f"response.excludes[{index}]"
    if unavailable or observation is None or observation.response is None:
        return _incomplete(
            assertion,
            "response_excludes",
            unavailable or "final response text was not observed",
            expected,
        )
    passed = expected not in observation.response
    return _checked(
        assertion,
        "response_excludes",
        passed,
        f"response excludes {expected!r}",
        f"response contains forbidden text {expected!r}",
        expected,
        {"response_length": len(observation.response)},
    )


def _refusal(
    expected: bool,
    observation: AgentObservation | None,
    unavailable: str | None,
) -> BehaviorAssertion:
    assertion = "refusal"
    if unavailable or observation is None or observation.refusal is None:
        return _incomplete(
            assertion,
            "refusal",
            unavailable or "explicit refusal evidence was not observed",
            expected,
        )
    return _checked(
        assertion,
        "refusal",
        observation.refusal is expected,
        f"explicit refusal is {expected}",
        f"explicit refusal is {observation.refusal}, expected {expected}",
        expected,
        observation.refusal,
    )


def _required_source(
    index: int,
    expected: str,
    observation: AgentObservation | None,
    unavailable: str | None,
) -> BehaviorAssertion:
    assertion = f"sources.required[{index}]"
    if unavailable or observation is None or observation.sources is None:
        return _incomplete(
            assertion,
            "source_required",
            unavailable or "explicit source evidence was not observed",
            expected,
        )
    passed = expected in observation.sources
    return _checked(
        assertion,
        "source_required",
        passed,
        f"required source {expected!r} was observed",
        f"required source {expected!r} was not observed",
        expected,
        {"source_count": len(observation.sources), "present": passed},
    )


def _observation_error(observation: AgentObservation | None) -> str | None:
    if observation is None:
        return "scenario observation is missing"
    if observation.error:
        return f"scenario observation failed: {observation.error}"
    return None


def _final_response_error(
    observation: AgentObservation | None,
    unavailable: str | None,
) -> str | None:
    if unavailable is not None or observation is None:
        return unavailable
    if observation.finish_reason is not None and observation.finish_reason != "stop":
        return (
            "final response is incomplete "
            f"(finish_reason={observation.finish_reason!r})"
        )
    if observation.response_complete is False:
        reason = observation.finish_reason or "unknown"
        return f"final response is incomplete (finish_reason={reason!r})"
    if observation.response_complete is None:
        return "final response completion evidence was not observed"
    return None


def _tool_calls_error(
    observation: AgentObservation | None,
    unavailable: str | None,
) -> str | None:
    if unavailable is not None or observation is None:
        return unavailable
    if observation.finish_reason is not None and observation.finish_reason not in {
        "stop",
        "tool_calls",
    }:
        return (
            "tool-call evidence is incomplete "
            f"(finish_reason={observation.finish_reason!r})"
        )
    if observation.tool_calls_complete is False:
        reason = observation.finish_reason or "unknown"
        return f"tool-call evidence is incomplete (finish_reason={reason!r})"
    if observation.tool_calls_complete is None:
        return "tool-call completion evidence was not observed"
    return None


def _combined_status(statuses) -> str:
    status_set = set(statuses)
    if "fail" in status_set:
        return "fail"
    if "incomplete" in status_set:
        return "incomplete"
    return "pass"


def _coverage(assertions: list[BehaviorAssertion]) -> dict[str, Any]:
    by_kind: dict[str, Counter[str]] = {}
    for assertion in assertions:
        by_kind.setdefault(assertion.kind, Counter())[assertion.status] += 1
    return {
        "requested": len(assertions),
        "completed": sum(item.status in {"pass", "fail"} for item in assertions),
        "incomplete": sum(item.status == "incomplete" for item in assertions),
        "by_assertion": {
            kind: {
                "requested": sum(counts.values()),
                "passed": counts["pass"],
                "failed": counts["fail"],
                "incomplete": counts["incomplete"],
            }
            for kind, counts in sorted(by_kind.items())
        },
    }
