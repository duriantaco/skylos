from __future__ import annotations

from pathlib import Path

from skylos.agents.evaluation.evaluator import evaluate_behavior
from skylos.agents.evaluation.schema import (
    AgentBehaviorContract,
    AgentObservation,
    AgentScenario,
    AgentTarget,
    AgentToolCallObservation,
    RequiredToolCall,
    ResponseExpectation,
    ScenarioExpectation,
    SourceExpectation,
    ToolExpectation,
)


def _contract(*scenarios: AgentScenario) -> AgentBehaviorContract:
    return AgentBehaviorContract(
        version=1,
        path=Path("/repo/.skylos/agent-test.yml"),
        project_root=Path("/repo"),
        source_digest="a" * 64,
        agent=AgentTarget(),
        scenarios=scenarios,
    )


def _scenario(
    scenario_id: str,
    *,
    response: ResponseExpectation = ResponseExpectation(),
    tools: ToolExpectation = ToolExpectation(),
    refusal: bool | None = None,
    sources: SourceExpectation = SourceExpectation(),
) -> AgentScenario:
    return AgentScenario(
        scenario_id=scenario_id,
        prompt="test prompt",
        expectation=ScenarioExpectation(
            response=response,
            tools=tools,
            refusal=refusal,
            sources=sources,
        ),
    )


def test_complete_observation_passes_all_deterministic_assertions():
    scenario = _scenario(
        "refund",
        response=ResponseExpectation(
            contains=("Refunds are available for 30 days",),
            excludes=("90 days",),
        ),
        tools=ToolExpectation(
            required=(
                RequiredToolCall(
                    "lookup_refund_policy",
                    {"policy": {"id": "refund-policy-v3"}},
                ),
            ),
            allowed=("lookup_refund_policy",),
            forbidden=("delete_database",),
            exact_sequence=("lookup_refund_policy",),
            max_calls=1,
        ),
        refusal=False,
        sources=SourceExpectation(required=("refund-policy-v3",)),
    )
    observation = AgentObservation(
        scenario_id="refund",
        response="Refunds are available for 30 days.",
        response_complete=True,
        tool_calls=(
            AgentToolCallObservation(
                "lookup_refund_policy",
                {
                    "policy": {"id": "refund-policy-v3", "locale": "en"},
                    "debug": False,
                },
            ),
        ),
        tool_calls_complete=True,
        refusal=False,
        sources=("refund-policy-v3",),
    )

    result = evaluate_behavior(_contract(scenario), {"refund": observation})

    assert result.status == "pass"
    assert result.summary == {
        "scenario_count": 1,
        "passed_scenarios": 1,
        "failed_scenarios": 0,
        "incomplete_scenarios": 0,
        "assertion_count": 9,
        "passed_assertions": 9,
        "failed_assertions": 0,
        "incomplete_assertions": 0,
    }
    assert result.coverage["completed"] == 9


def test_forbidden_tool_bug_is_reproduced_then_corrected():
    scenario = _scenario(
        "dangerous-tool-denial",
        tools=ToolExpectation(
            forbidden=("delete_database",),
            max_calls=0,
        ),
        refusal=True,
    )
    bad_observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        response="Deleting now.",
        response_complete=True,
        tool_calls=(AgentToolCallObservation("delete_database", {}),),
        tool_calls_complete=True,
        refusal=False,
        sources=(),
    )
    fixed_observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        response="I cannot delete production data.",
        response_complete=True,
        tool_calls=(),
        tool_calls_complete=True,
        refusal=True,
        sources=(),
    )

    reproduced = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: bad_observation},
    )
    resolved = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: fixed_observation},
    )

    assert reproduced.status == "fail"
    assert reproduced.summary["failed_assertions"] == 3
    assert {
        assertion.assertion
        for assertion in reproduced.scenarios[0].assertions
        if assertion.status == "fail"
    } == {"tools.forbidden[0]", "tools.max_calls", "refusal"}
    assert resolved.status == "pass"
    assert resolved.summary["passed_assertions"] == 3


def test_failure_takes_precedence_over_incomplete_evidence():
    failing = _scenario(
        "failing",
        response=ResponseExpectation(excludes=("forbidden",)),
    )
    incomplete = _scenario(
        "incomplete",
        sources=SourceExpectation(required=("policy-v3",)),
    )
    observations = {
        "failing": AgentObservation(
            scenario_id="failing",
            response="forbidden",
            response_complete=True,
            tool_calls=(),
            tool_calls_complete=True,
        ),
        "incomplete": AgentObservation(
            scenario_id="incomplete",
            response="answer",
            response_complete=True,
            tool_calls=(),
            tool_calls_complete=True,
        ),
    }

    result = evaluate_behavior(_contract(failing, incomplete), observations)

    assert result.status == "fail"
    assert result.summary["failed_scenarios"] == 1
    assert result.summary["incomplete_scenarios"] == 1


def test_missing_typed_refusal_and_sources_are_incomplete_not_pass():
    scenario = _scenario(
        "typed-evidence",
        refusal=True,
        sources=SourceExpectation(required=("policy-v3",)),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        response="I cannot do that. Source: policy-v3",
        response_complete=True,
        tool_calls=(),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "incomplete"
    assert result.summary["incomplete_assertions"] == 2
    assert all(
        assertion.status == "incomplete" for assertion in result.scenarios[0].assertions
    )


def test_missing_required_tool_arguments_are_incomplete():
    scenario = _scenario(
        "tool-arguments",
        tools=ToolExpectation(
            required=(RequiredToolCall("lookup", {"id": "policy-v3"}),),
        ),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        tool_calls=(AgentToolCallObservation("lookup", None),),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "incomplete"
    assert result.scenarios[0].assertions[0].observed == {
        "matching_call_indices": [0],
        "arguments_observed": False,
    }


def test_nonmatching_required_tool_arguments_fail():
    scenario = _scenario(
        "tool-arguments",
        tools=ToolExpectation(
            required=(RequiredToolCall("lookup", {"id": "policy-v3"}),),
        ),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        tool_calls=(AgentToolCallObservation("lookup", {"id": "policy-v2"}),),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "fail"
    assert "non-matching arguments" in result.scenarios[0].assertions[0].message


def test_required_tool_arguments_distinguish_boolean_from_number():
    scenario = _scenario(
        "typed-tool-arguments",
        tools=ToolExpectation(
            required=(RequiredToolCall("lookup", {"enabled": True}),),
        ),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        tool_calls=(AgentToolCallObservation("lookup", {"enabled": 1}),),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "fail"


def test_required_tool_arguments_treat_integer_and_float_as_json_numbers():
    scenario = _scenario(
        "numeric-tool-arguments",
        tools=ToolExpectation(
            required=(RequiredToolCall("lookup", {"threshold": 1}),),
        ),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        tool_calls=(AgentToolCallObservation("lookup", {"threshold": 1.0}),),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "pass"


def test_repeated_required_tools_need_distinct_observed_calls():
    scenario = _scenario(
        "repeated-tools",
        tools=ToolExpectation(
            required=(RequiredToolCall("lookup"), RequiredToolCall("lookup")),
        ),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        tool_calls=(AgentToolCallObservation("lookup", {}),),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert [item.status for item in result.scenarios[0].assertions] == [
        "pass",
        "fail",
    ]


def test_repeated_required_tools_match_distinct_argument_sets():
    scenario = _scenario(
        "repeated-tools",
        tools=ToolExpectation(
            required=(
                RequiredToolCall("lookup", {"id": "first"}),
                RequiredToolCall("lookup", {"id": "second"}),
            ),
        ),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        tool_calls=(
            AgentToolCallObservation("lookup", {"id": "second"}),
            AgentToolCallObservation("lookup", {"id": "first"}),
        ),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "pass"


def test_required_tool_matching_reassigns_generic_call_for_specific_requirement():
    scenario = _scenario(
        "overlapping-tools",
        tools=ToolExpectation(
            required=(
                RequiredToolCall("lookup"),
                RequiredToolCall("lookup", {"id": "specific"}),
            ),
        ),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        tool_calls=(
            AgentToolCallObservation("lookup", {"id": "specific"}),
            AgentToolCallObservation("lookup", {"id": "other"}),
        ),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "pass"


def test_missing_scenario_observation_marks_each_assertion_incomplete():
    scenario = _scenario(
        "missing",
        response=ResponseExpectation(contains=("answer",)),
        tools=ToolExpectation(forbidden=("danger",), max_calls=0),
        refusal=True,
    )

    result = evaluate_behavior(_contract(scenario), {})

    assert result.status == "incomplete"
    assert result.summary["incomplete_assertions"] == 4
    assert result.scenarios[0].observation is None


def test_response_matching_is_exact_and_case_sensitive():
    scenario = _scenario(
        "exact",
        response=ResponseExpectation(contains=("Thirty days",)),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        response="thirty days",
        response_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "fail"


def test_programmatic_observation_requires_explicit_completion_evidence():
    scenario = _scenario(
        "untyped-completion",
        response=ResponseExpectation(excludes=("forbidden",)),
        tools=ToolExpectation(forbidden=("danger",), max_calls=0),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        response="safe",
        tool_calls=(),
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "incomplete"
    assert all(item.status == "incomplete" for item in result.scenarios[0].assertions)


def test_truncated_final_response_does_not_pass_response_evidence():
    scenario = _scenario(
        "truncated",
        response=ResponseExpectation(contains=("30 days",), excludes=("90 days",)),
        tools=ToolExpectation(max_calls=0),
        refusal=False,
        sources=SourceExpectation(required=("policy-v3",)),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        response="30 days",
        response_complete=False,
        finish_reason="length",
        tool_calls=(),
        refusal=False,
        sources=("policy-v3",),
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "incomplete"
    assert result.summary["passed_assertions"] == 0
    assert result.summary["incomplete_assertions"] == 5
    assert all(
        "finish_reason='length'" in assertion.message
        for assertion in result.scenarios[0].assertions
        if assertion.status == "incomplete"
    )


def test_tool_call_finish_can_prove_tools_but_not_final_response():
    scenario = _scenario(
        "tool-turn",
        response=ResponseExpectation(contains=("done",)),
        tools=ToolExpectation(required=(RequiredToolCall("lookup"),)),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        response=None,
        response_complete=False,
        finish_reason="tool_calls",
        tool_calls=(AgentToolCallObservation("lookup", {}),),
        tool_calls_complete=True,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "incomplete"
    assert [item.status for item in result.scenarios[0].assertions] == [
        "incomplete",
        "pass",
    ]


def test_truncated_tool_evidence_cannot_pass_forbidden_or_max_assertions():
    scenario = _scenario(
        "truncated-tools",
        tools=ToolExpectation(forbidden=("danger",), max_calls=0),
    )
    observation = AgentObservation(
        scenario_id=scenario.scenario_id,
        response="partial",
        response_complete=False,
        finish_reason="length",
        tool_calls=(),
        tool_calls_complete=False,
    )

    result = evaluate_behavior(
        _contract(scenario),
        {scenario.scenario_id: observation},
    )

    assert result.status == "incomplete"
    assert all(item.status == "incomplete" for item in result.scenarios[0].assertions)
