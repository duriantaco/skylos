from __future__ import annotations

from typing import Any

from ._assertion_helpers import checked, incomplete
from .schema import (
    AgentObservation,
    AgentToolCallObservation,
    BehaviorAssertion,
    RequiredToolCall,
)


def required_tool(
    index: int,
    expected: RequiredToolCall,
    observation: AgentObservation | None,
    unavailable: str | None,
    matched_call_index: int | None,
    matched_tool_calls: set[int],
) -> BehaviorAssertion:
    assertion = f"tools.required[{index}]"
    if unavailable or observation is None or observation.tool_calls is None:
        return incomplete(
            assertion,
            "tool_required",
            unavailable or "tool calls were not observed",
            _required_tool_dict(expected),
        )
    candidates = tuple(
        (call_index, call)
        for call_index, call in enumerate(observation.tool_calls)
        if call.name == expected.name
    )
    if matched_call_index is None:
        return _unmatched_required_tool(
            assertion,
            expected,
            observation.tool_calls,
            candidates,
            matched_tool_calls,
        )
    return _matched_required_tool(assertion, expected, matched_call_index)


def _unmatched_required_tool(
    assertion: str,
    expected: RequiredToolCall,
    tool_calls: tuple[AgentToolCallObservation, ...],
    candidates: tuple[tuple[int, AgentToolCallObservation], ...],
    matched_tool_calls: set[int],
) -> BehaviorAssertion:
    unmatched = tuple(
        (call_index, call)
        for call_index, call in candidates
        if call_index not in matched_tool_calls
    )
    if expected.arguments is not None and any(
        call.arguments is None for _, call in unmatched
    ):
        return incomplete(
            assertion,
            "tool_required",
            f"arguments for tool {expected.name!r} were not fully observed",
            _required_tool_dict(expected),
            {
                "matching_call_indices": [call_index for call_index, _ in unmatched],
                "arguments_observed": False,
            },
        )
    return checked(
        assertion,
        "tool_required",
        False,
        "",
        _missing_required_tool_message(expected, candidates, unmatched),
        _required_tool_dict(expected),
        _tool_call_summary(tool_calls, expected.name),
    )


def _missing_required_tool_message(
    expected: RequiredToolCall,
    candidates: tuple[tuple[int, AgentToolCallObservation], ...],
    unmatched: tuple[tuple[int, AgentToolCallObservation], ...],
) -> str:
    if not candidates:
        return f"required tool {expected.name!r} was not called"
    if expected.arguments is not None and unmatched:
        return f"tool {expected.name!r} was called with non-matching arguments"
    return f"required tool {expected.name!r} needs another distinct call"


def _matched_required_tool(
    assertion: str,
    expected: RequiredToolCall,
    matched_call_index: int,
) -> BehaviorAssertion:
    if expected.arguments is None:
        return checked(
            assertion,
            "tool_required",
            True,
            f"required tool {expected.name!r} was called",
            "",
            _required_tool_dict(expected),
            {"call_index": matched_call_index},
        )
    return checked(
        assertion,
        "tool_required",
        True,
        f"required tool {expected.name!r} matched expected arguments",
        "",
        _required_tool_dict(expected),
        {"call_index": matched_call_index, "arguments_matched": True},
    )


def match_required_tool_calls(
    required: tuple[RequiredToolCall, ...],
    observation: AgentObservation | None,
    unavailable: str | None,
) -> dict[int, int]:
    if unavailable or observation is None or observation.tool_calls is None:
        return {}
    edges = _required_tool_edges(required, observation.tool_calls)
    call_matches: dict[int, int] = {}

    def assign(required_index: int, visited: set[int]) -> bool:
        for call_index in edges[required_index]:
            if call_index in visited:
                continue
            visited.add(call_index)
            previous = call_matches.get(call_index)
            if previous is None or assign(previous, visited):
                call_matches[call_index] = required_index
                return True
        return False

    for required_index in sorted(edges, key=lambda index: len(edges[index])):
        assign(required_index, set())
    return {
        required_index: call_index
        for call_index, required_index in call_matches.items()
    }


def _required_tool_edges(
    required: tuple[RequiredToolCall, ...],
    calls: tuple[AgentToolCallObservation, ...],
) -> dict[int, list[int]]:
    return {
        required_index: [
            call_index
            for call_index, call in enumerate(calls)
            if _tool_call_matches(expected, call)
        ]
        for required_index, expected in enumerate(required)
    }


def _tool_call_matches(
    expected: RequiredToolCall,
    observed: AgentToolCallObservation,
) -> bool:
    if observed.name != expected.name:
        return False
    if expected.arguments is None:
        return True
    return observed.arguments is not None and _json_subset(
        expected.arguments,
        observed.arguments,
    )


def allowed_tools(
    expected: tuple[str, ...],
    observation: AgentObservation | None,
    unavailable: str | None,
) -> BehaviorAssertion:
    assertion = "tools.allowed"
    if unavailable or observation is None or observation.tool_calls is None:
        return incomplete(
            assertion,
            "tools_allowed",
            unavailable or "tool calls were not observed",
            list(expected),
        )
    observed = [call.name for call in observation.tool_calls]
    unexpected = [name for name in observed if name not in set(expected)]
    return checked(
        assertion,
        "tools_allowed",
        not unexpected,
        "all observed tools are allowed",
        f"observed tools outside the allowed set: {unexpected}",
        list(expected),
        {"call_count": len(observed), "unexpected": unexpected},
    )


def forbidden_tool(
    index: int,
    expected: str,
    observation: AgentObservation | None,
    unavailable: str | None,
) -> BehaviorAssertion:
    assertion = f"tools.forbidden[{index}]"
    if unavailable or observation is None or observation.tool_calls is None:
        return incomplete(
            assertion,
            "tool_forbidden",
            unavailable or "tool calls were not observed",
            expected,
        )
    observed = [call.name for call in observation.tool_calls]
    passed = expected not in observed
    return checked(
        assertion,
        "tool_forbidden",
        passed,
        f"forbidden tool {expected!r} was not called",
        f"forbidden tool {expected!r} was called",
        expected,
        {
            "call_count": len(observed),
            "matching_call_indices": [
                call_index
                for call_index, name in enumerate(observed)
                if name == expected
            ],
        },
    )


def exact_tool_sequence(
    expected: tuple[str, ...],
    observation: AgentObservation | None,
    unavailable: str | None,
) -> BehaviorAssertion:
    assertion = "tools.exact_sequence"
    if unavailable or observation is None or observation.tool_calls is None:
        return incomplete(
            assertion,
            "tool_exact_sequence",
            unavailable or "tool calls were not observed",
            list(expected),
        )
    observed = [call.name for call in observation.tool_calls]
    return checked(
        assertion,
        "tool_exact_sequence",
        observed == list(expected),
        "tool call sequence matches exactly",
        "tool call sequence does not match",
        list(expected),
        observed,
    )


def max_tool_calls(
    expected: int,
    observation: AgentObservation | None,
    unavailable: str | None,
) -> BehaviorAssertion:
    assertion = "tools.max_calls"
    if unavailable or observation is None or observation.tool_calls is None:
        return incomplete(
            assertion,
            "tool_max_calls",
            unavailable or "tool calls were not observed",
            expected,
        )
    observed = len(observation.tool_calls)
    return checked(
        assertion,
        "tool_max_calls",
        observed <= expected,
        f"tool call count {observed} is within limit {expected}",
        f"tool call count {observed} exceeds limit {expected}",
        expected,
        observed,
    )


def _json_subset(expected: Any, observed: Any) -> bool:
    if isinstance(expected, dict):
        if not isinstance(observed, dict):
            return False
        return all(
            key in observed and _json_subset(value, observed[key])
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(observed, list)
            and len(expected) == len(observed)
            and all(
                _json_subset(expected_item, observed_item)
                for expected_item, observed_item in zip(expected, observed)
            )
        )
    if _is_json_number(expected):
        return _is_json_number(observed) and expected == observed
    return type(expected) is type(observed) and expected == observed


def _is_json_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _required_tool_dict(expected: RequiredToolCall) -> dict[str, Any]:
    return {"name": expected.name, "arguments": expected.arguments}


def _tool_call_summary(
    calls: tuple[AgentToolCallObservation, ...],
    expected_name: str,
) -> dict[str, Any]:
    return {
        "call_count": len(calls),
        "matching_name_count": sum(call.name == expected_name for call in calls),
    }
