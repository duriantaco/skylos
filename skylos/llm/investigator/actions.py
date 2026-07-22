"""Validation and tracking for investigator protocol actions."""

from __future__ import annotations

import json
from typing import Any

from skylos.audit.investigator_tools import AuditReadOnlyTools
from skylos.llm.schemas import normalize_json_response_text

from .models import InvestigationIncompleteError
from .protocol import TOOL_ARGUMENTS_SCHEMA


_ACTION_FIELDS = {
    "action",
    "tool",
    "arguments",
    "status",
    "reasoning",
    "findings",
    "clean_evidence",
    "covered_candidate_ids",
}
_TEXT_ARGUMENT_FIELDS = ("path", "query", "path_prefix", "name_contains")
_LINE_ARGUMENT_FIELDS = ("start_line", "end_line")


def parse_action(response: Any) -> dict[str, Any]:
    text = normalize_json_response_text(str(response or ""))
    payload = _decode_action(text)
    _validate_action_fields(payload)
    _validate_action_argument_fields(payload["arguments"])
    _validate_action_result_fields(payload)
    _validate_action_argument_values(payload["arguments"])
    if payload["action"] == "tool":
        _validate_tool_action(payload)
    else:
        _validate_finish_action(payload)
    return payload


def _decode_action(text: str) -> dict[str, Any]:
    if not text:
        raise InvestigationIncompleteError("investigator returned an empty response")
    if text.startswith("Error:"):
        raise InvestigationIncompleteError("investigator adapter returned an error")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvestigationIncompleteError(
            "investigator returned malformed JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise InvestigationIncompleteError("investigator response must be an object")
    return payload


def _validate_action_fields(payload: dict[str, Any]) -> None:
    if set(payload) != _ACTION_FIELDS:
        raise InvestigationIncompleteError(
            "investigator response has missing or unsupported fields"
        )
    if payload["action"] not in {"tool", "finish"}:
        raise InvestigationIncompleteError("investigator action is invalid")
    if not isinstance(payload["reasoning"], str):
        raise InvestigationIncompleteError("investigator reasoning must be a string")
    if not isinstance(payload["arguments"], dict):
        raise InvestigationIncompleteError("investigator arguments must be an object")


def _validate_action_argument_fields(arguments: dict[str, Any]) -> None:
    argument_fields = set(TOOL_ARGUMENTS_SCHEMA["required"])
    if set(arguments) != argument_fields:
        raise InvestigationIncompleteError(
            "investigator arguments have missing or unsupported fields"
        )


def _validate_action_argument_values(arguments: dict[str, Any]) -> None:
    for key in _TEXT_ARGUMENT_FIELDS:
        value = arguments.get(key)
        if value is not None and not isinstance(value, str):
            raise InvestigationIncompleteError(
                f"investigator argument {key} must be a string or null"
            )
    for key in _LINE_ARGUMENT_FIELDS:
        _validate_line_argument(key, arguments.get(key))


def _validate_action_result_fields(payload: dict[str, Any]) -> None:
    if (
        not isinstance(payload["findings"], list)
        or not isinstance(payload["clean_evidence"], list)
        or not isinstance(payload["covered_candidate_ids"], list)
    ):
        raise InvestigationIncompleteError(
            "investigator findings, clean evidence, and candidate coverage must be arrays"
        )
    if not all(isinstance(item, str) for item in payload["covered_candidate_ids"]):
        raise InvestigationIncompleteError("covered candidate IDs must be strings")


def _validate_line_argument(key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvestigationIncompleteError(
            f"investigator argument {key} must be a positive integer or null"
        )


def _validate_tool_action(payload: dict[str, Any]) -> None:
    if payload["tool"] not in AuditReadOnlyTools.TOOL_NAMES:
        raise InvestigationIncompleteError("investigator requested an unknown tool")
    if payload["status"] is not None or any(
        (
            payload["findings"],
            payload["clean_evidence"],
            payload["covered_candidate_ids"],
        )
    ):
        raise InvestigationIncompleteError("tool action contains final result fields")


def _validate_finish_action(payload: dict[str, Any]) -> None:
    if payload["tool"] is not None:
        raise InvestigationIncompleteError("finish action must not request a tool")
    if any(value is not None for value in payload["arguments"].values()):
        raise InvestigationIncompleteError("finish action contains tool arguments")
    if payload["status"] not in {"complete", "incomplete"}:
        raise InvestigationIncompleteError("finish status is invalid")
    if not payload["reasoning"].strip():
        raise InvestigationIncompleteError("finish reasoning is required")
    if payload["findings"] and payload["clean_evidence"]:
        raise InvestigationIncompleteError(
            "finding completions cannot include clean evidence"
        )


def validate_candidate_coverage(covered: list[str], expected: tuple[str, ...]) -> None:
    if len(covered) != len(set(covered)):
        raise InvestigationIncompleteError("candidate coverage contains duplicates")
    if set(covered) != set(expected):
        raise InvestigationIncompleteError(
            "investigator did not explicitly cover every supplied candidate"
        )


def action_fingerprint(action: dict[str, Any]) -> str:
    return json.dumps(
        {"tool": action["tool"], "arguments": action["arguments"]},
        sort_keys=True,
        separators=(",", ":"),
    )
