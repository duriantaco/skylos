from __future__ import annotations

import json
import re
from typing import Any

from ._openai_transport import AgentEndpointError
from .schema import AgentObservation, AgentToolCallObservation


MAX_ENDPOINT_RESPONSE_DEPTH = 64
MAX_ENDPOINT_RESPONSE_VALUES = 50_000
MAX_ENDPOINT_TOOL_CALLS = 250
MAX_ENDPOINT_SOURCES = 1_000
MAX_NORMALIZED_RESPONSE_CHARS = 200_000
MAX_NORMALIZED_SOURCE_CHARS = 100_000
MAX_FINISH_REASON_CHARS = 64
AUTH_TOKEN_REDACTION = "[REDACTED]"
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def decode_openai_response(body: bytes, *, scenario_id: str) -> AgentObservation:
    try:
        raw = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_response_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AgentEndpointError("agent endpoint returned invalid JSON") from exc
    _validate_response_shape(raw)
    return normalize_openai_chat_response(raw, scenario_id=scenario_id)


def normalize_openai_chat_response(
    raw: Any,
    *,
    scenario_id: str,
) -> AgentObservation:
    if not isinstance(raw, dict):
        raise AgentEndpointError("agent endpoint response must be an object")
    choices = raw.get("choices")
    if not isinstance(choices, list) or not choices:
        raise AgentEndpointError("agent endpoint response requires choices[0]")
    choice = choices[0]
    if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
        raise AgentEndpointError("agent endpoint response requires choices[0].message")
    message = choice["message"]
    finish_reason, response_complete, tool_calls_complete = _completion_evidence(choice)
    response, response_shape_complete = _response_text(message.get("content"))
    tool_calls, tool_shape_complete = _tool_calls(message)
    if finish_reason is not None:
        response_complete = response_complete and response_shape_complete
        tool_calls_complete = tool_calls_complete and tool_shape_complete
    return AgentObservation(
        scenario_id=scenario_id,
        response=response,
        response_complete=response_complete,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
        tool_calls_complete=tool_calls_complete,
        refusal=_refusal_value(message),
        sources=_source_values(message),
    )


def _completion_evidence(
    choice: dict[str, Any],
) -> tuple[str | None, bool | None, bool | None]:
    finish_reason = choice.get("finish_reason")
    if not (
        isinstance(finish_reason, str)
        and finish_reason.strip()
        and len(finish_reason.strip()) <= MAX_FINISH_REASON_CHARS
    ):
        return None, None, None
    normalized = finish_reason.strip()
    return normalized, normalized == "stop", normalized in {"stop", "tool_calls"}


def _response_text(value: Any) -> tuple[str | None, bool]:
    if value is None:
        return None, True
    if isinstance(value, str):
        if len(value) > MAX_NORMALIZED_RESPONSE_CHARS:
            return None, False
        return value, True
    if not isinstance(value, list):
        return None, False
    parts: list[str] = []
    complete = True
    for part in value:
        if not isinstance(part, dict):
            complete = False
            continue
        part_type = part.get("type")
        text = part.get("text")
        if part_type not in {None, "text", "output_text"} or not isinstance(text, str):
            complete = False
        else:
            parts.append(text)
    response = "".join(parts) if parts else None
    if response is not None and len(response) > MAX_NORMALIZED_RESPONSE_CHARS:
        return None, False
    return response, complete


def _tool_calls(
    message: dict[str, Any],
) -> tuple[tuple[AgentToolCallObservation, ...] | None, bool]:
    if "tool_calls" not in message:
        return None, False
    if message.get("tool_calls") is None:
        return (), True
    raw_calls = message.get("tool_calls")
    if not isinstance(raw_calls, list) or len(raw_calls) > MAX_ENDPOINT_TOOL_CALLS:
        return None, False
    calls: list[AgentToolCallObservation] = []
    for raw_call in raw_calls:
        call = _tool_call(raw_call)
        if call is None:
            return None, False
        calls.append(call)
    return tuple(calls), True


def _tool_call(value: Any) -> AgentToolCallObservation | None:
    if not isinstance(value, dict):
        return None
    function = value.get("function")
    if not isinstance(function, dict):
        return None
    name = function.get("name")
    if not isinstance(name, str) or not _TOOL_NAME_RE.fullmatch(name.strip()):
        return None
    return AgentToolCallObservation(
        name=name.strip(),
        arguments=_tool_arguments(function.get("arguments")),
    )


def _tool_arguments(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return dict(value)
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_unique_response_object,
            parse_constant=_reject_json_constant,
        )
        _validate_response_shape(parsed)
    except (
        AgentEndpointError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ):
        return None
    return parsed if isinstance(parsed, dict) else None


def _refusal_value(message: dict[str, Any]) -> bool | None:
    if "refusal" not in message:
        return None
    value = message.get("refusal")
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return bool(value.strip())
    return None


def _source_values(message: dict[str, Any]) -> tuple[str, ...] | None:
    if "sources" not in message:
        return None
    values = message.get("sources")
    if not isinstance(values, list) or len(values) > MAX_ENDPOINT_SOURCES:
        return None
    sources: list[str] = []
    for value in values:
        source_id = _source_value(value)
        if not source_id or len(source_id) > MAX_NORMALIZED_SOURCE_CHARS:
            return None
        sources.append(source_id)
    return tuple(sources)


def _source_value(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, dict):
        return None
    candidate = value.get("id") or value.get("source")
    return candidate.strip() if isinstance(candidate, str) else None


def _unique_response_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AgentEndpointError("agent endpoint response contains duplicate keys")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON value {value}")


def _validate_response_shape(value: Any) -> None:
    pending: list[tuple[Any, int]] = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        if depth > MAX_ENDPOINT_RESPONSE_DEPTH:
            raise AgentEndpointError(
                f"agent endpoint response nesting exceeds {MAX_ENDPOINT_RESPONSE_DEPTH}"
            )
        count += 1
        if count > MAX_ENDPOINT_RESPONSE_VALUES:
            raise AgentEndpointError(
                f"agent endpoint response exceeds {MAX_ENDPOINT_RESPONSE_VALUES} values"
            )
        if isinstance(item, dict):
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)


def redact_observation(
    observation: AgentObservation,
    secret: str,
) -> AgentObservation:
    tool_calls = observation.tool_calls
    if tool_calls is not None:
        tool_calls = tuple(
            AgentToolCallObservation(
                name=redact_text(call.name, secret),
                arguments=redact_json(call.arguments, secret),
            )
            for call in tool_calls
        )
    sources = observation.sources
    if sources is not None:
        sources = tuple(redact_text(source, secret) for source in sources)
    return AgentObservation(
        scenario_id=observation.scenario_id,
        response=(
            None
            if observation.response is None
            else redact_text(observation.response, secret)
        ),
        response_complete=observation.response_complete,
        finish_reason=(
            None
            if observation.finish_reason is None
            else redact_text(observation.finish_reason, secret)
        ),
        tool_calls=tool_calls,
        tool_calls_complete=observation.tool_calls_complete,
        refusal=observation.refusal,
        sources=sources,
        error=(
            None
            if observation.error is None
            else redact_text(observation.error, secret)
        ),
    )


def redact_json(value: Any, secret: str) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return redact_text(value, secret)
    if isinstance(value, list):
        return [redact_json(item, secret) for item in value]
    if isinstance(value, dict):
        return {
            redact_text(str(key), secret): redact_json(item, secret)
            for key, item in value.items()
        }
    return value


def redact_text(value: str, secret: str) -> str:
    replacement = (
        AUTH_TOKEN_REDACTION
        if len(secret) >= len(AUTH_TOKEN_REDACTION)
        else "*" * len(secret)
    )
    return value.replace(secret, replacement)
