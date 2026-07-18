from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_project_text_no_symlink

from ._loader_support import (
    MAX_SCENARIOS,
    boolean,
    json_mapping,
    list_value,
    mapping,
    optional_text,
    reject_duplicates,
    reject_unknown,
    required_int,
    resolve_project_file,
    resolved_root,
    safe_id,
    parse_text,
    tool_name,
    unique_json_object,
    validate_loaded_shape,
)
from .schema import (
    OBSERVATION_SCHEMA_VERSION,
    AgentBehaviorError,
    AgentObservation,
    AgentToolCallObservation,
    BehaviorObservationSet,
)


MAX_BEHAVIOR_OBSERVATIONS_BYTES = 2 * 1024 * 1024
MAX_OBSERVED_TOOL_CALLS = 250
MAX_OBSERVED_SOURCES = 1_000


def load_behavior_observations(
    path: str | Path,
    *,
    project_root: str | Path,
) -> BehaviorObservationSet:
    root = resolved_root(project_root)
    observation_path = resolve_project_file(path, root, "Observation file")
    source = read_project_text_no_symlink(
        root,
        observation_path,
        max_bytes=MAX_BEHAVIOR_OBSERVATIONS_BYTES,
        encoding="utf-8",
    )
    if source is None:
        raise AgentBehaviorError(
            "Observation file must be a regular non-symlink file no larger than "
            f"{MAX_BEHAVIOR_OBSERVATIONS_BYTES} bytes"
        )
    try:
        raw = json.loads(source, object_pairs_hook=unique_json_object)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AgentBehaviorError(f"Invalid observation JSON: {exc}") from exc
    validate_loaded_shape(raw, "Observation file")
    if not isinstance(raw, dict):
        raise AgentBehaviorError("Observation file must be a JSON object")
    return BehaviorObservationSet(
        version=OBSERVATION_SCHEMA_VERSION,
        path=observation_path,
        source_digest=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        observations=_parse_observations(raw),
    )


def _parse_observations(raw: dict[str, Any]) -> dict[str, AgentObservation]:
    reject_unknown(raw, {"version", "scenarios"}, "")
    version = required_int(raw, "version", "version")
    if version != OBSERVATION_SCHEMA_VERSION:
        raise AgentBehaviorError(
            f"observation version must be {OBSERVATION_SCHEMA_VERSION}, got {version}"
        )
    scenarios_raw = list_value(raw.get("scenarios"), "scenarios", required=True)
    if len(scenarios_raw) > MAX_SCENARIOS:
        raise AgentBehaviorError(f"scenarios cannot exceed {MAX_SCENARIOS} entries")
    observations = [
        _parse_observation(item, index) for index, item in enumerate(scenarios_raw)
    ]
    reject_duplicates(
        [observation.scenario_id for observation in observations],
        "observation scenario id",
    )
    return {observation.scenario_id: observation for observation in observations}


def _parse_observation(value: Any, index: int) -> AgentObservation:
    field = f"scenarios[{index}]"
    raw = mapping(value, field, required=True)
    reject_unknown(raw, _OBSERVATION_FIELDS, field)
    response, response_complete, finish_reason = _response_evidence(raw, field)
    tool_calls, tool_calls_complete = _tool_evidence(raw, field, finish_reason)
    refusal = _optional_boolean(raw, "refusal", field)
    sources = _observed_sources(raw, field)
    error = _optional_field_text(raw, "error", field)
    return AgentObservation(
        scenario_id=safe_id(raw.get("id"), f"{field}.id"),
        response=response,
        response_complete=response_complete,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
        tool_calls_complete=tool_calls_complete,
        refusal=refusal,
        sources=sources,
        error=error,
    )


_OBSERVATION_FIELDS = {
    "id",
    "response",
    "response_complete",
    "finish_reason",
    "tool_calls",
    "tool_calls_complete",
    "refusal",
    "sources",
    "error",
}


def _response_evidence(
    raw: dict[str, Any],
    field: str,
) -> tuple[str | None, bool | None, str | None]:
    response = _optional_field_text(raw, "response", field)
    response_complete = _optional_boolean(raw, "response_complete", field)
    finish_reason = _optional_field_text(raw, "finish_reason", field)
    if finish_reason is not None and response_complete is not (finish_reason == "stop"):
        raise AgentBehaviorError(
            f"{field}.response_complete conflicts with finish_reason"
        )
    return response, response_complete, finish_reason


def _tool_evidence(
    raw: dict[str, Any],
    field: str,
    finish_reason: str | None,
) -> tuple[tuple[AgentToolCallObservation, ...] | None, bool | None]:
    complete = _optional_boolean(raw, "tool_calls_complete", field)
    if finish_reason is not None and complete is not (
        finish_reason in {"stop", "tool_calls"}
    ):
        raise AgentBehaviorError(
            f"{field}.tool_calls_complete conflicts with finish_reason"
        )
    if "tool_calls" not in raw:
        return None, complete
    calls = list_value(raw.get("tool_calls"), f"{field}.tool_calls")
    if len(calls) > MAX_OBSERVED_TOOL_CALLS:
        raise AgentBehaviorError(
            f"{field}.tool_calls cannot exceed {MAX_OBSERVED_TOOL_CALLS}"
        )
    return (
        tuple(
            _parse_observed_tool_call(item, call_index, field)
            for call_index, item in enumerate(calls)
        ),
        complete,
    )


def _observed_sources(raw: dict[str, Any], field: str) -> tuple[str, ...] | None:
    if "sources" not in raw:
        return None
    source_values = _source_ids(raw.get("sources"), f"{field}.sources")
    if len(source_values) > MAX_OBSERVED_SOURCES:
        raise AgentBehaviorError(
            f"{field}.sources cannot exceed {MAX_OBSERVED_SOURCES}"
        )
    return tuple(source_values)


def _optional_boolean(
    raw: dict[str, Any],
    key: str,
    field: str,
) -> bool | None:
    if key not in raw:
        return None
    return boolean(raw.get(key), f"{field}.{key}")


def _optional_field_text(
    raw: dict[str, Any],
    key: str,
    field: str,
) -> str | None:
    if key not in raw:
        return None
    return optional_text(raw.get(key), f"{field}.{key}")


def _parse_observed_tool_call(
    value: Any,
    index: int,
    field: str,
) -> AgentToolCallObservation:
    item_field = f"{field}.tool_calls[{index}]"
    raw = mapping(value, item_field, required=True)
    reject_unknown(raw, {"name", "arguments"}, item_field)
    arguments = None
    if "arguments" in raw:
        arguments = json_mapping(raw.get("arguments"), f"{item_field}.arguments")
    return AgentToolCallObservation(
        name=tool_name(raw.get("name"), f"{item_field}.name"),
        arguments=arguments,
    )


def _source_ids(value: Any, field: str) -> list[str]:
    items = list_value(value, field)
    result: list[str] = []
    for index, item in enumerate(items):
        item_field = f"{field}[{index}]"
        result.append(_source_id(item, item_field))
    return result


def _source_id(value: Any, field: str) -> str:
    if isinstance(value, str):
        return parse_text(value, field)
    raw = mapping(value, field, required=True)
    reject_unknown(raw, {"id", "source"}, field)
    source_id = optional_text(raw.get("id"), f"{field}.id")
    source_id = source_id or optional_text(raw.get("source"), f"{field}.source")
    if source_id is None:
        raise AgentBehaviorError(f"{field} requires id or source")
    return source_id
