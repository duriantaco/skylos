from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from skylos.core.contribution_settings import (
    ContributionSettings,
    load_contribution_settings,
)
from skylos.core.safe_cache_io import load_project_json_cache, save_project_json_cache


EVENT_SCHEMA_VERSION = 1
EVENT_CACHE_PATH = Path(".skylos") / "contribution" / "events.json"
MAX_LOCAL_EVENTS = 1_000


def record_structural_event(
    project_root: str | Path,
    finding: dict[str, Any] | None,
    *,
    event_type: str,
    settings: ContributionSettings | None = None,
) -> bool:
    if finding is None:
        return False

    resolved_settings = _settings(project_root, settings)
    if not resolved_settings.collect_local_signals:
        return False

    event = build_structural_event(finding, event_type=event_type)
    payload = load_local_events(project_root)
    events = _events_list(payload)
    events.append(event)
    payload["events"] = _bounded_events(events)
    return save_project_json_cache(project_root, EVENT_CACHE_PATH, payload)


def load_local_events(project_root: str | Path) -> dict[str, Any]:
    payload = load_project_json_cache(project_root, EVENT_CACHE_PATH)
    if not isinstance(payload, dict):
        return _empty_payload()
    if payload.get("schema_version") != EVENT_SCHEMA_VERSION:
        return _empty_payload()

    events = payload.get("events")
    if not isinstance(events, list):
        payload["events"] = []
    return payload


def build_structural_event(
    finding: dict[str, Any],
    *,
    event_type: str,
) -> dict[str, Any]:
    event = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_type": str(event_type),
        "rule_id": _string_field(finding, ("rule_id", "ruleId", "rule")),
        "category": _string_field(finding, ("category",)),
        "severity": _string_field(finding, ("severity",)),
        "vibe_category": _string_field(finding, ("vibe_category",)),
        "ai_likelihood": _string_field(finding, ("ai_likelihood",)),
        "file_ext": _file_ext(finding),
        "line_bucket": _line_bucket(finding.get("line")),
        "message_hash": _hash_value(_string_field(finding, ("message",))),
        "created_at": _utc_timestamp(),
    }
    event["structural_hash"] = _structural_hash(event)
    return event


def _settings(
    project_root: str | Path,
    settings: ContributionSettings | None,
) -> ContributionSettings:
    if settings is not None:
        return settings
    return load_contribution_settings(project_root)


def _empty_payload() -> dict[str, Any]:
    return {"schema_version": EVENT_SCHEMA_VERSION, "events": []}


def _events_list(payload: dict[str, Any]) -> list[dict[str, Any]]:
    events = payload.get("events")
    if not isinstance(events, list):
        return []

    safe_events = []
    for event in events:
        if isinstance(event, dict):
            safe_events.append(copy.deepcopy(event))
    return safe_events


def _bounded_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(events) <= MAX_LOCAL_EVENTS:
        return events
    start = len(events) - MAX_LOCAL_EVENTS
    return events[start:]


def _string_field(finding: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = finding.get(key)
        if isinstance(value, str):
            return value
    return ""


def _file_ext(finding: dict[str, Any]) -> str:
    file_value = _string_field(finding, ("file", "absolute_file", "relativePath"))
    if not file_value:
        return ""
    return Path(file_value).suffix.lower()


def _line_bucket(value: Any) -> str:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return "unknown"

    if line <= 0:
        return "unknown"
    bucket_start = ((line - 1) // 10) * 10 + 1
    bucket_end = bucket_start + 9
    return f"{bucket_start}-{bucket_end}"


def _hash_value(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:16]


def _structural_hash(event: dict[str, Any]) -> str:
    structural = {}
    for key, value in event.items():
        if key == "created_at":
            continue
        if key == "structural_hash":
            continue
        structural[key] = value
    raw = json.dumps(structural, sort_keys=True, separators=(",", ":"))
    return _hash_value(raw)


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
