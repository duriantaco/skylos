from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .schema import AgentBehaviorError, AgentObservation


BEHAVIOR_EVIDENCE_KEYS = (
    "schema_version",
    "kind",
    "status",
    "mode",
    "contract",
    "summary",
    "coverage",
    "scenarios",
    "provenance",
    "artifacts",
)
VALID_BEHAVIOR_STATUSES = frozenset({"pass", "fail", "incomplete"})


def behavior_evidence_digest(payload: Mapping[str, Any]) -> str:
    core = {key: payload.get(key) for key in BEHAVIOR_EVIDENCE_KEYS}
    return _canonical_digest(core)


def observation_evidence_digest(
    observations: Mapping[str, AgentObservation],
    scenario_ids: Sequence[str],
) -> str:
    payload = {
        "version": 1,
        "scenarios": [
            observations[scenario_id].to_dict()
            for scenario_id in sorted(scenario_ids)
            if scenario_id in observations
        ],
    }
    return _canonical_digest(payload)


def serialized_observation_evidence_digest(scenarios: Any) -> str:
    if not isinstance(scenarios, list):
        raise AgentBehaviorError("behavior evidence scenarios must be a list")
    observations: list[dict[str, Any]] = []
    sortable: list[tuple[str, dict[str, Any]]] = []
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise AgentBehaviorError(
                f"behavior evidence scenarios[{index}] must be an object"
            )
        scenario_id = scenario.get("id")
        observation = scenario.get("observation")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise AgentBehaviorError(
                f"behavior evidence scenarios[{index}].id must be a string"
            )
        if observation is None:
            continue
        if not isinstance(observation, dict) or observation.get("id") != scenario_id:
            raise AgentBehaviorError(
                f"behavior evidence observation does not match scenario {scenario_id!r}"
            )
        sortable.append((scenario_id, observation))
    observations.extend(observation for _, observation in sorted(sortable))
    return _canonical_digest({"version": 1, "scenarios": observations})


def derive_behavior_totals(
    scenarios: Any,
) -> tuple[str, dict[str, int], dict[str, Any]]:
    if not isinstance(scenarios, list):
        raise AgentBehaviorError("behavior evidence scenarios must be a list")

    scenario_statuses: list[str] = []
    assertion_statuses: list[str] = []
    by_kind: dict[str, Counter[str]] = {}
    for scenario_index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise AgentBehaviorError(
                f"behavior evidence scenarios[{scenario_index}] must be an object"
            )
        assertions = scenario.get("assertions")
        if not isinstance(assertions, list):
            raise AgentBehaviorError(
                f"behavior evidence scenarios[{scenario_index}].assertions must be a list"
            )
        current_statuses: list[str] = []
        for assertion_index, assertion in enumerate(assertions):
            if not isinstance(assertion, dict):
                raise AgentBehaviorError(
                    "behavior evidence assertion must be an object at "
                    f"scenarios[{scenario_index}].assertions[{assertion_index}]"
                )
            status = assertion.get("status")
            kind = assertion.get("kind")
            if status not in VALID_BEHAVIOR_STATUSES:
                raise AgentBehaviorError(
                    "behavior evidence assertion has invalid status at "
                    f"scenarios[{scenario_index}].assertions[{assertion_index}]"
                )
            if not isinstance(kind, str) or not kind:
                raise AgentBehaviorError(
                    "behavior evidence assertion has invalid kind at "
                    f"scenarios[{scenario_index}].assertions[{assertion_index}]"
                )
            current_statuses.append(status)
            assertion_statuses.append(status)
            by_kind.setdefault(kind, Counter())[status] += 1

        derived_status = _combined_status(current_statuses)
        if scenario.get("status") != derived_status:
            raise AgentBehaviorError(
                f"behavior evidence scenario {scenario.get('id')!r} status does not match assertions"
            )
        scenario_statuses.append(derived_status)

    status = _combined_status(scenario_statuses)
    summary = {
        "scenario_count": len(scenario_statuses),
        "passed_scenarios": scenario_statuses.count("pass"),
        "failed_scenarios": scenario_statuses.count("fail"),
        "incomplete_scenarios": scenario_statuses.count("incomplete"),
        "assertion_count": len(assertion_statuses),
        "passed_assertions": assertion_statuses.count("pass"),
        "failed_assertions": assertion_statuses.count("fail"),
        "incomplete_assertions": assertion_statuses.count("incomplete"),
    }
    coverage = {
        "requested": len(assertion_statuses),
        "completed": sum(status in {"pass", "fail"} for status in assertion_statuses),
        "incomplete": assertion_statuses.count("incomplete"),
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
    return status, summary, coverage


def _canonical_digest(payload: Any) -> str:
    try:
        encoded = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AgentBehaviorError("behavior evidence must contain JSON values") from exc
    return hashlib.sha256(encoded).hexdigest()


def _combined_status(statuses: Sequence[str]) -> str:
    if "fail" in statuses:
        return "fail"
    if "incomplete" in statuses:
        return "incomplete"
    return "pass"
