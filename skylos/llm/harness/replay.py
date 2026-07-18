from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skylos.agents.evaluation.evidence import (
    behavior_evidence_digest,
    derive_behavior_totals,
    serialized_observation_evidence_digest,
)
from skylos.agents.evaluation.schema import (
    BEHAVIOR_RESULT_VERSION,
    AgentBehaviorError,
    MAX_BEHAVIOR_RESULT_BYTES,
)
from skylos.core.safe_cache_io import read_project_text_no_symlink

from .trace import EVENTS_FILENAME, STATE_FILENAME, SUMMARY_FILENAME
from .types import HARNESS_SCHEMA_VERSION

MAX_REPLAY_EVENTS_BYTES = 5_000_000
MAX_REPLAY_ARTIFACT_BYTES = 1_000_000
BEHAVIOR_RESULTS_FILENAME = "behavior-results.json"
MAX_REPLAY_JSON_DEPTH = 64
MAX_REPLAY_JSON_VALUES = 100_000


class HarnessReplayError(AssertionError):
    pass


@dataclass(frozen=True)
class HarnessReplayIssue:
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
        }


@dataclass
class HarnessReplay:
    run_dir: Path
    events: list[dict[str, Any]] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    behavior_results: dict[str, Any] = field(default_factory=dict)
    behavior_artifact_present: bool = False
    issues: list[HarnessReplayIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues

    def event_names(self) -> list[str]:
        return [str(event.get("event", "")) for event in self.events]

    def phase_sequence(self) -> list[str]:
        steps = self.state.get("steps") if isinstance(self.state, dict) else []
        if not isinstance(steps, list):
            return []
        return [str(step.get("name", "")) for step in steps if isinstance(step, dict)]

    def tool_sequence(self) -> list[str]:
        calls = self.state.get("tool_calls") if isinstance(self.state, dict) else []
        if not isinstance(calls, list):
            return []
        return [str(call.get("name", "")) for call in calls if isinstance(call, dict)]

    def decision_codes(self) -> list[str]:
        decisions = self.state.get("decisions") if isinstance(self.state, dict) else []
        if not isinstance(decisions, list):
            return []
        return [
            str(decision.get("code", ""))
            for decision in decisions
            if isinstance(decision, dict)
        ]

    def assert_valid(self) -> None:
        if self.issues:
            formatted = "; ".join(
                f"{issue.code}: {issue.message}" for issue in self.issues
            )
            raise HarnessReplayError(formatted)


def load_harness_replay(run_dir: str | Path) -> HarnessReplay:
    path = Path(run_dir).expanduser().absolute()
    replay = HarnessReplay(run_dir=path)
    replay.events = _read_events(path / EVENTS_FILENAME, replay.issues)
    replay.state = _read_json_artifact(path / STATE_FILENAME, replay.issues)
    replay.summary = _read_json_artifact(path / SUMMARY_FILENAME, replay.issues)
    behavior_path = path / BEHAVIOR_RESULTS_FILENAME
    replay.behavior_artifact_present = _artifact_entry_present(behavior_path)
    if _is_behavior_replay(replay):
        replay.behavior_results = _read_json_artifact(
            behavior_path,
            replay.issues,
            max_bytes=MAX_BEHAVIOR_RESULT_BYTES,
        )
    if replay.issues:
        return replay
    replay.issues.extend(_validate_replay(replay))
    return replay


def _read_events(
    path: Path,
    issues: list[HarnessReplayIssue],
) -> list[dict[str, Any]]:
    payload = _read_safe_text(
        path,
        issues,
        max_bytes=MAX_REPLAY_EVENTS_BYTES,
        error_code="invalid_events",
    )
    if payload is None:
        return []
    events: list[dict[str, Any]] = []
    value_count = 0
    try:
        for index, line in enumerate(payload.splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(
                line,
                object_pairs_hook=_unique_replay_object,
                parse_constant=_reject_replay_constant,
            )
            value_count += _validate_replay_json_shape(
                event,
                label=f"{EVENTS_FILENAME}:{index}",
                max_values=MAX_REPLAY_JSON_VALUES - value_count,
            )
            if not isinstance(event, dict):
                issues.append(
                    HarnessReplayIssue(
                        "invalid_event",
                        f"{EVENTS_FILENAME}:{index} is not an object",
                    )
                )
                continue
            events.append(event)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        issues.append(
            HarnessReplayIssue(
                "invalid_events",
                f"could not read {EVENTS_FILENAME}: {exc}",
            )
        )
    return events


def _read_json_artifact(
    path: Path,
    issues: list[HarnessReplayIssue],
    *,
    max_bytes: int = MAX_REPLAY_ARTIFACT_BYTES,
) -> dict[str, Any]:
    payload_text = _read_safe_text(
        path,
        issues,
        max_bytes=max_bytes,
        error_code="invalid_artifact",
    )
    if payload_text is None:
        return {}
    try:
        payload = json.loads(
            payload_text,
            object_pairs_hook=_unique_replay_object,
            parse_constant=_reject_replay_constant,
        )
        _validate_replay_json_shape(payload, label=path.name)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        issues.append(
            HarnessReplayIssue(
                "invalid_artifact",
                f"could not read {path.name}: {exc}",
            )
        )
        return {}
    if not isinstance(payload, dict):
        issues.append(
            HarnessReplayIssue(
                "invalid_artifact",
                f"{path.name} is not an object",
            )
        )
        return {}
    return payload


def _validate_replay_json_shape(
    value: Any,
    *,
    label: str,
    max_values: int = MAX_REPLAY_JSON_VALUES,
) -> int:
    pending: list[tuple[Any, int]] = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        if depth > MAX_REPLAY_JSON_DEPTH:
            raise ValueError(f"{label} nesting exceeds {MAX_REPLAY_JSON_DEPTH}")
        count += 1
        if count > max_values:
            raise ValueError(f"{label} exceeds {MAX_REPLAY_JSON_VALUES} values")
        if isinstance(item, dict):
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return count


def _read_safe_text(
    path: Path,
    issues: list[HarnessReplayIssue],
    *,
    max_bytes: int,
    error_code: str,
) -> str | None:
    entry = _artifact_entry_stat(path)
    if entry is None:
        issues.append(HarnessReplayIssue("missing_artifact", f"{path.name} is missing"))
        return None
    if stat.S_ISLNK(entry.st_mode) or not stat.S_ISREG(entry.st_mode):
        issues.append(
            HarnessReplayIssue(
                "unsafe_artifact",
                f"{path.name} is not a regular non-symlink file",
            )
        )
        return None
    if entry.st_size > max_bytes:
        issues.append(
            HarnessReplayIssue(
                "oversized_artifact",
                f"{path.name} exceeds {max_bytes} bytes",
            )
        )
        return None
    payload = read_project_text_no_symlink(
        path.parent.parent,
        path,
        max_bytes=max_bytes,
        encoding="utf-8",
    )
    if payload is None:
        issues.append(
            HarnessReplayIssue(error_code, f"could not safely read {path.name}")
        )
    return payload


def _artifact_entry_stat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except OSError:
        return None


def _artifact_entry_present(path: Path) -> bool:
    return _artifact_entry_stat(path) is not None


def _declared_kinds(replay: HarnessReplay) -> set[str]:
    values = [
        replay.state.get("kind"),
        replay.summary.get("kind"),
        *[event.get("kind") for event in replay.events],
    ]
    if replay.behavior_results:
        values.append(replay.behavior_results.get("kind"))
    return {value for value in values if isinstance(value, str) and value}


def _is_behavior_replay(replay: HarnessReplay) -> bool:
    if replay.behavior_artifact_present or "agent_behavior" in _declared_kinds(replay):
        return True
    metadata = replay.state.get("metadata")
    if isinstance(metadata, dict) and any(
        key in metadata
        for key in (
            "behavior_evidence_digest",
            "behavior_provenance",
            "observation_evidence_digest",
        )
    ):
        return True
    if any(
        isinstance(decision, dict)
        and isinstance(decision.get("code"), str)
        and decision["code"].startswith("behavior_assertion_")
        for decision in _dict_list(replay.state.get("decisions"))
    ):
        return True
    return any(
        isinstance(event.get("metadata"), dict)
        and "behavior_evidence_digest" in event["metadata"]
        for event in replay.events
    )


def _validate_kind(
    replay: HarnessReplay,
    issues: list[HarnessReplayIssue],
) -> None:
    values = [
        replay.state.get("kind"),
        replay.summary.get("kind"),
        *[event.get("kind") for event in replay.events],
    ]
    if replay.behavior_results:
        values.append(replay.behavior_results.get("kind"))
    if not values or any(not isinstance(value, str) or not value for value in values):
        issues.append(
            HarnessReplayIssue(
                "kind_mismatch",
                "harness artifacts must all declare a kind",
            )
        )
        return
    kinds = set(values)
    if len(kinds) != 1 or (_is_behavior_replay(replay) and kinds != {"agent_behavior"}):
        issues.append(
            HarnessReplayIssue(
                "kind_mismatch",
                f"harness artifacts contain inconsistent kinds: {sorted(kinds)}",
            )
        )


def _validate_replay(replay: HarnessReplay) -> list[HarnessReplayIssue]:
    issues: list[HarnessReplayIssue] = []
    events = replay.events
    state = replay.state
    summary = replay.summary

    if not events:
        return [HarnessReplayIssue("empty_events", "events.jsonl has no events")]
    if events[0].get("event") != "run_started":
        issues.append(
            HarnessReplayIssue("event_order", "first event is not run_started")
        )

    _validate_kind(replay, issues)

    run_ids = {
        str(value)
        for value in [
            state.get("run_id"),
            summary.get("run_id"),
            *[event.get("run_id") for event in events],
        ]
        if value
    }
    if len(run_ids) != 1:
        issues.append(
            HarnessReplayIssue(
                "run_id_mismatch",
                f"artifacts contain multiple run ids: {sorted(run_ids)}",
            )
        )

    _validate_schema_version(events, state, summary, issues)
    _validate_run_completion(events, state, summary, issues)
    _validate_steps(events, state, summary, issues)
    _validate_tool_calls(events, state, summary, issues)
    _validate_decisions(state, summary, issues)
    _validate_budget(state, summary, issues)
    if _is_behavior_replay(replay):
        _validate_behavior_results(replay, issues)
    return issues


def _validate_behavior_results(
    replay: HarnessReplay,
    issues: list[HarnessReplayIssue],
) -> None:
    report = replay.behavior_results
    if not report:
        issues.append(
            HarnessReplayIssue(
                "behavior_evidence_invalid",
                f"{BEHAVIOR_RESULTS_FILENAME} must be a non-empty object",
            )
        )
        return
    _validate_behavior_header(replay, report, issues)
    metadata = _behavior_metadata(replay.state)
    provenance = _validate_behavior_bindings(report, metadata, issues)
    derived = _derived_behavior_evidence(report, issues)
    if derived is None:
        return
    derived_status, derived_summary, derived_coverage, observed_digest, digest = derived
    _validate_behavior_totals(
        report,
        derived_status,
        derived_summary,
        derived_coverage,
        issues,
    )
    _validate_behavior_observation_digests(
        provenance,
        metadata,
        observed_digest,
        issues,
    )
    _validate_behavior_evidence_digests(
        replay,
        report,
        metadata,
        digest,
        issues,
    )
    _validate_behavior_scenario_ids(report, metadata, issues)
    _validate_behavior_decisions(report, replay.state, issues)


def _validate_behavior_header(
    replay: HarnessReplay,
    report: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    if report.get("schema_version") != BEHAVIOR_RESULT_VERSION:
        issues.append(
            HarnessReplayIssue(
                "behavior_schema_mismatch",
                f"{BEHAVIOR_RESULTS_FILENAME} has an unsupported schema version",
            )
        )
    if report.get("kind") != "agent_behavior":
        issues.append(
            HarnessReplayIssue(
                "behavior_kind_mismatch",
                f"{BEHAVIOR_RESULTS_FILENAME} kind is not agent_behavior",
            )
        )
    if report.get("harness") != replay.summary:
        issues.append(
            HarnessReplayIssue(
                "behavior_harness_mismatch",
                "behavior evidence harness summary does not match summary.json",
            )
        )
    _validate_behavior_artifact_paths(replay, report, issues)


def _behavior_metadata(state: dict[str, Any]) -> dict[str, Any]:
    metadata = state.get("metadata")
    if not isinstance(metadata, dict):
        return {}
    return metadata


def _validate_behavior_bindings(
    report: dict[str, Any],
    metadata: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> dict[str, Any]:
    contract = report.get("contract")
    provenance = report.get("provenance")
    if not isinstance(contract, dict) or contract.get("digest") != metadata.get(
        "contract_digest"
    ):
        issues.append(
            HarnessReplayIssue(
                "behavior_contract_mismatch",
                "behavior evidence contract digest does not match harness metadata",
            )
        )
    if report.get("mode") != metadata.get("mode"):
        issues.append(
            HarnessReplayIssue(
                "behavior_mode_mismatch",
                "behavior evidence mode does not match harness metadata",
            )
        )
    if not isinstance(provenance, dict):
        issues.append(
            HarnessReplayIssue(
                "behavior_provenance_invalid",
                "behavior evidence provenance is missing",
            )
        )
        return {}
    if provenance != metadata.get("behavior_provenance"):
        issues.append(
            HarnessReplayIssue(
                "behavior_provenance_mismatch",
                "behavior evidence provenance does not match harness metadata",
            )
        )
    return provenance


def _derived_behavior_evidence(
    report: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> tuple[str, dict[str, int], dict[str, Any], str, str] | None:
    try:
        derived_status, derived_summary, derived_coverage = derive_behavior_totals(
            report.get("scenarios")
        )
        observed_digest = serialized_observation_evidence_digest(
            report.get("scenarios")
        )
        evidence_digest = behavior_evidence_digest(report)
    except AgentBehaviorError as exc:
        issues.append(HarnessReplayIssue("behavior_evidence_invalid", str(exc)))
        return None
    return (
        derived_status,
        derived_summary,
        derived_coverage,
        observed_digest,
        evidence_digest,
    )


def _validate_behavior_totals(
    report: dict[str, Any],
    derived_status: str,
    derived_summary: dict[str, int],
    derived_coverage: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    if report.get("status") != derived_status:
        issues.append(
            HarnessReplayIssue(
                "behavior_status_mismatch",
                "behavior evidence status does not match scenario assertions",
            )
        )
    if report.get("summary") != derived_summary:
        issues.append(
            HarnessReplayIssue(
                "behavior_summary_mismatch",
                "behavior evidence summary does not match scenario assertions",
            )
        )
    if report.get("coverage") != derived_coverage:
        issues.append(
            HarnessReplayIssue(
                "behavior_coverage_mismatch",
                "behavior evidence coverage does not match scenario assertions",
            )
        )


def _validate_behavior_observation_digests(
    provenance: dict[str, Any],
    metadata: dict[str, Any],
    observed_digest: str,
    issues: list[HarnessReplayIssue],
) -> None:
    if provenance.get("selected_digest") != observed_digest:
        issues.append(
            HarnessReplayIssue(
                "behavior_observation_digest_mismatch",
                "behavior evidence observations do not match provenance digest",
            )
        )
    if metadata.get("observation_evidence_digest") != observed_digest:
        issues.append(
            HarnessReplayIssue(
                "behavior_observation_digest_mismatch",
                "behavior evidence observations do not match harness metadata",
            )
        )
    if provenance.get("source_digest") != metadata.get("observation_source_digest"):
        issues.append(
            HarnessReplayIssue(
                "behavior_source_digest_mismatch",
                "observation source digest does not match harness metadata",
            )
        )


def _validate_behavior_evidence_digests(
    replay: HarnessReplay,
    report: dict[str, Any],
    metadata: dict[str, Any],
    evidence_digest: str,
    issues: list[HarnessReplayIssue],
) -> None:
    expected_digest = report.get("evidence_digest")
    if expected_digest != evidence_digest:
        issues.append(
            HarnessReplayIssue(
                "behavior_evidence_digest_mismatch",
                "behavior evidence digest does not match report content",
            )
        )
    if metadata.get("behavior_evidence_digest") != evidence_digest:
        issues.append(
            HarnessReplayIssue(
                "behavior_evidence_digest_mismatch",
                "behavior evidence digest does not match state metadata",
            )
        )
    _validate_completed_behavior_digest(replay, evidence_digest, issues)


def _validate_completed_behavior_digest(
    replay: HarnessReplay,
    evidence_digest: str,
    issues: list[HarnessReplayIssue],
) -> None:
    completed = [
        event for event in replay.events if event.get("event") == "run_completed"
    ]
    completed_metadata = completed[0].get("metadata") if len(completed) == 1 else {}
    if (
        not isinstance(completed_metadata, dict)
        or completed_metadata.get("behavior_evidence_digest") != evidence_digest
    ):
        issues.append(
            HarnessReplayIssue(
                "behavior_evidence_digest_mismatch",
                "behavior evidence digest does not match run_completed metadata",
            )
        )


def _validate_behavior_scenario_ids(
    report: dict[str, Any],
    metadata: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    scenario_ids = [
        scenario.get("id")
        for scenario in report.get("scenarios", [])
        if isinstance(scenario, dict)
    ]
    if sorted(scenario_ids) != metadata.get("scenario_ids"):
        issues.append(
            HarnessReplayIssue(
                "behavior_scenario_mismatch",
                "behavior evidence scenarios do not match harness metadata",
            )
        )


def _validate_behavior_artifact_paths(
    replay: HarnessReplay,
    report: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    artifacts = report.get("artifacts")
    if not isinstance(artifacts, dict):
        issues.append(
            HarnessReplayIssue(
                "behavior_artifact_path_mismatch",
                "behavior evidence artifact paths are missing",
            )
        )
        return
    harness = report.get("harness")
    if not isinstance(harness, dict):
        return
    state_path = harness.get("state_path")
    if not isinstance(state_path, str):
        issues.append(
            HarnessReplayIssue(
                "behavior_artifact_path_mismatch",
                "behavior evidence harness state path is missing",
            )
        )
        return
    expected = {
        "run_dir": ".",
        "events": EVENTS_FILENAME,
        "state": STATE_FILENAME,
        "summary": SUMMARY_FILENAME,
        "behavior_results": BEHAVIOR_RESULTS_FILENAME,
    }
    if artifacts != expected:
        issues.append(
            HarnessReplayIssue(
                "behavior_artifact_path_mismatch",
                "behavior evidence must use the canonical relative artifact layout",
            )
        )
        return
    if any(
        (entry := _artifact_entry_stat(replay.run_dir / filename)) is None
        or not stat.S_ISREG(entry.st_mode)
        for filename in (
            EVENTS_FILENAME,
            STATE_FILENAME,
            SUMMARY_FILENAME,
            BEHAVIOR_RESULTS_FILENAME,
        )
    ):
        issues.append(
            HarnessReplayIssue(
                "behavior_artifact_path_mismatch",
                "opened replay directory does not contain the canonical artifacts",
            )
        )
        return
    harness_names = {
        "trace_path": EVENTS_FILENAME,
        "state_path": STATE_FILENAME,
        "summary_path": SUMMARY_FILENAME,
    }
    if any(
        not isinstance(harness.get(key), str) or Path(harness[key]).name != filename
        for key, filename in harness_names.items()
    ):
        issues.append(
            HarnessReplayIssue(
                "behavior_artifact_path_mismatch",
                "behavior harness paths do not use the expected artifact names",
            )
        )


def _validate_behavior_decisions(
    report: dict[str, Any],
    state: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    expected: list[tuple[Any, ...]] = []
    for scenario in report.get("scenarios", []):
        if not isinstance(scenario, dict):
            continue
        for assertion in scenario.get("assertions", []):
            if not isinstance(assertion, dict):
                continue
            expected.append(
                (
                    f"behavior_assertion_{assertion.get('status')}",
                    scenario.get("id"),
                    assertion.get("assertion"),
                    assertion.get("kind"),
                    assertion.get("message"),
                    assertion.get("expected"),
                    assertion.get("observed"),
                )
            )
    observed: list[tuple[Any, ...]] = []
    for decision in _dict_list(state.get("decisions")):
        code = decision.get("code")
        if not isinstance(code, str) or not code.startswith("behavior_assertion_"):
            continue
        target = decision.get("target")
        details = decision.get("details")
        if not isinstance(target, dict) or not isinstance(details, dict):
            observed.append((code, None, None, None, None, None, None))
            continue
        observed.append(
            (
                code,
                target.get("scenario_id"),
                target.get("assertion"),
                target.get("kind"),
                details.get("message"),
                details.get("expected"),
                details.get("observed"),
            )
        )
    if observed != expected:
        issues.append(
            HarnessReplayIssue(
                "behavior_decision_mismatch",
                "behavior assertion decisions do not match behavior evidence",
            )
        )


def _validate_schema_version(
    events: list[dict[str, Any]],
    state: dict[str, Any],
    summary: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    expected = HARNESS_SCHEMA_VERSION
    for artifact_name, payload in (("state.json", state), ("summary.json", summary)):
        version = payload.get("schema_version")
        if version != expected:
            issues.append(
                HarnessReplayIssue(
                    "schema_version_mismatch",
                    f"{artifact_name} schema_version={version!r}, expected {expected}",
                )
            )

    for index, event in enumerate(events, 1):
        version = event.get("schema_version")
        if version != expected:
            issues.append(
                HarnessReplayIssue(
                    "schema_version_mismatch",
                    f"{EVENTS_FILENAME}:{index} schema_version={version!r}, expected {expected}",
                )
            )


def _validate_run_completion(
    events: list[dict[str, Any]],
    state: dict[str, Any],
    summary: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    completed = [event for event in events if event.get("event") == "run_completed"]
    if state.get("status") in {"completed", "failed"}:
        if len(completed) != 1:
            issues.append(
                HarnessReplayIssue(
                    "run_completion",
                    "finished run must have exactly one run_completed event",
                )
            )
        elif events[-1].get("event") != "run_completed":
            issues.append(
                HarnessReplayIssue(
                    "event_order",
                    "run_completed is not the final event",
                )
            )
    if state.get("status") != summary.get("status"):
        issues.append(
            HarnessReplayIssue(
                "status_mismatch",
                "state and summary statuses differ",
            )
        )


def _validate_steps(
    events: list[dict[str, Any]],
    state: dict[str, Any],
    summary: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    steps = _dict_list(state.get("steps"))
    started = _event_items(events, "step_started")
    finished = _event_items(events, {"step_completed", "step_failed"})

    _validate_step_sequences(steps, started, finished, issues)
    _validate_step_statuses(steps, finished, issues)
    _validate_step_summary(steps, summary, issues)


def _validate_step_sequences(
    steps: list[dict[str, Any]],
    started: list[dict[str, Any]],
    finished: list[dict[str, Any]],
    issues: list[HarnessReplayIssue],
) -> None:
    state_names = [str(step.get("name", "")) for step in steps]
    started_names = [str(event.get("name", "")) for event in started]
    finished_names = [str(event.get("name", "")) for event in finished]
    if state_names != started_names:
        issues.append(
            HarnessReplayIssue(
                "step_sequence_mismatch",
                "state steps do not match step_started events",
            )
        )
    if state_names != finished_names:
        issues.append(
            HarnessReplayIssue(
                "step_sequence_mismatch",
                "state steps do not match completed/failed step events",
            )
        )


def _validate_step_statuses(
    steps: list[dict[str, Any]],
    finished: list[dict[str, Any]],
    issues: list[HarnessReplayIssue],
) -> None:
    state_statuses = [str(step.get("status", "")) for step in steps]
    event_statuses = [
        "completed" if event.get("event") == "step_completed" else "failed"
        for event in finished
    ]
    if state_statuses != event_statuses:
        issues.append(
            HarnessReplayIssue(
                "step_status_mismatch",
                "state step statuses do not match step events",
            )
        )


def _validate_step_summary(
    steps: list[dict[str, Any]],
    summary: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    completed_names = [
        str(step.get("name", "")) for step in steps if step.get("status") == "completed"
    ]
    if completed_names != summary.get("completed_phases"):
        issues.append(
            HarnessReplayIssue(
                "completed_phase_mismatch",
                "summary completed phases do not match state",
            )
        )
    failed_phase = next(
        (
            str(step.get("name", ""))
            for step in reversed(steps)
            if step.get("status") == "failed"
        ),
        None,
    )
    if failed_phase != summary.get("failed_phase"):
        issues.append(
            HarnessReplayIssue(
                "failed_phase_mismatch",
                "summary failed phase does not match state",
            )
        )
    if len(steps) != summary.get("phase_count"):
        issues.append(
            HarnessReplayIssue(
                "phase_count_mismatch",
                "summary phase count does not match state",
            )
        )


def _validate_tool_calls(
    events: list[dict[str, Any]],
    state: dict[str, Any],
    summary: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    calls = _dict_list(state.get("tool_calls"))
    started = _event_items(events, "tool_started")
    finished = _event_items(events, {"tool_completed", "tool_failed"})

    state_names = [str(call.get("name", "")) for call in calls]
    started_names = [str(event.get("name", "")) for event in started]
    finished_names = [str(event.get("name", "")) for event in finished]
    if state_names != started_names:
        issues.append(
            HarnessReplayIssue(
                "tool_sequence_mismatch",
                "state tool calls do not match tool_started events",
            )
        )
    if state_names != finished_names:
        issues.append(
            HarnessReplayIssue(
                "tool_sequence_mismatch",
                "state tool calls do not match completed/failed tool events",
            )
        )

    state_statuses = [str(call.get("status", "")) for call in calls]
    event_statuses = [
        "completed" if event.get("event") == "tool_completed" else "failed"
        for event in finished
    ]
    if state_statuses != event_statuses:
        issues.append(
            HarnessReplayIssue(
                "tool_status_mismatch",
                "state tool statuses do not match tool events",
            )
        )
    if len(calls) != summary.get("tool_call_count", 0):
        issues.append(
            HarnessReplayIssue(
                "tool_call_count_mismatch",
                "summary tool call count does not match state",
            )
        )


def _validate_decisions(
    state: dict[str, Any],
    summary: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    decisions = _dict_list(state.get("decisions"))
    if len(decisions) != summary.get("decision_count"):
        issues.append(
            HarnessReplayIssue(
                "decision_count_mismatch",
                "summary decision count does not match state",
            )
        )


def _validate_budget(
    state: dict[str, Any],
    summary: dict[str, Any],
    issues: list[HarnessReplayIssue],
) -> None:
    for key in ("budget", "budget_used", "budget_remaining"):
        if state.get(key) != summary.get(key):
            issues.append(
                HarnessReplayIssue(
                    "budget_mismatch",
                    f"summary {key} does not match state",
                )
            )


def _event_items(
    events: list[dict[str, Any]],
    event_names: str | set[str],
) -> list[dict[str, Any]]:
    names = {event_names} if isinstance(event_names, str) else event_names
    return [event for event in events if event.get("event") in names]


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _unique_replay_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_replay_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON value {value}")
