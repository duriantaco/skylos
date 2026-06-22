from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .trace import EVENTS_FILENAME, STATE_FILENAME, SUMMARY_FILENAME

MAX_REPLAY_EVENTS_BYTES = 5_000_000
MAX_REPLAY_ARTIFACT_BYTES = 1_000_000


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
        return [
            str(step.get("name", ""))
            for step in steps
            if isinstance(step, dict)
        ]

    def tool_sequence(self) -> list[str]:
        calls = self.state.get("tool_calls") if isinstance(self.state, dict) else []
        if not isinstance(calls, list):
            return []
        return [
            str(call.get("name", ""))
            for call in calls
            if isinstance(call, dict)
        ]

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
    path = Path(run_dir)
    replay = HarnessReplay(run_dir=path)
    replay.events = _read_events(path / EVENTS_FILENAME, replay.issues)
    replay.state = _read_json_artifact(path / STATE_FILENAME, replay.issues)
    replay.summary = _read_json_artifact(path / SUMMARY_FILENAME, replay.issues)
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
    try:
        for index, line in enumerate(payload.splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                issues.append(
                    HarnessReplayIssue(
                        "invalid_event",
                        f"{EVENTS_FILENAME}:{index} is not an object",
                    )
                )
                continue
            events.append(event)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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
) -> dict[str, Any]:
    payload_text = _read_safe_text(
        path,
        issues,
        max_bytes=MAX_REPLAY_ARTIFACT_BYTES,
        error_code="invalid_artifact",
    )
    if payload_text is None:
        return {}
    try:
        payload = json.loads(payload_text)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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


def _read_safe_text(
    path: Path,
    issues: list[HarnessReplayIssue],
    *,
    max_bytes: int,
    error_code: str,
) -> str | None:
    if not _is_safe_file(path, issues, max_bytes=max_bytes):
        return None

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] guarded no-follow replay read
            path, flags
        )
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            issues.append(
                HarnessReplayIssue(
                    "unsafe_artifact",
                    f"{path.name} is not a regular file",
                )
            )
            return None
        if file_stat.st_size > max_bytes:
            issues.append(
                HarnessReplayIssue(
                    "oversized_artifact",
                    f"{path.name} exceeds {max_bytes} bytes",
                )
            )
            return None
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = None
            return handle.read()
    except (OSError, UnicodeError) as exc:
        issues.append(
            HarnessReplayIssue(error_code, f"could not read {path.name}: {exc}")
        )
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _is_safe_file(
    path: Path,
    issues: list[HarnessReplayIssue],
    *,
    max_bytes: int,
) -> bool:
    try:
        if path.is_symlink():
            issues.append(
                HarnessReplayIssue("unsafe_artifact", f"{path.name} is a symlink")
            )
            return False
        if not path.is_file():
            issues.append(
                HarnessReplayIssue("missing_artifact", f"{path.name} is missing")
            )
            return False
        if path.stat().st_size > max_bytes:
            issues.append(
                HarnessReplayIssue(
                    "oversized_artifact",
                    f"{path.name} exceeds {max_bytes} bytes",
                )
            )
            return False
    except OSError as exc:
        issues.append(
            HarnessReplayIssue("unsafe_artifact", f"could not inspect {path.name}: {exc}")
        )
        return False
    return True


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

    _validate_run_completion(events, state, summary, issues)
    _validate_steps(events, state, summary, issues)
    _validate_tool_calls(events, state, summary, issues)
    _validate_decisions(state, summary, issues)
    _validate_budget(state, summary, issues)
    return issues


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
        str(step.get("name", ""))
        for step in steps
        if step.get("status") == "completed"
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
