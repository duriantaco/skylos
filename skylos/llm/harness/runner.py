from __future__ import annotations

import time
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, TypeVar
from uuid import uuid4

from .guards import enforce_elapsed_budget, enforce_step_budget
from .trace import (
    EVENTS_FILENAME,
    STATE_FILENAME,
    SUMMARY_FILENAME,
    default_trace_root,
    write_json_artifact,
    write_jsonl_trace,
)
from .tools import HarnessToolRegistry
from .types import (
    HarnessBudget,
    HarnessDecision,
    HARNESS_SCHEMA_VERSION,
    HarnessRun,
    HarnessStep,
    HarnessToolCall,
    resolved_project_root,
    sanitize_run_id,
    utc_now_iso,
)

T = TypeVar("T")


class HarnessRunner:
    def __init__(
        self,
        *,
        kind: str,
        project_root: str | Path,
        budget: HarnessBudget | None = None,
        run_id: str | None = None,
        trace_root: str | Path | None = None,
        metadata: dict[str, Any] | None = None,
        tool_registry: HarnessToolRegistry | None = None,
    ):
        root = resolved_project_root(project_root)
        self._started_monotonic = time.monotonic()
        self._events: list[dict[str, Any]] = []
        self._live_usage_keys: set[str] = set()
        self._trace_root = Path(trace_root) if trace_root is not None else None
        self._tool_registry = tool_registry
        metadata_dict = dict(metadata or {})
        if self._tool_registry is not None:
            metadata_dict["registered_tools"] = self._tool_registry.to_dict()
        self.run = HarnessRun(
            run_id=sanitize_run_id(run_id) if run_id else self._generate_run_id(),
            kind=kind,
            project_root=str(root),
            budget=budget or HarnessBudget(),
            metadata=metadata_dict,
        )
        if self._trace_root is not None:
            self._set_artifact_paths()
        self._record("run_started", self.run.to_dict())

    @classmethod
    def with_default_trace_root(
        cls,
        *,
        kind: str,
        project_root: str | Path,
        budget: HarnessBudget | None = None,
        run_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        tool_registry: HarnessToolRegistry | None = None,
    ) -> "HarnessRunner":
        root = resolved_project_root(project_root)
        return cls(
            kind=kind,
            project_root=root,
            budget=budget,
            run_id=run_id,
            trace_root=default_trace_root(root),
            metadata=metadata,
            tool_registry=tool_registry,
        )

    def run_step(
        self,
        name: str,
        fn: Callable[[], T],
        *,
        input_summary: dict[str, Any] | None = None,
        output_summary: Callable[[T], dict[str, Any]] | None = None,
    ) -> T:
        enforce_elapsed_budget(self._started_monotonic, self.run.budget)
        enforce_step_budget(len(self.run.steps), self.run.budget)

        step = HarnessStep(
            name=name,
            status="running",
            started_at=utc_now_iso(),
            input_summary=dict(input_summary or {}),
        )
        step_started = time.monotonic()
        self.run.steps.append(step)
        self._record("step_started", step.to_dict())
        try:
            output = fn()
        except Exception as exc:
            self._finish_step(
                step,
                status="failed",
                started_monotonic=step_started,
                error=f"{type(exc).__name__}: {exc}",
            )
            self.run.status = "failed"
            self.run.error = step.error
            self.finish(status="failed", error=step.error)
            raise

        summary = output_summary(output) if output_summary is not None else {}
        self._finish_step(
            step,
            status="completed",
            started_monotonic=step_started,
            output_summary=summary,
        )
        return output

    def step(
        self,
        name: str,
        *,
        input_summary: dict[str, Any] | None = None,
    ) -> "HarnessStepContext":
        return HarnessStepContext(
            self,
            name=name,
            input_summary=input_summary,
        )

    def run_tool(
        self,
        name: str,
        fn: Callable[[], T],
        *,
        input_summary: dict[str, Any] | None = None,
        output_summary: Callable[[T], dict[str, Any]] | None = None,
    ) -> T:
        enforce_elapsed_budget(self._started_monotonic, self.run.budget)
        if self._tool_registry is not None:
            self._tool_registry.get(name)

        call = HarnessToolCall(
            name=name,
            status="running",
            phase=self.run.current_phase(),
            started_at=utc_now_iso(),
            input_summary=dict(input_summary or {}),
        )
        call_started = time.monotonic()
        self.run.tool_calls.append(call)
        self._record("tool_started", call.to_dict())
        try:
            output = fn()
            summary = output_summary(output) if output_summary is not None else {}
        except Exception as exc:
            self._finish_tool(
                call,
                status="failed",
                started_monotonic=call_started,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise

        self._finish_tool(
            call,
            status="completed",
            started_monotonic=call_started,
            output_summary=summary,
        )
        return output

    def finish(self, *, status: str = "completed", error: str | None = None) -> None:
        if self.run.ended_at is not None:
            return
        self.run.status = status
        self.run.error = error
        self.run.ended_at = utc_now_iso()
        self.run.duration_ms = _elapsed_ms(self._started_monotonic)
        self.update_usage(seconds=round(self.run.duration_ms / 1000, 3), persist=False)
        self._record("run_completed", self.run.to_dict())
        if self._trace_root is not None:
            trace_path = write_jsonl_trace(
                self._trace_root, self.run.run_id, self._events
            )
            if trace_path is None:
                self.run.trace_path = None
            summary_path = write_json_artifact(
                self._trace_root,
                self.run.run_id,
                SUMMARY_FILENAME,
                self.run.summary_dict(),
            )
            if summary_path is None:
                self.run.summary_path = None
            self._persist_state()

    def enforce_budget(self) -> None:
        enforce_elapsed_budget(self._started_monotonic, self.run.budget)

    def remaining_seconds(self) -> float | None:
        maximum = self.run.budget.max_seconds
        if maximum is None:
            return None
        elapsed = time.monotonic() - self._started_monotonic
        return max(0.0, maximum - elapsed)

    @staticmethod
    def _generate_run_id() -> str:
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        return f"{timestamp}-{uuid4().hex[:8]}"

    def _finish_step(
        self,
        step: HarnessStep,
        *,
        status: str,
        started_monotonic: float,
        output_summary: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        step.status = status
        step.ended_at = utc_now_iso()
        step.duration_ms = _elapsed_ms(started_monotonic)
        step.output_summary = dict(output_summary or {})
        step.error = error
        if status == "completed":
            self._ingest_usage(step.output_summary)
        self._record(f"step_{status}", step.to_dict())

    def _finish_tool(
        self,
        call: HarnessToolCall,
        *,
        status: str,
        started_monotonic: float,
        output_summary: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        call.status = status
        call.ended_at = utc_now_iso()
        call.duration_ms = _elapsed_ms(started_monotonic)
        call.output_summary = dict(output_summary or {})
        call.error = error
        self._record(f"tool_{status}", call.to_dict())

    def _record(self, event: str, payload: dict[str, Any]) -> None:
        self._events.append(
            {
                "event": event,
                "run_id": self.run.run_id,
                "kind": self.run.kind,
                "timestamp": utc_now_iso(),
                **payload,
                "schema_version": HARNESS_SCHEMA_VERSION,
            }
        )
        self._persist_events()
        self._persist_state()

    def _persist_events(self) -> None:
        if self._trace_root is None:
            return
        trace_path = write_jsonl_trace(
            self._trace_root,
            self.run.run_id,
            self._events,
        )
        self.run.trace_path = str(trace_path) if trace_path is not None else None

    def update_usage(
        self,
        *,
        persist: bool = True,
        live: bool = True,
        **usage: int | float,
    ) -> None:
        for key, value in usage.items():
            if live:
                self._live_usage_keys.add(key)
            current = self.run.usage.get(key, 0)
            self.run.usage[key] = current + value
        if persist:
            self._persist_state()

    def _ingest_usage(self, summary: dict[str, Any]) -> None:
        llm_calls = summary.get("llm_calls")
        if (
            isinstance(llm_calls, int | float)
            and "llm_calls" not in self._live_usage_keys
        ):
            self.update_usage(llm_calls=llm_calls, persist=False, live=False)
        fixes = summary.get("fixes")
        if isinstance(fixes, int | float) and "fixes" not in self._live_usage_keys:
            self.update_usage(fixes=fixes, persist=False, live=False)

    def record_decision(
        self,
        *,
        phase: str,
        code: str,
        target: dict[str, Any],
        details: dict[str, Any] | None = None,
        persist: bool = True,
    ) -> None:
        self.run.decisions.append(
            HarnessDecision(
                phase=phase,
                code=code,
                target=dict(target),
                details=dict(details or {}),
            )
        )
        if persist:
            self._persist_state()

    def _set_artifact_paths(self) -> None:
        if self._trace_root is None:
            return
        run_dir = self._trace_root / self.run.run_id
        self.run.trace_path = str(run_dir / EVENTS_FILENAME)
        self.run.state_path = str(run_dir / STATE_FILENAME)
        self.run.summary_path = str(run_dir / SUMMARY_FILENAME)

    def _persist_state(self) -> None:
        if self._trace_root is None:
            return
        state_path = write_json_artifact(
            self._trace_root,
            self.run.run_id,
            STATE_FILENAME,
            self.run.state_dict(),
        )
        if state_path is None:
            self.run.state_path = None


class HarnessStepContext:
    def __init__(
        self,
        runner: HarnessRunner,
        *,
        name: str,
        input_summary: dict[str, Any] | None = None,
    ):
        self._runner = runner
        self._name = name
        self._input_summary = dict(input_summary or {})
        self._output_summary: dict[str, Any] = {}
        self._step: HarnessStep | None = None
        self._started_monotonic: float | None = None

    def __enter__(self) -> "HarnessStepContext":
        enforce_elapsed_budget(
            self._runner._started_monotonic,
            self._runner.run.budget,
        )
        enforce_step_budget(len(self._runner.run.steps), self._runner.run.budget)
        self._step = HarnessStep(
            name=self._name,
            status="running",
            started_at=utc_now_iso(),
            input_summary=self._input_summary,
        )
        self._started_monotonic = time.monotonic()
        self._runner.run.steps.append(self._step)
        self._runner._record("step_started", self._step.to_dict())
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self._step is None or self._started_monotonic is None:
            return False

        if exc is not None:
            error = f"{type(exc).__name__}: {exc}"
            self._runner._finish_step(
                self._step,
                status="failed",
                started_monotonic=self._started_monotonic,
                error=error,
            )
            self._runner.run.status = "failed"
            self._runner.run.error = error
            self._runner.finish(status="failed", error=error)
            return False

        self._runner._finish_step(
            self._step,
            status="completed",
            started_monotonic=self._started_monotonic,
            output_summary=self._output_summary,
        )
        return False

    def set_output_summary(self, **summary: Any) -> None:
        self._output_summary.update(summary)


def _elapsed_ms(started_monotonic: float) -> int:
    return int(round((time.monotonic() - started_monotonic) * 1000))
