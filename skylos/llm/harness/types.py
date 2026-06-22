from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

SAFE_RUN_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._-"
)
MAX_RUN_ID_LENGTH = 96


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_run_id(value: str | None) -> str:
    cleaned = "".join(
        char if char in SAFE_RUN_ID_CHARS else "_" for char in str(value or "").strip()
    )
    cleaned = cleaned.strip("._-")
    cleaned = cleaned[:MAX_RUN_ID_LENGTH].strip("._-")
    if not cleaned or cleaned in {".", ".."}:
        return f"run-{uuid4().hex[:8]}"
    return cleaned


class HarnessBudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class HarnessBudget:
    max_steps: int | None = None
    max_findings: int | None = None
    max_llm_calls: int | None = None
    max_seconds: float | None = None
    max_fixes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_steps": self.max_steps,
            "max_findings": self.max_findings,
            "max_llm_calls": self.max_llm_calls,
            "max_seconds": self.max_seconds,
            "max_fixes": self.max_fixes,
        }


@dataclass
class HarnessStep:
    name: str
    status: str
    started_at: str
    input_summary: dict[str, Any] = field(default_factory=dict)
    output_summary: dict[str, Any] = field(default_factory=dict)
    ended_at: str | None = None
    duration_ms: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "input_summary": dict(self.input_summary),
            "output_summary": dict(self.output_summary),
            "error": self.error,
        }


@dataclass
class HarnessToolCall:
    name: str
    status: str
    started_at: str
    input_summary: dict[str, Any] = field(default_factory=dict)
    output_summary: dict[str, Any] = field(default_factory=dict)
    phase: str | None = None
    ended_at: str | None = None
    duration_ms: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "phase": self.phase,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "input_summary": dict(self.input_summary),
            "output_summary": dict(self.output_summary),
            "error": self.error,
        }


@dataclass(frozen=True)
class HarnessDecision:
    phase: str
    code: str
    target: dict[str, Any]
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "code": self.code,
            "target": dict(self.target),
            "details": dict(self.details),
            "timestamp": self.timestamp,
        }


@dataclass
class HarnessRun:
    run_id: str
    kind: str
    project_root: str
    budget: HarnessBudget = field(default_factory=HarnessBudget)
    status: str = "running"
    started_at: str = field(default_factory=utc_now_iso)
    ended_at: str | None = None
    duration_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    steps: list[HarnessStep] = field(default_factory=list)
    tool_calls: list[HarnessToolCall] = field(default_factory=list)
    decisions: list[HarnessDecision] = field(default_factory=list)
    usage: dict[str, int | float] = field(default_factory=dict)
    trace_path: str | None = None
    state_path: str | None = None
    summary_path: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "kind": self.kind,
            "project_root": self.project_root,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "metadata": dict(self.metadata),
            "budget": self.budget.to_dict(),
            "budget_used": self.budget_used(),
            "budget_remaining": self.budget_remaining(),
            "steps": [step.to_dict() for step in self.steps],
            "current_phase": self.current_phase(),
            "completed_phases": self.completed_phases(),
            "failed_phase": self.failed_phase(),
            "tool_calls": [call.to_dict() for call in self.tool_calls],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "trace_path": self.trace_path,
            "state_path": self.state_path,
            "summary_path": self.summary_path,
            "error": self.error,
        }

    def state_dict(self) -> dict[str, Any]:
        return self.to_dict()

    def summary_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "kind": self.kind,
            "project_root": self.project_root,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "budget": self.budget.to_dict(),
            "budget_used": self.budget_used(),
            "budget_remaining": self.budget_remaining(),
            "phase_count": len(self.steps),
            "completed_phases": self.completed_phases(),
            "failed_phase": self.failed_phase(),
            "tool_call_count": len(self.tool_calls),
            "decision_count": len(self.decisions),
            "trace_path": self.trace_path,
            "state_path": self.state_path,
            "summary_path": self.summary_path,
            "error": self.error,
        }

    def current_phase(self) -> str | None:
        for step in reversed(self.steps):
            if step.status == "running":
                return step.name
        return None

    def completed_phases(self) -> list[str]:
        return [step.name for step in self.steps if step.status == "completed"]

    def failed_phase(self) -> str | None:
        for step in reversed(self.steps):
            if step.status == "failed":
                return step.name
        return None

    def budget_remaining(self) -> dict[str, int | float | None]:
        remaining: dict[str, int | float | None] = {}
        budget_map = {
            "steps": self.budget.max_steps,
            "findings": self.budget.max_findings,
            "llm_calls": self.budget.max_llm_calls,
            "seconds": self.budget.max_seconds,
            "fixes": self.budget.max_fixes,
        }
        used_map = self.budget_used()
        for key, max_value in budget_map.items():
            if max_value is None:
                remaining[key] = None
            else:
                remaining[key] = max_value - used_map[key]
        return remaining

    def budget_used(self) -> dict[str, int | float]:
        return {
            "steps": len(self.steps),
            "findings": self.usage.get("findings", 0),
            "llm_calls": self.usage.get("llm_calls", 0),
            "seconds": self.usage.get("seconds", 0),
            "fixes": self.usage.get("fixes", 0),
        }


@dataclass(frozen=True)
class HarnessResult:
    output: Any
    run: HarnessRun

    def to_dict(self) -> dict[str, Any]:
        return {
            "output": self.output,
            "run": self.run.to_dict(),
        }


def resolved_project_root(path: str | Path) -> Path:
    resolved = Path(path).resolve()
    return resolved.parent if resolved.is_file() else resolved
