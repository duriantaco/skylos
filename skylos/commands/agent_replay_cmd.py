from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from skylos.llm.harness.replay import HarnessReplay, load_harness_replay

ReplayPayload = dict[str, Any]

SUMMARY_FIELDS: tuple[tuple[str, str], ...] = (
    ("Run", "run_id"),
    ("Kind", "kind"),
    ("Status", "status"),
    ("Project", "project_root"),
    ("Events", "event_count"),
    ("Phases", "phase_count"),
    ("Tool calls", "tool_call_count"),
    ("Decisions", "decision_count"),
    ("Duration", "duration_ms"),
)


def add_agent_replay_parser(agent_sub) -> None:
    parser = agent_sub.add_parser(
        "replay",
        help="Validate and inspect a saved agent harness run",
    )
    parser.add_argument(
        "run_dir",
        help="Path to a harness run directory, for example .skylos/runs/<run-id>",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Replay output format",
    )


def run_agent_replay_command(args, console: Console) -> int:
    replay = load_harness_replay(Path(args.run_dir))
    payload = harness_replay_payload(replay)
    _write_replay_output(console, payload, output_format=args.format)
    return 0 if payload["ok"] else 1


def harness_replay_payload(replay: HarnessReplay) -> ReplayPayload:
    state, summary = _replay_documents(replay)
    phases = _dict_list(state.get("steps"))
    tool_calls = _dict_list(state.get("tool_calls"))
    decisions = _dict_list(state.get("decisions"))

    return {
        "ok": replay.ok,
        "schema_version": _artifact_value(summary, state, "schema_version"),
        "run_dir": str(replay.run_dir),
        "run_id": _artifact_value(summary, state, "run_id"),
        "kind": _artifact_value(summary, state, "kind"),
        "status": _artifact_value(summary, state, "status"),
        "project_root": _artifact_value(summary, state, "project_root"),
        "started_at": _artifact_value(summary, state, "started_at"),
        "ended_at": _artifact_value(summary, state, "ended_at"),
        "duration_ms": _artifact_value(summary, state, "duration_ms"),
        "event_count": len(replay.events),
        "phase_count": _count_value(summary, "phase_count", phases),
        "tool_call_count": _count_value(summary, "tool_call_count", tool_calls),
        "decision_count": _count_value(summary, "decision_count", decisions),
        "completed_phases": _list_value(summary.get("completed_phases")),
        "failed_phase": summary.get("failed_phase"),
        "budget": _dict_value(_artifact_value(summary, state, "budget")),
        "budget_used": _dict_value(_artifact_value(summary, state, "budget_used")),
        "budget_remaining": _dict_value(
            _artifact_value(summary, state, "budget_remaining")
        ),
        "artifact_paths": _artifact_paths(replay, state, summary),
        "phases": phases,
        "tool_calls": tool_calls,
        "decisions": decisions,
        "issues": [issue.to_dict() for issue in replay.issues],
    }


def print_harness_replay(console: Console, payload: ReplayPayload) -> None:
    status = "[green]valid[/green]" if payload["ok"] else "[red]invalid[/red]"
    console.print(f"[bold]Harness replay:[/bold] {status}")
    _print_summary_table(console, payload)
    _print_issue_table(console, payload)
    _print_phase_table(console, payload)
    _print_tool_table(console, payload)
    _print_decision_table(console, payload)
    console.print(f"[dim]Run dir:[/dim] {payload['run_dir']}")


def _write_replay_output(
    console: Console,
    payload: ReplayPayload,
    *,
    output_format: str,
) -> None:
    if output_format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return
    print_harness_replay(console, payload)


def _print_summary_table(console: Console, payload: ReplayPayload) -> None:
    table = Table(expand=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for label, key in SUMMARY_FIELDS:
        table.add_row(label, _format_summary_value(key, payload.get(key)))
    console.print(table)


def _print_issue_table(console: Console, payload: ReplayPayload) -> None:
    if not payload.get("issues"):
        return
    table = Table(title="Replay Issues", expand=True)
    table.add_column("Code", style="red", no_wrap=True)
    table.add_column("Message", overflow="fold")
    for issue in payload["issues"]:
        table.add_row(str(issue.get("code", "")), str(issue.get("message", "")))
    console.print(table)


def _print_phase_table(console: Console, payload: ReplayPayload) -> None:
    if not payload.get("phases"):
        return
    table = Table(title="Phases", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Name")
    table.add_column("Status", width=10)
    table.add_column("Duration", width=10)
    table.add_column("Output", overflow="fold")
    for index, phase in enumerate(payload["phases"], 1):
        duration = phase.get("duration_ms")
        table.add_row(
            str(index),
            str(phase.get("name", "")),
            str(phase.get("status", "")),
            "" if duration is None else f"{duration}ms",
            _compact_json(phase.get("output_summary")),
        )
    console.print(table)


def _print_tool_table(console: Console, payload: ReplayPayload) -> None:
    if not payload.get("tool_calls"):
        return
    table = Table(title="Tool Calls", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Name")
    table.add_column("Phase")
    table.add_column("Status", width=10)
    table.add_column("Output", overflow="fold")
    for index, call in enumerate(payload["tool_calls"], 1):
        table.add_row(
            str(index),
            str(call.get("name", "")),
            str(call.get("phase") or ""),
            str(call.get("status", "")),
            _compact_json(call.get("output_summary")),
        )
    console.print(table)


def _print_decision_table(console: Console, payload: ReplayPayload) -> None:
    if not payload.get("decisions"):
        return
    table = Table(title="Decisions", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Phase")
    table.add_column("Code")
    table.add_column("Target", overflow="fold")
    for index, decision in enumerate(payload["decisions"], 1):
        table.add_row(
            str(index),
            str(decision.get("phase", "")),
            str(decision.get("code", "")),
            _compact_json(decision.get("target")),
        )
    console.print(table)


def _replay_documents(
    replay: HarnessReplay,
) -> tuple[dict[str, Any], dict[str, Any]]:
    state = replay.state if isinstance(replay.state, dict) else {}
    summary = replay.summary if isinstance(replay.summary, dict) else {}
    return state, summary


def _artifact_value(
    summary: dict[str, Any],
    state: dict[str, Any],
    key: str,
) -> Any:
    summary_value = summary.get(key)
    if _has_artifact_value(summary_value):
        return summary_value
    return state.get(key)


def _artifact_paths(
    replay: HarnessReplay,
    state: dict[str, Any],
    summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "events": str(replay.run_dir / "events.jsonl"),
        "state": _artifact_value(summary, state, "state_path"),
        "summary": _artifact_value(summary, state, "summary_path"),
        "trace": _artifact_value(summary, state, "trace_path"),
    }


def _count_value(
    payload: dict[str, Any],
    key: str,
    fallback_items: list[dict[str, Any]],
) -> int:
    value = payload.get(key)
    return value if isinstance(value, int) else len(fallback_items)


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _has_artifact_value(value: Any) -> bool:
    if value is None:
        return False
    if value == "":
        return False
    if value == []:
        return False
    if value == {}:
        return False
    return True


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _list_value(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _format_summary_value(key: str, value: Any) -> str:
    if value is None:
        return ""
    if key == "duration_ms":
        return f"{value}ms"
    return str(value)


def _compact_json(value: Any, *, limit: int = 120) -> str:
    if not value:
        return ""
    text = json.dumps(value, sort_keys=True, default=str)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."
