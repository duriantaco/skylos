"""Harness registration and bounded repository-tool execution."""

from __future__ import annotations

from typing import Any

from skylos.audit.investigator_tools import (
    AuditReadOnlyTools,
    AuditToolBudgetExceeded,
    AuditToolError,
)
from skylos.llm.harness import HarnessBudget, HarnessRunner, HarnessToolRegistry

from .models import (
    INVESTIGATOR_PROTOCOL_VERSION,
    InvestigationIncompleteError,
    InvestigationLimits,
)
from .protocol import INVESTIGATOR_DEFINITION_HASH


def new_runner(
    *,
    tools: AuditReadOnlyTools,
    run_id: str,
    limits: InvestigationLimits,
    persist_trace: bool,
) -> HarnessRunner:
    registry = HarnessToolRegistry()
    for name in AuditReadOnlyTools.TOOL_NAMES:
        registry.register(
            name,
            category="read_only_repository",
            description="Bounded investigator source retrieval",
        )
    kwargs = {
        "kind": "deep_logic_investigation",
        "project_root": tools.project_root,
        "run_id": run_id,
        "budget": HarnessBudget(
            max_steps=limits.max_turns,
            max_findings=limits.max_findings,
            max_llm_calls=limits.max_model_calls,
            max_seconds=limits.max_seconds,
        ),
        "metadata": {
            "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
            "definition_hash": INVESTIGATOR_DEFINITION_HASH,
            "tool_schema_version": tools.metadata()["tool_schema_version"],
        },
        "tool_registry": registry,
    }
    if persist_trace:
        return HarnessRunner.with_default_trace_root(**kwargs)
    return HarnessRunner(**kwargs)


def execute_tool(
    *,
    runner: HarnessRunner,
    tools: AuditReadOnlyTools,
    action: dict[str, Any],
) -> dict[str, Any]:
    tool = action["tool"]
    arguments = _non_null_arguments(action["arguments"])
    try:
        observation = runner.run_tool(
            tool,
            lambda: tools.execute(tool, arguments),
            input_summary=_tool_input_summary(arguments),
            output_summary=lambda result: _tool_output_summary(result.summary),
        )
    except AuditToolBudgetExceeded:
        raise InvestigationIncompleteError(
            "investigator repository-tool budget exhausted"
        ) from None
    except AuditToolError:
        return {
            "ok": False,
            "kind": "tool_denial",
            "tool": tool,
            "error_code": "REPOSITORY_TOOL_DENIED",
            "untrusted_repository_data": True,
        }
    return {
        "ok": True,
        "untrusted_repository_data": True,
        **observation.to_prompt_dict(),
    }


def safe_tool_failure_reason(exc: AuditToolError) -> str:
    """Map internal tool failures to fixed, source-free public reasons."""

    detail = exc.args[0] if exc.args and isinstance(exc.args[0], str) else ""
    if isinstance(exc, AuditToolBudgetExceeded) and "catalog budget" in detail:
        return "repository catalog budget was truncated"
    if "not inspected" in detail or "not exposed" in detail:
        return "finding evidence was not inspected by the investigator"
    if isinstance(exc, AuditToolBudgetExceeded):
        return "investigator repository-tool budget exhausted"
    return "investigator repository-tool request failed"


def _non_null_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in arguments.items() if value is not None}


def _tool_input_summary(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": arguments.get("path"),
        "path_prefix": arguments.get("path_prefix"),
        "start_line": arguments.get("start_line"),
        "end_line": arguments.get("end_line"),
        "query_length": len(str(arguments.get("query") or "")),
        "name_filter_length": len(str(arguments.get("name_contains") or "")),
    }


def _tool_output_summary(summary: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "path",
        "start_line",
        "end_line",
        "file_lines",
        "matches",
        "matched_files",
        "truncated",
    }
    return {key: value for key, value in summary.items() if key in allowed}
