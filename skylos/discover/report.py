from __future__ import annotations

import json
from datetime import datetime, timezone

from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


def format_table(
    integrations: list[LLMIntegration],
    files_scanned: int = 0,
    project_path: str = ".",  ## its not unused
) -> str:
    if not integrations:
        return f"No LLM integrations found in {files_scanned} files."

    lines = []
    lines.append(
        f"\nFound {len(integrations)} LLM integration(s) in {files_scanned} files:\n"
    )
    lines.append(
        f"  {'Provider':<14} {'Type':<12} {'Location':<25} {'Input Sources':<20} "
        f"{'Tools':<6} {'Dangerous Sinks'}"
    )
    lines.append(f"  {'─' * 14} {'─' * 12} {'─' * 25} {'─' * 20} {'─' * 6} {'─' * 20}")

    details: list[str] = []
    for integ in integrations:
        inputs = _input_labels(integ)
        input_src = ", ".join(inputs) or "none"
        if len(input_src) > 18:
            input_src = input_src[:17] + "…"

        sink_labels = _sink_labels(integ)
        sinks = ", ".join(sink_labels) or "none"
        if len(sinks) > 20:
            sinks = sinks[:19] + "…"

        location = integ.location
        if len(location) > 23:
            location = "…" + location[-22:]

        lines.append(
            f"  {integ.provider:<14} {integ.integration_type:<12} {location:<25} "
            f"{input_src:<20} {len(integ.tools):<6} {sinks}"
        )
        details.extend(_detail_lines(integ, inputs, sink_labels))

    if details:
        lines.append("")
        lines.extend(details)

    lines.append("")
    lines.append("Run 'skylos defend .' to check defenses.")
    return "\n".join(lines)


def _input_labels(integ: LLMIntegration) -> list[str]:
    labels = list(integ.input_sources)
    labels.extend(item.label for item in integ.prompt_inputs)
    return labels


def _sink_labels(integ: LLMIntegration) -> list[str]:
    return list(integ.output_sinks) + list(integ.output_sink_flows)


def _tool_label(tool) -> str:
    label = f"{tool.name} ({tool.location})"
    if tool.kind == "schema" and not tool.handler_location:
        label += ", no handler called with model output"
    elif tool.handler_location and tool.handler_location != tool.location:
        label += f", handler {tool.handler_location}"
    if tool.dangerous_calls:
        label += f": {', '.join(tool.dangerous_calls)}"
    return label


def _detail_lines(
    integ: LLMIntegration, inputs: list[str], sinks: list[str]
) -> list[str]:
    if not (integ.prompt_inputs or integ.tools or integ.output_sink_flows):
        return []
    lines = [f"  {integ.location}"]
    for label in inputs:
        lines.append(f"    Input: {label}")
    for tool in integ.tools:
        lines.append(f"    Tool:  {_tool_label(tool)}")
    for label in sinks:
        lines.append(f"    Sink:  {label}")
    return lines


def format_json(
    integrations: list[LLMIntegration],
    graph: AIIntegrationGraph,
    files_scanned: int = 0,
    project_path: str = ".",
) -> str:
    data = {
        "version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project": project_path,
        "files_scanned": files_scanned,
        "integrations_found": len(integrations),
        "integrations": [i.to_dict() for i in integrations],
        "graph": graph.to_dict(),
    }
    return json.dumps(data, indent=2)
