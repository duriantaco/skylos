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

    for integ in integrations:
        input_src = ", ".join(integ.input_sources) if integ.input_sources else "none"
        if len(input_src) > 18:
            input_src = input_src[:17] + "…"

        sinks = ", ".join(integ.output_sinks) if integ.output_sinks else "none"
        if len(sinks) > 20:
            sinks = sinks[:19] + "…"

        location = integ.location
        if len(location) > 23:
            location = "…" + location[-22:]

        lines.append(
            f"  {integ.provider:<14} {integ.integration_type:<12} {location:<25} "
            f"{input_src:<20} {len(integ.tools):<6} {sinks}"
        )

    lines.append("")
    lines.append("Run 'skylos defend .' to check defenses.")
    return "\n".join(lines)


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
