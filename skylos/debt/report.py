from __future__ import annotations

import json

from skylos.debt.result import DebtSnapshot


def format_debt_table(snapshot: DebtSnapshot, *, top: int | None = None) -> str:
    summary = snapshot.summary or {}
    baseline = summary.get("baseline") or {}
    scope = summary.get("scope") or {}
    hotspot_scope = scope.get("hotspots", "project")
    project_hotspot_count = int(summary.get("project_hotspot_count") or len(snapshot.hotspots))
    ordered = sorted(
        snapshot.hotspots,
        key=lambda hotspot: (
            -float(getattr(hotspot, "priority_score", hotspot.score)),
            -hotspot.score,
            hotspot.file,
        ),
    )
    hotspots = ordered[:top] if top else ordered

    lines = []
    lines.append("")
    lines.append("Skylos Technical Debt Report")
    if hotspot_scope == "changed":
        lines.append(
            f"Scanned: {snapshot.files_scanned} files | "
            f"Total LOC: {snapshot.total_loc} | "
            f"Hotspots: {len(snapshot.hotspots)} shown ({project_hotspot_count} project total) | "
            f"Score: {snapshot.score.score_pct}% ({snapshot.score.risk_rating}, project scope)"
        )
        lines.append("View: changed files only")
    else:
        lines.append(
            f"Scanned: {snapshot.files_scanned} files | "
            f"Total LOC: {snapshot.total_loc} | "
            f"Hotspots: {len(snapshot.hotspots)} | "
            f"Score: {snapshot.score.score_pct}% ({snapshot.score.risk_rating})"
        )
    if baseline:
        lines.append(
            "Baseline: "
            f"{baseline.get('new', 0)} new | "
            f"{baseline.get('worsened', 0)} worsened | "
            f"{baseline.get('improved', 0)} improved | "
            f"{baseline.get('unchanged', 0)} unchanged | "
            f"{baseline.get('resolved', 0)} resolved"
        )

    if not hotspots:
        lines.append("")
        if hotspot_scope == "changed":
            lines.append("No debt hotspots found in changed files.")
        else:
            lines.append("No debt hotspots found.")
        return "\n".join(lines)

    lines.append("")
    lines.append("Top Hotspots:")
    for index, hotspot in enumerate(hotspots, 1):
        dimensions = ", ".join(
            sorted({signal.dimension for signal in hotspot.signals})
        )
        status = hotspot.baseline_status
        if hotspot.score_delta:
            status = f"{status} ({hotspot.score_delta:+.2f})"

        lines.append(
            f"{index:>2}. {hotspot.file} | score={hotspot.score:.2f} | "
            f"priority={hotspot.priority_score:.2f} | "
            f"signals={hotspot.signal_count} | dimensions={dimensions} | {status}"
        )
        for signal in hotspot.signals[:3]:
            lines.append(
                f"    - [{signal.rule_id}] {signal.message} "
                f"(points={signal.points:.2f})"
            )
        if hotspot.advisory:
            lines.append(f"    advisor: {hotspot.advisory.summary}")
            for step in hotspot.advisory.refactor_steps[:2]:
                lines.append(f"      step: {step}")
    return "\n".join(lines)


def format_debt_json(snapshot: DebtSnapshot) -> str:
    return json.dumps(snapshot.to_dict(), indent=2)
