from __future__ import annotations

import json

from skylos.debt.result import DebtSnapshot


def format_debt_table(snapshot: DebtSnapshot, *, top: int | None = None) -> str:
    hotspots = snapshot.hotspots[:top] if top else snapshot.hotspots
    summary = snapshot.summary or {}
    baseline = summary.get("baseline") or {}

    lines = []
    lines.append("")
    lines.append("Skylos Technical Debt Report")
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
