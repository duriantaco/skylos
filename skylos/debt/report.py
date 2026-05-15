from __future__ import annotations

import json

from skylos.debt.result import DebtSnapshot
from skylos.debt.scoring import DIMENSION_WEIGHTS, SEVERITY_WEIGHTS


def _ordered_hotspots(snapshot: DebtSnapshot, top: int | None) -> list:
    ordered = sorted(
        snapshot.hotspots,
        key=lambda hotspot: (
            -float(getattr(hotspot, "priority_score", hotspot.score)),
            -hotspot.score,
            hotspot.file,
        ),
    )
    return ordered[:top] if top else ordered


def _summary_lines(
    snapshot: DebtSnapshot,
    *,
    hotspot_scope: str,
    project_hotspot_count: int,
) -> list[str]:
    if hotspot_scope == "changed":
        return [
            (
                f"Scanned: {snapshot.files_scanned} files | "
                f"Total LOC: {snapshot.total_loc} | "
                f"Hotspots: {len(snapshot.hotspots)} shown ({project_hotspot_count} project total) | "
                f"Score: {snapshot.score.score_pct}% ({snapshot.score.risk_rating}, project scope)"
            ),
            "View: changed files only",
        ]

    return [
        (
            f"Scanned: {snapshot.files_scanned} files | "
            f"Total LOC: {snapshot.total_loc} | "
            f"Hotspots: {len(snapshot.hotspots)} | "
            f"Score: {snapshot.score.score_pct}% ({snapshot.score.risk_rating})"
        )
    ]


def _baseline_line(baseline: dict) -> str:
    return (
        "Baseline: "
        f"{baseline.get('new', 0)} new | "
        f"{baseline.get('worsened', 0)} worsened | "
        f"{baseline.get('improved', 0)} improved | "
        f"{baseline.get('unchanged', 0)} unchanged | "
        f"{baseline.get('resolved', 0)} resolved"
    )


def _empty_hotspot_line(hotspot_scope: str) -> str:
    if hotspot_scope == "changed":
        return "No debt hotspots found in changed files."
    return "No debt hotspots found."


def _hotspot_status(hotspot) -> str:
    status = hotspot.baseline_status
    if hotspot.score_delta:
        return f"{status} ({hotspot.score_delta:+.2f})"
    return status


def _score_breakdown_lines(snapshot: DebtSnapshot) -> list[str]:
    breakdown = (snapshot.summary or {}).get("score_breakdown") or {}
    dimensions = breakdown.get("dimensions") or []
    if not dimensions:
        return []

    lines = ["", "Score Breakdown:"]
    for item in dimensions[:5]:
        dimension = item.get("dimension") or "unknown"
        points = float(item.get("points") or 0.0)
        share_pct = float(item.get("share_pct") or 0.0)
        signal_count = int(item.get("signal_count") or 0)
        weight = float(item.get("weight") or DIMENSION_WEIGHTS.get(dimension, 1.0))
        lines.append(
            f"  {dimension}: {points:.2f} pts ({share_pct:.1f}%) from "
            f"{signal_count} signal(s), weight={weight:.2f}"
        )

    top_rules = breakdown.get("top_rules") or []
    if top_rules:
        rendered_rules = ", ".join(
            f"{rule.get('rule_id')} {float(rule.get('points') or 0.0):.2f} pts"
            for rule in top_rules[:5]
        )
        lines.append(f"  Top rules: {rendered_rules}")
    return lines


def _score_model_lines(snapshot: DebtSnapshot) -> list[str]:
    model = (snapshot.summary or {}).get("score_model") or {}
    breakdown = (snapshot.summary or {}).get("score_breakdown") or {}
    if not model and not breakdown:
        return []

    severity_bits = " ".join(
        f"{severity}={weight}" for severity, weight in SEVERITY_WEIGHTS.items()
    )
    dimension_bits = " ".join(
        f"{dimension}={weight:.2f}"
        for dimension, weight in DIMENSION_WEIGHTS.items()
    )
    lines = ["", "How Score Is Calculated:"]
    lines.append(
        "  score_pct = clamp(round(100 - "
        f"{snapshot.score.total_points:.2f}/{snapshot.score.normalizer:.2f}), 0, 100) "
        f"= {snapshot.score.score_pct}%"
    )
    lines.append(
        "  signal points = severity weight * dimension weight * magnitude; "
        "metrics above threshold can scale up to 3.0x"
    )
    lines.append(
        f"  weights: severity {severity_bits}; dimension {dimension_bits}"
    )
    lines.append(
        "  hotspot score = signal points + 2 pts for each extra debt dimension "
        "in the same file"
    )
    included_sources = model.get("included_sources") or []
    if included_sources:
        lines.append(f"  included sources: {', '.join(included_sources)}")
    if breakdown.get("breadth_bonus_points"):
        lines.append(
            "  breadth bonus total: "
            f"{float(breakdown.get('breadth_bonus_points') or 0.0):.2f} pts"
        )
    return lines


def _gate_lines(summary: dict) -> list[str]:
    gate = summary.get("gate") or {}
    if not gate:
        return []

    status = "passed" if gate.get("passed", True) else "failed"
    lines = ["", f"Gate: {status}"]
    min_score = gate.get("min_score")
    fail_on_status = gate.get("fail_on_status")
    if min_score is not None:
        lines.append(f"  min_score={min_score}")
    if fail_on_status:
        lines.append(f"  fail_on_status={fail_on_status}")
    for failure in gate.get("failures") or []:
        lines.append(f"  - {failure}")
    return lines


def _signal_location(signal) -> str:
    if signal.file and signal.line:
        return f"{signal.file}:{signal.line}"
    if signal.file:
        return signal.file
    return "-"


def _metric_detail(signal) -> str:
    parts = []
    if signal.metric_value is not None:
        parts.append(f"metric={signal.metric_value}")
    if signal.threshold is not None:
        parts.append(f"threshold={signal.threshold}")
    return " ".join(parts)


def _signal_detail(signal) -> str:
    detail = _metric_detail(signal)
    if detail:
        return f"{detail} points={signal.points:.2f}"
    return f"points={signal.points:.2f}"


def _signal_lines(hotspot) -> list[str]:
    return [
        (
            f"    - {signal.rule_id} | {str(signal.severity).upper()} | "
            f"{signal.dimension} | {_signal_location(signal)} | "
            f"{signal.message} ({_signal_detail(signal)})"
        )
        for signal in hotspot.signals[:3]
    ]


def _strongest_severity(hotspot) -> str:
    if not hotspot.signals:
        return "LOW"
    return max(
        (str(signal.severity).upper() for signal in hotspot.signals),
        key=lambda severity: SEVERITY_WEIGHTS.get(severity, 1),
    )


def _hotspot_explanation_line(hotspot) -> str:
    breadth_bonus = max(0, int(hotspot.dimension_count) - 1) * 2
    priority_bonus = round(
        float(getattr(hotspot, "priority_score", hotspot.score))
        - float(hotspot.score),
        2,
    )
    return (
        "    why: "
        f"primary={hotspot.primary_dimension}, "
        f"strongest={_strongest_severity(hotspot)}, "
        f"breadth_bonus={breadth_bonus:.2f}, "
        f"priority_bonus={priority_bonus:.2f}"
    )


def _advisory_lines(hotspot) -> list[str]:
    if not hotspot.advisory:
        return []

    lines = [f"    advisor: {hotspot.advisory.summary}"]
    lines.extend(f"      step: {step}" for step in hotspot.advisory.refactor_steps[:2])
    return lines


def _hotspot_lines(index: int, hotspot) -> list[str]:
    dimensions = ", ".join(sorted({signal.dimension for signal in hotspot.signals}))
    lines = [
        (
            f"{index:>2}. {hotspot.file} | score={hotspot.score:.2f} | "
            f"priority={hotspot.priority_score:.2f} | "
            f"signals={hotspot.signal_count} | dimensions={dimensions} | "
            f"{_hotspot_status(hotspot)}"
        )
    ]
    lines.append(_hotspot_explanation_line(hotspot))
    lines.extend(_signal_lines(hotspot))
    lines.extend(_advisory_lines(hotspot))
    return lines


def format_debt_table(snapshot: DebtSnapshot, *, top: int | None = None) -> str:
    summary = snapshot.summary or {}
    baseline = summary.get("baseline") or {}
    scope = summary.get("scope") or {}
    hotspot_scope = scope.get("hotspots", "project")
    project_hotspot_count = int(
        summary.get("project_hotspot_count") or len(snapshot.hotspots)
    )
    hotspots = _ordered_hotspots(snapshot, top)

    lines = ["", "Skylos Technical Debt Report"]
    lines.extend(
        _summary_lines(
            snapshot,
            hotspot_scope=hotspot_scope,
            project_hotspot_count=project_hotspot_count,
        )
    )
    if baseline:
        lines.append(_baseline_line(baseline))
    lines.extend(_gate_lines(summary))
    lines.extend(_score_breakdown_lines(snapshot))
    lines.extend(_score_model_lines(snapshot))

    if not hotspots:
        lines.append("")
        lines.append(_empty_hotspot_line(hotspot_scope))
        return "\n".join(lines)

    lines.append("")
    lines.append("Top Hotspots:")
    for index, hotspot in enumerate(hotspots, 1):
        lines.extend(_hotspot_lines(index, hotspot))
    return "\n".join(lines)


def format_debt_json(snapshot: DebtSnapshot) -> str:
    return json.dumps(snapshot.to_dict(), indent=2)


def _history_score_pct(entry: dict) -> int | None:
    score_pct = (entry.get("score") or {}).get("score_pct")
    if score_pct is None or isinstance(score_pct, bool):
        return None
    try:
        return int(score_pct)
    except (TypeError, ValueError):
        return None


def _history_value(score: dict, key: str) -> str:
    value = score.get(key)
    return "-" if value is None else str(value)


def _history_row(entry: dict, previous_score: int | None) -> tuple[str, int | None]:
    score = entry.get("score") or {}
    score_pct = _history_score_pct(entry)
    score_text = "-" if score_pct is None else f"{score_pct}%"
    delta_text = (
        "-"
        if score_pct is None or previous_score is None
        else f"{score_pct - previous_score:+d}"
    )
    line = (
        f"{str(entry.get('timestamp') or '-'):<32} "
        f"{score_text:>6} "
        f"{delta_text:>6} "
        f"{_history_value(score, 'risk_rating'):<10} "
        f"{_history_value(score, 'hotspot_count'):>8} "
        f"{_history_value(score, 'signal_count'):>8}"
    )
    return line, score_pct


def _history_hotspots(entry: dict) -> list[dict]:
    hotspots = entry.get("hotspots") or []
    if not isinstance(hotspots, list):
        return []
    return [hotspot for hotspot in hotspots if isinstance(hotspot, dict)]


def _history_hotspot_value(hotspot: dict, key: str) -> str:
    value = hotspot.get(key)
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def _history_hotspot_line(index: int, hotspot: dict) -> str:
    return (
        f"  {index}. {_history_hotspot_value(hotspot, 'file')} | "
        f"score={_history_hotspot_value(hotspot, 'score')} | "
        f"signals={_history_hotspot_value(hotspot, 'signal_count')} | "
        f"{_history_hotspot_value(hotspot, 'primary_dimension')}"
    )


def _latest_hotspot_lines(entry: dict) -> list[str]:
    hotspots = _history_hotspots(entry)
    lines = ["", "Latest Top Hotspots:"]
    if not hotspots:
        lines.append("  Not recorded in saved history.")
        return lines
    lines.extend(
        _history_hotspot_line(index, hotspot)
        for index, hotspot in enumerate(hotspots, 1)
    )
    return lines


def format_debt_history_table(
    entries: list[dict],
    *,
    limit: int | None = None,
) -> str:
    if not entries:
        return "\nSkylos Debt History\nNo debt history found."

    visible = entries[-limit:] if limit else entries
    lines = [
        "",
        "Skylos Debt History",
        f"Entries: {len(visible)} shown ({len(entries)} total)",
        "",
        "Timestamp                         Score  Delta Risk       Hotspots  Signals",
    ]
    first_visible_index = len(entries) - len(visible)
    previous_score = (
        _history_score_pct(entries[first_visible_index - 1])
        if first_visible_index > 0
        else None
    )
    for entry in visible:
        line, score_pct = _history_row(entry, previous_score)
        lines.append(line)
        if score_pct is not None:
            previous_score = score_pct
    lines.extend(_latest_hotspot_lines(visible[-1]))
    return "\n".join(lines)


def format_debt_history_json(entries: list[dict]) -> str:
    return json.dumps({"history": entries}, indent=2)
