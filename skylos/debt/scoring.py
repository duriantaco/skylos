from __future__ import annotations

from collections import defaultdict

from skylos.debt.result import DebtHotspot, DebtScore, DebtSignal

SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 20,
    "HIGH": 12,
    "MEDIUM": 7,
    "WARN": 5,
    "LOW": 3,
    "INFO": 1,
}

DIMENSION_WEIGHTS: dict[str, float] = {
    "architecture": 1.25,
    "modularity": 1.15,
    "complexity": 1.0,
    "maintainability": 0.9,
    "dead_code": 0.65,
}


def _coerce_number(value) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def compute_signal_points(signal: DebtSignal) -> float:
    base = SEVERITY_WEIGHTS.get(str(signal.severity).upper(), 1)
    dimension_weight = DIMENSION_WEIGHTS.get(signal.dimension, 1.0)
    magnitude = 1.0

    metric_value = _coerce_number(signal.metric_value)
    threshold = _coerce_number(signal.threshold)

    if (
        metric_value is not None
        and threshold is not None
        and threshold > 0
        and metric_value > threshold
    ):
        excess_ratio = (metric_value - threshold) / threshold
        magnitude += min(excess_ratio, 2.0)

    return round(base * dimension_weight * magnitude, 2)


def build_hotspots(
    signals: list[DebtSignal],
    *,
    changed_files: set[str] | None = None,
) -> list[DebtHotspot]:
    by_file: dict[str, list[DebtSignal]] = defaultdict(list)
    changed = changed_files or set()

    for signal in signals:
        signal.points = signal.points or compute_signal_points(signal)
        key = signal.file or signal.subject or "<unknown>"
        by_file[key].append(signal)

    hotspots: list[DebtHotspot] = []
    for file_path, file_signals in by_file.items():
        dim_points: dict[str, float] = defaultdict(float)
        for signal in file_signals:
            dim_points[signal.dimension] += signal.points

        base_score = sum(signal.points for signal in file_signals)
        breadth_bonus = max(0, len(dim_points) - 1) * 2
        is_changed = file_path in changed
        if is_changed:
            base_score *= 1.15

        primary_dimension = max(
            dim_points.items(),
            key=lambda item: (item[1], item[0]),
        )[0]
        score = round(base_score + breadth_bonus, 2)

        hotspots.append(
            DebtHotspot(
                fingerprint=f"hotspot:{file_path}",
                file=file_path,
                score=score,
                signal_count=len(file_signals),
                dimension_count=len(dim_points),
                primary_dimension=primary_dimension,
                changed=is_changed,
                signals=sorted(
                    file_signals,
                    key=lambda signal: (-signal.points, signal.line, signal.rule_id),
                ),
            )
        )

    hotspots.sort(
        key=lambda hotspot: (
            not hotspot.changed,
            -hotspot.score,
            -hotspot.signal_count,
            hotspot.file,
        )
    )
    return hotspots


def compute_debt_score(
    hotspots: list[DebtHotspot],
    *,
    total_loc: int = 0,
) -> DebtScore:
    signal_count = sum(hotspot.signal_count for hotspot in hotspots)
    if not hotspots:
        return DebtScore(
            total_points=0.0,
            normalizer=1.0,
            score_pct=100,
            risk_rating="LOW",
            hotspot_count=0,
            signal_count=0,
        )

    total_points = round(sum(hotspot.score for hotspot in hotspots), 2)
    normalizer = max(1.0, (total_loc / 250.0)) if total_loc > 0 else max(
        1.0, float(len(hotspots))
    )
    penalty = total_points / normalizer
    score_pct = max(0, min(100, round(100 - penalty)))

    if score_pct >= 90:
        risk_rating = "LOW"
    elif score_pct >= 75:
        risk_rating = "MODERATE"
    elif score_pct >= 50:
        risk_rating = "HIGH"
    else:
        risk_rating = "CRITICAL"

    return DebtScore(
        total_points=total_points,
        normalizer=round(normalizer, 2),
        score_pct=score_pct,
        risk_rating=risk_rating,
        hotspot_count=len(hotspots),
        signal_count=signal_count,
    )
