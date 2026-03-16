from __future__ import annotations

from skylos.defend.result import DefenseResult, DefenseScore, OpsScore

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 8,
    "high": 5,
    "medium": 3,
    "low": 1,
}


def _score_pct(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 100
    return round(numerator / denominator * 100)


def compute_defense_score(results: list[DefenseResult]) -> DefenseScore:
    defense_results: list[DefenseResult] = []
    for result in results:
        if result.category != "defense":
            continue
        defense_results.append(result)

    if not defense_results:
        return DefenseScore(
            weighted_score=0,
            weighted_max=0,
            score_pct=100,
            risk_rating="SECURE",
            passed=0,
            total=0,
        )

    weighted_max = 0
    weighted_score = 0
    passed = 0

    for result in defense_results:
        weighted_max += result.weight
        if not result.passed:
            continue
        weighted_score += result.weight
        passed += 1

    pct = _score_pct(weighted_score, weighted_max)

    if pct < 25:
        risk = "CRITICAL"
    elif pct < 50:
        risk = "HIGH"
    elif pct < 75:
        risk = "MEDIUM"
    elif pct < 90:
        risk = "LOW"
    else:
        risk = "SECURE"

    return DefenseScore(
        weighted_score=weighted_score,
        weighted_max=weighted_max,
        score_pct=pct,
        risk_rating=risk,
        passed=passed,
        total=len(defense_results),
    )


def compute_ops_score(results: list[DefenseResult]) -> OpsScore:
    ops_results: list[DefenseResult] = []
    for result in results:
        if result.category != "ops":
            continue
        ops_results.append(result)

    if not ops_results:
        return OpsScore(passed=0, total=0, score_pct=100, rating="EXCELLENT")

    passed = 0
    total = 0

    for result in ops_results:
        total += 1
        if result.passed:
            passed += 1

    pct = _score_pct(passed, total)

    if pct >= 80:
        rating = "EXCELLENT"
    elif pct >= 60:
        rating = "GOOD"
    elif pct >= 40:
        rating = "FAIR"
    else:
        rating = "POOR"

    return OpsScore(passed=passed, total=total, score_pct=pct, rating=rating)
