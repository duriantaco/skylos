from __future__ import annotations

from html import escape
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import quote


GRADE_TABLE: list[tuple[str, int, int]] = [
    ("A+", 97, 100),
    ("A", 93, 96),
    ("A-", 90, 92),
    ("B+", 87, 89),
    ("B", 83, 86),
    ("B-", 80, 82),
    ("C+", 77, 79),
    ("C", 73, 76),
    ("C-", 70, 72),
    ("D+", 67, 69),
    ("D", 63, 66),
    ("D-", 60, 62),
    ("F", 0, 59),
]

CATEGORY_WEIGHTS: dict[str, float] = {
    "security": 0.35,
    "quality": 0.25,
    "dead_code": 0.20,
    "dependencies": 0.10,
    "secrets": 0.10,
}
CATEGORY_ORDER: tuple[str, ...] = tuple(CATEGORY_WEIGHTS)

SEVERITY_CAPS: dict[str, int] = {
    "CRITICAL": 55,
    "HIGH": 79,
    "MEDIUM": 100,
    "LOW": 100,
}

SEVERITY_PENALTIES: dict[str, int] = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 1,
}

DEAD_CODE_DENSITY_TABLE: list[tuple[float, int]] = [
    (0, 100),
    (5, 85),
    (15, 55),
    (30, 20),
    (50, 0),
]

HARD_CAP_CRITICAL_SECURITY_OVERALL = 79
HARD_CAP_SECRETS_SUBGRADE = 69

_COMMENT_PREFIXES: dict[str, str] = {
    ".py": "#",
    ".ts": "//",
    ".tsx": "//",
    ".go": "//",
    ".js": "//",
    ".jsx": "//",
    ".php": "//",
    ".rs": "//",
    ".dart": "//",
}


def score_to_letter(score: int) -> str:
    score = max(0, min(100, score))
    for letter, low, high in GRADE_TABLE:
        if low <= score <= high:
            return letter
    return "F"


def count_lines_of_code(files: list[Path] | list[str]) -> int:
    total = 0
    for f in files:
        p = Path(f)
        prefix = _COMMENT_PREFIXES.get(p.suffix)
        try:
            text = p.read_text(errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if (
                prefix
                and stripped.startswith(prefix)
                and not stripped.startswith(prefix * 2 + "!")
            ):
                continue
            total += 1
    return total


def _score_severity_based(
    findings: list[dict],
    normalize_per_1k: bool = False,
    total_loc: int = 0,
) -> tuple[int, str]:
    if not findings:
        return 100, "No issues found"

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    worst: str | None = None
    worst_message = ""
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    for f in findings:
        sev = (f.get("severity") or "LOW").upper()
        if sev not in counts:
            sev = "LOW"
        counts[sev] += 1
        if worst is None or severity_order.index(sev) < severity_order.index(worst):
            worst = sev
            worst_message = f.get("message") or f.get("name") or sev

    score = min(100, SEVERITY_CAPS.get(worst or "LOW", 100))

    scale = 1.0
    if normalize_per_1k and total_loc > 0:
        scale = 1000.0 / total_loc

    for sev in severity_order:
        penalty = SEVERITY_PENALTIES.get(sev, 0) * counts[sev] * scale
        score -= penalty

    score = max(0, min(100, round(score)))

    key_issue = worst_message
    if worst and counts[worst] > 1:
        key_issue = f"{worst}: {worst_message} ({counts[worst]} hits)"

    return score, key_issue


def score_security(findings: list[dict]) -> tuple[int, str]:
    return _score_severity_based(findings, normalize_per_1k=False)


def score_quality(findings: list[dict], total_loc: int) -> tuple[int, str]:
    return _score_severity_based(findings, normalize_per_1k=True, total_loc=total_loc)


def _interpolate_dead_code_score(density: float) -> int:
    if density <= 0:
        return 100
    table = DEAD_CODE_DENSITY_TABLE
    if density >= table[-1][0]:
        return table[-1][1]
    for i in range(len(table) - 1):
        d0, s0 = table[i]
        d1, s1 = table[i + 1]
        if d0 <= density <= d1:
            t = (density - d0) / (d1 - d0)
            return round(s0 + t * (s1 - s0))
    return 0


def score_dead_code(result: dict, total_loc: int) -> tuple[int, str]:
    dead_lists = [
        result.get("unused_functions") or [],
        result.get("unused_imports") or [],
        result.get("unused_classes") or [],
        result.get("unused_variables") or [],
        result.get("unused_parameters") or [],
    ]
    dead_count = sum(len(lst) for lst in dead_lists)

    if dead_count == 0:
        return 100, "No dead code found"

    if total_loc > 0:
        density = dead_count / (total_loc / 1000.0)
    else:
        density = float(dead_count)

    score = _interpolate_dead_code_score(density)

    key_issue = f"{dead_count} dead symbols ({density:.1f}/1K LOC)"
    return score, key_issue


def score_dependencies(findings: list[dict]) -> tuple[int, str]:
    return _score_severity_based(findings, normalize_per_1k=False)


def score_secrets(findings: list[dict]) -> tuple[int, str]:
    if not findings:
        return 100, "No secrets found"

    score = HARD_CAP_SECRETS_SUBGRADE
    extra = len(findings) - 1
    score -= extra * 20
    score = max(0, score)

    key_issue = findings[0].get("message") or "Secret detected"
    if len(findings) > 1:
        key_issue = f"{len(findings)} secrets detected"

    return score, key_issue


def _included_categories(categories: Iterable[str] | None) -> list[str]:
    if categories is None:
        return list(CATEGORY_ORDER)

    included: list[str] = []
    for category in categories:
        if category in CATEGORY_WEIGHTS and category not in included:
            included.append(category)

    return included or list(CATEGORY_ORDER)


def _renormalized_weights(categories: list[str]) -> dict[str, float]:
    total = sum(CATEGORY_WEIGHTS[category] for category in categories)
    if total <= 0:
        even_weight = 1.0 / len(categories)
        return {category: even_weight for category in categories}
    return {category: CATEGORY_WEIGHTS[category] / total for category in categories}


def compute_grade(
    result: dict,
    total_loc: int,
    *,
    included_categories: Iterable[str] | None = None,
) -> dict:
    active_categories = _included_categories(included_categories)
    active_weights = _renormalized_weights(active_categories)

    sec_score, sec_issue = score_security(result.get("danger") or [])
    qual_score, qual_issue = score_quality(result.get("quality") or [], total_loc)
    dc_score, dc_issue = score_dead_code(result, total_loc)
    dep_score, dep_issue = score_dependencies(
        result.get("dependency_vulnerabilities") or []
    )
    secrets_score, secrets_issue = score_secrets(result.get("secrets") or [])

    category_scores = {
        "security": (sec_score, sec_issue),
        "quality": (qual_score, qual_issue),
        "dead_code": (dc_score, dc_issue),
        "dependencies": (dep_score, dep_issue),
        "secrets": (secrets_score, secrets_issue),
    }

    overall_numeric = round(
        sum(
            category_scores[category][0] * active_weights[category]
            for category in active_categories
        )
    )

    has_critical_security = "security" in active_categories and any(
        (f.get("severity") or "").upper() == "CRITICAL"
        for f in (result.get("danger") or [])
    )
    if has_critical_security:
        overall_numeric = min(overall_numeric, HARD_CAP_CRITICAL_SECURITY_OVERALL)

    overall_numeric = max(0, min(100, overall_numeric))

    categories = {}
    for cat_name in active_categories:
        score_val, issue = category_scores[cat_name]
        categories[cat_name] = {
            "score": score_val,
            "letter": score_to_letter(score_val),
            "weight": active_weights[cat_name],
            "base_weight": CATEGORY_WEIGHTS[cat_name],
            "key_issue": issue,
        }

    return {
        "overall": {
            "score": overall_numeric,
            "letter": score_to_letter(overall_numeric),
        },
        "categories": categories,
        "scanned_categories": active_categories,
        "total_loc": total_loc,
    }


_BADGE_COLORS: dict[str, str] = {
    "A+": "brightgreen",
    "A": "brightgreen",
    "A-": "brightgreen",
    "B+": "green",
    "B": "green",
    "B-": "green",
    "C+": "yellow",
    "C": "yellow",
    "C-": "yellow",
    "D+": "orange",
    "D": "orange",
    "D-": "orange",
    "F": "red",
}

_BADGE_HEX: dict[str, str] = {
    "A+": "#4c1",
    "A": "#4c1",
    "A-": "#4c1",
    "B+": "#97CA00",
    "B": "#97CA00",
    "B-": "#97CA00",
    "C+": "#dfb317",
    "C": "#dfb317",
    "C-": "#dfb317",
    "D+": "#fe7d37",
    "D": "#fe7d37",
    "D-": "#fe7d37",
    "F": "#e05d44",
}


def generate_badge_url(grade_letter: str, score: int) -> str:
    color = _BADGE_COLORS.get(grade_letter, "lightgrey")
    label = f"{grade_letter} ({score})"
    return f"https://img.shields.io/badge/Skylos-{quote(label)}-{color}"


def generate_badge_svg(grade_letter: str, score: int) -> str:
    color = _BADGE_HEX.get(grade_letter, "#9f9f9f")
    label = escape(f"{grade_letter} ({score})", quote=True)
    return (  # skylos: ignore[SKY-D228] label is HTML-escaped and color is a constant
        f'<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">'
        f'<rect width="60" height="20" fill="#555"/>'
        f'<rect x="60" width="60" height="20" fill="{color}"/>'
        f'<text x="30" y="14" fill="#fff" text-anchor="middle" '
        f'font-size="11" font-family="sans-serif">Skylos</text>'
        f'<text x="90" y="14" fill="#fff" text-anchor="middle" '
        f'font-size="11" font-family="sans-serif">{label}</text>'
        f"</svg>"
    )
