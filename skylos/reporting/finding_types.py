"""Finding purpose is independent of severity and of presentation grouping.

Defect checks detect concrete correctness patterns; Review checks require
context to decide what to change; Advice describes maintainability or policy.
None of these labels certifies a finding as a proven production incident.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping

from skylos.reporting.rollups import FINDING_SECTIONS
from skylos.rules.catalog import get_rule_finding_type, get_rule_name

FINDING_TYPES = ("defect", "review", "advice")
# When a complete record is mirrored in several buckets, retain the security
# bucket first so assessment cannot lose the security or secret category.
_PRIORITY_SECTIONS = ("danger", "secrets", "dependency_vulnerabilities")
_CANONICAL_SECTIONS = tuple(
    sorted(
        FINDING_SECTIONS,
        key=lambda pair: (
            _PRIORITY_SECTIONS.index(pair[0])
            if pair[0] in _PRIORITY_SECTIONS
            else len(_PRIORITY_SECTIONS)
        ),
    )
)


def get_finding_type(finding, category=None) -> str:
    """Use the built-in rule classification; custom or unknown checks are Review.

    A caller-supplied ``finding_type`` cannot downgrade a built-in risk check.
    Raw dead-code records without a catalog ID also require review.
    """
    if isinstance(finding, Mapping):
        if str(finding.get("category") or "").lower() in {"custom", "custom_rules"}:
            return "review"
        source = str(finding.get("source") or "").lower()
        if source == "custom" or finding.get("custom_rule") is True:
            return "review"
        rule_id = finding.get("rule_id") or finding.get("id")
    else:
        rule_id = finding if isinstance(finding, str) else None
    if str(category or "").lower() in {"custom", "custom_rules"}:
        return "review"
    return get_rule_finding_type(rule_id)


def _dict_rows(rows) -> Iterator[dict]:
    if not isinstance(rows, (list, tuple)):
        return
    for finding in rows:
        if isinstance(finding, dict):
            yield finding


def _architecture_signals(metrics) -> Iterator[dict]:
    if not isinstance(metrics, Mapping):
        return
    advisories = metrics.get("advisories")
    if not isinstance(advisories, (list, tuple)):
        return
    for advisory in advisories:
        if isinstance(advisory, Mapping):
            yield from _dict_rows(advisory.get("signals"))


def _all_result_findings(result) -> Iterator[tuple[str, dict, str]]:
    if not isinstance(result, Mapping):
        return
    sections = (
        *_CANONICAL_SECTIONS,
        ("circular_dependencies", "quality"),
        ("publisher_change_findings", "ai_defects"),
        ("code_health", "quality"),
    )
    for section, category in sections:
        for finding in _dict_rows(result.get(section)):
            yield (
                "custom_rules" if section == "custom_rules" else category,
                finding,
                section,
            )
    for finding in _architecture_signals(result.get("architecture_metrics")):
        yield "quality", finding, "architecture_advisories"


def _first_value(finding, fields):
    return next((finding[field] for field in fields if finding.get(field)), "")


def _finding_key(category, finding) -> tuple:
    rule_id = str(_first_value(finding, ("rule_id", "id"))).upper()
    return (
        (category, rule_id) if category == "custom_rules" else rule_id or category,
        str(_first_value(finding, ("file", "file_path"))),
        str(_first_value(finding, ("line",))),
        str(_first_value(finding, ("col", "column"))),
        str(_first_value(finding, ("full_name", "symbol", "name"))),
        str(_first_value(finding, ("message",))),
        str(_first_value(finding, ("metric",))),
        repr(finding.get("value")),
    )


def iter_result_findings(result) -> Iterator[tuple[str, dict]]:
    """Yield canonical findings once, excluding raw symbols and report mirrors.

    The evidence ledger, suppressed/whitelisted entries, directory rollups,
    and parse-error notes are not additional findings. Every row within a
    canonical array is preserved; only identical complete records mirrored
    across arrays are counted once. Evidence or severity variants stay separate.
    """
    seen = {}
    for category, finding, section in _all_result_findings(result):
        key = _finding_key(category, finding)
        representations = seen.setdefault(key, {})
        if any(
            prior is finding or prior == finding
            for other, rows in representations.items()
            if other != section
            for prior in rows
        ):
            continue
        representations.setdefault(section, []).append(finding)
        yield category, finding


def annotate_finding_types(result):
    """Add the classification to every canonical output record in place."""
    for category, finding, _section in _all_result_findings(result):
        finding["finding_type"] = get_finding_type(finding, category)
    return result


def group_advice(result) -> list[dict]:
    """Group advice by rule while retaining every original message and location."""
    grouped = {}
    for category, finding in iter_result_findings(result):
        if get_finding_type(finding, category) != "advice":
            continue
        rule_id = str(finding.get("rule_id") or finding.get("id") or "").upper()
        group = grouped.setdefault(
            rule_id,
            {
                "rule_id": rule_id,
                "count": 0,
                "files": set(),
                "name": get_rule_name(rule_id, "Maintainability advice"),
                "findings": [],
            },
        )
        group["count"] += 1
        file = finding.get("file") or finding.get("file_path")
        if file:
            group["files"].add(str(file))
        group["findings"].append(finding)
    for group in grouped.values():
        group["files"] = sorted(group["files"])
    return [grouped[key] for key in sorted(grouped)]


def summarize_finding_types(result) -> dict[str, int]:
    counts = dict.fromkeys(FINDING_TYPES, 0)
    advice_rules = set()
    for category, finding in iter_result_findings(result):
        finding_type = get_finding_type(finding, category)
        counts[finding_type] += 1
        if finding_type == "advice":
            advice_rules.add(
                str(finding.get("rule_id") or finding.get("id") or "").upper()
            )
    counts["advice_groups"] = len(advice_rules)
    return counts
