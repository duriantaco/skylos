"""The shared, lossless listing decision used by report consumers."""

from __future__ import annotations

from collections.abc import Mapping
import re

from skylos.reporting.finding_types import get_finding_type
from skylos.reporting.rollups import FINDING_SECTIONS

LISTING_VERSION = 1
COMBINED_REASON = "combined"
_RULE_ID = re.compile(r"SKY-[A-Z0-9]+\Z")


def normalize_rule_ids(value):
    if isinstance(value, str):
        value = re.split(r"[,\s]+", value)
    if isinstance(value, Mapping):
        value = [key for key, setting in value.items() if setting is not False]
    if not isinstance(value, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(
        item.strip().upper()
        for item in value
        if isinstance(item, str) and _RULE_ID.fullmatch(item.strip().upper())
    )


def explicit_rule_ids(config):
    """Rules explicitly named for enforcement, rather than default limits."""
    if not isinstance(config, Mapping):
        return frozenset()
    gate = config.get("gate")
    result = set(
        normalize_rule_ids(gate.get("rules")) if isinstance(gate, Mapping) else ()
    )
    result.update(normalize_rule_ids(config.get("select")))
    rules = config.get("rules")
    if isinstance(rules, Mapping):
        result.update(normalize_rule_ids(rules))
    elif isinstance(rules, (list, tuple)):
        for rule in rules:
            if isinstance(rule, Mapping) and rule.get("enabled") is not False:
                result.update(
                    normalize_rule_ids([rule.get("rule_id") or rule.get("id")])
                )
    return frozenset(result)


def listing_decision(finding):
    if not isinstance(finding, Mapping):
        return None
    mark = finding.get("listing")
    if (
        not isinstance(mark, Mapping)
        or type(mark.get("version")) is not int
        or mark["version"] != LISTING_VERSION
        or type(mark.get("listed")) is not bool
        or not isinstance(mark.get("reason"), str)
        or not mark["reason"]
    ):
        return None
    return mark


def is_combined(finding):
    """Listed as part of another issue at the same location (``listing.lead``)."""
    mark = listing_decision(finding)
    return mark is not None and not mark["listed"] and mark["reason"] == COMBINED_REASON


def is_listed(finding, category=None, *, explicit_rules=()):
    """Unknown metadata and risk/custom findings remain visible and enforceable."""
    if (
        not isinstance(finding, Mapping)
        or get_finding_type(finding, category) != "advice"
    ):
        return True
    rule = str(finding.get("rule_id") or finding.get("id") or "").upper()
    if rule in explicit_rules:
        return True
    mark = listing_decision(finding)
    return mark["listed"] if mark is not None else True


def map_listing_paths(mark, normalize_path):
    """Copy group references using the same path convention as their records."""
    mapped = dict(mark)
    lead = mark.get("lead")
    if not isinstance(lead, Mapping):
        return mapped
    lead_path = lead.get("file") or lead.get("file_path")
    if not isinstance(lead_path, str):
        return mapped
    normalized = normalize_path(lead_path)
    if normalized is None:
        mapped.pop("lead", None)
        return mapped
    mapped_lead = dict(lead)
    mapped_lead["file"] = normalized
    mapped_lead.pop("file_path", None)
    mapped["lead"] = mapped_lead
    return mapped


def map_finding_rows(result, transform):
    """Copy physical finding arrays, including mirrors; None filters one row."""
    view = dict(result)
    sections = {
        **dict(FINDING_SECTIONS),
        "circular_dependencies": "quality",
        "publisher_change_findings": "ai_defects",
        "code_health": "quality",
    }
    for section, category in sections.items():
        rows = result.get(section)
        if isinstance(rows, (list, tuple)):
            category = "custom_rules" if section == "custom_rules" else category
            view[section] = [
                new for row in rows if (new := transform(row, category)) is not None
            ]
    metrics = result.get("architecture_metrics")
    if isinstance(metrics, Mapping) and isinstance(
        metrics.get("advisories"), (list, tuple)
    ):
        groups = []
        for group in metrics["advisories"]:
            if not isinstance(group, Mapping) or not isinstance(
                group.get("signals"), (list, tuple)
            ):
                groups.append(group)
                continue
            signals = [
                new
                for row in group["signals"]
                if (new := transform(row, "quality")) is not None
            ]
            if signals:
                groups.append(
                    {
                        **group,
                        "signals": signals,
                        "rule_ids": [
                            row.get("rule_id")
                            for row in signals
                            if isinstance(row, Mapping)
                        ],
                    }
                )
        view["architecture_metrics"] = {
            **metrics,
            "advisories": groups,
            "advisory_count": len(groups),
            "advisory_signal_count": sum(
                len(group.get("signals") or [])
                for group in groups
                if isinstance(group, Mapping)
            ),
        }
    return view


def listed_result(result, *, explicit_rules=(), include_combined=False):
    """Rows consumers list; ``include_combined`` also keeps rows shown inside
    their lead issue, for views that render the whole group."""

    def keep(row, category):
        if is_listed(row, category, explicit_rules=explicit_rules):
            return row
        if include_combined and is_combined(row):
            return row
        return None

    return map_finding_rows(result, keep)
