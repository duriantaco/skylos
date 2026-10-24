"""The shared, lossless listing decision used by report consumers."""

from __future__ import annotations

from collections.abc import Mapping
import re

from skylos.reporting.finding_types import get_finding_type
from skylos.reporting.rollups import FINDING_SECTIONS

LISTING_VERSION = 1
COMBINED_REASON = "combined"
PUBLIC_IDENTIFIER_REASON = "likely-public-identifier"
LOW_RISK_REASON = "low-risk-context"
SCA_RULE_PREFIX = "SKY-SCA-"
SCA_LOW_RISK_REASONS = frozenset({"dev-only-dependency"})
LOW_RISK_REASONS = {
    "SKY-D292": frozenset({"github-owned-action-tag"}),
    "SKY-D299": frozenset({"non-credential-secret"}),
    "SKY-D203": frozenset({"constant-shell-command"}),
    "SKY-D209": frozenset({"constant-shell-command"}),
    "SKY-D207": frozenset({"non-sensitive-hash-input"}),
    "SKY-D208": frozenset({"non-sensitive-hash-input"}),
}
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


def is_demoted_secret(finding):
    """A secret candidate the scanner saw as a public identifier: hidden from
    the default list only. Gates count raw secrets, so it stays enforced."""
    if not isinstance(finding, Mapping) or not finding.get(
        "public_identifier_evidence"
    ):
        return False
    return str(finding.get("rule_id") or "").upper() == "SKY-S101"


def low_risk_context(finding):
    """The detector's evidence that a true risk finding is low-risk where it
    occurs, or None. Only the reasons a rule's own detector can prove count,
    so a finding cannot be hidden by a reason another rule defines."""
    if not isinstance(finding, Mapping):
        return None
    context = finding.get("low_risk_context")
    if not isinstance(context, Mapping):
        return None
    rule = str(finding.get("rule_id") or "").upper()
    if rule.startswith(SCA_RULE_PREFIX):
        allowed = SCA_LOW_RISK_REASONS
    else:
        allowed = LOW_RISK_REASONS.get(rule, frozenset())
    if context.get("reason") in allowed:
        return context
    return None


def demotion_reason(finding):
    """The listing reason a risk finding is hidden under by default, or None."""
    if is_demoted_secret(finding):
        return PUBLIC_IDENTIFIER_REASON
    if low_risk_context(finding) is not None:
        return LOW_RISK_REASON
    return None


def is_combined_advisory(finding):
    """One advisory of a package version that lists once under its lead."""
    if not is_combined(finding):
        return False
    return str(finding.get("rule_id") or "").upper().startswith(SCA_RULE_PREFIX)


def is_listed(finding, category=None, *, explicit_rules=()):
    """Unknown metadata and risk/custom findings remain visible. A risk
    finding is hidden only for a demotion its detector proved (a likely
    public identifier, a low-risk context) or as one advisory of a package
    already listed; gates count raw results, so it stays enforced."""
    if not isinstance(finding, Mapping):
        return True
    rule = str(finding.get("rule_id") or finding.get("id") or "").upper()
    if get_finding_type(finding, category) != "advice":
        if rule in explicit_rules:
            return True
        mark = listing_decision(finding)
        if mark is None or mark["listed"]:
            return True
        if is_combined_advisory(finding):
            return False
        reason = demotion_reason(finding)
        return reason is None or mark["reason"] != reason
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
