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
SCA_LOW_RISK_REASONS = frozenset({"dev-only-dependency", "informational-advisory"})
CONSTANT_ARGUMENT_REASON = "constant-argument"
LOW_RISK_REASONS = {
    "SKY-D292": frozenset({"github-owned-action-tag"}),
    "SKY-D294": frozenset({"no-outsider-input"}),
    "SKY-D299": frozenset({"non-credential-secret"}),
    "SKY-D309": frozenset({"non-credential-secret"}),
    "SKY-D201": frozenset({CONSTANT_ARGUMENT_REASON}),
    "SKY-D202": frozenset({CONSTANT_ARGUMENT_REASON}),
    "SKY-D203": frozenset({"constant-shell-command", CONSTANT_ARGUMENT_REASON}),
    "SKY-D205": frozenset({CONSTANT_ARGUMENT_REASON}),
    "SKY-D206": frozenset({CONSTANT_ARGUMENT_REASON}),
    "SKY-D209": frozenset({"constant-shell-command", CONSTANT_ARGUMENT_REASON}),
    "SKY-D212": frozenset({CONSTANT_ARGUMENT_REASON}),
    "SKY-D207": frozenset({"non-sensitive-hash-input"}),
    "SKY-D208": frozenset({"non-sensitive-hash-input"}),
}
_RULE_ID = re.compile(r"SKY-[A-Z0-9]+(?:-[A-Z0-9]+)*\Z")


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


def unrecognized_rule_ids(value):
    """Entries of a rule list that ``normalize_rule_ids`` drops."""
    if isinstance(value, str):
        value = [item for item in re.split(r"[,\s]+", value) if item]
    if isinstance(value, Mapping):
        value = [key for key, setting in value.items() if setting is not False]
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return [
        str(item)
        for item in value
        if not (isinstance(item, str) and _RULE_ID.fullmatch(item.strip().upper()))
    ]


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
    if is_unproven_source_review(finding):
        return UNPROVEN_SOURCE_REASON
    if low_risk_context(finding) is not None:
        return LOW_RISK_REASON
    return None


UNPROVEN_SOURCE_REASON = "unproven-source"
UNPROVEN_SOURCE_KIND = "unproven_source"
_PATH_UNPROVEN_RULES = frozenset({"SKY-D215", "SKY-D324", "SKY-D325"})
# Pattern sinks whose only proof is the shape of the call: a request URL
# (SKY-D216) built from a variable that no request value was traced into.
_PATTERN_UNPROVEN_RULES = frozenset({"SKY-D216"})
# A YAML loader proven safe in its own file, in a project too large for the
# whole-project proof (see skylos.rules.danger.calls).
YAML_PROJECT_TOO_LARGE = "project_too_large"
# Shell findings whose only source is the script's own command-line
# arguments: the operator's choice, like a Python CLI argument.
_SCRIPT_ARGUMENT_RULES = frozenset({"SKY-D212", "SKY-D215", "SKY-D216"})
# Rust command and path findings whose only inputs are environment variables,
# command-line arguments or a function's parameters: the operator's or the
# calling code's choice, as in the Go engine's source model.
_RUST_OPERATOR_RULES = frozenset({"SKY-D212", "SKY-D215"})


def is_unproven_source_review(finding):
    """A sink the analysis could not connect to attacker input.

    Precise taint analysis reports a sink only when untrusted input is shown
    to reach it. These records stay in the report as review signals but are
    not listed and do not fail gates:

    * a Python path or symlink finding (SKY-D215/D324/D325) whose caller
      provenance (``metadata.path_provenance``) stopped incomplete before any
      chain reached web request data, an upload, a network message or an
      archive member, so only "callers not visible" remains;
    * a pattern SSRF finding (SKY-D216) that request taint never reached: the
      URL is a variable whose value comes from configuration, stored settings,
      a constant or a caller the analysis cannot see;
    * a shell command, path or URL (SKY-D212/D215/D216) whose only source is
      the script's own command-line arguments, which its operator chooses;
    * a Rust command or path (SKY-D212/D215) whose only inputs are environment
      variables, command-line arguments or a function's parameters
      (``metadata.rust_source == "operator_input"``, no request source).
    * a YAML load (SKY-D206) whose loader this file proves is a native safe
      loader, where only the whole-project proof that no other module
      replaces it is missing because the project exceeds the source snapshot
      limits (``metadata.yaml_loader_proof == "project_too_large"``).

    The detector records the evidence; a ``review_item`` of another kind or a
    finding with request evidence is never demoted."""
    if not isinstance(finding, Mapping):
        return False
    item = finding.get("review_item")
    if not isinstance(item, Mapping) or item.get("kind") != UNPROVEN_SOURCE_KIND:
        return False
    if item.get("blocking") is not False:
        return False
    rule = str(finding.get("rule_id") or "").upper()
    metadata = finding.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    if metadata.get("rust_source") is not None:
        evidence = metadata.get("security_evidence")
        sources = evidence.get("sources") if isinstance(evidence, Mapping) else None
        return (
            rule in _RUST_OPERATOR_RULES
            and metadata.get("rust_source") == "operator_input"
            and isinstance(sources, list)
            and not any(
                isinstance(source, str) and source.startswith("request:")
                for source in sources
            )
        )
    if metadata.get("shell_source") is not None:
        return (
            rule in _SCRIPT_ARGUMENT_RULES
            and metadata.get("shell_source") == "script_arguments"
            and not finding.get("security_evidence")
        )
    if rule in _PATH_UNPROVEN_RULES:
        provenance = metadata.get("path_provenance")
        return (
            isinstance(provenance, Mapping)
            and provenance.get("status") == "incomplete"
            and not provenance.get("untrusted")
            and not provenance.get("shared_temp_path")
            and metadata.get("path_source") != "resolved_caller"
        )
    if rule == "SKY-D206":
        return metadata.get("yaml_loader_proof") == YAML_PROJECT_TOO_LARGE
    if rule in _PATTERN_UNPROVEN_RULES:
        return not finding.get("security_evidence") and not metadata.get(
            "security_evidence"
        )
    return False


NONBLOCKING_REVIEW_RULES = frozenset({"SKY-D324", "SKY-D325"})


def is_nonblocking_review(finding):
    """A symlink finding whose only open question is who can create entries
    in the directory: the caller selects one validated filename component
    (``metadata.path_provenance.component_review``). It stays reported as a
    review item but does not fail gates. Other rules cannot use this."""
    if not isinstance(finding, Mapping):
        return False
    rule = str(finding.get("rule_id") or "").upper()
    item = finding.get("review_item")
    metadata = finding.get("metadata")
    if rule not in NONBLOCKING_REVIEW_RULES or not isinstance(item, Mapping):
        return False
    if item.get("kind") != "directory_entry_access" or item.get("blocking") is not False:
        return False
    provenance = metadata.get("path_provenance") if isinstance(metadata, Mapping) else None
    if not isinstance(provenance, Mapping) or provenance.get("complete_project") is not True:
        return False
    review = provenance.get("component_review")
    if not isinstance(review, Mapping):
        return False
    group = item.get("group")
    proofs = review.get("proofs")
    return (
        provenance.get("status") == "untrusted"
        and not provenance.get("shared_temp_path")
        and review.get("status") == "caller_selects_one_filename_component"
        and isinstance(group, str) and bool(group.strip())
        and group == review.get("group")
        and isinstance(proofs, list) and bool(proofs)
        and all(isinstance(proof, str) and proof.strip() for proof in proofs)
    )


def is_gate_exempt_review(finding):
    """A review item that stays reported but does not fail gates: a symlink
    directory-entry question or a sink with no proven untrusted source."""
    return is_nonblocking_review(finding) or is_unproven_source_review(finding)


def is_combined_review(finding):
    """One finding of a review item that lists once under its lead."""
    return is_combined(finding) and is_nonblocking_review(finding)


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
        if is_combined_advisory(finding) or is_combined_review(finding):
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
