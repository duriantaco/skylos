"""Lossless advice records with one listing policy for report consumers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

from skylos.reporting.advice_display import (
    _advice_identity,
    _compatible_names,
    _rule_id,
    standalone_function_advice,
)
from skylos.reporting.advice_evidence import (
    ARCHITECTURE_METRIC_RULES,
    DEFAULT_ADVICE_RULES,
    corroborated,
    is_gated_function_metric,
)
from skylos.reporting.finding_types import get_finding_type, iter_result_findings
from skylos.reporting.rollups import FINDING_SECTIONS


@dataclass(frozen=True)
class AdviceVisibility:
    total_checks: int
    omitted_checks: int = 0
    reasons: tuple[tuple[str, int], ...] = ()
    rules: tuple[tuple[str, int], ...] = ()

    @property
    def message(self) -> str:
        if not self.omitted_checks:
            return ""
        measured = dict(self.reasons).get("measurement", 0)
        if measured and self.rules:
            from skylos.rules.catalog import get_rule_name

            top = sorted(self.rules, key=lambda item: (-item[1], item[0]))[:4]
            names = ", ".join(
                f"{count} {get_rule_name(rule, rule)}" for rule, count in top
            )
            others = self.omitted_checks - sum(count for _rule, count in top)
            more = f" and {others} more" if others > 0 else ""
            return (
                f"{self.omitted_checks} further advice "
                f"{'finding' if self.omitted_checks == 1 else 'findings'} measured, not listed "
                f"({names}{more}). --all-advice lists them."
            )
        labels = {
            "boolean_signature": "Boolean signatures without call evidence",
            "architecture": "file-level architecture metrics",
            "test": "tests",
            "example": "examples",
            "profiling": "profiling inputs",
            "vendored": "vendored code",
            "single_function_metric": "standalone length, nesting or return metrics",
            "identifier_literal": "repeated identifier tokens",
            "local_literal": "strings repeated within one function",
            "optional_signature": "wide named or optional signatures",
            "inherited_signature": "signatures constrained by a project base class",
            "single_dimension": "function metrics without two agreeing complexity measures",
            "generated": "generated files",
            "tooling": "docs, scripts and tooling folders",
            "measurement": "measurements outside the default advice set",
        }
        detail = ", ".join(
            f"{count} {labels.get(reason, 'other optional advice')}"
            for reason, count in self.reasons
        )
        return (
            f"{self.omitted_checks} optional advice "
            f"{'finding' if self.omitted_checks == 1 else 'findings'} ({detail}) available "
            "with --all-advice."
        )


def _signature_only_boolean(finding: Mapping, rule_id: str) -> bool:
    """Recognize only the built-in's known signature-only evidence contracts.

    Unknown messages remain visible. Observed positional calls have different
    messages and stay in the focused view; the raw rule is never disabled.
    """
    if rule_id != "SKY-L029":
        return False
    # Positive or unknown evidence must remain available for review, even
    # when an older producer retained the signature-only wording.
    if "call_evidence" in finding and finding["call_evidence"] not in (None, []):
        return False
    parameter = finding.get("value")
    if not isinstance(parameter, str) or not parameter:
        return False
    if not str(finding.get("name") or "").endswith(f".{parameter}"):
        return False
    return finding.get("message") in {
        f"Boolean parameter '{parameter}' permits positional calls, which can obscure their meaning. Prefer named calls; consider keyword-only arguments when the public or callback contract permits it.",
        f"Boolean parameter '{parameter}' is positional-only, so calls cannot name it. Consider a descriptive enum or a separate named operation when the public or callback contract permits it.",
    }


def _literal_signal_reason(finding: Mapping) -> str | None:
    evidence = finding.get("literal_context")
    if (
        not isinstance(evidence, Mapping)
        or type(evidence.get("version")) is not int
        or evidence.get("version") != 1
        or evidence.get("scope_complete") is not True
    ):
        return None
    count = evidence.get("occurrence_count")
    functions = evidence.get("distinct_function_count")
    outside = evidence.get("non_function_occurrences")
    if (
        any(
            type(value) is not int or value < 0 for value in (count, functions, outside)
        )
        or count != finding.get("value")
        or count < 2
        or outside > count
        or functions > count - outside
    ):
        return None
    if functions == 1 and outside == 0:
        if (
            evidence.get("identifier_like") is True
            and evidence.get("all_occurrences_contract_tokens") is True
        ):
            return "identifier_literal"
        return "local_literal"
    return None


def _argument_signal_reason(finding: Mapping) -> str | None:
    evidence = finding.get("argument_evidence")
    if (
        not isinstance(evidence, Mapping)
        or type(evidence.get("version")) is not int
        or evidence.get("version") != 1
    ):
        return None
    if evidence.get("complete") is not True:
        return None
    binding = evidence.get("receiver_binding")
    if not isinstance(binding, str) or binding not in {
        "function",
        "instance",
        "class",
        "static",
    }:
        return None
    metric = evidence.get("metric")
    if not isinstance(metric, str) or metric not in {
        "required_positional",
        "total_parameters",
    }:
        return None
    limits = evidence.get("limits")
    required = evidence.get("required_positional")
    total = evidence.get("total_parameters")
    if not isinstance(limits, Mapping):
        return None
    maximum = limits.get("required_positional")
    total_maximum = limits.get("total_parameters")
    if (
        any(
            type(value) is not int or value < 0
            for value in (required, total, maximum, total_maximum)
        )
        or required > total
    ):
        return None
    contract = evidence.get("override_contract")
    if isinstance(contract, Mapping) and (
        binding != "function"
        and contract.get("kind") == "project_base_signature"
        and contract.get("parameter_shape") == "identical"
        and contract.get("receiver_binding") == binding
        and type(contract.get("required_positional")) is int
        and contract["required_positional"] == required
        and type(contract.get("total_parameters")) is int
        and contract["total_parameters"] == total
        and all(
            isinstance(contract.get(field), str) and contract[field].strip()
            for field in ("base_class", "base_file")
        )
        and all(
            type(contract.get(field)) is int and contract[field] > 0
            for field in ("base_line", "method_line")
        )
    ):
        return "inherited_signature"
    if (
        metric == "total_parameters"
        and 0 <= required <= maximum
        and total > total_maximum
        and "required_positional_range" not in evidence
    ):
        return "optional_signature"
    return None


def optional_advice_reason(finding, category=None, *, project_root=None):
    """Only built-in Advice is eligible; Defect/Review/custom rows stay visible."""
    if not isinstance(finding, Mapping):
        return None
    if category not in (None, "quality"):
        return None
    if get_finding_type(finding, category) != "advice":
        return None
    rule_id = str(finding.get("rule_id") or finding.get("id") or "").strip().upper()
    annotation = finding.get("annotation_evidence")
    if (
        rule_id in {"SKY-T101", "SKY-T102"}
        and isinstance(annotation, Mapping)
        and annotation.get("version") == 1
        and annotation.get("required") is True
        and annotation.get("source") == "annotation_policy"
    ):
        return None
    if rule_id in {"SKY-Q802", "SKY-Q803"}:
        if finding.get("advisory") is True and finding.get("scope") == "file":
            return "architecture"
        # Explicitly enforced architecture policy and unknown contracts keep
        # their visibility even when the source is a test or example.
        return None
    if rule_id in ARCHITECTURE_METRIC_RULES:
        # Coupling and cohesion scores are measurements; they name no change.
        return "architecture"
    if _signature_only_boolean(finding, rule_id):
        return "boolean_signature"
    if rule_id == "SKY-L027":
        reason = _literal_signal_reason(finding)
        if reason:
            return reason
    if rule_id == "SKY-C303":
        reason = _argument_signal_reason(finding)
        if reason:
            return reason
    from skylos.reporting.advice_scope import advice_source_context

    context = advice_source_context(finding, project_root)
    if context:
        return context
    if rule_id not in DEFAULT_ADVICE_RULES:
        return "measurement"
    return None


def _uncorroborated_functions(canonical) -> set[tuple]:
    """Functions where no two complexity measures agree.

    Agreement is cyclomatic with cognitive, or cognitive with nesting. Python
    and JS/TS record cognitive complexity; other languages are not gated. A
    location with an unknown identity keeps every metric visible.
    """
    rules_at = {}
    names_at = {}
    uncertain = set()
    for category, row in canonical:
        if not isinstance(row, Mapping):
            continue
        rule_id = str(row.get("rule_id") or "").strip().upper()
        if not is_gated_function_metric(category, row, rule_id):
            continue
        if get_finding_type(row, category) != "advice":
            continue
        identity = _advice_identity(category, row)
        if identity is None:
            file = row.get("file") or row.get("file_path")
            uncertain.add((file, row.get("line")))
            continue
        location, (names, _columns, _language) = identity
        rules = rules_at.setdefault(location, [])
        if rule_id in rules:
            # Duplicate or conflicting records are not one known measurement.
            uncertain.add((location[1], location[2]))
        rules.append(rule_id)
        names_at.setdefault(location, []).extend(names)
    return {
        location
        for location, rules in rules_at.items()
        if not corroborated(rules)
        and (location[1], location[2]) not in uncertain
        and _compatible_names(names_at[location])
    }


def _recorded_visibility(result) -> AdviceVisibility | None:
    recorded = result.get("advice_visibility") if isinstance(result, Mapping) else None
    if not isinstance(recorded, Mapping):
        return None
    total, omitted = recorded.get("total_checks"), recorded.get("omitted_checks")
    reasons = recorded.get("reasons")
    if (
        type(total) is not int
        or type(omitted) is not int
        or not isinstance(reasons, Mapping)
    ):
        return None
    rules = recorded.get("rules") if isinstance(recorded.get("rules"), Mapping) else {}
    return AdviceVisibility(
        total,
        omitted,
        tuple(sorted((str(k), v) for k, v in reasons.items() if type(v) is int)),
        tuple(sorted((str(k), v) for k, v in rules.items() if type(v) is int)),
    )


def apply_advice_policy(
    result, *, project_root=None, all_advice=False, explicit_rules=()
):
    """Keep every finding and attach the shared, versioned listing decision."""
    from skylos.reporting.finding_types import _finding_key
    from skylos.reporting.listing import (
        LISTING_VERSION,
        demotion_reason,
        map_finding_rows,
        normalize_rule_ids,
    )

    # Complete records can be mirrored in several physical arrays. Use the
    # canonical walk's category priority for every exactly equivalent mirror,
    # so adding a listing field cannot turn one observation into two. The key
    # keeps custom categories separate; equality retains evidence/severity
    # variants and does not collapse repeated rows within a physical array.
    canonical_rows = {}
    for category, row in iter_result_findings(result):
        canonical_rows.setdefault(_finding_key(category, row), []).append(
            (category, row)
        )

    decisions = {}
    if not all_advice:
        _prepare_unmarked_advice_view(
            result, project_root=project_root, _decisions=decisions
        )
    explicit_rules = normalize_rule_ids(explicit_rules)

    def mark(row, category):
        if not isinstance(row, Mapping):
            return row
        decision_category, decision_row = next(
            (
                (prior_category, prior)
                for prior_category, prior in canonical_rows.get(
                    _finding_key(category, row), ()
                )
                if prior is row or prior == row
            ),
            (category, row),
        )
        rule = str(row.get("rule_id") or row.get("id") or "").upper()
        if get_finding_type(decision_row, decision_category) != "advice":
            reason, listed = "finding", True
            demoted = demotion_reason(decision_row)
            if demoted and not all_advice and rule not in explicit_rules:
                reason, listed = demoted, False
        elif rule in explicit_rules:
            reason, listed = "explicit_rule", True
        elif all_advice:
            reason, listed = "all_advice", True
        else:
            reason = decisions.get((id(decision_row), decision_category))
            listed = reason is None
            reason = reason or "default"
        return {
            **row,
            "listing": {"version": LISTING_VERSION, "listed": listed, "reason": reason},
        }

    view = map_finding_rows(result, mark)
    if not all_advice:
        view = _combine_same_location_advice(view)
        view = _combine_package_advisories(view, explicit_rules)
    view["listing_policy_version"] = LISTING_VERSION
    return refresh_listing_summary(view)


def _combine_package_advisories(view, explicit_rules=()):
    """List one dependency issue per installed package version.

    Every advisory against one package version in one lockfile is fixed by the
    same upgrade, so the worst one stays listed and names the others in
    ``listing.combines``; each other is unlisted as ``combined`` with a
    ``listing.lead`` reference, as the terminal table already prints them.
    Gates read the raw advisories, and every record stays in the report."""
    from skylos.reporting.advice_display import SEVERITY_RANK
    from skylos.reporting.listing import COMBINED_REASON, SCA_RULE_PREFIX, is_listed

    rows = view.get("dependency_vulnerabilities")
    if not isinstance(rows, list):
        return view
    groups = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or not isinstance(row.get("listing"), Mapping):
            continue
        rule = _rule_id(row).upper()
        if not rule.startswith(SCA_RULE_PREFIX) or rule in explicit_rules:
            continue
        if not is_listed(row, "dependency_vulnerabilities"):
            continue
        meta = row.get("metadata")
        if not isinstance(meta, Mapping) or not meta.get("package_name"):
            continue
        key = (
            str(row.get("file") or row.get("file_path") or ""),
            str(meta.get("ecosystem") or ""),
            str(meta.get("package_name")).lower(),
            str(meta.get("package_version") or ""),
        )
        groups.setdefault(key, []).append(index)

    def rank(index):
        severity = str(rows[index].get("severity") or "").strip().upper()
        return (SEVERITY_RANK.get(severity, len(SEVERITY_RANK)), index)

    updated = list(rows)
    for indices in groups.values():
        if len(indices) < 2:
            continue
        lead_index = min(indices, key=rank)
        lead = rows[lead_index]
        reference = {
            "rule_id": _rule_id(lead),
            "file": lead.get("file") or lead.get("file_path"),
            "line": lead.get("line"),
        }
        combines = []
        for index in indices:
            if index == lead_index:
                continue
            row = rows[index]
            combines.append({"rule_id": _rule_id(row), "line": row.get("line")})
            updated[index] = {
                **row,
                "listing": {
                    **row["listing"],
                    "listed": False,
                    "reason": COMBINED_REASON,
                    "lead": reference,
                },
            }
        updated[lead_index] = {
            **lead,
            "listing": {**lead["listing"], "combines": combines},
        }
    return {**view, "dependency_vulnerabilities": updated}


def _combine_same_location_advice(view):
    """List one issue per function or module location.

    Checks at one location (cyclomatic, cognitive, nesting, length, returns)
    describe one problem with one fix. The most severe of them stays listed
    and names the others in ``listing.combines``; each other is unlisted with
    reason ``combined`` and points at it in ``listing.lead``, so gates, the
    assessment and uploads count the location once while every record stays in
    the report. Only checks at the same line are grouped, so a line filter
    keeps or drops a group whole. Explicitly selected rules remain independently
    listed, including when a later rule filter removes other measurements."""
    from skylos.reporting.advice_display import (
        SEVERITY_RANK,
        same_location_advice_groups,
    )
    from skylos.reporting.finding_types import _finding_key
    from skylos.reporting.listing import COMBINED_REASON, is_listed, map_finding_rows

    rows = []
    for category, row in iter_result_findings(view):
        if get_finding_type(row, category) != "advice":
            continue
        if not is_listed(row, category):
            continue
        if row["listing"]["reason"] == "explicit_rule":
            continue
        rows.append((category, row))

    def severity_rank(member):
        severity = str(member[1].get("severity") or "").strip().upper()
        return SEVERITY_RANK.get(severity, len(SEVERITY_RANK))

    marks = {}
    for indices in same_location_advice_groups(rows):
        members = []
        for index in indices:
            members.append(rows[index])
        lead_category, lead = min(members, key=severity_rank)
        reference = {
            "rule_id": _rule_id(lead),
            "file": lead.get("file") or lead.get("file_path"),
            "line": lead.get("line"),
        }
        others = []
        for member in members:
            if member[1] is not lead:
                others.append(member)
        combines = []
        for _category, row in others:
            combines.append({"rule_id": _rule_id(row), "line": row.get("line")})
        marks.setdefault(_finding_key(lead_category, lead), []).append(
            (lead, {"combines": combines})
        )
        for category, row in others:
            update = {
                "listed": False,
                "reason": COMBINED_REASON,
                "lead": reference,
            }
            marks.setdefault(_finding_key(category, row), []).append((row, update))
    if not marks:
        return view

    def apply(row, category):
        if not isinstance(row, Mapping) or not isinstance(row.get("listing"), Mapping):
            return row
        for original, update in marks.get(_finding_key(category, row), ()):
            if original is row or original == row:
                return {**row, "listing": {**row["listing"], **update}}
        return row

    return map_finding_rows(view, apply)


def refresh_listing_summary(result, *, preserve_assessment=False):
    """Refresh counts after scope filters without changing listing decisions."""
    from skylos.reporting.finding_types import summarize_finding_types
    from skylos.reporting.listing import (
        LISTING_VERSION,
        is_combined,
        is_listed,
        listed_result,
    )

    if result.get("listing_policy_version") != LISTING_VERSION:
        return result
    view = dict(result)
    canonical = list(iter_result_findings(view))
    omitted = []
    for category, row in canonical:
        if not is_listed(row, category) and not is_combined(row):
            omitted.append((category, row))
    combined = sum(is_combined(row) for _category, row in canonical)
    total = sum(
        get_finding_type(row, category) == "advice" for category, row in canonical
    )
    reasons = Counter(row["listing"]["reason"] for _category, row in omitted)
    rules = Counter(str(row.get("rule_id") or "").upper() for _category, row in omitted)
    visibility = AdviceVisibility(
        total,
        len(omitted),
        tuple(sorted(reasons.items())),
        tuple(sorted(rules.items())),
    )
    view["advice_visibility"] = {
        "total_checks": visibility.total_checks,
        "omitted_checks": visibility.omitted_checks,
        "combined_checks": combined,
        "reasons": dict(visibility.reasons),
        "rules": dict(visibility.rules),
        "include_with": "--all-advice",
    }
    selected = listed_result(view)
    summary = dict(view.get("analysis_summary") or {})
    summary["finding_type_counts"] = summarize_finding_types(view)
    summary["listed_finding_type_counts"] = summarize_finding_types(selected)
    summary["quality_count"] = len(view.get("quality") or [])
    summary["listed_quality_count"] = len(selected.get("quality") or [])
    if not preserve_assessment:
        summary["assessment_scope"] = "listed_findings"
    view["analysis_summary"] = summary
    if result.get("assessment") and not preserve_assessment:
        from skylos.reporting.assessment import compute_assessment

        view["assessment"] = compute_assessment(selected)
    return view


def prepare_advice_view(result, *, project_root=None, all_advice=False):
    """Read shared marks for presentation; older reports retain legacy focus."""
    from skylos.reporting.listing import LISTING_VERSION, listed_result

    if result.get("listing_policy_version") == LISTING_VERSION:
        total = sum(
            get_finding_type(row, category) == "advice"
            for category, row in iter_result_findings(result)
        )
        if all_advice:
            return result, AdviceVisibility(total)
        return listed_result(result, include_combined=True), _recorded_visibility(
            result
        ) or AdviceVisibility(
            total
        )
    return _prepare_unmarked_advice_view(
        result, project_root=project_root, all_advice=all_advice
    )


def _prepare_unmarked_advice_view(
    result, *, project_root=None, all_advice=False, _decisions=None
):
    """Return a shallow presentation copy and an explicit optional-advice count.

    A result whose scan already applied the policy carries its decisions in
    ``advice_visibility`` and is returned unchanged. Category classification
    is authoritative even if a custom check claims a built-in rule ID.
    Mirrored records are counted once via the canonical walk.
    """
    canonical = list(iter_result_findings(result))
    total = sum(
        get_finding_type(row, category) == "advice" for category, row in canonical
    )
    if all_advice:
        return result, AdviceVisibility(total)
    reasons = Counter()
    decisions = {}
    standalone = standalone_function_advice(canonical)
    uncorroborated = _uncorroborated_functions(canonical)

    def reason(row, category):
        key = (id(row), category)
        if key not in decisions:
            decisions[key] = optional_advice_reason(
                row, category, project_root=project_root
            )
            if (
                decisions[key] is None
                and category == "quality"
                and isinstance(row, Mapping)
            ):
                identity = _advice_identity(category, row)
                candidate = standalone.get(identity[0]) if identity else None
                if candidate is not None and row == candidate:
                    decisions[key] = "single_function_metric"
                elif (
                    identity is not None
                    and identity[0] in uncorroborated
                    and get_finding_type(row, category) == "advice"
                ):
                    decisions[key] = "single_dimension"
        if _decisions is not None:
            _decisions[key] = decisions[key]
        return decisions[key]

    omitted_rules = Counter()
    for category, row in canonical:
        optional = reason(row, category)
        if optional:
            reasons[optional] += 1
            if isinstance(row, Mapping):
                omitted_rules[str(row.get("rule_id") or "").upper()] += 1
    omitted = sum(reasons.values())
    visibility = AdviceVisibility(
        total,
        omitted,
        tuple(sorted(reasons.items())),
        tuple(sorted(omitted_rules.items())),
    )
    if not omitted:
        return result, visibility

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
            effective_category = (
                "custom_rules" if section == "custom_rules" else category
            )
            view[section] = [row for row in rows if not reason(row, effective_category)]
    metrics = result.get("architecture_metrics")
    if isinstance(metrics, Mapping) and isinstance(
        metrics.get("advisories"), (list, tuple)
    ):
        groups = []
        for advisory in metrics["advisories"]:
            if not isinstance(advisory, Mapping):
                groups.append(advisory)
                continue
            signals = advisory.get("signals")
            if not isinstance(signals, (list, tuple)):
                groups.append(advisory)
                continue
            selected = [row for row in signals if not reason(row, "quality")]
            if selected:
                groups.append(
                    {
                        **advisory,
                        "signals": selected,
                        "rule_ids": [
                            row.get("rule_id")
                            for row in selected
                            if isinstance(row, Mapping)
                        ],
                    }
                )
        signal_count = sum(
            len(group.get("signals") or [])
            for group in groups
            if isinstance(group, Mapping)
        )
        view["architecture_metrics"] = {
            **metrics,
            "advisories": groups,
            "advisory_count": len(groups),
            "advisory_signal_count": signal_count,
        }
        summary = result.get("analysis_summary")
        if isinstance(summary, Mapping):
            view["analysis_summary"] = {
                **summary,
                "architecture_advisory_count": len(groups),
            }
    if result.get("assessment") or result.get("grade"):
        view["analysis_summary"] = {
            **(view.get("analysis_summary") or {}),
            "assessment_includes_filtered_findings": True,
        }
    return view, visibility
