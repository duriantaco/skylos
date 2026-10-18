"""Focused human advice views, separate from findings and gate policy."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

from skylos.reporting.advice_display import _advice_identity, standalone_function_advice
from skylos.reporting.finding_types import get_finding_type, iter_result_findings
from skylos.reporting.rollups import FINDING_SECTIONS


@dataclass(frozen=True)
class AdviceVisibility:
    total_checks: int
    omitted_checks: int = 0
    reasons: tuple[tuple[str, int], ...] = ()

    @property
    def message(self) -> str:
        if not self.omitted_checks:
            return ""
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
        }
        detail = ", ".join(
            f"{count} {labels[reason]}" for reason, count in self.reasons
        )
        return (
            f"{self.omitted_checks} optional advice checks ({detail}) available "
            "with --all-advice. JSON and gates retain all findings."
        )


def _signature_only_boolean(finding: Mapping, rule_id: str) -> bool:
    """Recognize only the built-in's known signature-only evidence contracts.

    Unknown messages remain visible. Observed positional calls have different
    messages and stay in the focused view; the raw rule is never disabled.
    """
    if rule_id != "SKY-L029":
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
        any(type(value) is not int or value < 0 for value in (count, functions, outside))
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
    if not isinstance(binding, str) or binding not in {"function", "instance", "class", "static"}:
        return None
    metric = evidence.get("metric")
    if not isinstance(metric, str) or metric not in {"required_positional", "total_parameters"}:
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
    if rule_id in {"SKY-Q802", "SKY-Q803"}:
        if finding.get("advisory") is True and finding.get("scope") == "file":
            return "architecture"
        # Explicitly enforced architecture policy and unknown contracts keep
        # their visibility even when the source is a test or example.
        return None
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

    return advice_source_context(finding, project_root)


def prepare_advice_view(result, *, project_root=None, all_advice=False):
    """Return a shallow presentation copy and an explicit optional-advice count.

    Originals, raw output, assessments and gate inputs are never modified.
    Category classification is authoritative even if a custom check claims a
    built-in rule ID. Mirrored records are counted once via the canonical walk.
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
        return decisions[key]

    for category, row in canonical:
        optional = reason(row, category)
        if optional:
            reasons[optional] += 1
    omitted = sum(reasons.values())
    visibility = AdviceVisibility(total, omitted, tuple(sorted(reasons.items())))
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
