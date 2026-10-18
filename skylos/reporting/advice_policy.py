"""Focused human advice views, separate from findings and gate policy."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

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
        }
        detail = ", ".join(
            f"{count} {labels[reason]}" for reason, count in self.reasons
        )
        return (
            f"{self.omitted_checks} optional advice "
            f"{'finding' if self.omitted_checks == 1 else 'findings'} ({detail}) available "
            "with --all-advice. JSON and gates retain all findings."
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

    def reason(row, category):
        key = (id(row), category)
        if key not in decisions:
            decisions[key] = optional_advice_reason(
                row, category, project_root=project_root
            )
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
