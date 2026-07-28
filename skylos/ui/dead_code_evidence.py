from __future__ import annotations

from typing import Any


CLASSIFICATION_LABELS = {
    "alive": "alive",
    "dead": "dead",
    "likely_dead": "likely dead",
    "validated_dead": "validated dead",
    "uncertain": "uncertain",
}

REASON_TAG_LABELS = {
    "no_refs": "no refs",
    "not_exported": "not exported",
    "no_entrypoint": "no entrypoint",
    "static_reference": "has refs",
    "reachable_from_root": "root reachable",
    "top_level_execution": "import-time call",
    "framework_root": "framework entry",
    "package_entrypoint": "package entry",
    "test_entrypoint": "test entry",
    "dynamic_pattern": "dynamic ref",
    "coverage_hit": "coverage hit",
    "trace_hit": "trace hit",
    "grep_rescue": "grep usage",
    "uncertainty": "uncertain",
    "validated_dead": "validated dead",
    "validation_failed": "live use found",
    "no_liveness_evidence": "no live evidence",
}

_ROLE_ORDER = {
    "alive": ("supports_live", "uncertainty", "supports_dead", "context"),
    "uncertain": ("uncertainty", "supports_live", "supports_dead", "context"),
    "dead": ("supports_dead", "uncertainty", "supports_live", "context"),
    "likely_dead": ("supports_dead", "uncertainty", "supports_live", "context"),
    "validated_dead": (
        "supports_dead",
        "uncertainty",
        "supports_live",
        "context",
    ),
}


def dead_code_classification(item: dict[str, Any]) -> str:
    classification = item.get("dead_code_classification")
    if classification:
        return str(classification)
    decision = item.get("dead_code_decision")
    if isinstance(decision, dict) and decision.get("classification"):
        return str(decision["classification"])
    return ""


def compact_dead_code_evidence(
    item: dict[str, Any],
    *,
    max_events: int = 3,
) -> str:
    classification = dead_code_classification(item)
    label = CLASSIFICATION_LABELS.get(classification, classification.replace("_", " "))
    events = _ordered_events(item, classification)
    visible = [_compact_event(event) for event in events[: max(0, max_events)]]
    visible = [text for text in visible if text]

    if visible:
        prefix = f"{label} — " if label else ""
        suffix = ""
        if len(events) > len(visible):
            suffix = f" · +{len(events) - len(visible)}"
        return prefix + " · ".join(visible) + suffix

    fallback = _fallback_reason(item)
    if label and fallback:
        return f"{label} — {fallback}"
    return label or fallback


def dead_code_evidence_detail_lines(item: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    classification = dead_code_classification(item)
    if classification:
        label = CLASSIFICATION_LABELS.get(
            classification,
            classification.replace("_", " "),
        )
        lines.append(f"Decision: {label}")

    decision = item.get("dead_code_decision")
    if isinstance(decision, dict):
        reason = decision.get("primary_reason")
        if reason:
            lines.append(f"Reason: {reason}")
        lines.append(
            "Support: "
            f"live {int(decision.get('live_evidence_count') or 0)}, "
            f"dead {int(decision.get('dead_evidence_count') or 0)}, "
            f"uncertain {int(decision.get('uncertainty_count') or 0)}"
        )

    events = _ordered_events(item, classification)
    if events:
        lines.append("Evidence:")
        for event in events:
            role = str(event.get("role") or "context").replace("_", " ")
            reason = str(event.get("reason") or event.get("kind") or "evidence")
            source = str(event.get("source") or "unknown")
            confidence = _confidence_label(event.get("confidence"))
            lines.append(f"- {role}: {reason} [{source}, {confidence}]")
    return lines


def dead_code_candidate_counts(result: dict[str, Any]) -> dict[str, int]:
    summary = result.get("analysis_summary")
    if not isinstance(summary, dict):
        return {}
    evidence = summary.get("dead_code_evidence")
    if not isinstance(evidence, dict):
        return {}
    decisions = evidence.get("candidate_decisions")
    if not isinstance(decisions, dict):
        return {}
    return {
        "reported": _safe_int(decisions.get("reported")),
        "rescued": _safe_int(decisions.get("rescued")),
        "abstained": _safe_int(decisions.get("abstained")),
    }


def _ordered_events(item: dict[str, Any], classification: str) -> list[dict[str, Any]]:
    raw_events = item.get("dead_code_evidence")
    if not isinstance(raw_events, list):
        return []
    events = [event for event in raw_events if isinstance(event, dict)]
    order = _ROLE_ORDER.get(
        classification,
        ("supports_dead", "supports_live", "uncertainty", "context"),
    )
    rank = {role: index for index, role in enumerate(order)}
    return sorted(
        events,
        key=lambda event: rank.get(str(event.get("role") or "context"), len(rank)),
    )


def _compact_event(event: dict[str, Any]) -> str:
    reason = str(event.get("reason") or event.get("kind") or "").strip()
    if not reason:
        return ""
    source = str(event.get("source") or "").strip()
    if source:
        return f"{reason} [{source}]"
    return reason


def _fallback_reason(item: dict[str, Any]) -> str:
    tags = item.get("dead_code_reason_tags")
    if not isinstance(tags, (list, tuple)):
        decision = item.get("dead_code_decision")
        if isinstance(decision, dict):
            tags = decision.get("reason_tags")

    if isinstance(tags, (list, tuple)):
        visible = []
        for raw_tag in tags:
            tag = str(raw_tag)
            if tag == "confidence_ge_threshold":
                continue
            label = REASON_TAG_LABELS.get(tag)
            if label:
                visible.append(label)
        if visible:
            return " · ".join(visible[:3])

    reason = item.get("dead_code_reason")
    if reason:
        return str(reason)
    decision = item.get("dead_code_decision")
    if isinstance(decision, dict) and decision.get("primary_reason"):
        return str(decision["primary_reason"])
    return ""


def _confidence_label(value: Any) -> str:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return "confidence unknown"
    if confidence <= 1:
        confidence *= 100
    return f"{round(confidence)}%"


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
