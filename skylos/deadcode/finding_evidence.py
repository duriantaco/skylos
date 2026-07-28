from __future__ import annotations

from typing import Any


_VALIDATED_DEAD_OUTCOMES = {
    "true_positive",
    "validated_dead",
    "validation_pass",
}
_ALIVE_OUTCOMES = {
    "alive",
    "false_positive",
    "validation_fail",
}
_UNCERTAIN_OUTCOMES = {
    "inconclusive",
    "uncertain",
}


def dead_code_finding_evidence_payload(
    finding: dict[str, Any],
    *,
    max_events: int | None = None,
) -> dict[str, Any] | None:
    decision = finding.get("dead_code_decision")
    events = finding.get("dead_code_evidence")
    classification = finding.get("dead_code_classification")
    reason = finding.get("dead_code_reason")
    reason_tags = finding.get("dead_code_reason_tags")

    has_decision = isinstance(decision, dict) and bool(decision)
    has_events = isinstance(events, list) and bool(events)
    if not any((classification, reason, reason_tags, has_decision, has_events)):
        return None

    payload: dict[str, Any] = {}
    if classification:
        payload["classification"] = str(classification)
    disposition = finding.get("dead_code_disposition")
    if disposition:
        payload["disposition"] = str(disposition)
    if reason:
        payload["reason"] = str(reason)
    if isinstance(reason_tags, (list, tuple)):
        payload["reason_tags"] = [str(tag) for tag in reason_tags]
    if has_decision:
        payload["decision"] = dict(decision)
    if isinstance(events, list):
        visible = [dict(event) for event in events if isinstance(event, dict)]
        if max_events is not None:
            visible = visible[: max(0, max_events)]
        payload["events"] = visible
        if max_events is not None and len(events) > len(visible):
            payload["events_truncated"] = len(events) - len(visible)
    return payload


def attach_dead_code_validation(
    finding: dict[str, Any],
    outcome: str,
    *,
    reason: str,
    source: str,
    confidence: float = 1.0,
) -> dict[str, Any]:
    normalized = str(outcome or "").strip().lower()
    if normalized in _VALIDATED_DEAD_OUTCOMES:
        classification = "validated_dead"
        disposition = "reported"
        kind = "validation_pass"
        role = "supports_dead"
        primary_reason = "Validator confirmed no live use"
        reason_tags = ["validated_dead"]
    elif normalized in _ALIVE_OUTCOMES:
        classification = "alive"
        disposition = "rescued"
        kind = "validation_fail"
        role = "supports_live"
        primary_reason = "Validator found live use"
        reason_tags = ["validation_failed"]
    elif normalized in _UNCERTAIN_OUTCOMES:
        classification = "uncertain"
        disposition = "abstained"
        kind = "uncertainty"
        role = "uncertainty"
        primary_reason = "Validator was inconclusive"
        reason_tags = ["uncertainty"]
    else:
        raise ValueError(f"Unsupported dead-code validation outcome: {outcome}")

    event = {
        "kind": kind,
        "role": role,
        "reason": str(reason or primary_reason),
        "source": str(source or "validator"),
        "confidence": _confidence_float(confidence),
        "details": {"validation_outcome": normalized},
    }
    events = [
        dict(existing)
        for existing in finding.get("dead_code_evidence", [])
        if isinstance(existing, dict)
    ]
    if event not in events:
        events.append(event)

    current_decision = finding.get("dead_code_decision")
    decision = dict(current_decision) if isinstance(current_decision, dict) else {}
    decision.update(
        {
            "classification": classification,
            "primary_reason": primary_reason,
            "reason_tags": reason_tags,
            "live_evidence_count": _role_count(events, "supports_live"),
            "dead_evidence_count": _role_count(events, "supports_dead"),
            "uncertainty_count": _role_count(events, "uncertainty"),
        }
    )

    finding["dead_code_classification"] = classification
    finding["dead_code_disposition"] = disposition
    finding["dead_code_evidence"] = events
    finding["dead_code_decision"] = decision
    finding["dead_code_reason"] = primary_reason
    finding["dead_code_reason_tags"] = reason_tags
    return finding


def _role_count(events: list[dict[str, Any]], role: str) -> int:
    return sum(1 for event in events if event.get("role") == role)


def _confidence_float(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 1.0
    if numeric > 1:
        numeric /= 100.0
    return max(0.0, min(numeric, 1.0))
