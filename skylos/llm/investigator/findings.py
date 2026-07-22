"""Conversion of validated investigator output into Skylos findings."""

from __future__ import annotations

from dataclasses import dataclass as _dataclass
from typing import Any

from skylos.audit.investigator_tools import AuditReadOnlyTools
from skylos.llm.schemas import (
    CodeLocation,
    Confidence,
    Finding,
    IssueType,
    Severity,
)

from .evidence import (
    enum_string,
    optional_strict_positive_int,
    required_string,
    required_string_list,
    strict_positive_int,
    validate_evidence_list,
    validate_mitigation_checks,
)
from .models import (
    INVESTIGATION_CATEGORIES,
    LOGIC_CATEGORIES,
    LOGIC_RULE_ID,
    SECURITY_RULE_ID,
    InvestigationIncompleteError,
)
from .protocol import LOGIC_FINDING_SCHEMA


@_dataclass(frozen=True)
class _FindingClassification:
    category: str
    issue_type: str
    severity: str
    confidence: str
    primary_file: str
    line: int
    end_line: int | None


@_dataclass(frozen=True)
class _FindingEvidence:
    evidence: list[dict[str, Any]]
    mitigations: list[str]
    mitigation_evidence: list[dict[str, Any]]
    counterevidence: list[str]


@_dataclass(frozen=True)
class _FindingNarrative:
    actor: str
    action: str
    resource: str
    trigger: str
    invariant: str
    actual_behavior: str
    impact: str
    suggestion: str
    message: str
    symbol: str | None


def build_findings(
    raw_findings: list[Any],
    *,
    entry_file: str,
    tools: AuditReadOnlyTools,
) -> list[Finding]:
    findings: list[Finding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise InvestigationIncompleteError("logic finding must be an object")
        findings.append(_build_finding(raw, entry_file=entry_file, tools=tools))
    return findings


def _build_finding(
    raw: dict[str, Any],
    *,
    entry_file: str,
    tools: AuditReadOnlyTools,
) -> Finding:
    _validate_finding_shape(raw)
    classification = _validate_classification(raw, entry_file=entry_file, tools=tools)
    evidence = _validate_finding_evidence(
        raw,
        classification=classification,
        tools=tools,
    )
    narrative = _validate_narrative(raw)
    logic_evidence = _build_logic_evidence(classification, evidence, narrative)
    return _create_finding(classification, evidence, narrative, logic_evidence)


def _validate_finding_shape(raw: dict[str, Any]) -> None:
    expected = set(LOGIC_FINDING_SCHEMA["required"])
    if set(raw) != expected:
        raise InvestigationIncompleteError(
            "logic finding has missing or unsupported fields"
        )


def _validate_classification(
    raw: dict[str, Any],
    *,
    entry_file: str,
    tools: AuditReadOnlyTools,
) -> _FindingClassification:
    category = enum_string(raw, "category", set(INVESTIGATION_CATEGORIES))
    issue_type = enum_string(raw, "issue_type", {"security", "bug"})
    severity = enum_string(raw, "severity", {"critical", "high", "medium", "low"})
    confidence = enum_string(raw, "confidence", {"high", "medium"})
    primary_file = required_string(raw, "primary_file")
    if primary_file != entry_file:
        raise InvestigationIncompleteError(
            "logic finding must be anchored to the investigated entry file"
        )
    line = strict_positive_int(raw.get("line"), "finding line")
    end_line = optional_strict_positive_int(raw.get("end_line"), "finding end_line")
    tools.validate_evidence(primary_file, line, end_line)
    return _FindingClassification(
        category=category,
        issue_type=issue_type,
        severity=severity,
        confidence=confidence,
        primary_file=primary_file,
        line=line,
        end_line=end_line,
    )


def _validate_finding_evidence(
    raw: dict[str, Any],
    *,
    classification: _FindingClassification,
    tools: AuditReadOnlyTools,
) -> _FindingEvidence:
    evidence = validate_evidence_list(raw, "evidence", tools=tools)
    _require_primary_evidence(evidence, classification)
    mitigations = required_string_list(raw, "mitigations_checked", allow_empty=False)
    mitigation_evidence = validate_mitigation_checks(
        raw.get("mitigation_evidence"),
        mitigations=mitigations,
        tools=tools,
    )
    _require_related_mitigation_evidence(classification, mitigation_evidence, tools)
    counterevidence = required_string_list(raw, "counterevidence", allow_empty=True)
    _validate_evidence_list_sizes(mitigations, counterevidence)
    return _FindingEvidence(
        evidence=evidence,
        mitigations=mitigations,
        mitigation_evidence=mitigation_evidence,
        counterevidence=counterevidence,
    )


def _require_primary_evidence(
    evidence: list[dict[str, Any]],
    classification: _FindingClassification,
) -> None:
    covers_location = any(
        item["file"] == classification.primary_file
        and item["line"] <= classification.line <= item["end_line"]
        for item in evidence
    )
    if not covers_location:
        raise InvestigationIncompleteError(
            "logic finding requires primary-file evidence covering its location"
        )


def _require_related_mitigation_evidence(
    classification: _FindingClassification,
    mitigation_evidence: list[dict[str, Any]],
    tools: AuditReadOnlyTools,
) -> None:
    if classification.category not in LOGIC_CATEGORIES or tools.catalog_size <= 1:
        return
    if _has_related_evidence(mitigation_evidence, classification.primary_file):
        return
    raise InvestigationIncompleteError(
        "logic finding requires related-file mitigation evidence"
    )


def _has_related_evidence(
    mitigation_evidence: list[dict[str, Any]],
    primary_file: str,
) -> bool:
    for check in mitigation_evidence:
        for item in check["evidence"]:
            if item["file"] != primary_file:
                return True
    return False


def _validate_evidence_list_sizes(
    mitigations: list[str],
    counterevidence: list[str],
) -> None:
    if len(mitigations) > 12 or len(counterevidence) > 12:
        raise InvestigationIncompleteError("logic finding evidence lists are too large")


def _validate_narrative(raw: dict[str, Any]) -> _FindingNarrative:
    values = {
        key: required_string(raw, key)
        for key in (
            "actor",
            "action",
            "resource",
            "trigger",
            "invariant",
            "actual_behavior",
            "impact",
            "suggestion",
        )
    }
    message = required_string(raw, "message")
    if len(message) > 500:
        raise InvestigationIncompleteError("logic finding message is too long")
    symbol_value = raw.get("symbol")
    if symbol_value is not None and not isinstance(symbol_value, str):
        raise InvestigationIncompleteError(
            "logic finding symbol must be a string or null"
        )
    return _FindingNarrative(
        **values,
        message=message,
        symbol=symbol_value,
    )


def _build_logic_evidence(
    classification: _FindingClassification,
    evidence: _FindingEvidence,
    narrative: _FindingNarrative,
) -> dict[str, Any]:
    return {
        "category": classification.category,
        "actor": narrative.actor,
        "action": narrative.action,
        "resource": narrative.resource,
        "trigger": narrative.trigger,
        "invariant": narrative.invariant,
        "actual_behavior": narrative.actual_behavior,
        "impact": narrative.impact,
        "evidence": evidence.evidence,
        "mitigations_checked": evidence.mitigations,
        "mitigation_evidence": evidence.mitigation_evidence,
        "counterevidence": evidence.counterevidence,
    }


def _build_explanation(
    narrative: _FindingNarrative,
    evidence: _FindingEvidence,
) -> str:
    mitigations = "; ".join(evidence.mitigations)
    return (
        f"Invariant: {narrative.invariant}\n\n"
        f"Actual behavior: {narrative.actual_behavior}\n\n"
        f"Trigger: {narrative.trigger}\n\n"
        f"Mitigations checked: {mitigations}"
    )


def _build_security_details(
    classification: _FindingClassification,
    evidence: _FindingEvidence,
    narrative: _FindingNarrative,
) -> dict[str, Any] | None:
    if classification.issue_type != "security":
        return None
    primary_lines = [
        item["line"]
        for item in evidence.evidence
        if item["file"] == classification.primary_file
    ]
    return {
        "attack_path": (
            f"{narrative.actor} can {narrative.action} on "
            f"{narrative.resource}: {narrative.trigger}"
        ),
        "impact": narrative.impact,
        "fix": narrative.suggestion,
        "evidence_lines": sorted(set(primary_lines or [classification.line])),
        "unsafe_if": narrative.invariant,
    }


def _build_metadata(
    category: str,
    logic_evidence: dict[str, Any],
) -> dict[str, Any]:
    metadata = {"investigation_evidence": logic_evidence}
    if category in LOGIC_CATEGORIES:
        metadata["logic_evidence"] = logic_evidence
    return metadata


def _create_finding(
    classification: _FindingClassification,
    evidence: _FindingEvidence,
    narrative: _FindingNarrative,
    logic_evidence: dict[str, Any],
) -> Finding:
    category = classification.category
    rule_id = LOGIC_RULE_ID if category in LOGIC_CATEGORIES else SECURITY_RULE_ID
    symbol = narrative.symbol.strip() if narrative.symbol is not None else None
    references = [
        f"{item['file']}:{item['line']}-{item['end_line']}"
        for item in evidence.evidence
    ]
    explanation = _build_explanation(narrative, evidence)
    security_details = _build_security_details(classification, evidence, narrative)
    metadata = _build_metadata(category, logic_evidence)
    return Finding(
        rule_id=rule_id,
        issue_type=IssueType(classification.issue_type),
        severity=Severity(classification.severity),
        message=narrative.message,
        location=CodeLocation(
            file=classification.primary_file,
            line=classification.line,
            end_line=classification.end_line,
        ),
        confidence=Confidence(classification.confidence),
        explanation=explanation,
        suggestion=narrative.suggestion,
        references=references,
        symbol=symbol,
        metadata=metadata,
        security_details=security_details,
    )
