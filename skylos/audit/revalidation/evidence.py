"""Validation and matching for revalidation source evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from skylos.audit.investigator_tools import AuditReadOnlyTools
from skylos.audit.revalidation.constants import (
    INVESTIGATOR_EVIDENCE_FIELDS,
    MAX_REFUTING_INVARIANT_CHARS,
    STATE_EVIDENCE_PURPOSES,
    VALID_EVIDENCE_PURPOSES,
)
from skylos.audit.types import AuditFileRecord
from skylos.llm.investigator import InvestigationIncompleteError


@dataclass(frozen=True)
class ValidatedCleanEvidence:
    """Validated source proof and its reviewable refuting invariant."""

    evidence: list[dict[str, Any]]
    refuting_invariant: str


def validate_exact_evidence(
    value: Any,
    *,
    tools: AuditReadOnlyTools,
    record: AuditFileRecord,
    finding: dict[str, Any],
) -> list[dict[str, Any]]:
    """Validate legacy evidence and require it to cover the stored finding."""

    items = _required_evidence_list(value, "suppressing revalidation")
    validated = [_validate_exact_item(item, tools=tools) for item in items]
    require_evidence_covers_finding(validated, record=record, finding=finding)
    return validated


def _validate_exact_item(
    item: Any,
    *,
    tools: AuditReadOnlyTools,
) -> dict[str, Any]:
    required = {"file", "line", "end_line", "role"}
    if not isinstance(item, dict) or set(item) != required:
        raise InvestigationIncompleteError("revalidation evidence shape is invalid")
    role = required_string(item.get("role"), "revalidation evidence role")
    path, start, end = tools.validate_evidence(
        str(item.get("file") or ""),
        strict_positive_int(item.get("line"), "evidence line"),
        strict_positive_int(item.get("end_line"), "evidence end_line"),
    )
    return {
        "file": path,
        "line": start,
        "end_line": end,
        "role": role,
        "file_hash": tools.related_file_hashes[path],
    }


def validate_clean_evidence(
    value: Any,
    *,
    candidate_id: str,
    record: AuditFileRecord,
    finding: dict[str, Any],
    tools: AuditReadOnlyTools,
) -> ValidatedCleanEvidence:
    """Validate current-protocol clean proof for a suppressing verdict."""

    proofs = _required_evidence_list(value, "clean revalidation proof")
    validated = [
        _validate_clean_proof(proof, tools=tools) for proof in proofs
    ]
    mapped = [
        candidate
        for candidate_ids, _invariant, _evidence in validated
        for candidate in candidate_ids
    ]
    if mapped != [candidate_id]:
        raise InvestigationIncompleteError(
            "clean proof did not map the finding exactly"
        )
    evidence = [
        item
        for _candidate_ids, _invariant, proof_evidence in validated
        for item in proof_evidence
    ]
    _require_clean_source_coverage(evidence, record=record, tools=tools)
    require_evidence_covers_finding(evidence, record=record, finding=finding)
    if not any(item["purpose"] == "mitigation" for item in evidence):
        raise InvestigationIncompleteError(
            "clean proof lacks evidence supporting its refuting invariant"
        )
    tools.assert_completion_safe()
    invariants = [invariant for _ids, invariant, _evidence in validated]
    refuting_invariant = " | ".join(dict.fromkeys(invariants))
    return ValidatedCleanEvidence(
        evidence=evidence,
        refuting_invariant=validate_refuting_invariant(refuting_invariant),
    )


def _validate_clean_proof(
    proof: Any,
    *,
    tools: AuditReadOnlyTools,
) -> tuple[list[str], str, list[dict[str, Any]]]:
    if not isinstance(proof, dict) or set(proof) != {
        "invariant",
        "candidate_ids",
        "evidence",
    }:
        raise InvestigationIncompleteError("clean revalidation proof is malformed")
    candidate_ids = proof.get("candidate_ids")
    if not isinstance(candidate_ids, list) or not all(
        isinstance(item, str) for item in candidate_ids
    ):
        raise InvestigationIncompleteError("clean proof candidate map is invalid")
    evidence = validate_normalized_evidence(proof.get("evidence"), tools=tools)
    _require_complete_causal_pairs(evidence)
    return (
        list(candidate_ids),
        validate_refuting_invariant(proof.get("invariant")),
        evidence,
    )


def _require_clean_source_coverage(
    evidence: list[dict[str, Any]],
    *,
    record: AuditFileRecord,
    tools: AuditReadOnlyTools,
) -> None:
    evidence_files = {item["file"] for item in evidence}
    if record.file not in evidence_files:
        raise InvestigationIncompleteError("clean proof does not cover the entry file")
    if tools.catalog_size > 1 and evidence_files == {record.file}:
        raise InvestigationIncompleteError("clean proof lacks related-source evidence")
    if tools.source_observation_calls == 0:
        raise InvestigationIncompleteError("clean proof lacks a repository source read")


def validate_normalized_evidence(
    value: Any,
    *,
    tools: AuditReadOnlyTools,
) -> list[dict[str, Any]]:
    """Validate evidence normalized by the protocol-v3 investigator."""

    items = _required_evidence_list(value, "investigator")
    return [_validate_normalized_item(item, tools=tools) for item in items]


def _validate_normalized_item(
    item: Any,
    *,
    tools: AuditReadOnlyTools,
) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != INVESTIGATOR_EVIDENCE_FIELDS:
        raise InvestigationIncompleteError("investigator evidence is malformed")
    path, start, end = tools.validate_evidence(
        str(item.get("file") or ""),
        strict_positive_int(item.get("line"), "evidence line"),
        strict_positive_int(item.get("end_line"), "evidence end_line"),
    )
    if item.get("file_hash") != tools.related_file_hashes[path]:
        raise InvestigationIncompleteError("investigator evidence hash is stale")
    purpose = required_string(item.get("purpose"), "evidence purpose").lower()
    if purpose not in VALID_EVIDENCE_PURPOSES:
        raise InvestigationIncompleteError("investigator evidence purpose is invalid")
    return {
        "file": path,
        "line": start,
        "end_line": end,
        "role": required_string(item.get("role"), "investigator evidence role"),
        "purpose": purpose,
        "causal_pair": _validate_causal_pair(
            item.get("causal_pair"),
            purpose=purpose,
        ),
        "file_hash": tools.related_file_hashes[path],
    }


def _validate_causal_pair(value: Any, *, purpose: str) -> str | None:
    if value is None:
        if purpose in STATE_EVIDENCE_PURPOSES:
            raise InvestigationIncompleteError(
                "shared-state evidence requires a causal pair"
            )
        return None
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 80:
        raise InvestigationIncompleteError(
            "investigator evidence causal_pair is invalid"
        )
    if purpose not in STATE_EVIDENCE_PURPOSES:
        raise InvestigationIncompleteError(
            "causal pair is allowed only for shared-state evidence"
        )
    return value.strip()


def _require_complete_causal_pairs(evidence: list[dict[str, Any]]) -> None:
    pairs: dict[str, set[str]] = {}
    for item in evidence:
        pair = item["causal_pair"]
        if pair is not None:
            pairs.setdefault(pair, set()).add(item["purpose"])
    if any(purposes != STATE_EVIDENCE_PURPOSES for purposes in pairs.values()):
        raise InvestigationIncompleteError(
            "shared-state causal pair requires population and consumption evidence"
        )


def validate_investigator_finding_evidence(
    finding: dict[str, Any],
    *,
    tools: AuditReadOnlyTools,
    record: AuditFileRecord,
) -> list[dict[str, Any]]:
    metadata = finding.get("metadata")
    investigation = (
        metadata.get("investigation_evidence") if isinstance(metadata, dict) else None
    )
    if not isinstance(investigation, dict):
        raise InvestigationIncompleteError("matching finding lacks investigator proof")
    evidence = validate_normalized_evidence(investigation.get("evidence"), tools=tools)
    _require_complete_causal_pairs(evidence)
    location = finding.get("location")
    location_range = line_range(location) if isinstance(location, dict) else None
    if location_range is None or not _evidence_covers_range(
        evidence,
        file=record.file,
        location_range=location_range,
    ):
        raise InvestigationIncompleteError("finding proof does not cover its location")
    tools.assert_completion_safe()
    return evidence


def require_evidence_covers_finding(
    evidence: list[dict[str, Any]],
    *,
    record: AuditFileRecord,
    finding: dict[str, Any],
) -> None:
    """Require proof to span the complete stored finding location."""

    location = finding.get("location")
    location_range = line_range(location) if isinstance(location, dict) else None
    if location_range is None or not _evidence_covers_range(
        evidence,
        file=record.file,
        location_range=location_range,
    ):
        raise InvestigationIncompleteError(
            "suppressing evidence does not cover the stored finding location"
        )


def _evidence_covers_range(
    evidence: list[dict[str, Any]],
    *,
    file: str,
    location_range: tuple[int, int],
) -> bool:
    start, end = location_range
    return any(
        item["file"] == file
        and item["line"] <= start
        and item["end_line"] >= end
        for item in evidence
    )


def validate_refuting_invariant(value: Any) -> str:
    invariant = required_string(value, "refuting invariant")
    if len(invariant) > MAX_REFUTING_INVARIANT_CHARS:
        raise InvestigationIncompleteError("refuting invariant is too long")
    return invariant


def _required_evidence_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list) or not value or len(value) > 12:
        raise InvestigationIncompleteError(f"{label} evidence is missing")
    return value


def finding_payload(value: Any) -> dict[str, Any] | None:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return value if isinstance(value, dict) else None


def investigator_finding_matches(
    candidate: dict[str, Any],
    stored: dict[str, Any],
    record: AuditFileRecord,
) -> bool:
    location = candidate.get("location")
    stored_location = stored.get("location")
    if not isinstance(location, dict) or not isinstance(stored_location, dict):
        return False
    if location.get("file") != record.file:
        return False
    candidate_range = line_range(location)
    stored_range = line_range(stored_location)
    if candidate_range is None or stored_range is None:
        return False
    if candidate_range[1] < stored_range[0] or stored_range[1] < candidate_range[0]:
        return False
    stored_type = stored.get("issue_type")
    candidate_type = candidate.get("issue_type")
    return not (stored_type and candidate_type and stored_type != candidate_type)


def line_range(location: dict[str, Any]) -> tuple[int, int] | None:
    try:
        line = strict_positive_int(location.get("line"), "finding line")
        end = strict_positive_int(location.get("end_line") or line, "finding end line")
    except InvestigationIncompleteError:
        return None
    return (line, end) if end >= line else None


def origin_source_hash(finding: dict[str, Any]) -> str | None:
    value = finding.get("audit_source_hash")
    if not isinstance(value, str) or len(value) != 64:
        return None
    if any(character not in "0123456789abcdef" for character in value):
        return None
    return value


def required_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvestigationIncompleteError(f"{name} is invalid")
    return value.strip()


def strict_positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvestigationIncompleteError(f"{name} must be a positive integer")
    return value


def positive_int(value: Any) -> int:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else 1
    )
