"""Source-evidence validation for findings and clean completions."""

from __future__ import annotations

from typing import Any

from skylos.audit.investigator_tools import AuditReadOnlyTools

from .models import InvestigationIncompleteError
from .protocol import EVIDENCE_SCHEMA


def validate_evidence_list(
    raw: dict[str, Any],
    key: str,
    *,
    tools: AuditReadOnlyTools,
) -> list[dict[str, Any]]:
    return _validate_evidence_items(
        raw.get(key),
        key,
        tools=tools,
        max_items=12,
    )


def _validate_evidence_items(
    raw_items: Any,
    label: str,
    *,
    tools: AuditReadOnlyTools,
    max_items: int = 24,
) -> list[dict[str, Any]]:
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > max_items:
        raise InvestigationIncompleteError(f"investigation requires {label}")
    evidence: list[dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict) or set(item) != set(EVIDENCE_SCHEMA["required"]):
            raise InvestigationIncompleteError(f"{label} shape is invalid")
        evidence_file = required_string(item, "file")
        evidence_line = strict_positive_int(item.get("line"), f"{label} line")
        evidence_end = optional_strict_positive_int(
            item.get("end_line"), f"{label} end_line"
        )
        rel_path, start, end = tools.validate_evidence(
            evidence_file,
            evidence_line,
            evidence_end,
        )
        evidence.append(
            {
                "file": rel_path,
                "line": start,
                "end_line": end,
                "role": required_string(item, "role"),
                "file_hash": tools.related_file_hashes[rel_path],
            }
        )
    return evidence


def validate_mitigation_checks(
    raw_items: Any,
    *,
    mitigations: list[str],
    tools: AuditReadOnlyTools,
) -> list[dict[str, Any]]:
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 12:
        raise InvestigationIncompleteError(
            "logic finding requires structured mitigation evidence"
        )
    checks: list[dict[str, Any]] = []
    names: list[str] = []
    for item in raw_items:
        if not isinstance(item, dict) or set(item) != {
            "mitigation",
            "outcome",
            "evidence",
        }:
            raise InvestigationIncompleteError(
                "logic finding mitigation evidence shape is invalid"
            )
        name = required_string(item, "mitigation")
        outcome = enum_string(
            item,
            "outcome",
            {"absent", "insufficient", "bypassed", "not_applicable"},
        )
        names.append(name)
        checks.append(
            {
                "mitigation": name,
                "outcome": outcome,
                "evidence": _validate_evidence_items(
                    item.get("evidence"),
                    f"mitigation evidence for {name}",
                    tools=tools,
                    max_items=6,
                ),
            }
        )
    if len(names) != len(set(names)) or set(names) != set(mitigations):
        raise InvestigationIncompleteError(
            "every mitigation claim must map exactly once to source evidence"
        )
    return checks


def validate_clean_proofs(
    raw_items: Any,
    *,
    expected_candidate_ids: tuple[str, ...],
    tools: AuditReadOnlyTools,
) -> list[dict[str, Any]]:
    if not isinstance(raw_items, list) or not raw_items or len(raw_items) > 12:
        raise InvestigationIncompleteError(
            "investigation requires clean_evidence proof bundles"
        )
    expected = set(expected_candidate_ids)
    mapped: list[str] = []
    proofs: list[dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict) or set(item) != {
            "invariant",
            "candidate_ids",
            "evidence",
        }:
            raise InvestigationIncompleteError("clean_evidence proof shape is invalid")
        candidate_ids = item.get("candidate_ids")
        if not isinstance(candidate_ids, list) or not all(
            isinstance(candidate_id, str) for candidate_id in candidate_ids
        ):
            raise InvestigationIncompleteError(
                "clean_evidence candidate IDs must be an array of strings"
            )
        if len(candidate_ids) != len(set(candidate_ids)) or not set(
            candidate_ids
        ).issubset(expected):
            raise InvestigationIncompleteError(
                "clean_evidence references unknown or duplicate candidate IDs"
            )
        mapped.extend(candidate_ids)
        proofs.append(
            {
                "invariant": required_string(item, "invariant"),
                "candidate_ids": list(candidate_ids),
                "evidence": _validate_evidence_items(
                    item.get("evidence"),
                    "clean_evidence source evidence",
                    tools=tools,
                    max_items=12,
                ),
            }
        )
    if len(mapped) != len(set(mapped)) or set(mapped) != expected:
        raise InvestigationIncompleteError(
            "clean_evidence must map every supplied candidate exactly once"
        )
    return proofs


def required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InvestigationIncompleteError(f"logic finding requires {key}")
    return value.strip()


def required_string_list(
    payload: dict[str, Any], key: str, *, allow_empty: bool
) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise InvestigationIncompleteError(f"logic finding {key} must be strings")
    if not allow_empty and not value:
        raise InvestigationIncompleteError(f"logic finding requires {key}")
    return [item.strip() for item in value]


def enum_string(payload: dict[str, Any], key: str, allowed: set[str]) -> str:
    value = required_string(payload, key).lower()
    if value not in allowed:
        raise InvestigationIncompleteError(f"logic finding {key} is invalid")
    return value


def strict_positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvestigationIncompleteError(f"{name} must be a positive integer")
    return value


def optional_strict_positive_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    return strict_positive_int(value, name)
