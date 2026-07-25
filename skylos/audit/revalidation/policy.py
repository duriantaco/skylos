"""Policy, freshness, and provenance helpers for finding revalidation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skylos.audit.freshness import (
    REVALIDATION_DEFINITION_HASH,
    REVALIDATION_PROTOCOL_VERSION,
    finding_fingerprint,
    latest_current_revalidation,
)
from skylos.audit.investigator_tools import (
    DEFAULT_EXCLUDED_FOLDERS,
    INVESTIGATOR_TOOL_SCHEMA_VERSION,
    AuditReadOnlyTools,
)
from skylos.audit.redaction import redact_text, sanitize_for_audit
from skylos.audit.revalidation.constants import (
    MAX_REFUTING_INVARIANT_CHARS,
    MAX_REVALIDATION_SOURCE_BYTES,
    SUPPRESSING_VERDICTS,
    VALID_VERDICTS,
)
from skylos.audit.store import AuditStore
from skylos.audit.types import AuditFileRecord, sha256_text
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.llm.investigator import (
    INVESTIGATOR_DEFINITION_HASH,
    InvestigationIncompleteError,
)


CatalogPolicy = dict[str, list[str]]
CatalogFreshnessCache = dict[tuple[Any, ...], bool]


def catalog_policy(
    store: AuditStore,
    records: list[AuditFileRecord],
) -> CatalogPolicy:
    stored_folders, stored_paths = store.read_scan_excludes()
    exclude_folders = list(dict.fromkeys((*DEFAULT_EXCLUDED_FOLDERS, *stored_folders)))
    denied_paths = sorted(
        record.file for record in records if is_secret_bearing_record(record)
    )
    return {
        "exclude_folders": exclude_folders,
        "excluded_paths": list(stored_paths),
        "denied_paths": denied_paths,
    }


def has_secret_candidate(record: AuditFileRecord) -> bool:
    return any(
        candidate.redacted or candidate.rule_id.startswith("SKY-S")
        for candidate in record.candidates
    )


def is_secret_bearing_record(record: AuditFileRecord) -> bool:
    name = Path(record.file).name.lower()
    return (
        record.language == "env"
        or name == ".env"
        or name.startswith(".env.")
        or has_secret_candidate(record)
    )


def finding_id(finding: dict[str, Any]) -> str:
    existing = finding.get("audit_finding_id")
    if existing:
        return str(existing)
    payload = json.dumps(finding, sort_keys=True, default=str)
    return "finding-" + sha256_text(payload)[:16]


def has_current_verdict(
    record: AuditFileRecord,
    finding: dict[str, Any],
    *,
    model: str,
    provider: str | None,
    challenge: bool,
    catalog_cache: CatalogFreshnessCache,
) -> bool:
    mode = "challenge" if challenge else "revalidate"
    entry = latest_current_revalidation(
        record,
        finding,
        catalog_cache=catalog_cache,
    )
    return bool(
        entry
        and entry.get("model") == model
        and entry.get("provider") == provider
        and entry.get("mode", "revalidate") == mode
    )


def latest_verdict(record: AuditFileRecord, finding_id_value: str) -> str | None:
    for item in reversed(record.revalidation):
        if not isinstance(item, dict):
            continue
        if str(item.get("finding_id") or "") == finding_id_value:
            return str(item.get("verdict") or "").lower()
    return None


def read_current_source(store: AuditStore, record: AuditFileRecord) -> str:
    source = read_project_text_no_symlink(
        store.project_root,
        record.file,
        max_bytes=MAX_REVALIDATION_SOURCE_BYTES,
        encoding="utf-8",
        errors=None,
        newline="",
    )
    if source is None:
        raise InvestigationIncompleteError(
            f"source file could not be read safely: {record.file}"
        )
    if sha256_text(source) != record.file_hash:
        raise InvestigationIncompleteError(
            f"source changed after the stored scan: {record.file}"
        )
    return source


def build_revalidation_context(
    record: AuditFileRecord,
    finding: dict[str, Any],
    *,
    source: str,
    mode: str,
) -> dict[str, Any]:
    return sanitize_for_audit(
        {
            "mode": mode,
            "file": record.file,
            "language": record.language,
            "status": record.status,
            "finding": finding,
            "candidates": [candidate.to_dict() for candidate in record.candidates],
            "analysis_history": record.analysis_history[-5:],
            "redacted_source": redact_text(source),
            "untrusted_repository_data": True,
        }
    )


def normalize_verdict(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        payload = incomplete_verdict("Revalidation response was malformed.")
    verdict = canonical_verdict(payload.get("verdict"))
    reason = str(payload.get("reason") or "").strip() or "No reason provided."
    complete = payload.get("complete", True) is True
    evidence_validated = payload.get("evidence_validated") is True
    if _verdict_is_incomplete(payload, verdict, complete):
        verdict = "uncertain"
        complete = False
        evidence_validated = False
    refuting_invariant = _normalized_refuting_invariant(payload)
    if verdict in SUPPRESSING_VERDICTS and (
        not evidence_validated or refuting_invariant is None
    ):
        verdict = "uncertain"
        complete = False
        evidence_validated = False
        reason = (
            "Suppressing verdict lacked exact validated source evidence and "
            "a refuting invariant."
        )
    return {
        "verdict": verdict,
        "reason": reason,
        "evidence": _list_value(payload.get("evidence")),
        "evidence_validated": evidence_validated,
        "complete": complete,
        "refuting_invariant": refuting_invariant,
        "provenance": _dict_value(payload.get("provenance")),
    }


def _verdict_is_incomplete(
    payload: dict[str, Any],
    verdict: str | None,
    complete: bool,
) -> bool:
    return verdict is None or payload_indicates_refusal(payload) or not complete


def _normalized_refuting_invariant(payload: dict[str, Any]) -> str | None:
    value = payload.get("refuting_invariant")
    if not isinstance(value, str) or not value.strip():
        return None
    invariant = value.strip()
    return invariant if len(invariant) <= MAX_REFUTING_INVARIANT_CHARS else None


def _list_value(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def canonical_verdict(value: Any) -> str | None:
    verdict = str(value or "").strip().lower()
    aliases = {
        "supported": "true_positive",
        "true": "true_positive",
        "tp": "true_positive",
        "refuted": "false_positive",
        "fp": "false_positive",
    }
    verdict = aliases.get(verdict, verdict)
    return verdict if verdict in VALID_VERDICTS else None


def payload_indicates_refusal(payload: dict[str, Any]) -> bool:
    if payload.get("refusal") or payload.get("refused") or payload.get("error"):
        return True
    verdict = str(payload.get("verdict") or "").strip().lower()
    if verdict in {"refused", "denied", "error", "incomplete"}:
        return True
    reason = str(payload.get("reason") or payload.get("message") or "").lower()
    return any(
        marker in reason
        for marker in (
            "i refuse",
            "cannot comply",
            "can't comply",
            "unable to comply",
            "cannot assist",
            "won't comply",
            "will not comply",
        )
    )


def metadata_indicates_refusal(metadata: dict[str, Any]) -> bool:
    return bool(
        metadata.get("refusal")
        or metadata.get("refused")
        or metadata.get("denied")
        or metadata.get("error")
    )


def tool_provenance(
    tools: AuditReadOnlyTools,
    catalog_policy_value: CatalogPolicy,
    *,
    evidence_source: str,
) -> dict[str, Any]:
    metadata = tools.metadata()
    return {
        "evidence_source": evidence_source,
        "catalog_digest": metadata["catalog_digest"],
        "catalog_exclude_folders": list(catalog_policy_value["exclude_folders"]),
        "catalog_excluded_paths": list(catalog_policy_value["excluded_paths"]),
        "catalog_denied_paths": list(catalog_policy_value["denied_paths"]),
        "related_files": metadata["related_files"],
        "investigator_definition_hash": INVESTIGATOR_DEFINITION_HASH,
        "tool_schema_version": INVESTIGATOR_TOOL_SCHEMA_VERSION,
    }


def base_provenance(
    record: AuditFileRecord,
    finding: dict[str, Any],
    catalog_policy_value: CatalogPolicy,
) -> dict[str, Any]:
    return {
        "source_hash": record.file_hash,
        "finding_hash": finding_fingerprint(finding),
        "config_hash": record.config_hash,
        "candidate_engine_version": record.candidate_engine_version,
        "protocol_version": REVALIDATION_PROTOCOL_VERSION,
        "definition_hash": REVALIDATION_DEFINITION_HASH,
        "investigator_definition_hash": INVESTIGATOR_DEFINITION_HASH,
        "tool_schema_version": INVESTIGATOR_TOOL_SCHEMA_VERSION,
        "catalog_exclude_folders": list(catalog_policy_value["exclude_folders"]),
        "catalog_excluded_paths": list(catalog_policy_value["excluded_paths"]),
        "catalog_denied_paths": list(catalog_policy_value["denied_paths"]),
        "related_files": [],
    }


def incomplete_verdict(reason: str) -> dict[str, Any]:
    return {
        "verdict": "uncertain",
        "reason": reason,
        "evidence": [],
        "evidence_validated": False,
        "complete": False,
        "refuting_invariant": None,
        "provenance": {},
    }
