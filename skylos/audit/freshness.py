"""Freshness checks for evidence-backed Deep Audit revalidation verdicts."""

from __future__ import annotations

import json
import re
from typing import Any

from skylos.audit.investigator_tools import (
    INVESTIGATOR_TOOL_SCHEMA_VERSION,
    AuditReadOnlyTools,
)
from skylos.audit.revalidation.constants import (
    INVESTIGATOR_EVIDENCE_FIELDS,
    LEGACY_EVIDENCE_FIELDS,
    MAX_REFUTING_INVARIANT_CHARS,
    MAX_REVALIDATION_SOURCE_BYTES,
    STATE_EVIDENCE_PURPOSES,
    SUPPRESSING_VERDICTS,
    VALID_EVIDENCE_PURPOSES,
    VALID_VERDICTS,
)
from skylos.audit.types import (
    CANDIDATE_ENGINE_VERSION,
    AuditFileRecord,
    sha256_text,
    stable_json_hash,
)
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.llm.investigator import INVESTIGATOR_DEFINITION_HASH


REVALIDATION_PROTOCOL_VERSION = "deep-audit-revalidation-v3"
REVALIDATION_DEFINITION_HASH = stable_json_hash(
    {
        "protocol_version": REVALIDATION_PROTOCOL_VERSION,
        "investigator_definition_hash": INVESTIGATOR_DEFINITION_HASH,
        "tool_schema_version": INVESTIGATOR_TOOL_SCHEMA_VERSION,
        "policy": (
            "repository-match-is-true-positive; suppressing-evidence-covers-"
            "stored-location-and-supports-refuting-invariant; validated-clean-"
            "same-source-is-false-positive; validated-clean-changed-source-with-"
            "origin-hash-is-fixed; all-malformed-refusal-denial-error-results-"
            "are-incomplete; catalog-success-is-never-cached"
        ),
    }
)
_EVIDENCE_SOURCES = frozenset(
    {
        "repository_investigator",
        "legacy_verify_finding",
        "structured_adapter",
    }
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Return a deterministic fingerprint for the complete stored finding."""

    return stable_json_hash(finding)


def is_revalidation_entry_current(
    record: AuditFileRecord,
    finding: dict[str, Any],
    entry: dict[str, Any],
    *,
    catalog_cache: dict[tuple[Any, ...], bool] | None = None,
) -> bool:
    """Return whether a verdict's proof and all relevant inputs are current."""

    if not _entry_identity_is_current(record, finding, entry):
        return False
    verdict = str(entry.get("verdict") or "").lower()
    if verdict not in VALID_VERDICTS:
        return False
    evidence_validated = entry.get("evidence_validated")
    if not isinstance(evidence_validated, bool):
        return False
    related_files = entry.get("related_files")
    if not _related_files_are_current(record, related_files):
        return False
    if evidence_validated and not _evidence_matches_related_files(
        entry.get("evidence"), related_files
    ):
        return False
    if verdict in SUPPRESSING_VERDICTS and not _suppression_is_current(
        record, finding, entry
    ):
        return False
    return _catalog_is_current(record, entry, cache=catalog_cache)


def _entry_identity_is_current(
    record: AuditFileRecord,
    finding: dict[str, Any],
    entry: Any,
) -> bool:
    if not isinstance(entry, dict) or entry.get("complete") is not True:
        return False
    if record.candidate_engine_version != CANDIDATE_ENGINE_VERSION:
        return False
    if str(entry.get("finding_id") or "") != _finding_id(finding):
        return False
    expected = _expected_entry_identity(record, finding)
    return all(entry.get(key) == value for key, value in expected.items())


def _expected_entry_identity(
    record: AuditFileRecord,
    finding: dict[str, Any],
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
    }


def _suppression_is_current(
    record: AuditFileRecord,
    finding: dict[str, Any],
    entry: dict[str, Any],
) -> bool:
    if entry.get("evidence_validated") is not True:
        return False
    if not _valid_refuting_invariant(entry.get("refuting_invariant")):
        return False
    evidence_source = entry.get("evidence_source")
    if evidence_source not in _EVIDENCE_SOURCES:
        return False
    evidence = entry.get("evidence")
    if not _suppression_evidence_shape_is_current(evidence, evidence_source):
        return False
    if not _evidence_covers_stored_finding(evidence, record, finding):
        return False
    return _origin_hash_supports_verdict(record, finding, entry)


def _suppression_evidence_shape_is_current(
    evidence: Any,
    evidence_source: Any,
) -> bool:
    if not isinstance(evidence, list):
        return False
    if evidence_source == "repository_investigator":
        return all(
            isinstance(item, dict)
            and set(item) == INVESTIGATOR_EVIDENCE_FIELDS
            for item in evidence
        ) and any(item.get("purpose") == "mitigation" for item in evidence)
    return all(
        isinstance(item, dict) and set(item) == LEGACY_EVIDENCE_FIELDS
        for item in evidence
    )


def _origin_hash_supports_verdict(
    record: AuditFileRecord,
    finding: dict[str, Any],
    entry: dict[str, Any],
) -> bool:
    origin_hash = finding.get("audit_source_hash")
    if not _is_sha256(origin_hash):
        return False
    verdict = str(entry.get("verdict") or "").lower()
    if verdict == "false_positive":
        return origin_hash == record.file_hash
    return verdict == "fixed" and origin_hash != record.file_hash


def latest_current_revalidation(
    record: AuditFileRecord,
    finding: dict[str, Any],
    *,
    catalog_cache: dict[tuple[Any, ...], bool] | None = None,
) -> dict[str, Any] | None:
    """Return the newest complete revalidation whose proof is still current."""

    finding_id = _finding_id(finding)
    for entry in reversed(record.revalidation):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("finding_id") or "") != finding_id:
            continue
        if is_revalidation_entry_current(
            record,
            finding,
            entry,
            catalog_cache=catalog_cache,
        ):
            return entry
    return None


def _finding_id(finding: dict[str, Any]) -> str:
    existing = finding.get("audit_finding_id")
    if existing:
        return str(existing)
    return (
        "finding-" + sha256_text(json.dumps(finding, sort_keys=True, default=str))[:16]
    )


def _related_files_are_current(record: AuditFileRecord, value: Any) -> bool:
    if not isinstance(value, list) or not value or len(value) > 24:
        return False
    seen: set[str] = set()
    current_files = [
        _current_related_file(record, item, seen=seen) for item in value
    ]
    if any(item is None for item in current_files):
        return False
    current_hashes = dict(item for item in current_files if item is not None)
    return current_hashes.get(record.file) == record.file_hash


def _current_related_file(
    record: AuditFileRecord,
    item: Any,
    *,
    seen: set[str],
) -> tuple[str, str] | None:
    if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
        return None
    path = item.get("path")
    expected_hash = item.get("sha256")
    if (
        not isinstance(path, str)
        or not path
        or path in seen
        or not _is_sha256(expected_hash)
    ):
        return None
    seen.add(path)
    source = read_project_text_no_symlink(
        record.project_root,
        path,
        max_bytes=MAX_REVALIDATION_SOURCE_BYTES,
        encoding="utf-8",
        errors=None,
        newline="",
    )
    if source is None or sha256_text(source) != expected_hash:
        return None
    return path, expected_hash


def _catalog_is_current(
    record: AuditFileRecord,
    entry: dict[str, Any],
    *,
    cache: dict[tuple[Any, ...], bool] | None,
) -> bool:
    policy = _catalog_policy_from_entry(entry)
    digest = entry.get("catalog_digest")
    if policy is None or not _is_sha256(digest):
        return False
    cache_key = (record.project_root, digest, *map(tuple, policy))
    if cache is not None and cache.get(cache_key) is False:
        return False
    try:
        metadata = _current_catalog_metadata(record, policy)
    except (OSError, RuntimeError, ValueError):
        return _cache_catalog_failure(cache, cache_key)
    current = metadata.get("catalog_digest") == digest and not metadata.get(
        "catalog_truncated"
    )
    if not current:
        _cache_catalog_failure(cache, cache_key)
    return current


def _catalog_policy_from_entry(
    entry: dict[str, Any],
) -> tuple[list[str], list[str], list[str]] | None:
    exclude_folders = _string_list(entry.get("catalog_exclude_folders"))
    excluded_paths = _string_list(entry.get("catalog_excluded_paths"))
    denied_paths = _string_list(entry.get("catalog_denied_paths"))
    if exclude_folders is None or excluded_paths is None or denied_paths is None:
        return None
    return exclude_folders, excluded_paths, denied_paths


def _current_catalog_metadata(
    record: AuditFileRecord,
    policy: tuple[list[str], list[str], list[str]],
) -> dict[str, Any]:
    exclude_folders, excluded_paths, denied_paths = policy
    tools = AuditReadOnlyTools(
        record.project_root,
        exclude_folders=tuple(exclude_folders),
        denied_paths=tuple(denied_paths),
        excluded_paths=tuple(excluded_paths),
    )
    return tools.metadata()


def _cache_catalog_failure(
    cache: dict[tuple[Any, ...], bool] | None,
    cache_key: tuple[Any, ...],
) -> bool:
    if cache is not None:
        cache[cache_key] = False
    return False


def _evidence_matches_related_files(value: Any, related_files: Any) -> bool:
    if not isinstance(value, list) or not value or len(value) > 24:
        return False
    related_hashes = _related_hashes(related_files)
    if related_hashes is None:
        return False
    if not all(_evidence_item_is_valid(item, related_hashes) for item in value):
        return False
    return _causal_pairs_are_complete(value)


def _related_hashes(value: Any) -> dict[str, str] | None:
    if not isinstance(value, list):
        return None
    return {
        item.get("path"): item.get("sha256")
        for item in value
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("sha256"), str)
    }


def _evidence_item_is_valid(
    item: Any,
    related_hashes: dict[str, str],
) -> bool:
    if not isinstance(item, dict):
        return False
    fields = frozenset(item)
    if fields not in {LEGACY_EVIDENCE_FIELDS, INVESTIGATOR_EVIDENCE_FIELDS}:
        return False
    if not _base_evidence_fields_are_valid(item, related_hashes):
        return False
    return (
        fields == LEGACY_EVIDENCE_FIELDS
        or _investigator_evidence_fields_are_valid(item)
    )


def _base_evidence_fields_are_valid(
    item: dict[str, Any],
    related_hashes: dict[str, str],
) -> bool:
    path = item.get("file")
    line = item.get("line")
    end_line = item.get("end_line")
    role = item.get("role")
    return bool(
        isinstance(path, str)
        and _is_positive_int(line)
        and _is_positive_int(end_line)
        and end_line >= line
        and isinstance(role, str)
        and role.strip()
        and related_hashes.get(path) == item.get("file_hash")
    )


def _investigator_evidence_fields_are_valid(item: dict[str, Any]) -> bool:
    purpose = item.get("purpose")
    pair = item.get("causal_pair")
    if purpose not in VALID_EVIDENCE_PURPOSES:
        return False
    if purpose in STATE_EVIDENCE_PURPOSES:
        return isinstance(pair, str) and 0 < len(pair.strip()) <= 80
    return pair is None


def _causal_pairs_are_complete(value: list[Any]) -> bool:
    pairs: dict[str, set[str]] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        pair = item.get("causal_pair")
        if isinstance(pair, str):
            pairs.setdefault(pair, set()).add(str(item.get("purpose")))
    return all(purposes == STATE_EVIDENCE_PURPOSES for purposes in pairs.values())


def _evidence_covers_stored_finding(
    evidence: Any,
    record: AuditFileRecord,
    finding: dict[str, Any],
) -> bool:
    location = finding.get("location")
    location_range = _location_range(location)
    if not isinstance(evidence, list) or location_range is None:
        return False
    start, end = location_range
    return any(
        isinstance(item, dict)
        and item.get("file") == record.file
        and _is_positive_int(item.get("line"))
        and _is_positive_int(item.get("end_line"))
        and item["line"] <= start
        and item["end_line"] >= end
        for item in evidence
    )


def _location_range(value: Any) -> tuple[int, int] | None:
    if not isinstance(value, dict):
        return None
    line = value.get("line")
    end_line = value.get("end_line") or line
    if not _is_positive_int(line) or not _is_positive_int(end_line):
        return None
    return (line, end_line) if end_line >= line else None


def _valid_refuting_invariant(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= MAX_REFUTING_INVARIANT_CHARS
    )


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or len(value) > 1000:
        return None
    if not all(isinstance(item, str) and item for item in value):
        return None
    if len(value) != len(set(value)):
        return None
    return list(value)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None
