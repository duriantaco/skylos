from __future__ import annotations

from collections.abc import Iterable
from typing import Any


SCHEMA_VERSION = 1

PROOF_STATE_VERIFIED = "verified"
PROOF_STATE_CANDIDATE = "candidate"
PROOF_STATE_REFUTED = "refuted"
PROOF_STATE_INCOMPLETE = "incomplete"

PROOF_STATES = {
    PROOF_STATE_VERIFIED,
    PROOF_STATE_CANDIDATE,
    PROOF_STATE_REFUTED,
    PROOF_STATE_INCOMPLETE,
}

_PROOF_STATE_ALIASES = {
    "confirmed": PROOF_STATE_VERIFIED,
    "proven": PROOF_STATE_VERIFIED,
    "review_supported": PROOF_STATE_VERIFIED,
    "supported": PROOF_STATE_VERIFIED,
    "true_positive": PROOF_STATE_VERIFIED,
    "tp": PROOF_STATE_VERIFIED,
    "hypothesis": PROOF_STATE_CANDIDATE,
    "pending": PROOF_STATE_CANDIDATE,
    "speculative": PROOF_STATE_CANDIDATE,
    "static_unvalidated": PROOF_STATE_CANDIDATE,
    "unverified": PROOF_STATE_INCOMPLETE,
    "unknown": PROOF_STATE_INCOMPLETE,
    "unsupported": PROOF_STATE_INCOMPLETE,
    "false_positive": PROOF_STATE_REFUTED,
    "fp": PROOF_STATE_REFUTED,
}

AI_DEFECT_RULE_IDS = {
    "SKY-A101",
    "SKY-A102",
    "SKY-A103",
    "SKY-A104",
    "SKY-A105",
    "SKY-D222",
    "SKY-D224",
    "SKY-D225",
    "SKY-L011",
    "SKY-L012",
    "SKY-L023",
}

AI_VIBE_CATEGORIES = {
    "api_signature_hallucination",
    "assertion_weakening",
    "ci_permission_expansion",
    "dependency_hallucination",
    "disabled_security_control",
    "ghost_config",
    "hallucinated_reference",
    "incomplete_generation",
    "missing_contract_guardrail",
    "missing_resilience_control",
    "public_api_surface_drift",
    "stale_reference",
    "test_impact_gap",
}

_HIGH_IMPACT_CATEGORIES = {"ai_defect", "security", "danger"}
_HIGH_IMPACT_SEVERITIES = {"HIGH", "CRITICAL"}


def finding_evidence_contract(finding: dict[str, Any]) -> dict[str, Any] | None:
    """Return a normalized evidence contract for high-impact findings."""
    explicit = _explicit_contract(finding)
    if explicit is not None:
        return normalize_evidence_contract(explicit, finding=finding)

    if not _is_high_impact_finding(finding):
        return None

    return synthesize_evidence_contract(finding)


def attach_evidence_contract(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy with `evidence_contract` when the finding needs one."""
    evidence_contract = finding_evidence_contract(finding)
    if evidence_contract is None:
        return dict(finding)

    enriched = dict(finding)
    enriched["evidence_contract"] = evidence_contract
    return enriched


def normalize_evidence_contract(
    evidence_contract: dict[str, Any],
    *,
    finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    limitations = _normal_list(_first_present(evidence_contract, "limitations", "limitation"))

    sources = _normal_list(_first_present(evidence_contract, "sources", "source"))
    sinks = _normal_list(_first_present(evidence_contract, "sinks", "sink"))
    symbols = _normal_list(_first_present(evidence_contract, "symbols", "symbol"))
    traces = _normal_list(_first_present(evidence_contract, "traces", "trace"))

    if finding is not None:
        _merge_synthetic_fields(finding, sources, sinks, symbols, traces, limitations)

    has_evidence = any((sources, sinks, symbols, traces))
    proof_state = _normalize_proof_state(
        _first_present(evidence_contract, "proof_state", "state", "verification_state"),
        has_evidence=has_evidence,
        limitations=limitations,
    )

    if not has_evidence:
        _append_unique(limitations, "No structured evidence fields supplied.")

    return {
        "schema_version": SCHEMA_VERSION,
        "proof_state": proof_state,
        "sources": sources,
        "sinks": sinks,
        "symbols": symbols,
        "traces": traces,
        "limitations": limitations,
    }


def synthesize_evidence_contract(finding: dict[str, Any]) -> dict[str, Any]:
    sources: list[Any] = []
    sinks: list[Any] = []
    symbols: list[Any] = []
    traces: list[Any] = []
    limitations: list[Any] = []

    _merge_synthetic_fields(finding, sources, sinks, symbols, traces, limitations)

    has_evidence = any((sources, sinks, symbols, traces))
    proof_state = _normalize_proof_state(
        _metadata_proof_state(finding),
        has_evidence=has_evidence,
        limitations=limitations,
    )

    if not has_evidence:
        _append_unique(limitations, "No structured evidence fields supplied.")

    return {
        "schema_version": SCHEMA_VERSION,
        "proof_state": proof_state,
        "sources": sources,
        "sinks": sinks,
        "symbols": symbols,
        "traces": traces,
        "limitations": limitations,
    }


def _merge_synthetic_fields(
    finding: dict[str, Any],
    sources: list[Any],
    sinks: list[Any],
    symbols: list[Any],
    traces: list[Any],
    limitations: list[Any],
) -> None:
    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    _merge_many(symbols, _finding_symbols(finding, metadata))
    _merge_many(sources, _finding_sources(metadata))
    _merge_many(sinks, _finding_sinks(metadata))
    _merge_many(traces, _finding_traces(finding, metadata))
    _merge_many(limitations, _finding_limitations(metadata))


def _explicit_contract(finding: dict[str, Any]) -> dict[str, Any] | None:
    value = finding.get("evidence_contract")
    if isinstance(value, dict):
        return value

    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        value = metadata.get("evidence_contract")
        if isinstance(value, dict):
            return value
    return None


def _is_high_impact_finding(finding: dict[str, Any]) -> bool:
    rule_id = str(finding.get("rule_id") or finding.get("rule") or "")
    if rule_id in AI_DEFECT_RULE_IDS:
        return True

    vibe_category = str(finding.get("vibe_category") or finding.get("defect_type") or "")
    if vibe_category in AI_VIBE_CATEGORIES:
        return True

    category = str(finding.get("category") or "").strip().lower()
    severity = str(finding.get("severity") or "").strip().upper()
    return category in _HIGH_IMPACT_CATEGORIES and severity in _HIGH_IMPACT_SEVERITIES


def _normalize_proof_state(
    value: Any,
    *,
    has_evidence: bool,
    limitations: list[Any],
) -> str:
    if value is None:
        if has_evidence:
            return PROOF_STATE_CANDIDATE
        return PROOF_STATE_INCOMPLETE

    normalized: str | None = None
    raw = str(value).strip().lower()
    if raw in PROOF_STATES:
        normalized = raw
    else:
        normalized = _PROOF_STATE_ALIASES.get(raw)
        if normalized == PROOF_STATE_INCOMPLETE:
            _append_unique(
                limitations,
                f"Proof state '{raw}' is incomplete and must not be treated as verified.",
            )

    if normalized is None:
        _append_unique(
            limitations,
            f"Unknown proof_state '{raw}' treated as incomplete.",
        )
        return PROOF_STATE_INCOMPLETE

    if normalized in {PROOF_STATE_VERIFIED, PROOF_STATE_REFUTED} and not has_evidence:
        _append_unique(
            limitations,
            f"Proof state '{normalized}' requires structured evidence; treated as incomplete.",
        )
        return PROOF_STATE_INCOMPLETE

    return normalized


def _metadata_proof_state(finding: dict[str, Any]) -> Any:
    for key in ("proof_state", "evidence_state", "verification_state"):
        value = finding.get(key)
        if _has_value(value):
            return value

    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        return None

    for key in ("proof_state", "evidence_state", "verification_state"):
        value = metadata.get(key)
        if _has_value(value):
            return value

    security_evidence = metadata.get("security_evidence")
    if isinstance(security_evidence, str) and _has_value(security_evidence):
        return security_evidence

    dependency_truth_state = metadata.get("dependency_truth_state")
    if dependency_truth_state in {"private_or_unverified", "unknown"}:
        return PROOF_STATE_INCOMPLETE

    return None


def _finding_symbols(finding: dict[str, Any], metadata: dict[str, Any]) -> list[Any]:
    symbols: list[Any] = []
    for key in ("symbol", "simple_name", "qualified_name", "name"):
        _append_unique(symbols, _json_safe_scalar(finding.get(key)))

    package_name = metadata.get("package_name")
    package_version = metadata.get("package_version")
    if _has_value(package_name) and _has_value(package_version):
        _append_unique(symbols, f"{package_name}@{package_version}")
    elif _has_value(package_name):
        _append_unique(symbols, _json_safe_scalar(package_name))

    for key in ("api_symbol", "member_name", "callable"):
        _append_unique(symbols, _json_safe_scalar(metadata.get(key)))
    return symbols


def _finding_sources(metadata: dict[str, Any]) -> list[Any]:
    sources: list[Any] = []
    for key in (
        "dependency_source",
        "dependency_truth_source",
        "api_surface_source",
        "contract_clause",
    ):
        _append_unique(sources, _json_safe_scalar(metadata.get(key)))

    security_evidence = metadata.get("security_evidence")
    if isinstance(security_evidence, dict):
        _merge_many(sources, _normal_list(security_evidence.get("source")))
        _merge_many(sources, _normal_list(security_evidence.get("sources")))
    return sources


def _finding_sinks(metadata: dict[str, Any]) -> list[Any]:
    sinks: list[Any] = []
    security_evidence = metadata.get("security_evidence")
    if isinstance(security_evidence, dict):
        _merge_many(sinks, _normal_list(security_evidence.get("sink")))
        _merge_many(sinks, _normal_list(security_evidence.get("sinks")))
    return sinks


def _finding_traces(finding: dict[str, Any], metadata: dict[str, Any]) -> list[Any]:
    traces: list[Any] = []

    file_path = finding.get("file") or finding.get("file_path")
    line = finding.get("line") or finding.get("line_number")
    if _has_value(file_path) and _has_value(line):
        _append_unique(traces, f"{file_path}:{line}")

    security_evidence = metadata.get("security_evidence")
    if isinstance(security_evidence, dict):
        _merge_many(traces, _normal_list(security_evidence.get("path")))
        _merge_many(traces, _normal_list(security_evidence.get("trace")))
        _merge_many(traces, _normal_list(security_evidence.get("traces")))

    dependency_truth_state = metadata.get("dependency_truth_state")
    if _has_value(dependency_truth_state):
        _append_unique(traces, f"dependency_truth_state:{dependency_truth_state}")

    for key in ("removed_assertion", "added_assertion", "changed_file"):
        _append_unique(traces, _json_safe_scalar(metadata.get(key)))

    return traces


def _finding_limitations(metadata: dict[str, Any]) -> list[Any]:
    limitations: list[Any] = []
    dependency_truth_state = metadata.get("dependency_truth_state")
    if dependency_truth_state == "private_or_unverified":
        _append_unique(
            limitations,
            "Dependency may resolve from a private or unverified registry.",
        )
    elif dependency_truth_state == "unknown":
        _append_unique(
            limitations,
            "Dependency truth could not be verified from available static evidence.",
        )
    return limitations


def _first_present(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if _has_value(value):
            return value
    return None


def _normal_list(value: Any) -> list[Any]:
    if value is None:
        return []

    if isinstance(value, (str, bytes, dict)):
        candidates = [value]
    elif isinstance(value, Iterable):
        candidates = list(value)
    else:
        candidates = [value]

    items: list[Any] = []
    for candidate in candidates:
        safe = _json_safe_value(candidate)
        _append_unique(items, safe)
    return items


def _merge_many(target: list[Any], values: list[Any]) -> None:
    for value in values:
        _append_unique(target, value)


def _append_unique(target: list[Any], value: Any) -> None:
    if not _has_value(value):
        return
    if value in target:
        return
    target.append(value)


def _json_safe_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        return text
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace").strip()
        if not text:
            return None
        return text
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            safe_key = _json_safe_scalar(key)
            safe_value = _json_safe_value(item)
            if _has_value(safe_key) and _has_value(safe_value):
                normalized[str(safe_key)] = safe_value
        return normalized or None
    if isinstance(value, Iterable):
        return _normal_list(value)
    return str(value)


def _json_safe_scalar(value: Any) -> Any:
    safe = _json_safe_value(value)
    if isinstance(safe, (list, dict)):
        return None
    return safe


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True
