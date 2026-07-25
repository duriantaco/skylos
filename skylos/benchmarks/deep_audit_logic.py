from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from skylos.audit.investigator_tools import AuditReadOnlyTools
from skylos.audit.redaction import sanitize_for_audit
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    read_text_no_symlink,
)
from skylos.llm.agents import AgentConfig, SecurityAuditAgent


DEFAULT_EXPECTED_PATH = Path("benchmarks/deep_audit_logic/expected.json")
DEFAULT_BENCHMARK_MAX_TOKENS = 4_096
MAX_EXPECTED_MANIFEST_BYTES = 256 * 1024
MAX_BENCHMARK_ENTRY_BYTES = 1_000_000
CASE_LABELS = frozenset({"vulnerable", "safe", "lookalike"})
_CASE_SET_CONTRACTS = {
    "rule_ids": ("required_rule_ids", "forbidden_rule_ids"),
    "categories": ("required_categories", "forbidden_categories"),
    "symbols": ("required_symbols", "forbidden_symbols"),
    "primary_files": (
        "required_primary_files",
        "forbidden_primary_files",
    ),
    "visited_files": ("required_visited_files", "forbidden_visited_files"),
    "evidence_files": (
        "required_evidence_files",
        "forbidden_evidence_files",
    ),
    "mitigation_evidence_files": (
        "required_mitigation_evidence_files",
        "forbidden_mitigation_evidence_files",
    ),
    "clean_evidence_files": (
        "required_clean_evidence_files",
        "forbidden_clean_evidence_files",
    ),
}
_CASE_ANY_CONTRACTS = {
    "categories": "required_any_categories",
}
_TARGET_IDENTITY_FIELDS = (
    "required_rule_ids",
    "required_categories",
    "required_any_categories",
    "required_symbols",
    "required_primary_files",
)
_REQUIRED_FINDING_EVIDENCE_ANCHORS = "required_finding_evidence_anchors"
_REQUIRED_CLEAN_EVIDENCE_ANCHORS = "required_clean_evidence_anchors"
_EVIDENCE_ANCHOR_CONTRACTS = (
    _REQUIRED_FINDING_EVIDENCE_ANCHORS,
    _REQUIRED_CLEAN_EVIDENCE_ANCHORS,
)
_FINDING_COUNT_FIELDS = frozenset({"exact", "min", "max"})
_NUMERIC_MINIMUM_FIELDS = ("min_tool_calls", "min_llm_calls")
_FINDING_TARGET_CONTRACTS = {
    key: value
    for key, value in _CASE_SET_CONTRACTS.items()
    if key
    in {
        "rule_ids",
        "categories",
        "symbols",
        "primary_files",
        "evidence_files",
        "mitigation_evidence_files",
    }
}


class DeepAuditLogicBenchmarkError(ValueError):
    """The checked-in benchmark contract or fixture is invalid."""


def _case_label(case: dict[str, Any]) -> str:
    """Return the explicit label, or infer one for legacy schema-v1 manifests."""
    label = case.get("label")
    if isinstance(label, str) and label in CASE_LABELS:
        return label

    count_contract = case.get("expect", {}).get("finding_count", {})
    if not isinstance(count_contract, dict):
        return "safe"
    for field in ("exact", "min"):
        value = count_contract.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return "vulnerable"
    return "safe"


def _require_nonnegative_integer(value: Any, *, field: str, case_id: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} {field} must be a non-negative integer"
        )
    if value < 0:
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} {field} must be a non-negative integer"
        )
    return value


def _validate_expected_contract(case: dict[str, Any], case_id: str) -> None:
    expected = case.get("expect")
    if not isinstance(expected, dict):
        return

    if expected.get("status") != "complete":
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} expect.status must be 'complete'"
        )

    count_contract = expected.get("finding_count")
    if not isinstance(count_contract, dict) or not count_contract:
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} finding_count must define exact, min, or max"
        )
    unknown_fields = sorted(set(count_contract) - _FINDING_COUNT_FIELDS)
    if unknown_fields:
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} finding_count has unsupported fields: "
            f"{unknown_fields}"
        )
    if "exact" in count_contract and len(count_contract) != 1:
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} finding_count exact cannot be combined "
            "with min or max"
        )

    validated_counts = {
        field: _require_nonnegative_integer(
            value,
            field=f"finding_count.{field}",
            case_id=case_id,
        )
        for field, value in count_contract.items()
    }
    if (
        "min" in validated_counts
        and "max" in validated_counts
        and validated_counts["min"] > validated_counts["max"]
    ):
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} finding_count min cannot exceed max"
        )

    for field in _NUMERIC_MINIMUM_FIELDS:
        if field in expected:
            _require_nonnegative_integer(
                expected[field],
                field=field,
                case_id=case_id,
            )


def _validate_case_label(case: dict[str, Any], case_id: str) -> None:
    label = case.get("label")
    if label is None:
        return
    if not isinstance(label, str) or label not in CASE_LABELS:
        allowed = ", ".join(sorted(CASE_LABELS))
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} label must be one of: {allowed}"
        )

    count_contract = case.get("expect", {}).get("finding_count", {})
    if not isinstance(count_contract, dict):
        return
    minimum = count_contract.get("exact", count_contract.get("min", 0))
    maximum = count_contract.get("exact", count_contract.get("max"))
    if label == "vulnerable" and minimum < 1:
        raise DeepAuditLogicBenchmarkError(
            f"vulnerable benchmark case {case_id} must expect at least one finding"
        )
    if label in {"safe", "lookalike"} and (maximum is None or maximum != 0):
        raise DeepAuditLogicBenchmarkError(
            f"{label} benchmark case {case_id} must expect zero findings"
        )


def _validate_set_contracts(case: dict[str, Any], case_id: str) -> None:
    expected = case.get("expect")
    if not isinstance(expected, dict):
        return
    fields = {
        field
        for required, forbidden in _CASE_SET_CONTRACTS.values()
        for field in (required, forbidden)
    }
    fields.update(_CASE_ANY_CONTRACTS.values())
    for field in sorted(fields):
        if field not in expected:
            continue
        values = expected[field]
        if (
            not isinstance(values, list)
            or not all(isinstance(value, str) and value.strip() for value in values)
            or len(values) != len(set(values))
        ):
            raise DeepAuditLogicBenchmarkError(
                f"benchmark case {case_id} {field} must be a list of unique "
                "non-empty strings"
            )
        if field in _CASE_ANY_CONTRACTS.values() and not values:
            raise DeepAuditLogicBenchmarkError(
                f"benchmark case {case_id} {field} must not be empty"
            )

    for required, forbidden in _CASE_SET_CONTRACTS.values():
        overlap = set(expected.get(required) or ()) & set(expected.get(forbidden) or ())
        if overlap:
            raise DeepAuditLogicBenchmarkError(
                f"benchmark case {case_id} has contradictory {required} and "
                f"{forbidden}: {sorted(overlap)}"
            )


def _validate_target_identity_contract(case: dict[str, Any], case_id: str) -> None:
    if _case_label(case) != "vulnerable":
        return
    expected = case.get("expect")
    if not isinstance(expected, dict):
        return
    if not any(expected.get(field) for field in _TARGET_IDENTITY_FIELDS):
        raise DeepAuditLogicBenchmarkError(
            f"vulnerable benchmark case {case_id} must define a non-empty target "
            "identity contract"
        )


def _load_manifest_source(path: str | Path) -> tuple[Path, str]:
    candidate = Path(path).expanduser()
    try:
        # The caller intentionally chooses the manifest location, so it is not
        # confined to the repository. Resolve only its parent: the bounded
        # no-follow read below must inspect the final path component itself.
        manifest_root = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise DeepAuditLogicBenchmarkError(
            f"could not load deep-audit logic expectations: {candidate}"
        ) from exc

    expected_path = manifest_root / candidate.name
    source = read_text_no_symlink(
        expected_path,
        max_bytes=MAX_EXPECTED_MANIFEST_BYTES,
        encoding="utf-8",
    )
    if source is None:
        raise DeepAuditLogicBenchmarkError(
            "deep-audit logic expectations must be a bounded, regular, "
            f"non-symlink file: {expected_path}"
        )
    return expected_path, source


def _relative_case_path(value: Any, *, field: str, case_id: str) -> Path:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} {field} must be a non-empty relative path"
        )
    path = Path(value)
    if (
        path.is_absolute()
        or path.anchor
        or path.drive
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} {field} must stay inside its benchmark root"
        )
    return path


def _case_paths(
    manifest_root: Path,
    case: dict[str, Any],
    case_id: str,
) -> tuple[Path, Path, str]:
    fixture_relative = _relative_case_path(
        case.get("fixture"), field="fixture", case_id=case_id
    )
    entry_relative = _relative_case_path(
        case.get("entry_file"), field="entry_file", case_id=case_id
    )
    combined_relative = fixture_relative / entry_relative
    source = read_project_text_no_symlink(
        manifest_root,
        combined_relative,
        max_bytes=MAX_BENCHMARK_ENTRY_BYTES,
        encoding="utf-8",
    )
    if source is None:
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} fixture or entry file is missing, unsafe, "
            "or oversized"
        )

    fixture_root = manifest_root / fixture_relative
    try:
        resolved_fixture_root = fixture_root.resolve(strict=True)
        resolved_fixture_root.relative_to(manifest_root)
    except (OSError, ValueError) as exc:
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} fixture must stay inside the manifest root"
        ) from exc
    if not resolved_fixture_root.is_dir():
        raise DeepAuditLogicBenchmarkError(
            f"benchmark case {case_id} fixture must be a directory"
        )
    return resolved_fixture_root, resolved_fixture_root / entry_relative, source


def _validate_evidence_anchors(
    case: dict[str, Any],
    case_id: str,
    fixture_root: Path,
) -> None:
    expected = case.get("expect")
    if not isinstance(expected, dict):
        return

    for contract_field in _EVIDENCE_ANCHOR_CONTRACTS:
        if contract_field not in expected:
            continue
        anchors = expected[contract_field]
        if not isinstance(anchors, list) or not anchors:
            raise DeepAuditLogicBenchmarkError(
                f"benchmark case {case_id} {contract_field} must be a non-empty list"
            )

        seen: set[tuple[str, int, str]] = set()
        for index, anchor in enumerate(anchors):
            field = f"{contract_field}[{index}]"
            if not isinstance(anchor, dict) or set(anchor) != {
                "file",
                "line",
                "token",
            }:
                raise DeepAuditLogicBenchmarkError(
                    f"benchmark case {case_id} {field} must contain exactly file, "
                    "line, and token"
                )
            relative_file = _relative_case_path(
                anchor.get("file"),
                field=f"{field}.file",
                case_id=case_id,
            )
            line = _require_nonnegative_integer(
                anchor.get("line"),
                field=f"{field}.line",
                case_id=case_id,
            )
            if line < 1:
                raise DeepAuditLogicBenchmarkError(
                    f"benchmark case {case_id} {field}.line must be a positive integer"
                )
            token = anchor.get("token")
            if (
                not isinstance(token, str)
                or not token.strip()
                or "\x00" in token
                or "\n" in token
                or "\r" in token
            ):
                raise DeepAuditLogicBenchmarkError(
                    f"benchmark case {case_id} {field}.token must be a non-empty "
                    "single-line string"
                )

            identity = (relative_file.as_posix(), line, token)
            if identity in seen:
                raise DeepAuditLogicBenchmarkError(
                    f"benchmark case {case_id} {contract_field} must contain "
                    "unique anchors"
                )
            seen.add(identity)

            source = read_project_text_no_symlink(
                fixture_root,
                relative_file,
                max_bytes=MAX_BENCHMARK_ENTRY_BYTES,
                encoding="utf-8",
            )
            if source is None:
                raise DeepAuditLogicBenchmarkError(
                    f"benchmark case {case_id} {field}.file must be a bounded, "
                    "regular, non-symlink fixture file"
                )
            source_lines = source.splitlines()
            if line > len(source_lines):
                raise DeepAuditLogicBenchmarkError(
                    f"benchmark case {case_id} {field}.line is outside the fixture file"
                )
            if token not in source_lines[line - 1]:
                raise DeepAuditLogicBenchmarkError(
                    f"benchmark case {case_id} {field}.token is not present on its "
                    "designated source line"
                )


def load_expected(path: str | Path = DEFAULT_EXPECTED_PATH) -> dict[str, Any]:
    expected_path, source = _load_manifest_source(path)
    try:
        payload = json.loads(source)
    except json.JSONDecodeError as exc:
        raise DeepAuditLogicBenchmarkError(
            f"could not load deep-audit logic expectations: {expected_path}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise DeepAuditLogicBenchmarkError(
            "deep-audit logic expectations require schema_version=1"
        )
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise DeepAuditLogicBenchmarkError(
            "deep-audit logic expectations require at least one case"
        )
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise DeepAuditLogicBenchmarkError("benchmark cases must be objects")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise DeepAuditLogicBenchmarkError(
                "benchmark case IDs must be unique non-empty strings"
            )
        seen.add(case_id)
        if not isinstance(case.get("candidates"), list) or not isinstance(
            case.get("expect"), dict
        ):
            raise DeepAuditLogicBenchmarkError(
                f"benchmark case {case_id} requires candidates and expect"
            )
        _validate_expected_contract(case, case_id)
        _validate_case_label(case, case_id)
        _validate_set_contracts(case, case_id)
        _validate_target_identity_contract(case, case_id)
        fixture_root, _, _ = _case_paths(expected_path.parent, case, case_id)
        _validate_evidence_anchors(case, case_id, fixture_root)
    payload["expected_path"] = str(expected_path)
    return payload


def _aggregate_metrics(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    true_positive = 0
    false_positive = 0
    false_negative = 0
    true_negative = 0
    false_clean = 0
    incomplete = 0
    abstention = 0
    wrong_target = 0
    usage = {
        "llm_calls": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cases_with_usage": 0,
    }

    for case in case_results:
        actual = case["actual"]
        expected_positive = case["label"] == "vulnerable"
        any_finding = int(actual.get("finding_count") or 0) > 0
        complete = actual.get("status") == "complete"
        expected = case.get("expected")
        if not isinstance(expected, dict):
            expected = {}
        matching_findings, unmatched_findings = _finding_target_counts(actual, expected)
        target_detected = matching_findings > 0
        if not complete:
            incomplete += 1
            if expected_positive:
                # An incomplete investigation never earns true-positive credit.
                false_negative += 1
                false_positive += unmatched_findings
            elif any_finding:
                false_positive += int(actual.get("finding_count") or 0)
            else:
                # Do not let a negative-case abstention inflate true negatives.
                abstention += 1
        elif expected_positive and target_detected:
            true_positive += 1
            false_positive += unmatched_findings
        elif expected_positive:
            false_negative += 1
            if any_finding:
                wrong_target += 1
                false_positive += unmatched_findings
        elif any_finding:
            false_positive += int(actual.get("finding_count") or 0)
        else:
            true_negative += 1

        if expected_positive and complete and not any_finding:
            false_clean += 1

        for key in ("llm_calls", "prompt_tokens", "completion_tokens", "total_tokens"):
            usage[key] += int(actual.get(key) or 0)
        if int(actual.get("total_tokens") or 0) > 0:
            usage["cases_with_usage"] += 1

    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "confusion_matrix": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "true_negative": true_negative,
        },
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_clean_count": false_clean,
        "incomplete_count": incomplete,
        "abstention_count": abstention,
        "wrong_target_count": wrong_target,
        "classified_count": (
            true_positive + false_positive + false_negative + true_negative
        ),
        "usage": usage,
    }


def _evidence_files(items: Any) -> set[str]:
    if not isinstance(items, list):
        return set()
    return {
        str(item["file"])
        for item in items
        if isinstance(item, dict) and isinstance(item.get("file"), str)
    }


def _target_detected(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    """Return whether one completed finding satisfies the expected target."""

    if actual.get("status") != "complete" or int(actual.get("finding_count") or 0) <= 0:
        return False

    matching_findings, _ = _finding_target_counts(actual, expected)
    return matching_findings > 0


def _finding_target_counts(
    actual: dict[str, Any],
    expected: dict[str, Any],
) -> tuple[int, int]:
    """Return matched and unmatched emitted-finding counts for one target family."""

    actual_count = int(actual.get("finding_count") or 0)
    if actual_count <= 0:
        return 0, 0

    projected_findings = actual.get("finding_targets")
    if not isinstance(projected_findings, list):
        # Preserve the aggregate projection fallback for a single legacy finding.
        # Additional emitted findings fail closed because their individual target
        # identity cannot be established from aggregate sets.
        projected_findings = [actual]
    considered = projected_findings[:actual_count]
    matching = sum(
        1
        for finding in considered
        if isinstance(finding, dict) and _finding_matches_target(finding, expected)
    )
    unprojected = max(actual_count - len(considered), 0)
    invalid_or_wrong_target = len(considered) - matching
    excess_projections = max(len(projected_findings) - actual_count, 0)
    return matching, unprojected + invalid_or_wrong_target + excess_projections


def _finding_matches_target(
    finding: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    for actual_key, (required_key, forbidden_key) in _FINDING_TARGET_CONTRACTS.items():
        values = set(finding.get(actual_key) or ())
        required = set(expected.get(required_key) or ())
        forbidden = set(expected.get(forbidden_key) or ())
        if not required.issubset(values) or forbidden.intersection(values):
            return False
    for actual_key, expected_key in _CASE_ANY_CONTRACTS.items():
        accepted = set(expected.get(expected_key) or ())
        if accepted and set(finding.get(actual_key) or ()).isdisjoint(accepted):
            return False
    for anchor in expected.get(_REQUIRED_FINDING_EVIDENCE_ANCHORS) or ():
        if not _evidence_locations_cite_anchor(
            finding.get("evidence_locations"), anchor
        ):
            return False
    return True


def _evidence_locations_cite_anchor(locations: Any, anchor: Any) -> bool:
    if not isinstance(anchor, dict):
        return False
    anchor_file = anchor.get("file")
    anchor_line = anchor.get("line")
    if (
        not isinstance(anchor_file, str)
        or isinstance(anchor_line, bool)
        or not isinstance(anchor_line, int)
    ):
        return False
    if not isinstance(locations, list):
        return False
    for location in locations:
        if not isinstance(location, dict) or location.get("file") != anchor_file:
            continue
        start_line = location.get("line")
        end_line = location.get("end_line")
        if isinstance(start_line, bool) or not isinstance(start_line, int):
            continue
        if end_line is None:
            end_line = start_line
        if isinstance(end_line, bool) or not isinstance(end_line, int):
            continue
        if start_line < 1 or end_line < start_line:
            continue
        if start_line <= anchor_line <= end_line:
            return True
    return False


def _bounded_text(value: Any, max_chars: int) -> str | None:
    if not isinstance(value, str):
        return None
    return value[:max_chars]


def _project_evidence(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    projected: list[dict[str, Any]] = []
    for item in items[:12]:
        if not isinstance(item, dict):
            continue
        projected.append(
            {
                "file": item.get("file"),
                "line": item.get("line"),
                "end_line": item.get("end_line"),
                "role": _bounded_text(item.get("role"), 500),
            }
        )
    return projected


def _project_evidence_locations(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    return [
        {
            "file": item.get("file"),
            "line": item.get("line"),
            "end_line": item.get("end_line"),
        }
        for item in items
        if isinstance(item, dict)
    ]


def _project_model_call_diagnostics(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    raw_items = metadata.get("model_call_diagnostics")
    if not isinstance(raw_items, list):
        return []
    projected: list[dict[str, Any]] = []
    for item in raw_items[:32]:
        if not isinstance(item, dict):
            continue
        projected.append(
            {
                key: item.get(key)
                for key in (
                    "call_index",
                    "finish_reason",
                    "content_chars",
                    "completion_tokens",
                    "reasoning_tokens",
                    "signal",
                )
            }
        )
    return projected


def project_result(
    result: Any,
    *,
    include_model_prose: bool = False,
) -> dict[str, Any]:
    findings = list(getattr(result, "findings", ()) or ())
    metadata = getattr(result, "metadata", {}) or {}
    rule_ids: set[str] = set()
    categories: set[str] = set()
    symbols: set[str] = set()
    primary_files: set[str] = set()
    evidence_files: set[str] = set()
    mitigation_evidence_files: set[str] = set()
    finding_targets: list[dict[str, Any]] = []
    finding_claims: list[dict[str, Any]] = []

    for finding in findings:
        finding_rule_ids: set[str] = set()
        finding_categories: set[str] = set()
        finding_symbols: set[str] = set()
        finding_primary_files: set[str] = set()
        finding_evidence_files: set[str] = set()
        finding_mitigation_evidence_files: set[str] = set()
        rule_id = getattr(finding, "rule_id", None)
        if isinstance(rule_id, str):
            rule_ids.add(rule_id)
            finding_rule_ids.add(rule_id)
        symbol = getattr(finding, "symbol", None)
        if isinstance(symbol, str) and symbol:
            symbols.add(symbol)
            finding_symbols.add(symbol)
        location = getattr(finding, "location", None)
        primary_file = getattr(location, "file", None)
        if isinstance(primary_file, str):
            primary_files.add(primary_file)
            finding_primary_files.add(primary_file)
        finding_metadata = getattr(finding, "metadata", {}) or {}
        investigation = finding_metadata.get("investigation_evidence") or {}
        category = investigation.get("category")
        if isinstance(category, str):
            categories.add(category)
            finding_categories.add(category)
        finding_evidence_files.update(_evidence_files(investigation.get("evidence")))
        evidence_files.update(finding_evidence_files)
        for check in investigation.get("mitigation_evidence") or ():
            if isinstance(check, dict):
                check_files = _evidence_files(check.get("evidence"))
                finding_mitigation_evidence_files.update(check_files)
                mitigation_evidence_files.update(check_files)
        finding_targets.append(
            {
                "rule_ids": sorted(finding_rule_ids),
                "categories": sorted(finding_categories),
                "symbols": sorted(finding_symbols),
                "primary_files": sorted(finding_primary_files),
                "evidence_files": sorted(finding_evidence_files),
                "mitigation_evidence_files": sorted(finding_mitigation_evidence_files),
                "evidence_locations": _project_evidence_locations(
                    investigation.get("evidence")
                ),
            }
        )
        if include_model_prose:
            finding_claims.append(
                sanitize_for_audit(
                    {
                        "rule_id": rule_id,
                        "category": category,
                        "symbol": symbol,
                        "primary_file": primary_file,
                        "line": getattr(location, "line", None),
                        "end_line": getattr(location, "end_line", None),
                        "message": _bounded_text(
                            getattr(finding, "message", None), 500
                        ),
                        "invariant": _bounded_text(investigation.get("invariant"), 750),
                        "trigger": _bounded_text(investigation.get("trigger"), 750),
                        "actual_behavior": _bounded_text(
                            investigation.get("actual_behavior"), 1_000
                        ),
                        "impact": _bounded_text(investigation.get("impact"), 750),
                        "evidence": _project_evidence(investigation.get("evidence")),
                    }
                )
            )

    clean_evidence_files: set[str] = set()
    clean_evidence_locations: list[dict[str, Any]] = []
    for proof in metadata.get("clean_evidence") or ():
        if isinstance(proof, dict):
            evidence = proof.get("evidence")
            clean_evidence_files.update(_evidence_files(evidence))
            clean_evidence_locations.extend(_project_evidence_locations(evidence))

    usage = metadata.get("usage") or {}
    if not isinstance(usage, dict):
        usage = {}

    projected = {
        "status": str(getattr(result, "status", "unknown")),
        "finding_count": len(findings),
        "rule_ids": sorted(rule_ids),
        "categories": sorted(categories),
        "symbols": sorted(symbols),
        "primary_files": sorted(primary_files),
        "evidence_files": sorted(evidence_files),
        "mitigation_evidence_files": sorted(mitigation_evidence_files),
        "finding_targets": finding_targets,
        "clean_evidence_files": sorted(clean_evidence_files),
        "clean_evidence_locations": clean_evidence_locations,
        "visited_files": sorted(
            path for path in metadata.get("visited_files", ()) if isinstance(path, str)
        ),
        "source_observed_files": sorted(
            path
            for path in metadata.get("source_observed_files", ())
            if isinstance(path, str)
        ),
        "tool_calls": int(metadata.get("tool_calls") or 0),
        "turns": int(metadata.get("turns") or 0),
        "llm_calls": int(metadata.get("llm_calls") or 0),
        "prompt_tokens": int(usage.get("prompt_tokens") or 0),
        "completion_tokens": int(usage.get("completion_tokens") or 0),
        "total_tokens": int(usage.get("total_tokens") or 0),
        "model_call_diagnostics": _project_model_call_diagnostics(metadata),
        "model_call_diagnostics_truncated": int(
            metadata.get("model_call_diagnostics_truncated") or 0
        ),
        "protocol_version": metadata.get("protocol_version"),
        "tool_schema_version": metadata.get("tool_schema_version"),
    }
    if include_model_prose:
        projected["finding_claims"] = finding_claims
    return projected


def evaluate_case(actual: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if actual.get("status") != expected.get("status"):
        failures.append(
            f"status expected {expected.get('status')!r}, found {actual.get('status')!r}"
        )

    count_contract = expected.get("finding_count") or {}
    actual_count = int(actual.get("finding_count") or 0)
    if "exact" in count_contract and actual_count != int(count_contract["exact"]):
        failures.append(
            f"finding_count expected exactly {count_contract['exact']}, found {actual_count}"
        )
    if "min" in count_contract and actual_count < int(count_contract["min"]):
        failures.append(
            f"finding_count expected at least {count_contract['min']}, found {actual_count}"
        )
    if "max" in count_contract and actual_count > int(count_contract["max"]):
        failures.append(
            f"finding_count expected at most {count_contract['max']}, found {actual_count}"
        )

    for actual_key, expected_key in (
        ("tool_calls", "min_tool_calls"),
        ("llm_calls", "min_llm_calls"),
    ):
        minimum = int(expected.get(expected_key) or 0)
        if int(actual.get(actual_key) or 0) < minimum:
            failures.append(
                f"{actual_key} expected at least {minimum}, "
                f"found {actual.get(actual_key, 0)}"
            )

    for actual_key, (required_key, forbidden_key) in _CASE_SET_CONTRACTS.items():
        values = set(actual.get(actual_key) or ())
        required = set(expected.get(required_key) or ())
        forbidden = set(expected.get(forbidden_key) or ())
        missing = sorted(required - values)
        present_forbidden = sorted(forbidden & values)
        if missing:
            failures.append(f"{actual_key} missing required values: {missing}")
        if present_forbidden:
            failures.append(
                f"{actual_key} contains forbidden values: {present_forbidden}"
            )

    for actual_key, expected_key in _CASE_ANY_CONTRACTS.items():
        accepted = set(expected.get(expected_key) or ())
        values = set(actual.get(actual_key) or ())
        if accepted and values.isdisjoint(accepted):
            failures.append(
                f"{actual_key} must contain at least one accepted value: "
                f"{sorted(accepted)}"
            )

    for anchor in expected.get(_REQUIRED_CLEAN_EVIDENCE_ANCHORS) or ():
        if _evidence_locations_cite_anchor(
            actual.get("clean_evidence_locations"), anchor
        ):
            continue
        anchor_file = anchor.get("file") if isinstance(anchor, dict) else None
        anchor_line = anchor.get("line") if isinstance(anchor, dict) else None
        failures.append(
            "clean evidence does not cite a range covering required anchor "
            f"{anchor_file}:{anchor_line}"
        )

    expected_minimum = int(
        count_contract.get("exact") or count_contract.get("min") or 0
    )
    if expected_minimum > 0 and actual.get("status") == "complete" and actual_count > 0:
        matching_findings, unmatched_findings = _finding_target_counts(actual, expected)
        if matching_findings == 0:
            failures.append(
                "no individual finding satisfied the complete expected target contract"
            )
        elif unmatched_findings:
            failures.append(
                f"{unmatched_findings} emitted finding(s) did not satisfy an "
                "explicitly allowed target contract"
            )
    return failures


def _production_agent(
    *,
    model: str,
    api_key: str | None,
    provider: str | None,
    base_url: str | None,
    reasoning_effort: str | None = None,
    max_tokens: int = DEFAULT_BENCHMARK_MAX_TOKENS,
) -> SecurityAuditAgent:
    config = AgentConfig(
        model=model,
        api_key=api_key,
        temperature=0.0,
        max_tokens=max_tokens,
        timeout=180,
        retry_attempts=1,
        stream=False,
        enable_cache=False,
        reasoning_effort=reasoning_effort,
    )
    config.provider = provider
    config.base_url = base_url
    return SecurityAuditAgent(config)


def run_manifest(
    expected_path: str | Path = DEFAULT_EXPECTED_PATH,
    *,
    model: str,
    api_key: str | None,
    provider: str | None = None,
    base_url: str | None = None,
    reasoning_effort: str | None = None,
    max_tokens: int = DEFAULT_BENCHMARK_MAX_TOKENS,
    selected_cases: set[str] | None = None,
    agent_factory: Callable[[dict[str, Any]], Any] | None = None,
    require_model_usage: bool = False,
    include_model_prose: bool = False,
) -> dict[str, Any]:
    if (
        isinstance(max_tokens, bool)
        or not isinstance(max_tokens, int)
        or max_tokens < 1
    ):
        raise DeepAuditLogicBenchmarkError("max_tokens must be a positive integer")
    contract = load_expected(expected_path)
    contract_path = Path(contract["expected_path"])
    selected = set(selected_cases or ())
    known_case_ids = {case["id"] for case in contract["cases"]}
    unknown_case_ids = sorted(selected - known_case_ids)
    if unknown_case_ids:
        raise DeepAuditLogicBenchmarkError(
            "unknown deep-audit logic benchmark case IDs: "
            + ", ".join(unknown_case_ids)
        )
    case_results: list[dict[str, Any]] = []

    for case in contract["cases"]:
        if selected and case["id"] not in selected:
            continue
        fixture_root, entry_path, entry_source = _case_paths(
            contract_path.parent,
            case,
            case["id"],
        )
        tools = AuditReadOnlyTools(fixture_root)
        agent = (
            agent_factory(case)
            if agent_factory is not None
            else _production_agent(
                model=model,
                api_key=api_key,
                provider=provider,
                base_url=base_url,
                reasoning_effort=reasoning_effort,
                max_tokens=max_tokens,
            )
        )
        try:
            result = agent.investigate(
                entry_source,
                entry_path.relative_to(fixture_root).as_posix(),
                context=None,
                candidates=list(case["candidates"]),
                tools=tools,
                run_id=f"benchmark-{case['id']}",
                persist_trace=False,
            )
            actual = project_result(
                result,
                include_model_prose=include_model_prose,
            )
        except Exception as exc:
            investigation_metadata = getattr(exc, "investigation_metadata", {})
            if not isinstance(investigation_metadata, dict):
                investigation_metadata = {}
            usage = investigation_metadata.get("usage") or {}
            if not isinstance(usage, dict):
                usage = {}
            projected_diagnostics = _project_model_call_diagnostics(
                investigation_metadata
            )
            output_budget_exhausted = any(
                diagnostic.get("signal") == "output_budget_exhausted"
                for diagnostic in projected_diagnostics
            )
            if include_model_prose:
                error = _bounded_text(
                    str(sanitize_for_audit(str(exc))).replace("\n", " "),
                    512,
                )
            elif output_budget_exhausted:
                error = "investigator output-token budget exhausted"
            elif type(exc).__name__ == "InvestigationIncompleteError":
                error = "investigation incomplete"
            else:
                error = "benchmark case execution failed"
            actual = {
                "status": "error",
                "finding_count": 0,
                "error_type": type(exc).__name__,
                "error": error,
                **tools.metadata(),
                "turns": int(investigation_metadata.get("turns") or 0),
                "llm_calls": int(investigation_metadata.get("llm_calls") or 0),
                "prompt_tokens": int(usage.get("prompt_tokens") or 0),
                "completion_tokens": int(usage.get("completion_tokens") or 0),
                "total_tokens": int(usage.get("total_tokens") or 0),
                "model_call_diagnostics": projected_diagnostics,
                "model_call_diagnostics_truncated": int(
                    investigation_metadata.get("model_call_diagnostics_truncated") or 0
                ),
            }
        failures = evaluate_case(actual, case["expect"])
        if require_model_usage and int(actual.get("total_tokens") or 0) <= 0:
            failures.append("live model run must report nonzero total_tokens")
        label = _case_label(case)
        expected = dict(case["expect"])
        case_results.append(
            {
                "id": case["id"],
                "label": label,
                "fixture": case["fixture"],
                "entry_file": case["entry_file"],
                "candidates": list(case["candidates"]),
                "expected": expected,
                "detection": {
                    "any_finding": int(actual.get("finding_count") or 0) > 0,
                    "target_detected": (
                        label == "vulnerable" and _target_detected(actual, expected)
                    ),
                    "wrong_target": (
                        label == "vulnerable"
                        and actual.get("status") == "complete"
                        and int(actual.get("finding_count") or 0) > 0
                        and not _target_detected(actual, expected)
                    ),
                },
                "passed": not failures,
                "failures": failures,
                "actual": actual,
            }
        )

    execution_mode = "injected_agent" if agent_factory else "live_model"
    case_count = len(case_results)
    pass_count = sum(1 for case in case_results if case["passed"])
    failure_count = sum(len(case["failures"]) for case in case_results)
    status = "pass" if all(case["passed"] for case in case_results) else "fail"
    metrics = _aggregate_metrics(case_results)

    return {
        "schema_version": 1,
        "benchmark": "deep_audit_logic",
        "expected_path": str(contract_path),
        "model": model,
        "provider": provider,
        "reasoning_effort": reasoning_effort,
        "max_tokens": max_tokens,
        "execution_mode": execution_mode,
        "model_usage_required": require_model_usage,
        "case_count": case_count,
        "pass_count": pass_count,
        "failure_count": failure_count,
        "status": status,
        **metrics,
        "cases": case_results,
    }


def format_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"Deep Audit logic benchmark: {summary['status'].upper()}",
        (
            f"Model/provider: {summary.get('model')} / {summary.get('provider')} "
            f"(reasoning_effort="
            f"{summary.get('reasoning_effort') or 'provider_default'}, "
            f"max_tokens={summary.get('max_tokens')})"
        ),
        f"Cases: {summary['pass_count']}/{summary['case_count']} passed",
        (
            "Classification: "
            f"precision={summary['precision']:.3f} recall={summary['recall']:.3f} "
            f"f1={summary['f1']:.3f} false-clean={summary['false_clean_count']} "
            f"wrong-target={summary['wrong_target_count']} "
            f"incomplete={summary['incomplete_count']} "
            f"abstentions={summary['abstention_count']}"
        ),
    ]
    for case in summary["cases"]:
        actual = case["actual"]

        if case["passed"]:
            label = "PASS"
        else:
            label = "FAIL"

        lines.append(
            f"{label} {case['id']} [{case['label']}]: "
            f"findings={actual.get('finding_count', 0)} "
            f"tools={actual.get('tool_calls', 0)} turns={actual.get('turns', 0)} "
            f"tokens={actual.get('total_tokens', 0)}"
        )
        lines.extend(f"  - {failure}" for failure in case["failures"])
    return "\n".join(lines)
