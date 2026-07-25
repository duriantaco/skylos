from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from skylos.benchmarks.deep_audit_logic import (
    DeepAuditLogicBenchmarkError,
    _aggregate_metrics,
    _finding_matches_target,
    evaluate_case,
    load_expected,
)
from skylos.core.safe_cache_io import save_project_json_cache


def _case(
    *,
    label: str = "safe",
    expect: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": "contract-case",
        "label": label,
        "fixture": "fixture",
        "entry_file": "entry.py",
        "candidates": [],
        "expect": expect
        or {
            "status": "complete",
            "finding_count": {"exact": 0},
        },
    }


def _load_contract(tmp_path: Path, case: dict[str, Any]) -> dict[str, Any]:
    assert save_project_json_cache(
        tmp_path,
        "fixture/entry.py",
        {"source": "decisive_call()"},
    )
    assert save_project_json_cache(
        tmp_path,
        "expected.json",
        {"schema_version": 1, "cases": [case]},
    )
    return load_expected(tmp_path / "expected.json")


@pytest.mark.parametrize("finding_count", [None, {}, {"minimum": 1}])
def test_manifest_rejects_missing_finding_count_contracts(
    tmp_path: Path,
    finding_count: Any,
) -> None:
    expected = {"status": "complete"}
    if finding_count is not None:
        expected["finding_count"] = finding_count

    with pytest.raises(DeepAuditLogicBenchmarkError, match="finding_count"):
        _load_contract(tmp_path, _case(expect=expected))


@pytest.mark.parametrize(
    "finding_count",
    [
        {"exact": 0, "min": 0},
        {"exact": 0, "max": 0},
        {"min": 2, "max": 1},
    ],
)
def test_manifest_rejects_contradictory_finding_count_contracts(
    tmp_path: Path,
    finding_count: dict[str, int],
) -> None:
    with pytest.raises(DeepAuditLogicBenchmarkError, match="finding_count"):
        _load_contract(
            tmp_path,
            _case(
                label="vulnerable",
                expect={
                    "status": "complete",
                    "finding_count": finding_count,
                    "required_categories": ["authorization_scope"],
                },
            ),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("finding_count", {"min": -1}),
        ("finding_count", {"min": "1"}),
        ("finding_count", {"max": 1.5}),
        ("finding_count", {"exact": True}),
        ("min_tool_calls", -1),
        ("min_tool_calls", "2"),
        ("min_llm_calls", 1.5),
        ("min_llm_calls", False),
    ],
)
def test_manifest_wraps_invalid_numeric_contracts_as_benchmark_errors(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    expected: dict[str, Any] = {
        "status": "complete",
        "finding_count": {"exact": 0},
    }
    expected[field] = value

    with pytest.raises(DeepAuditLogicBenchmarkError, match=field):
        _load_contract(tmp_path, _case(expect=expected))


def test_manifest_rejects_error_as_expected_negative_status(tmp_path: Path) -> None:
    with pytest.raises(DeepAuditLogicBenchmarkError, match=r"expect\.status"):
        _load_contract(
            tmp_path,
            _case(
                expect={
                    "status": "error",
                    "finding_count": {"exact": 0},
                }
            ),
        )


def test_manifest_requires_vulnerable_target_identity(tmp_path: Path) -> None:
    with pytest.raises(DeepAuditLogicBenchmarkError, match="target identity"):
        _load_contract(
            tmp_path,
            _case(
                label="vulnerable",
                expect={
                    "status": "complete",
                    "finding_count": {"min": 1},
                },
            ),
        )


def test_manifest_validates_evidence_anchor_token_against_fixture(
    tmp_path: Path,
) -> None:
    expected = {
        "status": "complete",
        "finding_count": {"min": 1},
        "required_categories": ["authorization_scope"],
        "required_finding_evidence_anchors": [
            {"file": "entry.py", "line": 2, "token": "decisive_call"}
        ],
    }

    contract = _load_contract(
        tmp_path,
        _case(label="vulnerable", expect=expected),
    )

    assert contract["cases"][0]["expect"] == expected


def test_manifest_validates_clean_evidence_anchor_token_against_fixture(
    tmp_path: Path,
) -> None:
    expected = {
        "status": "complete",
        "finding_count": {"exact": 0},
        "required_clean_evidence_anchors": [
            {"file": "entry.py", "line": 2, "token": "decisive_call"}
        ],
    }

    contract = _load_contract(tmp_path, _case(expect=expected))

    assert contract["cases"][0]["expect"] == expected


@pytest.mark.parametrize(
    "anchor",
    [
        {"file": "entry.py", "line": 1, "token": "absent_token"},
        {"file": "entry.py", "line": 4, "token": "decisive_call"},
        {"file": "entry.py", "line": "1", "token": "decisive_call"},
        {"file": "entry.py", "line": 1},
    ],
)
def test_manifest_rejects_invalid_evidence_anchors(
    tmp_path: Path,
    anchor: dict[str, Any],
) -> None:
    with pytest.raises(
        DeepAuditLogicBenchmarkError,
        match="required_finding_evidence_anchors",
    ):
        _load_contract(
            tmp_path,
            _case(
                label="vulnerable",
                expect={
                    "status": "complete",
                    "finding_count": {"min": 1},
                    "required_categories": ["authorization_scope"],
                    "required_finding_evidence_anchors": [anchor],
                },
            ),
        )


def test_manifest_rejects_invalid_clean_evidence_anchor(tmp_path: Path) -> None:
    with pytest.raises(
        DeepAuditLogicBenchmarkError,
        match="required_clean_evidence_anchors",
    ):
        _load_contract(
            tmp_path,
            _case(
                expect={
                    "status": "complete",
                    "finding_count": {"exact": 0},
                    "required_clean_evidence_anchors": [
                        {"file": "entry.py", "line": 2, "token": "missing"}
                    ],
                }
            ),
        )


def _target(
    category: str = "authorization_scope",
    *,
    line: int | None = 5,
    end_line: int | None = 5,
) -> dict[str, Any]:
    return {
        "rule_ids": ["SKY-AUDIT-LOGIC"],
        "categories": [category],
        "symbols": ["refund_endpoint"],
        "primary_files": ["api.py"],
        "evidence_files": ["policy.py"],
        "mitigation_evidence_files": [],
        "evidence_locations": [
            {"file": "policy.py", "line": line, "end_line": end_line}
        ],
    }


def _expected_target() -> dict[str, Any]:
    return {
        "status": "complete",
        "finding_count": {"min": 1, "max": 2},
        "required_rule_ids": ["SKY-AUDIT-LOGIC"],
        "required_categories": ["authorization_scope"],
        "required_symbols": ["refund_endpoint"],
        "required_primary_files": ["api.py"],
        "required_evidence_files": ["policy.py"],
        "required_finding_evidence_anchors": [
            {"file": "policy.py", "line": 5, "token": "authorize"}
        ],
    }


def _actual(*targets: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "complete",
        "finding_count": len(targets),
        "rule_ids": sorted({value for item in targets for value in item["rule_ids"]}),
        "categories": sorted(
            {value for item in targets for value in item["categories"]}
        ),
        "symbols": sorted({value for item in targets for value in item["symbols"]}),
        "primary_files": sorted(
            {value for item in targets for value in item["primary_files"]}
        ),
        "evidence_files": sorted(
            {value for item in targets for value in item["evidence_files"]}
        ),
        "mitigation_evidence_files": sorted(
            {
                value
                for item in targets
                for value in item.get("mitigation_evidence_files", ())
            }
        ),
        "finding_targets": list(targets),
    }


def test_positive_case_fails_and_counts_each_unmatched_finding_as_false_positive() -> (
    None
):
    expected = _expected_target()
    matching = _target()
    hallucinated = _target("cryptographic_trust")
    actual = _actual(matching, hallucinated)

    assert evaluate_case(actual, expected) == [
        "1 emitted finding(s) did not satisfy an explicitly allowed target contract"
    ]

    metrics = _aggregate_metrics(
        [{"label": "vulnerable", "expected": expected, "actual": actual}]
    )
    assert metrics["confusion_matrix"] == {
        "true_positive": 1,
        "false_positive": 1,
        "false_negative": 0,
        "true_negative": 0,
    }
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 1.0


def test_positive_case_preserves_multiple_findings_when_every_target_is_allowed() -> (
    None
):
    expected = _expected_target()
    actual = _actual(_target(), _target())

    assert evaluate_case(actual, expected) == []
    metrics = _aggregate_metrics(
        [{"label": "vulnerable", "expected": expected, "actual": actual}]
    )
    assert metrics["confusion_matrix"] == {
        "true_positive": 1,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 0,
    }


@pytest.mark.parametrize(
    "target",
    [
        _target(line=1, end_line=4),
        _target(line=None, end_line=None),
    ],
)
def test_same_evidence_filename_with_wrong_or_blank_range_fails(
    target: dict[str, Any],
) -> None:
    expected = _expected_target()
    actual = _actual(target)

    assert not _finding_matches_target(target, expected)
    assert evaluate_case(actual, expected) == [
        "no individual finding satisfied the complete expected target contract"
    ]


def test_direct_and_mitigation_evidence_cannot_satisfy_each_other() -> None:
    direct_only = _target()
    direct_only["evidence_files"].append("auth.py")
    direct_only["mitigation_evidence_files"] = ["pipeline.py"]
    mitigation_expected = _expected_target()
    mitigation_expected["required_mitigation_evidence_files"] = ["auth.py"]

    assert not _finding_matches_target(direct_only, mitigation_expected)
    mitigation_failures = evaluate_case(_actual(direct_only), mitigation_expected)
    assert (
        "mitigation_evidence_files missing required values: ['auth.py']"
        in mitigation_failures
    )
    assert (
        "no individual finding satisfied the complete expected target contract"
        in mitigation_failures
    )

    mitigation_only = _target()
    mitigation_only["evidence_files"] = ["policy.py"]
    mitigation_only["mitigation_evidence_files"] = ["auth.py"]
    direct_expected = _expected_target()
    direct_expected["required_evidence_files"] = ["policy.py", "auth.py"]

    assert not _finding_matches_target(mitigation_only, direct_expected)
    assert "evidence_files missing required values: ['auth.py']" in evaluate_case(
        _actual(mitigation_only),
        direct_expected,
    )


def test_all_shared_state_causal_anchors_require_covering_ranges() -> None:
    expected = _expected_target()
    expected["required_evidence_files"] = ["backend.py"]
    expected["required_finding_evidence_anchors"] = [
        {"file": "backend.py", "line": 11, "token": "return CACHE[key]"},
        {"file": "backend.py", "line": 15, "token": "CACHE[key] = value"},
    ]
    read_only = _target()
    read_only["evidence_files"] = ["backend.py"]
    read_only["evidence_locations"] = [
        {"file": "backend.py", "line": 8, "end_line": 12}
    ]

    assert not _finding_matches_target(read_only, expected)
    assert evaluate_case(_actual(read_only), expected) == [
        "no individual finding satisfied the complete expected target contract"
    ]

    read_and_write = dict(read_only)
    read_and_write["evidence_locations"] = [
        *read_only["evidence_locations"],
        {"file": "backend.py", "line": 15, "end_line": 15},
    ]
    assert _finding_matches_target(read_and_write, expected)
    assert evaluate_case(_actual(read_and_write), expected) == []


@pytest.mark.parametrize(
    "location",
    [
        {"file": "policy.py", "line": 1, "end_line": 4},
        {"file": "policy.py", "line": None, "end_line": None},
    ],
)
def test_same_clean_evidence_filename_with_wrong_or_blank_range_fails(
    location: dict[str, Any],
) -> None:
    expected = {
        "status": "complete",
        "finding_count": {"exact": 0},
        "required_clean_evidence_files": ["policy.py"],
        "required_clean_evidence_anchors": [
            {"file": "policy.py", "line": 5, "token": "authorize"}
        ],
    }
    actual = {
        "status": "complete",
        "finding_count": 0,
        "clean_evidence_files": ["policy.py"],
        "clean_evidence_locations": [location],
    }

    assert evaluate_case(actual, expected) == [
        "clean evidence does not cite a range covering required anchor policy.py:5"
    ]


def test_clean_evidence_anchor_accepts_a_covering_range() -> None:
    expected = {
        "status": "complete",
        "finding_count": {"exact": 0},
        "required_clean_evidence_anchors": [
            {"file": "policy.py", "line": 5, "token": "authorize"}
        ],
    }
    actual = {
        "status": "complete",
        "finding_count": 0,
        "clean_evidence_locations": [{"file": "policy.py", "line": 4, "end_line": 6}],
    }

    assert evaluate_case(actual, expected) == []
