"""Contracts for evaluation health and comparable before/after evidence."""

from copy import deepcopy

import pytest

from skylos.benchmarks.eval_report import compare_receipts, format_comparison


def _case(case_id="ssrf-safe", *, failures=None, findings=None, unresolved=None):
    failures = failures or []
    return {
        "id": case_id,
        "status": "failed" if failures else "passed",
        "failures": failures,
        "findings": findings or [],
        "unresolved_findings": unresolved or [],
    }


def _failure(expected="SKY-D216", *, mode="absent", kind="expectation", found=None):
    return {
        "failure_type": kind,
        "category": "danger",
        "mode": mode,
        "expected": expected,
        "found": found or [],
    }


def _receipt(*cases, phase="baseline"):
    records = list(cases) or [_case()]
    return {
        "schema_version": 1,
        "phase": phase,
        "suite": "security",
        "case_ids": [case["id"] for case in records],
        "inputs": {
            "dataset_sha256": "a" * 64,
            "harness_sha256": "b" * 64,
            "environment_sha256": "c" * 64,
            "options": {"scanner": "skylos", "strict_labels": False},
        },
        "source_unchanged": True,
        "cases": records,
        "runtime_errors": [],
        "elapsed_seconds": 0.75,
    }


def _pair(*cases):
    baseline = _receipt(*cases)
    candidate = deepcopy(baseline)
    candidate["phase"] = "candidate"
    return baseline, candidate


def test_complete_matching_receipts_pass_and_show_scope():
    baseline, candidate = _pair()
    report = compare_receipts(baseline, candidate)

    assert report["comparable"] is True
    assert report["no_new_regressions"] is True
    assert report["candidate_passed"] is True
    assert report["exit_code"] == 0
    assert report["baseline_counts"] == {
        "passed": 1,
        "failed": 0,
        "incomplete": 0,
        "unresolved": 0,
    }
    text = format_comparison(report)
    assert "1 selected cases (scoped)" in text
    assert "No new regressions: yes" in text
    assert "Broader validation: separate required checks" in text


def test_fix_does_not_mask_a_different_new_failure_with_the_same_total():
    baseline, candidate = _pair(
        _case("old-failure", failures=[_failure("SKY-D211")]),
        _case("new-failure"),
    )
    candidate["cases"] = [
        _case("old-failure"),
        _case("new-failure", failures=[_failure("SKY-D216")]),
    ]

    report = compare_receipts(baseline, candidate)

    assert report["baseline_counts"]["failed"] == 1
    assert report["candidate_counts"]["failed"] == 1
    assert report["new_failures"][0]["case_id"] == "new-failure"
    assert report["resolved_failures"][0]["case_id"] == "old-failure"
    assert not report["no_new_regressions"]
    assert not report["candidate_passed"]
    assert report["exit_code"] == 1


def test_existing_failure_is_no_new_regression_but_candidate_does_not_pass():
    baseline, candidate = _pair(_case(failures=[_failure()]))
    report = compare_receipts(baseline, candidate)

    assert report["comparable"]
    assert report["no_new_regressions"]
    assert not report["candidate_passed"]
    assert len(report["existing_failures"]) == 1
    assert report["exit_code"] == 1
    text = format_comparison(report)
    assert "Existing failures: 1" in text
    assert "Candidate checks: not passed" in text


def test_resolving_baseline_failure_can_pass():
    baseline, candidate = _pair(_case(failures=[_failure()]))
    candidate["cases"] = [_case()]
    report = compare_receipts(baseline, candidate)

    assert len(report["resolved_failures"]) == 1
    assert report["new_failures"] == []
    assert report["candidate_passed"]
    assert report["exit_code"] == 0


def test_changed_unlabelled_finding_cannot_hide_under_the_same_placeholder():
    old = _failure(
        "explicit unused/used label",
        mode="strict_labels",
        kind="unlabeled",
        found=["function:app.py:Owner.old"],
    )
    new = deepcopy(old)
    new["found"] = ["function:app.py:Owner.new"]
    baseline, candidate = _pair(_case(failures=[old]))
    candidate["cases"] = [_case(failures=[new])]

    report = compare_receipts(baseline, candidate)

    assert len(report["new_failures"]) == 1
    assert len(report["resolved_failures"]) == 1
    assert report["existing_failures"] == []
    assert report["exit_code"] == 1


def test_budget_observation_changes_do_not_invent_a_different_contract():
    failure = _failure("5.000s", mode="max_seconds", kind="budget", found=["6.100s"])
    baseline, candidate = _pair(_case(failures=[failure]))
    candidate["cases"][0]["failures"][0]["found"] = ["8.200s"]

    report = compare_receipts(baseline, candidate)

    assert report["new_failures"] == []
    assert len(report["existing_failures"]) == 1
    assert report["no_new_regressions"]
    assert report["exit_code"] == 1


def test_unknown_failure_shapes_keep_their_full_identity():
    baseline, candidate = _pair(_case(failures=[{"message": "old failure"}]))
    candidate["cases"][0]["failures"] = [{"message": "different failure"}]

    report = compare_receipts(baseline, candidate)

    assert len(report["new_failures"]) == 1
    assert len(report["resolved_failures"]) == 1
    assert not report["no_new_regressions"]


def test_execution_failure_cannot_be_downgraded_to_an_existing_expectation_failure():
    baseline, candidate = _pair(_case(failures=[_failure(kind="analysis")]))

    report = compare_receipts(baseline, candidate)

    assert not report["comparable"]
    assert not report["no_new_regressions"]
    assert report["exit_code"] == 1


@pytest.mark.parametrize(
    "field,new",
    [("owner", "Other"), ("rule_id", "SKY-D211"), ("file", "b.py"), ("line", 17)],
)
def test_full_finding_identity_preserves_owner_rule_file_and_line(field, new):
    finding = {"owner": "Primary", "rule_id": "SKY-D216", "file": "a.py", "line": 8}
    baseline, candidate = _pair(_case(findings=[finding]))
    candidate["cases"][0]["findings"][0][field] = new

    report = compare_receipts(baseline, candidate)

    changes = report["finding_changes"][0]
    assert changes["removed"] == [finding]
    assert changes["added"][0][field] == new


def test_finding_object_key_order_and_case_execution_order_do_not_change_identity():
    baseline, candidate = _pair(
        _case("a", findings=[{"rule_id": "SKY-D216", "line": 8}]), _case("b")
    )
    candidate["case_ids"].reverse()
    candidate["cases"][0]["findings"] = [{"line": 8, "rule_id": "SKY-D216"}]
    candidate["cases"].reverse()

    report = compare_receipts(baseline, candidate)

    assert report["comparable"]
    assert report["finding_changes"] == []
    assert report["exit_code"] == 0


def test_unresolved_candidate_findings_block_a_clean_claim_without_calling_them_fp():
    baseline, candidate = _pair()
    candidate["cases"][0]["unresolved_findings"] = [{"rule_id": "SKY-D211"}]

    report = compare_receipts(baseline, candidate)

    assert report["comparable"]
    assert report["candidate_counts"]["unresolved"] == 1
    assert not report["candidate_passed"]
    assert not report["no_new_regressions"]
    assert report["new_failures"] == []
    assert report["exit_code"] == 1


@pytest.mark.parametrize("side", ["baseline", "candidate"])
def test_incomplete_analysis_on_either_side_blocks_comparison(side):
    baseline, candidate = _pair()
    receipt = baseline if side == "baseline" else candidate
    receipt["cases"][0]["status"] = "incomplete"

    report = compare_receipts(baseline, candidate)

    assert not report["comparable"]
    assert not report["no_new_regressions"]
    assert report[f"{side}_counts"]["incomplete"] == 1
    assert report["exit_code"] == 1
    assert "Comparison: blocked" in format_comparison(report)


@pytest.mark.parametrize(
    "field", ["dataset_sha256", "harness_sha256", "environment_sha256"]
)
def test_changed_dataset_harness_or_environment_blocks_comparison(field):
    baseline, candidate = _pair()
    candidate["inputs"][field] = "d" * 64
    report = compare_receipts(baseline, candidate)

    assert not report["comparable"]
    assert (
        "baseline/candidate evaluation inputs mismatch" in report["comparison_issues"]
    )
    assert not report["no_new_regressions"]
    assert report["exit_code"] == 1


def test_changed_scan_option_blocks_comparison_even_for_bool_vs_int():
    baseline, candidate = _pair()
    candidate["inputs"]["options"]["strict_labels"] = 0
    report = compare_receipts(baseline, candidate)
    assert not report["comparable"]


@pytest.mark.parametrize("side", ["baseline", "candidate"])
def test_missing_successful_case_is_incomplete_not_a_resolved_failure(side):
    baseline, candidate = _pair(_case("a"), _case("b"))
    receipt = baseline if side == "baseline" else candidate
    receipt["cases"].pop()
    report = compare_receipts(baseline, candidate)

    assert not report["comparable"]
    assert report[f"{side}_counts"]["incomplete"] == 1
    assert report["new_failures"] == report["resolved_failures"] == []
    assert report["exit_code"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_record",
        "duplicate_selector",
        "extra_record",
        "different_cohort",
        "empty_cohort",
    ],
)
def test_invalid_or_changed_inventory_blocks_comparison(mutation):
    baseline, candidate = _pair()
    if mutation == "duplicate_record":
        candidate["cases"].append(deepcopy(candidate["cases"][0]))
    elif mutation == "duplicate_selector":
        candidate["case_ids"].append(candidate["case_ids"][0])
    elif mutation == "extra_record":
        candidate["cases"].append(_case("extra"))
    elif mutation == "different_cohort":
        candidate["case_ids"] = ["different"]
        candidate["cases"] = [_case("different")]
    else:
        candidate["case_ids"] = []
        candidate["cases"] = []

    report = compare_receipts(baseline, candidate)
    assert not report["comparable"]
    assert not report["no_new_regressions"]
    assert report["exit_code"] == 1


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("phase", "baseline"),
        ("suite", "other"),
        ("suite", {}),
        ("source_unchanged", False),
        ("source_unchanged", 1),
        ("runtime_errors", ["scanner crashed"]),
        ("runtime_errors", None),
        ("runtime_errors", [False]),
        ("elapsed_seconds", float("nan")),
        ("elapsed_seconds", float("inf")),
        ("elapsed_seconds", -1),
        ("elapsed_seconds", True),
        ("inputs", None),
        ("case_ids", [False]),
        ("cases", None),
    ],
)
def test_invalid_receipt_metadata_cannot_earn_a_pass(key, value):
    baseline, candidate = _pair()
    candidate[key] = value
    report = compare_receipts(baseline, candidate)

    assert not report["comparable"]
    assert not report["candidate_passed"]
    assert not report["no_new_regressions"]
    assert report["exit_code"] == 1


@pytest.mark.parametrize(
    "key,value",
    [
        ("status", "skipped"),
        ("status", {}),
        ("status", "failed"),
        ("failures", [{}]),
        ("failures", [_failure()]),
        ("failures", [{"failure_type": {}, "found": []}]),
        ("failures", [{"failure_type": "unlabeled", "found": "bad"}]),
        ("findings", "not findings"),
        ("findings", [None]),
        ("findings", [{"line": float("nan")}]),
        ("unresolved_findings", None),
    ],
)
def test_invalid_case_records_cannot_earn_a_pass(key, value):
    baseline, candidate = _pair()
    candidate["cases"][0][key] = value
    report = compare_receipts(baseline, candidate)

    assert not report["comparable"]
    assert not report["candidate_passed"]
    assert report["exit_code"] == 1


@pytest.mark.parametrize("invalid", [None, [], "", False])
def test_non_object_receipts_are_reported_without_crashing(invalid):
    report = compare_receipts(invalid, invalid)

    assert not report["comparable"]
    assert not report["candidate_passed"]
    assert report["exit_code"] == 1
    assert "Comparison: blocked" in format_comparison(report)
