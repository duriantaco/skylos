"""Retained optional advice is not a filtered or incomplete upload."""

from copy import deepcopy

import pytest

import skylos.api as api
from skylos.api._scan_coverage import scan_coverage_receipt
from skylos.core.gatekeeper import check_gate
from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.assessment import compute_assessment
from skylos.reporting.listing import is_listed, listed_result


def _raw_report():
    return {
        "analysis_summary": {
            "comparison_scope": {
                "kind": "repository_root",
                "complete_repository": True,
                "changed_files_only": False,
                "excluded_folders": [],
            },
            "grade_categories": ["security", "quality"],
            "analysis_error_count": 0,
            "resolution_scope_limited": False,
        },
        "analysis_errors": [],
        "suppressed": [],
        "quality": [
            {
                "rule_id": "SKY-L027",
                "file": "service.py",
                "line": 1,
                "severity": "MEDIUM",
                "message": "Measured recommendation",
            }
        ],
        "danger": [
            {
                "rule_id": "SKY-D212",
                "file": "service.py",
                "line": 2,
                "severity": "HIGH",
                "message": "Untrusted command",
            }
        ],
        "architecture_metrics": {"iad_enforced": False, "advisories": []},
        "provenance": {},
    }


def _listed_report(tmp_path, *, all_advice=False):
    result = _raw_report()
    result["assessment"] = compute_assessment(result)
    return apply_advice_policy(result, project_root=tmp_path, all_advice=all_advice)


def _coverage(result):
    return scan_coverage_receipt(result, analyzer_owned=True, analysis_mode="static")


@pytest.mark.parametrize("all_advice", [False, True])
def test_raw_and_listed_assessments_both_preserve_complete_upload_coverage(
    tmp_path, all_advice
):
    result = _listed_report(tmp_path, all_advice=all_advice)
    before = deepcopy(result)
    assert len(result["quality"]) == 1
    assert result["assessment"]["finding_counts"]["advice"] == int(all_advice)
    assert result["analysis_summary"]["finding_type_counts"]["advice"] == 1
    assert result["quality"][0]["listing"]["listed"] is all_advice
    receipt = _coverage(result)
    assert receipt["complete"] is True
    assert receipt["resolution_covered_checks"] == ["security", "quality"]
    assert result == before


def test_native_upload_preparation_retains_original_assessment_and_all_rows(
    tmp_path, monkeypatch
):
    result = _listed_report(tmp_path)
    before = deepcopy(result)
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "detect_ai_code", lambda *_: {"detected": False})
    monkeypatch.setattr(api, "_annotate_findings_with_blame", lambda *_: None)
    monkeypatch.setattr(api, "_load_repo_link", lambda *_: {})
    prepared = api._prepare_report_upload(result, analyzer_owned=True)
    for body in (
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
        prepared.metadata,
    ):
        assert body["scan_coverage"]["complete"] is True
        assert body["assessment"] == before["assessment"]
    rows = {row["ruleId"]: row for row in prepared.core_payload["runs"][0]["results"]}
    assert set(rows) == {"SKY-L027", "SKY-D212"}
    assert rows["SKY-L027"]["properties"]["listing"]["listed"] is False
    assert rows["SKY-D212"]["properties"]["listing"]["listed"] is True
    assert result == before


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r["quality"].clear(),
        lambda r: r["danger"].clear(),
        lambda r: r["assessment"]["risk"].update(finding_count=99),
        lambda r: r["analysis_summary"]["finding_type_counts"].update(advice=2),
        lambda r: r["analysis_summary"]["listed_finding_type_counts"].update(
            advice=False
        ),
        lambda r: r["analysis_summary"]["listed_finding_type_counts"].update(review=2),
        lambda r: r["analysis_summary"].pop("finding_type_counts"),
        lambda r: r["analysis_summary"].pop("listed_finding_type_counts"),
        lambda r: r["analysis_summary"].update(assessment_scope="unknown"),
        lambda r: r.update(listing_policy_version=2),
        lambda r: r.update(listing_policy_version=True),
        lambda r: r["assessment"].update(version=True),
    ],
    ids=[
        "removed_advice",
        "removed_risk",
        "forged_risk",
        "raw_count",
        "boolean_count",
        "listed_count",
        "missing_raw_count",
        "missing_listed_count",
        "unknown_scope",
        "future_listing_version",
        "boolean_listing_version",
        "boolean_assessment_version",
    ],
)
def test_missing_stale_or_inconsistent_listing_evidence_cannot_attest_absence(
    tmp_path, change
):
    result = _listed_report(tmp_path)
    change(result)
    before = deepcopy(result)
    receipt = _coverage(result)
    assert receipt["complete"] is False
    assert "filtered_findings" in receipt["reasons"]
    assert receipt["resolution_covered_checks"] == []
    assert result == before


@pytest.mark.parametrize(
    "change,reason",
    [
        (
            lambda r: r["analysis_summary"].update(selected_rules=["SKY-D212"]),
            "selected_rules",
        ),
        (
            lambda r: r["analysis_summary"].update(
                assessment_includes_filtered_findings=True
            ),
            "filtered_findings",
        ),
        (
            lambda r: r["analysis_summary"].update(resolution_scope_limited=True),
            "configured_suppression",
        ),
        (
            lambda r: r["suppressed"].append(deepcopy(r["danger"][0])),
            "suppressed_findings",
        ),
        (
            lambda r: r["analysis_errors"].append({"kind": "parse_error"}),
            "analysis_incomplete",
        ),
        (
            lambda r: r["analysis_summary"].update(grep_verify={"complete": False}),
            "analysis_incomplete",
        ),
        (
            lambda r: r["analysis_summary"]["comparison_scope"].update(
                changed_files_only=True
            ),
            "partial_repository",
        ),
    ],
)
def test_listing_compatibility_keeps_existing_completeness_guards(
    tmp_path, change, reason
):
    result = _listed_report(tmp_path)
    change(result)
    receipt = _coverage(result)
    assert receipt["complete"] is False
    assert reason in receipt["reasons"]
    assert receipt["resolution_covered_checks"] == []


def test_actual_display_filter_cannot_resolve_absent_issues(tmp_path):
    from skylos.cli import _apply_display_filters

    result = _listed_report(tmp_path)
    filtered = _apply_display_filters(result, severity="critical")
    assert filtered["danger"] == []
    assert _coverage(filtered)["complete"] is False


def test_risk_findings_cannot_be_hidden_by_an_optional_advice_mark(tmp_path):
    result = _listed_report(tmp_path)
    result["danger"][0]["listing"] = {
        "version": 1,
        "listed": False,
        "reason": "measurement",
    }
    assert is_listed(result["danger"][0], "danger") is True
    assert listed_result(result)["danger"] == result["danger"]
    assert check_gate(result, {"gate": {"max_high": 0, "max_security": 0}})[0] is False
    assert _coverage(result)["complete"] is True


@pytest.mark.parametrize("receipt_kind", ["grade", "assessment"])
def test_legacy_grade_and_unversioned_raw_assessment_still_work(receipt_kind):
    result = _raw_report()
    if receipt_kind == "grade":
        result["grade"] = {"overall": "A"}
    else:
        result["assessment"] = compute_assessment(result)
    assert "listing_policy_version" not in result
    assert _coverage(result)["complete"] is True


def test_complete_raw_count_proof_does_not_require_new_listing_summaries(tmp_path):
    result = _listed_report(tmp_path, all_advice=True)
    result["analysis_summary"].update(assessment_scope="all_analyzed_findings")
    result["analysis_summary"].pop("listed_finding_type_counts")
    result["analysis_summary"].pop("finding_type_counts")
    assert _coverage(result)["complete"] is True


def test_direct_analyzer_and_native_upload_keep_complete_raw_reports(
    tmp_path, monkeypatch
):
    import json
    from skylos.analyzer import analyze

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_quality=True,
            include_review_context=True,
            all_advice=True,
            grep_verify=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    assert result["analysis_summary"]["assessment_scope"] == "listed_findings"
    assert _coverage(result)["complete"] is True
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "detect_ai_code", lambda *_: {"detected": False})
    monkeypatch.setattr(api, "_annotate_findings_with_blame", lambda *_: None)
    monkeypatch.setattr(api, "_load_repo_link", lambda *_: {})
    prepared = api._prepare_report_upload(result, analyzer_owned=True)
    assert prepared.metadata["scan_coverage"]["complete"] is True
    assert prepared.metadata["assessment"] == result["assessment"]
