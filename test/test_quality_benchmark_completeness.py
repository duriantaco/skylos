"""A failed or unsupported quality scan must never earn clean-case credit."""

from copy import deepcopy
import json

import pytest

from skylos.benchmarks import quality


def _report():
    return {
        "analysis_summary": {
            "total_files": 1,
            "languages": {"Python": 1},
            "analysis_error_count": 0,
        },
        "analysis_errors": [],
        "quality": [],
    }


@pytest.fixture
def case_and_manifest(tmp_path):
    directory = tmp_path / "fixture"
    directory.mkdir()
    (directory / "app.py").write_text("def helper():\n    return 1\n")
    case = {
        "id": "quality-coverage",
        "path": "fixture",
        "languages": ["python"],
        "taxonomy": ["precision_guard"],
        "importance": "critical",
        "source": {
            "repo": "https://github.com/duriantaco/skylos",
            "license": "Apache-2.0",
        },
        "expect": {"present": {}, "absent": {"quality": ["SKY-UC002"]}},
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "cases": [case]}))
    return case, manifest


def _incomplete(change):
    report = _report()
    if change == "not_object":
        return []
    if change == "missing_summary":
        del report["analysis_summary"]
    elif change in {"zero_files", "bool_files", "float_files"}:
        report["analysis_summary"]["total_files"] = {
            "zero_files": 0,
            "bool_files": True,
            "float_files": 1.0,
        }[change]
    elif change == "errors":
        report["analysis_errors"] = [
            {"kind": "quality_scan_error", "message": "forced"}
        ]
    elif change == "error_count":
        report["analysis_summary"]["analysis_error_count"] = 1
    elif change == "malformed_errors":
        report["analysis_errors"] = "failed"
    elif change == "engine_unavailable":
        report["analysis_summary"]["language_engines"] = {
            "Python": {"status": "unavailable", "complete": False}
        }
    elif change == "wrong_language":
        report["analysis_summary"]["languages"] = {"Ruby": 1}
    elif change == "missing_language":
        del report["analysis_summary"]["languages"]
    elif change == "bool_language_count":
        report["analysis_summary"]["languages"] = {"Python": True}
    elif change == "partial_assessment":
        report["assessment"] = {"coverage": {"status": "incomplete"}}
    elif change == "bad_quality":
        report["quality"] = {"rule_id": "SKY-UC002"}
    elif change == "bad_finding":
        report["quality"] = [{}]
    elif change == "partial_status":
        report["analysis_status"] = "partial"
    return report


@pytest.mark.parametrize("mode", ["present", "absent"])
@pytest.mark.parametrize(
    "change",
    [
        "not_object",
        "missing_summary",
        "zero_files",
        "bool_files",
        "float_files",
        "errors",
        "error_count",
        "malformed_errors",
        "engine_unavailable",
        "wrong_language",
        "missing_language",
        "bool_language_count",
        "partial_assessment",
        "bad_quality",
        "bad_finding",
        "partial_status",
    ],
)
def test_incomplete_quality_reports_earn_no_presence_or_absence_credit(
    case_and_manifest, monkeypatch, change, mode
):
    case, manifest = case_and_manifest
    case["expect"] = {"present": {}, "absent": {}}
    case["expect"][mode] = {"quality": ["SKY-UC002"]}
    monkeypatch.setattr(quality, "_scan_case", lambda *a, **k: _incomplete(change))
    result = quality.run_case(case, manifest)
    assert result["scored"] is False
    assert result["analysis_status"] == "incomplete"
    assert result["analysis_issues"]
    assert result["present_matched"] == result["absent_total"] == 0
    assert all(value == 0 for value in result["scores"].values())
    assert {failure["failure_type"] for failure in result["failures"]} == {"analysis"}


@pytest.mark.parametrize("field", ["name", "full_name", "value", "type"])
@pytest.mark.parametrize("mode", ["present", "absent"])
def test_only_canonical_rule_identity_matches_a_quality_rule_expectation(
    case_and_manifest, monkeypatch, field, mode
):
    case, manifest = case_and_manifest
    case["expect"] = {"present": {}, "absent": {}}
    case["expect"][mode] = {"quality": ["SKY-UC002"]}
    report = _report()
    report["quality"] = [{"rule_id": "OTHER-RULE", field: "SKY-UC002"}]
    monkeypatch.setattr(quality, "_scan_case", lambda *a, **k: report)
    result = quality.run_case(case, manifest)
    assert result["scored"] is True
    assert result["present_matched"] == result["absent_violations"] == 0
    assert bool(result["failures"]) is (mode == "present")


def test_valid_empty_quality_analysis_can_earn_absence_credit(
    case_and_manifest, monkeypatch
):
    case, manifest = case_and_manifest
    monkeypatch.setattr(quality, "_scan_case", lambda *a, **k: _report())
    result = quality.run_case(case, manifest)
    assert result["scored"] is True
    assert result["analysis_issues"] == []
    assert result["absent_total"] == 1
    assert result["failures"] == []
    assert result["scores"]["overall_score"] == 100


def test_all_incomplete_quality_cases_have_no_score(case_and_manifest, monkeypatch):
    _, manifest = case_and_manifest
    monkeypatch.setattr(quality, "_scan_case", lambda *a, **k: _incomplete("errors"))
    result = quality.run_manifest(manifest)
    assert result["scored_case_count"] == 0
    assert result["unscored_case_count"] == 1
    assert result["score_unavailable_reason"] == "no_valid_cases"
    assert result["pass_count"] == 0
    assert result["failure_count"] > 0
    assert all(value == 0 for value in result["scores"].values())
    assert "UNSCORED quality-coverage" in quality.format_summary(result)


def test_partial_quality_aggregate_scores_only_complete_cases(
    case_and_manifest, monkeypatch
):
    case, manifest = case_and_manifest
    second = deepcopy(case)
    second["id"] = "incomplete"
    manifest.write_text(json.dumps({"version": 1, "cases": [case, second]}))
    reports = iter([_report(), _incomplete("errors")])
    monkeypatch.setattr(quality, "_scan_case", lambda *a, **k: next(reports))
    result = quality.run_manifest(manifest)
    assert result["scored_case_count"] == result["unscored_case_count"] == 1
    assert result["scores"]["overall_score"] == 100
    assert result["failure_count"] > 0
    assert result["analysis_status"] == "incomplete"
    assert result["taxonomy"]["precision_guard"]["unscored_case_count"] == 1


@pytest.mark.parametrize("language", ["php", "kotlin", "dart", "ruby", "unknown"])
def test_unsupported_quality_language_cannot_earn_a_clean_case(
    case_and_manifest, monkeypatch, language
):
    case, manifest = case_and_manifest
    case["languages"] = [language]
    monkeypatch.setattr(quality, "_scan_case", lambda *a, **k: _report())
    result = quality.run_case(case, manifest)
    assert result["scored"] is False
    assert result["analysis_issues"]


def test_unknown_selected_quality_case_is_an_error(case_and_manifest):
    _, manifest = case_and_manifest
    with pytest.raises(ValueError, match="unknown"):
        quality.run_manifest(manifest, selected_cases={"typo-case-id"})


def test_null_scan_options_keep_existing_defaults(case_and_manifest, monkeypatch):
    case, manifest = case_and_manifest
    case["scan"] = None
    monkeypatch.setattr(quality, "_scan_case", lambda *a, **k: _report())
    result = quality.run_case(case, manifest)
    assert result["scored"] is True
    assert result["failures"] == []


def test_disabled_quality_scan_cannot_earn_absence_credit(
    case_and_manifest, monkeypatch
):
    case, manifest = case_and_manifest
    case["scan"] = {"enable_quality": False}
    monkeypatch.setattr(quality, "_scan_case", lambda *a, **k: _report())
    result = quality.run_case(case, manifest)
    assert result["scored"] is False
    assert result["scores"]["overall_score"] == 0


def test_native_quality_rule_failure_is_unscored(case_and_manifest, monkeypatch):
    import skylos.analysis.file_worker as worker

    def fail_quality(*args, **kwargs):
        raise RuntimeError("forced quality rule failure")

    monkeypatch.setattr(worker, "scan_python_quality", fail_quality)
    case, manifest = case_and_manifest
    reports = []
    original = quality._scan_case

    def capture(*args, **kwargs):
        report = original(*args, **kwargs)
        reports.append(report)
        return report

    monkeypatch.setattr(quality, "_scan_case", capture)
    result = quality.run_case(case, manifest)
    assert reports[0]["analysis_summary"]["total_files"] == 1
    assert any(e["kind"] == "quality_scan_error" for e in reports[0]["analysis_errors"])
    assert result["scored"] is False
    assert result["scores"]["overall_score"] == 0


def test_native_go_engine_missing_stays_unscored_even_with_quality_findings(
    tmp_path, monkeypatch
):
    from pathlib import Path

    manifest = Path(__file__).resolve().parents[1] / "benchmarks/quality/manifest.json"
    case = next(
        c
        for c in quality.load_manifest(manifest)["cases"]
        if c["id"] == "go-service-quality-hotspot"
    )
    monkeypatch.setenv("SKYLOS_GO_BIN", str(tmp_path / "missing-skylos-go"))
    reports = []
    scan = quality._scan_case

    def capture(*args, **kwargs):
        report = scan(*args, **kwargs)
        reports.append(report)
        return report

    monkeypatch.setattr(quality, "_scan_case", capture)
    result = quality.run_case(case, manifest)
    report = reports[0]
    assert report["analysis_summary"]["languages"] == {"Go": 1}
    assert report["analysis_summary"]["total_files"] == 1
    assert {r["rule_id"] for r in report["quality"]} >= {"SKY-Q301", "SKY-C303"}
    assert any(
        e["error_type"] == "GoEngineUnavailable" for e in report["analysis_errors"]
    )
    assert result["scored"] is False
    assert result["analysis_status"] == "incomplete"
    assert result["present_matched"] == 0
    assert all(value == 0 for value in result["scores"].values())
