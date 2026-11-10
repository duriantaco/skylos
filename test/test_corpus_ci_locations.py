"""Precise expectations extend the existing corpus guard and its fail-closed rules."""

import json

import pytest

from skylos.benchmarks import corpus_ci


def _case(tmp_path, *, mode="present"):
    source = tmp_path / "fixture"
    source.mkdir()
    (source / "app.py").write_text(
        "def add(values=[]):\n    values.append(1)\n    return values\n"
    )
    (source / "other.py").write_text("def other():\n    return 1\n")
    return {
        "id": "located",
        "path": "fixture",
        "source": {"repo": "https://example.org", "license": "Apache-2.0"},
        "scan": {"enable_quality": True, "grep_verify": False},
        "expect": {
            mode: {
                "quality": [
                    {
                        "rule_id": "SKY-L001",
                        "file": "app.py",
                        "start_line": 1,
                        "end_line": 2,
                    }
                ]
            }
        },
    }


def _report(rows=()):
    return {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 2,
            "languages": {"Python": 2},
            "grade_categories": ["quality"],
        },
        "quality": list(rows),
    }


@pytest.mark.parametrize(
    "wrong",
    [
        {"rule_id": "SKY-L007", "file": "app.py", "line": 1},
        {"rule_id": "SKY-L001", "file": "other.py", "line": 1},
        {"rule_id": "SKY-L001", "file": "app.py", "line": 3},
    ],
)
def test_one_finding_must_match_rule_file_and_span(tmp_path, monkeypatch, wrong):
    case = _case(tmp_path)
    monkeypatch.setattr(
        corpus_ci, "_scan_case", lambda *args, **kwargs: _report([wrong])
    )
    result = corpus_ci.run_case(case, tmp_path / "manifest.json")
    assert result["scored"] is True
    assert len(result["failures"]) == 1
    assert (
        json.loads(result["failures"][0]["expected"])
        == case["expect"]["present"]["quality"][0]
    )


def test_constraints_from_different_findings_cannot_combine(tmp_path, monkeypatch):
    case = _case(tmp_path)
    rows = [
        {"rule_id": "SKY-L001", "file": "other.py", "line": 1},
        {"rule_id": "SKY-L007", "file": "app.py", "line": 1},
    ]
    monkeypatch.setattr(corpus_ci, "_scan_case", lambda *args, **kwargs: _report(rows))
    assert len(corpus_ci.run_case(case, tmp_path / "manifest.json")["failures"]) == 1


def test_absolute_copied_source_locations_match_and_controls_detect_violations(
    tmp_path, monkeypatch
):
    case = _case(tmp_path)

    def scan(path, **kwargs):
        return _report(
            [
                {
                    "rule_id": "SKY-L001",
                    "file": str((path / "app.py").resolve()),
                    "line": 1,
                }
            ]
        )

    monkeypatch.setattr(corpus_ci, "_scan_case", scan)
    assert corpus_ci.run_case(case, tmp_path / "manifest.json")["failures"] == []
    case["expect"]["absent"] = case["expect"].pop("present")
    result = corpus_ci.run_case(case, tmp_path / "manifest.json")
    assert len(result["failures"]) == 1
    assert result["failures"][0]["mode"] == "absent"


@pytest.mark.parametrize(
    "invalid",
    [
        {"line": True},
        {"line": 0},
        {"line": None},
        {"line": 99},
        {"file": None},
        {"file": " "},
        {"file": "../app.py"},
        {"rule_id": None},
    ],
)
def test_malformed_mapped_findings_cannot_pass_absence_controls(
    tmp_path, monkeypatch, invalid
):
    case = _case(tmp_path, mode="absent")
    finding = {"rule_id": "SKY-L001", "file": "app.py", "line": 1, "name": "add"}
    finding.update(invalid)
    monkeypatch.setattr(
        corpus_ci, "_scan_case", lambda *args, **kwargs: _report([finding])
    )
    result = corpus_ci.run_case(case, tmp_path / "manifest.json")
    assert result["scored"] is False
    assert result["analysis_status"] == "incomplete"
    assert result["checked_expectation_count"] == 0


@pytest.mark.parametrize("missing", ["enabled", "categories", "language", "summary"])
def test_quality_coverage_is_required_before_claiming_a_clean_control(
    tmp_path, monkeypatch, missing
):
    case = _case(tmp_path, mode="absent")
    report = _report()
    if missing == "enabled":
        case["scan"]["enable_quality"] = False
    if missing == "categories":
        report["analysis_summary"]["grade_categories"] = []
    if missing == "language":
        report["analysis_summary"]["languages"] = {}
    if missing == "summary":
        report["analysis_summary"] = None
    monkeypatch.setattr(corpus_ci, "_scan_case", lambda *args, **kwargs: report)
    result = corpus_ci.run_case(case, tmp_path / "manifest.json")
    assert result["scored"] is False
    assert result["failures"][0]["mode"] == "completeness"


@pytest.mark.parametrize(
    "change",
    [
        {"rule_id": "SKY-UNKNOWN"},
        {"start_line": True},
        {"start_line": 3, "end_line": 1},
        {"end_line": 99},
        {"file": "../outside.py"},
        {"file": "missing.py"},
        {"file": "./app.py"},
        {"typo": 1},
    ],
)
def test_manifest_rejects_mistyped_or_impossible_locations(tmp_path, change):
    case = _case(tmp_path)
    case["expect"]["present"]["quality"][0].update(change)
    with pytest.raises(ValueError):
        corpus_ci.validate_manifest(
            {"version": 1, "cases": [case]}, tmp_path / "manifest.json"
        )


def test_legacy_symbol_expectations_still_use_their_existing_token_contract(
    tmp_path, monkeypatch
):
    case = _case(tmp_path)
    case["expect"] = {"present": {"unused_functions": ["unused_helper"]}}
    monkeypatch.setattr(
        corpus_ci,
        "_scan_case",
        lambda *args, **kwargs: {
            **_report(),
            "unused_functions": [{"name": "unused_helper", "line": 1}],
        },
    )
    assert corpus_ci.run_case(case, tmp_path / "manifest.json")["failures"] == []


def test_single_file_case_cannot_check_an_unscanned_sibling(tmp_path):
    case = _case(tmp_path)
    case["path"] = "fixture/app.py"
    case["expect"]["present"]["quality"][0]["file"] = "other.py"
    with pytest.raises(ValueError, match="sibling"):
        corpus_ci.validate_manifest(
            {"version": 1, "cases": [case]}, tmp_path / "manifest.json"
        )
