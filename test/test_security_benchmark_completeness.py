import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from skylos.benchmarks import security as benchmark


def _manifest(tmp_path, ids=("sample",)):
    cases = []
    for case_id in ids:
        directory = tmp_path / case_id
        directory.mkdir()
        (directory / "app.py").write_text('print("ready")\n', encoding="utf-8")
        cases.append(
            {
                "id": case_id,
                "path": case_id,
                "description": "A static security benchmark validity contract.",
                "taxonomy": ["sql_injection", "precision_guard"],
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                },
                "expect": {"present": {}, "absent": {"danger": ["SKY-D211"]}},
            }
        )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"version": 1, "cases": cases}), encoding="utf-8")
    return path


def _valid(**updates):
    return {
        "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
        "analysis_errors": [],
        **updates,
    }


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        {},
        {"analysis_summary": None},
        *(
            {"analysis_summary": {"total_files": value}}
            for value in (0, -1, True, False, 1.0, "1", None)
        ),
        _valid(analysis_errors=[{"kind": "syntax_error"}]),
        {"analysis_summary": {"total_files": 1, "analysis_error_count": 1}},
        {"analysis_summary": {"total_files": 1, "analysis_error_count": True}},
        _valid(analysis_errors="failed"),
        {
            "analysis_summary": {
                "total_files": 1,
                "grade_unavailable_reason": "analysis_incomplete",
            }
        },
        {"analysis_summary": {"total_files": 1, "incomplete_languages": ["kotlin"]}},
        {"analysis_summary": {"total_files": 1, "grep_verify": {"complete": False}}},
        {
            "analysis_summary": {
                "total_files": 1,
                "language_engines": {"dart": {"status": "unavailable"}},
            }
        },
        _valid(assessment={"coverage": {"status": "incomplete"}}),
        *(
            _valid(danger=value)
            for value in (
                None,
                False,
                0,
                "",
                {},
                [None],
                [{}],
                [{"type": "sql"}],
                [{"message": "SKY-D211"}],
                [{"rule_id": " "}],
            )
        ),
    ],
)
def test_invalid_security_reports_are_unscored_instead_of_safe(
    tmp_path, monkeypatch, report
):
    path = _manifest(tmp_path)
    monkeypatch.setattr(
        benchmark, "_scan_case_with_scanner", lambda *a, **k: copy.deepcopy(report)
    )
    summary = benchmark.run_manifest(path)
    case = summary["cases"][0]
    assert case["scored"] is False
    assert case["analysis_status"] == "incomplete"
    assert case["scores"]["overall_score"] == 0
    assert all(value == 0 for value in summary["counts"].values())
    assert summary["failure_count"] > 0
    assert summary["pass_count"] == 0
    assert summary["scored_case_count"] == 0
    assert summary["unscored_case_count"] == 1
    assert summary["score_unavailable_reason"] == "no_valid_cases"
    assert summary["scores"]["overall_score"] == 0
    assert "UNSCORED sample" in benchmark.format_summary(summary)


@pytest.mark.parametrize("field", ["message", "name", "file", "type", "value"])
def test_rule_identity_cannot_be_impersonated_by_other_tokens(
    tmp_path, monkeypatch, field
):
    path = _manifest(tmp_path)
    report = _valid(danger=[{"rule_id": "SKY-D209", field: "SKY-D211"}])
    monkeypatch.setattr(benchmark, "_scan_case_with_scanner", lambda *a, **k: report)
    summary = benchmark.run_manifest(path)
    assert summary["failure_count"] == 0
    assert summary["counts"]["true_negatives"] == 1
    case = benchmark.load_manifest(path)["cases"][0]
    case["expect"] = {"present": {"danger": ["SKY-D211"]}, "absent": {}}
    result = benchmark.run_case(case, path)
    assert result["true_positives"] == 0
    assert result["false_negatives"] == 1


def test_incomplete_report_does_not_award_present_findings(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    case = benchmark.load_manifest(path)["cases"][0]
    case["expect"]["present"] = {"danger": ["SKY-D209"]}
    report = _valid(
        analysis_errors=[{"kind": "read_error"}], danger=[{"rule_id": "SKY-D209"}]
    )
    monkeypatch.setattr(benchmark, "_scan_case_with_scanner", lambda *a, **k: report)
    result = benchmark.run_case(case, path)
    assert result["scored"] is False
    assert result["true_positives"] == result["true_negatives"] == 0
    assert {f["failure_type"] for f in result["failures"]} == {"analysis"}


def test_valid_limited_scope_and_zero_symbol_file_remain_scoreable(tmp_path):
    path = _manifest(tmp_path)
    result = benchmark.run_manifest(path)
    assert result["failure_count"] == 0
    assert result["counts"]["true_negatives"] == 1
    assert result["cases"][0]["scored"] is True


def test_mixed_real_syntax_failure_is_visible_and_not_scored(tmp_path):
    path = _manifest(tmp_path, ids=("valid", "invalid"))
    (tmp_path / "invalid/app.py").write_text(
        "def broken(:\n    pass\n", encoding="utf-8"
    )
    summary = benchmark.run_manifest(path)
    assert summary["failure_count"] == 1
    assert summary["analysis_status"] == "incomplete"
    assert summary["metrics_scoped_to_scored_cases"] is True
    assert summary["scored_case_count"] == summary["unscored_case_count"] == 1
    assert summary["counts"]["true_negatives"] == 1
    assert summary["scores"]["overall_score"] == 100


def test_bandit_report_does_not_require_skylos_metadata(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    monkeypatch.setattr(benchmark, "_scan_case_with_scanner", lambda *a, **k: {})
    result = benchmark.run_manifest(path, scanner="bandit")
    assert result["failure_count"] == 0
    assert result["counts"]["true_negatives"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [],
        None,
        {"results": {}},
        {"results": [None]},
        {"results": [], "errors": [{"filename": "app.py", "reason": "syntax error"}]},
        {"results": [], "errors": "failed"},
    ],
)
def test_bandit_invalid_payload_or_errors_are_unscored(tmp_path, monkeypatch, payload):
    path = _manifest(tmp_path)
    monkeypatch.setattr(benchmark.shutil, "which", lambda name: "/usr/bin/bandit")
    monkeypatch.setattr(
        benchmark.subprocess,
        "run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(
            cmd, 0, json.dumps(payload), ""
        ),
    )
    result = benchmark.run_manifest(path, scanner="bandit")
    assert result["failure_count"] > 0
    assert result["cases"][0]["scored"] is False
    assert result["counts"]["true_negatives"] == 0


def test_unknown_requested_case_is_rejected(tmp_path):
    path = _manifest(tmp_path)
    with pytest.raises(ValueError, match="unknown.*missing"):
        benchmark.run_manifest(path, selected_cases={"missing"})


def test_all_skipped_cases_have_no_score(tmp_path):
    path = _manifest(tmp_path)
    manifest = benchmark.load_manifest(path)
    manifest["cases"][0]["languages"] = ["java"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = benchmark.run_manifest(path, scanner="bandit")
    assert result["skipped_case_count"] == 1
    assert result["case_count"] == 0
    assert result["scores"]["overall_score"] == 0
    assert result["score_unavailable_reason"] == "no_valid_cases"


def test_cli_exits_nonzero_for_failed_analysis(tmp_path):
    path = _manifest(tmp_path)
    (tmp_path / "sample/app.py").write_text(
        "def broken(:\n    pass\n", encoding="utf-8"
    )
    root = Path(__file__).resolve().parents[1]
    env = {
        k: v
        for k, v in os.environ.items()
        if not any(
            word in k.upper()
            for word in ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY")
        )
    }
    env.update(
        PYTHONPATH=str(root),
        PYTHONDONTWRITEBYTECODE="1",
        SKYLOS_CUSTOM_RULES="[]",
        SKYLOS_NO_UPLOAD="1",
        SKYLOS_NO_TELEMETRY="1",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/security_benchmark.py"),
            "--manifest",
            str(path),
            "--json",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    summary = json.loads(result.stdout)
    assert summary["cases"][0]["scored"] is False
    assert summary["counts"]["true_negatives"] == 0
