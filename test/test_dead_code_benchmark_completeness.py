import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import skylos.benchmarks.dead_code as benchmark


COUNTS = ("true_positives", "false_positives", "false_negatives", "true_negatives")


def _manifest(tmp_path, *, ids=("sample",), source=None, scan_paths=None):
    cases = []
    for case_id in ids:
        directory = tmp_path / case_id
        directory.mkdir()
        (directory / "app.py").write_text(
            source or "def measure():\n    return 7\n\nprint(measure())\n"
        )
        case = {
            "id": case_id,
            "path": case_id,
            "description": "A local static benchmark completeness contract.",
            "taxonomy": ["precision_guard"],
            "source": {"repo": "https://github.com/example/project", "license": "MIT"},
            "expect": {
                "unused": [],
                "used": [{"kind": "function", "file": "app.py", "symbol": "measure"}],
            },
        }
        if scan_paths:
            case["scan_paths"] = scan_paths
        cases.append(case)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"version": 1, "cases": cases}))
    return path


def _mock_report(monkeypatch, report):
    monkeypatch.setattr(
        benchmark, "_scan_case_with_scanner", lambda *a, **k: copy.deepcopy(report)
    )


def _static_analyzer(monkeypatch):
    original = benchmark.analyze

    def static(*args, **kwargs):
        kwargs.update(
            trace_file=False,
            grep_cache=False,
            enable_ai_defects=False,
            enable_dependency_hallucinations=False,
            enable_sca=False,
        )
        return original(*args, **kwargs)

    monkeypatch.setattr(benchmark, "analyze", static)
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")


@pytest.mark.parametrize(
    "report",
    [
        None,
        [],
        {},
        {"analysis_summary": None},
        {"analysis_summary": []},
        *(
            {"analysis_summary": {"total_files": value}}
            for value in (0, -1, True, False, 1.0, "1", None, float("nan"))
        ),
        {
            "analysis_summary": {"total_files": 1},
            "analysis_errors": [{"kind": "syntax_error"}],
        },
        {
            "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
            "analysis_errors": [{"kind": "syntax_error"}],
        },
        *(
            {"analysis_summary": {"total_files": 1, "analysis_error_count": value}}
            for value in (1, -1, True, "0", None)
        ),
        {"analysis_summary": {"total_files": 1}, "analysis_errors": "failed"},
        {
            "analysis_summary": {
                "total_files": 1,
                "grade_unavailable_reason": "analysis_incomplete",
            }
        },
        {"analysis_summary": {"total_files": 1, "incomplete_languages": ["python"]}},
        {"analysis_summary": {"total_files": 1, "grep_verify": {"complete": False}}},
        {
            "analysis_summary": {
                "total_files": 1,
                "language_engines": {"go": {"status": "unavailable"}},
            }
        },
        {
            "analysis_summary": {
                "total_files": 1,
                "language_engines": {"go": {"status": "available", "complete": False}},
            }
        },
        {
            "analysis_summary": {"total_files": 1},
            "assessment": {"coverage": {"status": "incomplete"}},
        },
        {
            "analysis_summary": {"total_files": 1},
            "assessment": {
                "coverage": {"status": "partial", "incomplete_checks": ["dead_code"]}
            },
        },
    ],
)
def test_incomplete_reports_are_unscored_instead_of_clean_absence(
    tmp_path, monkeypatch, report
):
    path = _manifest(tmp_path)
    _mock_report(monkeypatch, report)
    result = benchmark.run_manifest(path, strict_labels=True)
    case = result["cases"][0]
    assert case["scored"] is False
    assert case["analysis_status"] == "incomplete"
    assert all(case[key] == 0 for key in COUNTS)
    assert case["scores"]["overall_score"] == 0
    assert result["failure_count"] > 0
    assert result["pass_count"] == 0
    assert result["scored_case_count"] == 0
    assert result["unscored_case_count"] == 1
    assert result["score_unavailable_reason"] == "no_valid_cases"
    assert result["scores"]["overall_score"] == 0
    assert "UNSCORED" in benchmark.format_summary(result)


def test_incomplete_report_findings_cannot_award_semantic_counts(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text())
    manifest["cases"][0]["expect"]["unused"] = [
        {"kind": "function", "file": "app.py", "symbol": "reserve"}
    ]
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(
        benchmark,
        "_scan_case_with_scanner",
        lambda target, *a, **k: {
            "analysis_summary": {"total_files": 1},
            "analysis_errors": [{"kind": "read_error"}],
            "unused_functions": [
                {"file": str(target / "app.py"), "simple_name": name}
                for name in ("measure", "reserve", "extra")
            ],
        },
    )
    result = benchmark.run_manifest(path, strict_labels=True)
    assert all(result["counts"][key] == 0 for key in COUNTS)
    assert result["cases"][0]["unlabeled_finding_count"] == 0
    assert {failure["failure_type"] for failure in result["cases"][0]["failures"]} == {
        "analysis"
    }


@pytest.mark.parametrize("scanner", ["vulture", "ruff"])
def test_valid_competitors_do_not_need_skylos_metadata(tmp_path, monkeypatch, scanner):
    path = _manifest(tmp_path)
    _mock_report(monkeypatch, {})
    result = benchmark.run_manifest(path, scanner=scanner)
    assert result["failure_count"] == 0
    assert result["counts"]["true_negatives"] == 1
    assert result["cases"][0].get("scored", True) is True


@pytest.mark.parametrize("scanner", ["vulture", "ruff"])
def test_competitor_explicit_errors_are_unscored(tmp_path, monkeypatch, scanner):
    path = _manifest(tmp_path)
    _mock_report(monkeypatch, {"analysis_errors": [{"kind": "syntax_error"}]})
    result = benchmark.run_manifest(path, scanner=scanner)
    assert result["failure_count"] > 0
    assert result["cases"][0]["scored"] is False
    assert all(value == 0 for value in result["counts"].values())


def test_valid_partial_scope_and_limited_resolution_remain_scoreable(
    tmp_path, monkeypatch
):
    path = _manifest(tmp_path, scan_paths=["app.py"])
    _mock_report(
        monkeypatch,
        {
            "analysis_summary": {
                "total_files": 1,
                "analysis_error_count": 0,
                "resolution_scope_limited": True,
                "comparison_scope": {
                    "complete_repository": False,
                    "kind": "explicit_files",
                },
                "grep_verify": {"enabled": False},
            },
            "analysis_errors": [],
            "assessment": {
                "coverage": {
                    "status": "partial",
                    "incomplete_checks": [],
                    "reasons": ["selected_scan_scope", "configured_suppression"],
                }
            },
        },
    )
    result = benchmark.run_manifest(path)
    assert result["failure_count"] == 0
    assert result["counts"]["true_negatives"] == 1
    assert result["scores"]["overall_score"] == 100


def test_real_syntax_error_cannot_pass_used_only_contract(tmp_path, monkeypatch):
    path = _manifest(tmp_path, ids=("valid", "invalid"))
    with (tmp_path / "invalid/app.py").open("a") as stream:
        stream.write("\ndef broken(:\n    pass\n")
    _static_analyzer(monkeypatch)
    result = benchmark.run_manifest(path)
    cases = {case["id"]: case for case in result["cases"]}
    assert cases["valid"]["failures"] == []
    assert cases["valid"]["true_negatives"] == 1
    assert cases["invalid"]["scored"] is False
    assert cases["invalid"]["true_negatives"] == 0
    assert result["failure_count"] > 0
    assert result["counts"]["true_negatives"] == 1
    assert result["analysis_status"] == "incomplete"
    assert result["metrics_scoped_to_scored_cases"] is True
    assert result["scored_case_count"] == result["unscored_case_count"] == 1
    assert result["scores"]["overall_score"] == 100
    text = benchmark.format_summary(result)
    assert "incomplete" in text
    assert "UNSCORED invalid" in text


def test_zero_symbol_javascript_file_is_valid(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    root = tmp_path / "sample"
    (root / "app.py").unlink()
    (root / "app.js").write_text('console.log("ready");\n')
    (root / "index.html").write_text('<script src="app.js"></script>\n')
    manifest = json.loads(path.read_text())
    manifest["cases"][0]["languages"] = ["javascript"]
    manifest["cases"][0]["expect"]["used"] = [
        {"kind": "file", "file": "app.js", "symbol": "app.js"}
    ]
    path.write_text(json.dumps(manifest))
    _static_analyzer(monkeypatch)
    result = benchmark.run_manifest(path, strict_labels=True)
    assert result["failure_count"] == 0
    assert result["counts"]["true_negatives"] == 1


def test_unknown_case_selection_is_rejected(tmp_path):
    path = _manifest(tmp_path)
    with pytest.raises(ValueError, match="unknown.*missing"):
        benchmark.run_manifest(path, selected_cases={"missing"})


def test_supported_case_skipped_by_competitor_has_no_perfect_score(tmp_path):
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text())
    manifest["cases"][0]["languages"] = ["typescript"]
    path.write_text(json.dumps(manifest))
    result = benchmark.run_manifest(path, scanner="vulture")
    assert result["skipped_case_count"] == 1
    assert result["case_count"] == 0
    assert result["failure_count"] == 0
    assert result["scores"]["overall_score"] == 0
    assert result["score_unavailable_reason"] == "no_valid_cases"


def test_ruff_syntax_diagnostics_reach_completeness_guard(tmp_path, monkeypatch):
    path = _manifest(tmp_path, source="def measure(:\n    pass\n")
    monkeypatch.setattr(benchmark.shutil, "which", lambda executable: executable)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            json.dumps(
                [
                    {
                        "code": "invalid-syntax",
                        "message": "Expected a parameter name",
                        "filename": str(Path(kwargs["cwd"]) / "app.py"),
                        "location": {"row": 1, "column": 13},
                    }
                ]
            ),
            "",
        )

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)
    result = benchmark.run_manifest(path, scanner="ruff")
    assert result["failure_count"] > 0
    assert result["cases"][0]["scored"] is False
    assert result["counts"]["true_negatives"] == 0


@pytest.mark.parametrize("payload", [{}, {"diagnostics": []}, "report", None, [None]])
def test_ruff_malformed_json_shapes_are_unscored(tmp_path, monkeypatch, payload):
    path = _manifest(tmp_path)
    monkeypatch.setattr(benchmark.shutil, "which", lambda executable: executable)
    monkeypatch.setattr(
        benchmark.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, json.dumps(payload), ""
        ),
    )
    result = benchmark.run_manifest(path, scanner="ruff")
    assert result["failure_count"] > 0
    assert result["cases"][0]["scored"] is False
    assert all(value == 0 for value in result["counts"].values())


def test_cli_exits_nonzero_for_incomplete_analysis(tmp_path):
    path = _manifest(tmp_path, source="def measure(:\n    pass\n")
    root = Path(__file__).resolve().parents[1]
    env = {
        name: value
        for name, value in os.environ.items()
        if not any(
            part in name.upper()
            for part in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
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
            "-B",
            str(root / "scripts/dead_code_benchmark.py"),
            "--manifest",
            str(path),
            "--json",
        ],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 1
    summary = json.loads(result.stdout)
    assert summary["failure_count"] > 0
    assert summary["scores"]["overall_score"] == 0
