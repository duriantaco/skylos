"""Invalid analysis must not satisfy a Corpus Guard absence contract."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from skylos.benchmarks import corpus_ci


def _manifest(tmp_path, *, source=None, paired=False):
    directory = tmp_path / "sample"
    directory.mkdir()
    (directory / "app.py").write_text(
        source or "def measure():\n    return 7\n\nprint(measure())\n",
        encoding="utf-8",
    )
    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "sample",
                "path": "sample",
                "description": "Local static Corpus Guard validity contract.",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                },
                "expect": {
                    "absent": {"unused_functions": ["measure"]},
                    "present": {"unused_functions": ["reserve"]} if paired else {},
                },
            }
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _mock_report(monkeypatch, report):
    monkeypatch.setattr(corpus_ci, "_scan_case", lambda *a, **k: copy.deepcopy(report))


def _valid_report(**updates):
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
        _valid_report(analysis_errors=[{"kind": "syntax_error"}]),
        {"analysis_summary": {"total_files": 1, "analysis_error_count": 1}},
        {"analysis_summary": {"total_files": 1, "analysis_error_count": True}},
        {"analysis_summary": {"total_files": 1, "analysis_error_count": "0"}},
        _valid_report(analysis_errors="failed"),
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
                "language_engines": {"python": {"status": "unavailable"}},
            }
        },
        _valid_report(assessment={"coverage": {"status": "incomplete"}}),
    ],
)
def test_incomplete_reports_cannot_pass_absence_contract(tmp_path, monkeypatch, report):
    path = _manifest(tmp_path)
    _mock_report(monkeypatch, report)
    summary = corpus_ci.run_manifest(path)
    case = summary["cases"][0]
    assert case["scored"] is False
    assert case["analysis_status"] == "incomplete"
    assert case["checked_expectation_count"] == 0
    assert case["findings_by_category"] == {}
    assert {failure["mode"] for failure in case["failures"]} == {"completeness"}
    assert summary["failure_count"] == 1
    assert summary["pass_count"] == 0
    assert summary["scored_case_count"] == 0
    assert summary["unscored_case_count"] == 1
    assert summary["analysis_status"] == "incomplete"
    assert "UNSCORED sample" in corpus_ci.format_summary(summary)


@pytest.mark.parametrize(
    "findings", [None, False, 0, "", {}, [None], ["measure"], [{}]]
)
def test_invalid_requested_category_is_not_interpreted_as_clean_absence(
    tmp_path, monkeypatch, findings
):
    path = _manifest(tmp_path)
    _mock_report(monkeypatch, _valid_report(unused_functions=findings))
    summary = corpus_ci.run_manifest(path)
    assert summary["cases"][0]["scored"] is False
    assert summary["cases"][0]["checked_expectation_count"] == 0
    assert summary["failure_count"] == 1


@pytest.mark.parametrize(
    "finding",
    [
        {"type": "function"},
        {"rule_id": "SKY-U001"},
        {"value": "placeholder"},
        {"name": " \t", "type": "function"},
    ],
)
def test_unused_findings_require_a_symbol_identity(tmp_path, monkeypatch, finding):
    path = _manifest(tmp_path)
    _mock_report(monkeypatch, _valid_report(unused_functions=[finding]))
    summary = corpus_ci.run_manifest(path)
    assert summary["cases"][0]["scored"] is False
    assert summary["cases"][0]["checked_expectation_count"] == 0
    assert summary["cases"][0]["failures"][0]["mode"] == "completeness"


@pytest.mark.parametrize("mode", ["absent", "present"])
def test_unused_findings_match_the_symbol_instead_of_generic_value(
    tmp_path, monkeypatch, mode
):
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["cases"][0]["expect"] = {
        "absent": {},
        "present": {},
        mode: {"unused_functions": ["measure"]},
    }
    path.write_text(json.dumps(manifest), encoding="utf-8")
    _mock_report(
        monkeypatch,
        _valid_report(unused_functions=[{"name": "other", "value": "measure"}]),
    )
    summary = corpus_ci.run_manifest(path)
    assert summary["cases"][0]["scored"] is True
    if mode == "absent":
        assert summary["failure_count"] == 0
    else:
        assert summary["failure_count"] == 1
        assert summary["cases"][0]["failures"][0]["mode"] == "present"


def test_quality_findings_keep_rule_type_and_value_token_support(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["cases"][0]["expect"]["present"] = {
        "quality": ["SKY-UC001", "while_false", "constant_condition"]
    }
    path.write_text(json.dumps(manifest), encoding="utf-8")
    _mock_report(
        monkeypatch,
        _valid_report(
            quality=[
                {"rule_id": "SKY-UC001"},
                {"type": "while_false"},
                {"value": "constant_condition"},
            ]
        ),
    )
    summary = corpus_ci.run_manifest(path)
    assert summary["failure_count"] == 0
    assert summary["cases"][0]["scored"] is True
    assert summary["cases"][0]["checked_expectation_count"] == 4


def test_declared_file_scope_does_not_use_neighbouring_callers(tmp_path):
    path = _manifest(tmp_path, source='def paint_banner():\n    print("banner")\n')
    (tmp_path / "sample/consumer.py").write_text(
        "from app import paint_banner\n\npaint_banner()\n", encoding="utf-8"
    )
    manifest = json.loads(path.read_text(encoding="utf-8"))
    case = manifest["cases"][0]
    case["path"] = "sample/app.py"
    case["expect"] = {
        "absent": {},
        "present": {"unused_functions": ["paint_banner"]},
    }
    path.write_text(json.dumps(manifest), encoding="utf-8")

    # consumer.py is outside the declared closed program. Its real call must
    # not count as usage inside this single-file corpus case.
    summary = corpus_ci.run_manifest(path)
    assert summary["failure_count"] == 0, corpus_ci.format_summary(summary)
    assert summary["cases"][0]["analyzed_source_count"] == 1
    assert summary["cases"][0]["findings_by_category"]["unused_functions"] == 1


def test_incomplete_analysis_does_not_check_present_or_absent_tokens(
    tmp_path, monkeypatch
):
    path = _manifest(tmp_path, paired=True)
    _mock_report(
        monkeypatch,
        _valid_report(
            analysis_errors=[{"kind": "read_error"}],
            unused_functions=[{"simple_name": "measure"}],
        ),
    )
    summary = corpus_ci.run_manifest(path)
    failures = summary["cases"][0]["failures"]
    assert len(failures) == 1
    assert failures[0]["mode"] == "completeness"


def test_valid_paired_report_keeps_both_token_polarities(tmp_path, monkeypatch):
    path = _manifest(tmp_path, paired=True)
    _mock_report(
        monkeypatch, _valid_report(unused_functions=[{"simple_name": "reserve"}])
    )
    summary = corpus_ci.run_manifest(path)
    assert summary["failure_count"] == 0
    assert summary["cases"][0]["scored"] is True
    assert summary["cases"][0]["checked_expectation_count"] == 2
    assert summary["cases"][0]["findings_by_category"] == {"unused_functions": 1}
    assert summary["scored_case_count"] == summary["pass_count"] == 1


def test_valid_limited_resolution_report_and_omitted_category_remain_scoreable(
    tmp_path, monkeypatch
):
    path = _manifest(tmp_path)
    report = _valid_report()
    report["analysis_summary"].update(
        resolution_scope_limited=True,
        comparison_scope={"complete_repository": False, "kind": "explicit_files"},
    )
    report["assessment"] = {
        "coverage": {
            "status": "partial",
            "incomplete_checks": [],
            "reasons": ["selected_scan_scope"],
        }
    }
    _mock_report(monkeypatch, report)
    summary = corpus_ci.run_manifest(path)
    assert summary["failure_count"] == 0
    assert summary["cases"][0]["scored"] is True


def _static_analyzer(monkeypatch):
    original = corpus_ci.analyze

    def static(*args, **kwargs):
        kwargs.update(
            trace_file=False,
            grep_cache=False,
            enable_ai_defects=False,
            enable_dependency_hallucinations=False,
            enable_sca=False,
        )
        return original(*args, **kwargs)

    monkeypatch.setattr(corpus_ci, "analyze", static)


def test_real_parse_error_is_unscored_and_valid_twin_passes(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    _static_analyzer(monkeypatch)
    valid = corpus_ci.run_manifest(path)
    assert valid["failure_count"] == 0
    with (tmp_path / "sample/app.py").open("a", encoding="utf-8") as stream:
        stream.write("\ndef broken(:\n    pass\n")
    invalid = corpus_ci.run_manifest(path)
    assert invalid["failure_count"] == 1
    assert invalid["cases"][0]["scored"] is False
    assert invalid["cases"][0]["checked_expectation_count"] == 0


def test_real_zero_symbol_javascript_source_can_pass(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    root = tmp_path / "sample"
    (root / "app.py").unlink()
    (root / "app.js").write_text('console.log("ready");\n', encoding="utf-8")
    (root / "index.html").write_text(
        '<script src="app.js"></script>\n', encoding="utf-8"
    )
    _static_analyzer(monkeypatch)
    summary = corpus_ci.run_manifest(path)
    assert summary["failure_count"] == 0
    assert summary["cases"][0]["scored"] is True


def test_unknown_requested_case_is_rejected(tmp_path):
    path = _manifest(tmp_path)
    with pytest.raises(ValueError, match="unknown.*missing"):
        corpus_ci.run_manifest(path, selected_cases={"sample", "missing"})


def test_empty_expectations_are_rejected(tmp_path):
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["cases"][0]["expect"] = {"absent": {}, "present": {}}
    with pytest.raises(ValueError, match="at least one expectation"):
        corpus_ci.validate_manifest(manifest, path)


@pytest.mark.parametrize("single_file", [False, True])
def test_scan_stages_only_the_requested_case_and_preserves_report_path(
    tmp_path, monkeypatch, single_file
):
    path = _manifest(tmp_path)
    source = tmp_path / "sample"
    source_text = (source / "app.py").read_text(encoding="utf-8")
    (tmp_path / "neighbour.py").write_text("def broken(:\n", encoding="utf-8")
    config_text = '[project]\nname = "sample"\nversion = "1"\n'
    (source / "pyproject.toml").write_text(config_text, encoding="utf-8")
    if single_file:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["cases"][0]["path"] = "sample/app.py"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        source = source / "app.py"
    staged = []

    def scan(case_path, **kwargs):
        assert case_path.resolve() != source.resolve()
        assert case_path.name == source.name
        staged.append(case_path)
        staged_source = case_path if single_file else case_path / "app.py"
        assert staged_source.read_text(encoding="utf-8") == source_text
        assert not (case_path.parent / "neighbour.py").exists()
        if single_file:
            assert not (case_path.parent / "pyproject.toml").exists()
        else:
            assert (case_path / "pyproject.toml").read_text(
                encoding="utf-8"
            ) == config_text
        return _valid_report()

    monkeypatch.setattr(corpus_ci, "_scan_case", scan)
    summary = corpus_ci.run_manifest(path)
    assert summary["failure_count"] == 0
    assert summary["cases"][0]["path"] == str(source.resolve())
    assert len(staged) == 1
    assert not staged[0].exists()


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
            str(root / "scripts/corpus_ci.py"),
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
    assert summary["cases"][0]["checked_expectation_count"] == 0
