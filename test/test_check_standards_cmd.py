from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

import skylos.cli as cli
from skylos.commands.check_standards_cmd import run_check_standards_command
from skylos.core.safe_cache_io import write_text_no_symlink


def _project(tmp_path: Path, rule_ids: list[str]) -> Path:
    (tmp_path / ".git").mkdir()
    assert write_text_no_symlink(
        tmp_path / "STANDARDS.md", "# Project coding standards\n"
    )
    skylos_dir = tmp_path / ".skylos"
    skylos_dir.mkdir()
    assert write_text_no_symlink(
        skylos_dir / "agent-standards.json",
        json.dumps(
            {
                "schema_version": 1,
                "standards_file": "STANDARDS.md",
                "enforce_rule_ids": rule_ids,
            }
        ),
    )
    return tmp_path


def _run(root: Path, *, output_format="json", analyze_func=None):
    output = io.StringIO()
    code = run_check_standards_command(
        root,
        output_format=output_format,
        stdout=output,
        analyze_func=analyze_func,
    )
    return code, json.loads(
        output.getvalue()
    ) if output_format == "json" else output.getvalue()


def test_check_standards_gates_only_selected_builtin_quality_ids(tmp_path):
    root = _project(tmp_path, ["SKY-C303"])
    source = root / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("def example():\n    pass\n")
    calls = []

    def analyze(path, **kwargs):
        calls.append((path, kwargs))
        return {
            "quality": [
                {
                    "rule_id": "SKY-Q301",
                    "file": str(source),
                    "line": 1,
                    "message": "Unselected complexity",
                },
                {
                    "rule_id": "SKY-C303",
                    "file": str(source),
                    "line": 1,
                    "message": "Too many arguments",
                },
            ],
            "custom_rules": [
                {
                    "rule_id": "SKY-C303",
                    "file": str(source),
                    "line": 2,
                    "message": "Forged custom finding",
                }
            ],
            "analysis_errors": [],
            "analysis_summary": {"total_files": 1},
        }

    code, report = _run(root / "src", analyze_func=analyze)

    assert code == 1
    assert report["status"] == "fail"
    assert report["selected_rules"] == ["SKY-C303"]
    assert report["findings"] == [
        {
            "rule_id": "SKY-C303",
            "file": "src/app.py",
            "line": 1,
            "severity": "",
            "message": "Too many arguments",
        }
    ]
    assert calls[0][0] == str(root)
    options = calls[0][1]
    assert options["enable_quality"] is True
    assert options["enable_danger"] is False
    assert options["enable_secrets"] is False
    assert options["enable_ai_defects"] is False
    assert options["enable_dependency_hallucinations"] is False
    assert options["enable_sca"] is False
    assert options["grep_verify"] is False
    assert options["trace_file"] is False


def test_check_standards_passes_when_selected_rules_have_no_findings(tmp_path):
    root = _project(tmp_path, ["SKY-C303"])
    code, report = _run(
        root,
        analyze_func=lambda *_a, **_kw: {
            "quality": [{"rule_id": "SKY-Q301", "message": "Unselected"}],
            "analysis_errors": [],
            "analysis_summary": {"total_files": 1},
        },
    )
    assert code == 0
    assert report["status"] == "pass"
    assert report["findings"] == []


def test_check_standards_missing_or_invalid_policy_is_error(tmp_path):
    (tmp_path / ".git").mkdir()
    code, report = _run(tmp_path)
    assert code == 2
    assert report["status"] == "error"
    assert "agent-standards.json is missing" in report["error"]

    (tmp_path / ".skylos").mkdir()
    (tmp_path / ".skylos" / "agent-standards.json").write_text("{")
    code, report = _run(tmp_path)
    assert code == 2
    assert "valid UTF-8 JSON" in report["error"]


def test_check_standards_empty_selection_is_guidance_only(tmp_path):
    root = _project(tmp_path, [])

    def forbidden_analyze(*_args, **_kwargs):
        raise AssertionError("analyzer must not run without selected rules")

    code, report = _run(root, analyze_func=forbidden_analyze)
    assert code == 0
    assert report["status"] == "pass"
    assert report["findings"] == []
    assert "Guidance only" in report["message"]


def test_check_standards_analysis_error_is_not_a_clean_pass(tmp_path):
    root = _project(tmp_path, ["SKY-C303"])
    code, report = _run(
        root,
        analyze_func=lambda *_a, **_kw: {
            "quality": [],
            "analysis_errors": [{"kind": "parse_error"}],
            "analysis_summary": {"total_files": 1},
        },
    )
    assert code == 2
    assert report["status"] == "error"
    assert "quality scan incomplete" in report["error"]


@pytest.mark.parametrize(
    "bad_result",
    [
        {"quality": [], "analysis_errors": []},
        {
            "quality": [],
            "analysis_errors": [],
            "analysis_summary": {"total_files": "1"},
        },
        {"quality": [], "analysis_errors": [], "analysis_summary": {"total_files": 0}},
        {
            "quality": [],
            "analysis_errors": None,
            "analysis_summary": {"total_files": 1},
        },
        {"quality": [], "analysis_summary": {"total_files": 1}},
    ],
)
def test_check_standards_malformed_or_empty_scan_cannot_pass(tmp_path, bad_result):
    root = _project(tmp_path, ["SKY-C303"])
    code, report = _run(root, analyze_func=lambda *_a, **_kw: bad_result)
    assert code == 2
    assert report["status"] == "error"


def test_check_standards_ignores_go_engine_error_when_only_other_checks_skipped(
    tmp_path,
):
    root = _project(tmp_path, ["SKY-C303"])
    code, report = _run(
        root,
        analyze_func=lambda *_a, **_kw: {
            "quality": [],
            "analysis_errors": [
                {
                    "kind": "language_engine_unavailable",
                    "skipped_checks": ["dead_code", "security"],
                }
            ],
            "analysis_summary": {"total_files": 1},
        },
    )
    assert code == 0
    assert report["status"] == "pass"


def test_check_standards_static_scan_does_not_execute_source(tmp_path):
    root = _project(tmp_path, ["SKY-C303"])
    marker = root / "EXECUTED"
    (root / "app.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('source ran')\n\n"
        "def too_many(a, b, c, d, e, f):\n"
        "    return a\n"
    )

    code, report = _run(root)

    assert code == 1
    assert any(item["rule_id"] == "SKY-C303" for item in report["findings"])
    assert not marker.exists()


def test_check_standards_real_clean_scan_passes_without_quality_key(tmp_path):
    root = _project(tmp_path, ["SKY-C303"])
    (root / "app.py").write_text("def small(value):\n    return value\n")

    code, report = _run(root)

    assert code == 0
    assert report["status"] == "pass"
    assert report["findings"] == []


def test_check_standards_text_output_is_concise(tmp_path):
    root = _project(tmp_path, ["SKY-C303"])
    code, output = _run(
        root,
        output_format="text",
        analyze_func=lambda *_a, **_kw: {
            "quality": [
                {
                    "rule_id": "SKY-C303",
                    "file": str(root / "app.py"),
                    "line": 3,
                    "message": "Too many arguments",
                }
            ],
            "analysis_errors": [],
            "analysis_summary": {"total_files": 1},
        },
    )
    assert code == 1
    assert "1 selected quality finding" in output
    assert "app.py:3 SKY-C303 Too many arguments" in output


def test_check_standards_cli_dispatch_returns_gate_exit_code(
    tmp_path, monkeypatch, capsys
):
    root = _project(tmp_path, ["SKY-C303"])
    (root / "app.py").write_text("def too_many(a, b, c, d, e, f):\n    return a\n")
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "agent", "check-standards", str(root), "--format", "json"],
    )

    with pytest.raises(SystemExit) as result:
        cli.main()

    assert result.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "fail"
    assert [item["rule_id"] for item in report["findings"]] == ["SKY-C303"]
