import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from skylos.analyzer import (
    _dart_engine_analysis_error,
    _dart_engine_analysis_report,
    analyze,
)

DART_SOURCE = """void main() {
  print('hi');
}

int unusedHelper() {
  return 1;
}
"""


needs_dart_grammar = pytest.mark.skipif(
    importlib.util.find_spec("tree_sitter_dart_orchard") is None,
    reason='needs the optional "skylos[dart]" extra',
)


def _without_dart_grammar():
    return patch("skylos.visitors.languages.dart.core.DART_LANG", None)


def test_no_dart_report_without_dart_files():
    with _without_dart_grammar():
        assert _dart_engine_analysis_report([Path("app.py"), Path("main.go")]) is None


@needs_dart_grammar
def test_no_dart_report_when_grammar_installed():
    assert _dart_engine_analysis_report([Path("lib/main.dart")]) is None


def test_missing_grammar_marks_dart_checks_partial():
    files = [Path("lib/main.dart"), Path("lib/util.dart"), Path("tool.py")]
    with _without_dart_grammar():
        report = _dart_engine_analysis_report(files)

    assert report["status"] == "partial"
    assert report["file_count"] == 2
    assert report["completed_checks"] == []
    assert report["skipped_checks"] == ["dead_code", "security"]

    error = _dart_engine_analysis_error(files, report)
    assert error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert error["kind"] == "language_engine_unavailable"
    assert error["error_type"] == "DartGrammarUnavailable"
    assert error["language"] == "dart"
    assert error["file"] == str(Path("lib/main.dart"))
    assert error["affected_file_count"] == 2
    assert error["message"] == (
        "Dart analysis incomplete: Dart support is not installed. "
        "Skipped checks: dead code, security."
    )
    assert 'pip install "skylos[dart]"' in error["suggestion"]


def test_analyze_reports_missing_dart_grammar(tmp_path):
    source = tmp_path / "main.dart"
    source.write_text(DART_SOURCE, encoding="utf-8")

    with _without_dart_grammar():
        result = json.loads(analyze(str(tmp_path), grep_verify=False))

    summary = result["analysis_summary"]
    assert summary["language_engines"]["dart"]["status"] == "partial"
    assert summary["incomplete_languages"] == ["dart"]
    assert summary["analysis_error_count"] == 1
    assert summary["grade_unavailable_reason"] == "analysis_incomplete"
    assert "grade" not in result

    [error] = result["analysis_errors"]
    assert error["error_type"] == "DartGrammarUnavailable"
    assert error["file"] == str(source)
    assert error["skipped_checks"] == ["dead_code", "security"]
    assert "python_version" not in error


def test_analyze_without_dart_files_has_no_dart_report(tmp_path):
    (tmp_path / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")

    with _without_dart_grammar():
        result = json.loads(analyze(str(tmp_path), grep_verify=False))

    assert "dart" not in result["analysis_summary"].get("language_engines", {})
    assert result["analysis_errors"] == []


@needs_dart_grammar
def test_analyze_with_dart_grammar_is_unchanged(tmp_path):
    (tmp_path / "main.dart").write_text(DART_SOURCE, encoding="utf-8")

    result = json.loads(analyze(str(tmp_path), grep_verify=False))

    assert "language_engines" not in result["analysis_summary"]
    assert result["analysis_errors"] == []
    assert "unusedHelper" in {
        item.get("simple_name") or item.get("name")
        for item in result["unused_functions"]
    }


def test_doctor_json_reports_dart_support(capsys):
    from skylos.commands.doctor_cmd import run_doctor_command

    with (
        patch("skylos.commands.doctor_cmd._dart_available", return_value=False),
        patch(
            "skylos.commands.doctor_cmd._go_engine_status",
            return_value={"status": "available", "binary": "/bin/skylos-go"},
        ),
        patch("skylos.commands.doctor_cmd._ripgrep_available", return_value=True),
    ):
        run_doctor_command(["--format", "json"])

    checks = json.loads(capsys.readouterr().out)["checks"]
    assert checks["dart_support"] == {
        "status": "unavailable",
        "install": 'pip install "skylos[dart]"',
    }


def test_doctor_text_shows_install_hint_for_dart():
    from unittest.mock import Mock

    from skylos.commands.doctor_cmd import _print_optional_status

    console = Mock()
    with (
        patch("skylos.commands.doctor_cmd._dart_available", return_value=False),
        patch("skylos.commands.doctor_cmd._ripgrep_available", return_value=True),
    ):
        _print_optional_status(console)

    printed = " ".join(str(call.args[0]) for call in console.print.call_args_list)
    assert "Dart support not installed" in printed
    assert 'pip install "skylos\\[dart]"' in printed
