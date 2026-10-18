"""CRITICAL is reserved for shipped code; scope notes are never silent."""

import io
import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from skylos.analyzer import analyze
from skylos.cli import _skylos_console_theme
from skylos.commands.scan_cmd import _report_scope_options
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.reporting.report_scope import (
    cap_test_file_severity,
    drop_test_code_not_applicable,
)
from skylos.ui.rich_report import render_results
from skylos.ui.scope_notes import scope_note_lines
from skylos.ui.terminal_report import render_pretty_results


def _finding(file, severity="CRITICAL", rule_id="SKY-D216"):
    return {"rule_id": rule_id, "severity": severity, "file": file, "line": 3}


def test_critical_findings_in_test_files_are_reported_as_high(tmp_path):
    result = {
        "danger": [
            _finding(str(tmp_path / "app/tests/test_views.py")),
            _finding(str(tmp_path / "app/views.py")),
            _finding(str(tmp_path / "web/src/api.test.ts")),
            _finding(str(tmp_path / "app/test_utils.py"), severity="HIGH"),
        ],
        "ai_defects": [
            _finding(str(tmp_path / "tests/conftest.py"), rule_id="SKY-L012")
        ],
        "secrets": [_finding(str(tmp_path / "tests/test_api.py"), rule_id="SKY-S101")],
    }

    capped = cap_test_file_severity(result, tmp_path)

    assert capped == 3
    danger = result["danger"]
    assert [item["severity"] for item in danger] == ["HIGH", "CRITICAL", "HIGH", "HIGH"]
    assert danger[0]["original_severity"] == "CRITICAL"
    assert danger[0]["severity_reason"] == "test_file"
    assert "original_severity" not in danger[1]
    assert "original_severity" not in danger[3]
    assert result["ai_defects"][0]["severity"] == "HIGH"
    # A committed secret leaks wherever it lives.
    assert result["secrets"][0]["severity"] == "CRITICAL"


def test_scan_caps_test_file_critical_but_not_app_code(tmp_path):
    source = textwrap.dedent(
        """
        import subprocess


        def run(cmd):
            return subprocess.call(cmd, shell=True)


        def handler(request):
            return eval(request.GET["expr"])
        """
    ).lstrip()
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text(source, encoding="utf-8")

    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            grep_verify=False,
            enable_danger=True,
            exclude_folders=sorted(DEFAULT_EXCLUDE_FOLDERS),
        )
    )

    app_critical = [
        item
        for item in result.get("danger", [])
        if Path(item["file"]).name == "app.py" and item["severity"] == "CRITICAL"
    ]
    test_findings = [
        item
        for item in result.get("danger", [])
        if Path(item["file"]).name == "test_app.py"
    ]
    assert app_critical, result.get("danger")
    assert test_findings
    assert all(item["severity"] != "CRITICAL" for item in test_findings)
    assert any(item.get("original_severity") == "CRITICAL" for item in test_findings)
    assert result["analysis_summary"]["test_file_severity_capped"] == len(
        [item for item in test_findings if item.get("original_severity")]
    )


def _scoped_result():
    return {
        "analysis_summary": {
            "total_files": 3,
            "generated_files": {
                "skipped_count": 1201,
                "by_reason": {"django_migration": 1190, "minified": 11},
            },
        }
    }


def test_scope_note_lines():
    lines = scope_note_lines(_scoped_result())
    assert lines == [
        (
            "Skipped 1,201 generated/vendored files (1,190 Django migrations, "
            "11 minified files); use --include-generated to scan them."
        ),
    ]


def test_scope_notes_absent_when_nothing_was_left_out():
    assert scope_note_lines({"analysis_summary": {}}) == []
    assert (
        scope_note_lines(
            {
                "analysis_summary": {
                    "generated_files": {"skipped_count": 0, "by_reason": {}},
                }
            }
        )
        == []
    )


def _render(renderer, result):
    buffer = io.StringIO()
    console = Console(
        file=buffer, width=400, color_system=None, theme=_skylos_console_theme()
    )
    renderer(console, result)
    return buffer.getvalue()


def test_rich_and_pretty_reports_print_scope_notes():
    rich_text = _render(
        lambda console, result: render_results(console, result, copy_badge=False),
        _scoped_result(),
    )
    pretty_text = _render(render_pretty_results, _scoped_result())
    for text in (rich_text, pretty_text):
        assert "Skipped 1,201 generated/vendored files" in text
        assert "use --include-generated" in text


def _scope_args(**overrides):
    values = {
        "include_generated": False,
        "no_default_excludes": False,
        "include_folders": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_generated_files_are_skipped_by_default():
    options = _report_scope_options(_scope_args(), {})
    assert options == {"skip_generated": True, "generated_keep_paths": []}


def test_generated_skip_overrides():
    for overrides in (
        {"include_generated": True},
        {"no_default_excludes": True},
    ):
        options = _report_scope_options(_scope_args(**overrides), {})
        assert options["skip_generated"] is False, overrides
    options = _report_scope_options(_scope_args(), {"include_generated": True})
    assert options["skip_generated"] is False
    options = _report_scope_options(
        _scope_args(include_folders=["shop/migrations"]), {}
    )
    assert options["generated_keep_paths"] == ["shop/migrations"]


def test_performance_advice_is_dropped_in_test_code_but_security_is_not(tmp_path):
    result = {
        "quality": [
            _finding(str(tmp_path / "web/src/fetch.test.ts"), "LOW", "SKY-Q402"),
            _finding(str(tmp_path / "tests/test_load.py"), "LOW", "SKY-P401"),
            _finding(str(tmp_path / "web/src/fetch.ts"), "LOW", "SKY-Q402"),
        ],
        "danger": [
            # Shipped code can import a module under tests/ or a .test.ts
            # file: a path never proves code is not served.
            _finding(str(tmp_path / "tests/web_fixtures.py"), "CRITICAL", "SKY-D226"),
            _finding(str(tmp_path / "web/src/render.test.ts"), "HIGH", "SKY-D226"),
            _finding(str(tmp_path / "tests/test_views.py"), "HIGH", "SKY-D228"),
        ],
    }

    dropped = drop_test_code_not_applicable(result, tmp_path)

    assert dropped == {"quality": 2}
    assert [item["file"] for item in result["quality"]] == [
        str(tmp_path / "web/src/fetch.ts")
    ]
    assert [item["rule_id"] for item in result["danger"]] == [
        "SKY-D226",
        "SKY-D226",
        "SKY-D228",
    ]
