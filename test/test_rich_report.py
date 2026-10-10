from io import StringIO

from rich.console import Console
from rich.theme import Theme

from skylos.ui.rich_report import _render_analysis_errors


def _render_errors(result):
    output = StringIO()
    console = Console(
        file=output,
        force_terminal=False,
        color_system=None,
        theme=Theme({"bad": "bold red", "muted": "dim"}),
        width=180,
    )
    _render_analysis_errors(console, result)
    return output.getvalue()


def test_aggregate_go_engine_error_shows_affected_files_and_engine_runtime():
    rendered = _render_errors(
        {
            "analysis_errors": [
                {
                    "kind": "language_engine_unavailable",
                    "message": "Go analysis incomplete: engine unavailable.",
                    "file": "/repo/first.go",
                    "line": 1,
                    "language": "go",
                    "affected_file_count": 4,
                }
            ]
        }
    )

    assert "Analysis incomplete: 4 affected files across 1 analysis error." in rendered
    assert "4 files" in rendered
    assert "Go engine" in rendered
    assert "Python ?" not in rendered
    assert "How to fix" not in rendered


def test_missing_go_engine_table_says_how_to_fix_once():
    from skylos.analyzer import GO_ENGINE_SETUP_HINT

    error = {
        "kind": "language_engine_unavailable",
        "message": "Go analysis incomplete: engine unavailable.",
        "file": "/repo/first.go",
        "language": "go",
        "suggestion": GO_ENGINE_SETUP_HINT,
    }
    rendered = _render_errors({"analysis_errors": [error, dict(error)]})

    assert rendered.count("How to fix:") == 1
    flat = " ".join(rendered.split())
    assert "PyPI package does not include" in flat
    assert "SKYLOS_GO_BIN" in flat
    assert "go build -o skylos-go ./cmd/skylos-go" in flat


def test_syntax_error_keeps_python_runtime_and_single_file_rendering():
    rendered = _render_errors(
        {
            "analysis_errors": [
                {
                    "kind": "syntax_error",
                    "message": "invalid syntax",
                    "file": "/repo/broken.py",
                    "line": 7,
                    "python_version": "3.12.13",
                }
            ]
        }
    )

    assert "Analysis incomplete: 1 affected file across 1 analysis error." in rendered
    assert "syntax error: invalid syntax" in rendered
    assert "1 file" in rendered
    assert "Python 3.12.13" in rendered


import pytest  # noqa: E402

from skylos.cli import _skylos_console_theme  # noqa: E402
from skylos.ui.rich_report import _quality_detail, render_results  # noqa: E402


@pytest.mark.parametrize(
    ("finding", "detail"),
    [
        (
            {
                "rule_id": "SKY-C303",
                "kind": "structure",
                "value": 8,
                "threshold": 5,
                "message": "Function has 8 required arguments (limit: 5).",
            },
            "8 arguments (limit 5)",
        ),
        (
            {
                "rule_id": "SKY-C303",
                "kind": "structure",
                "value": 9,
                "threshold": 7,
                "message": "Function has 9 total parameters (limit: 7).",
            },
            "9 parameters (limit 7)",
        ),
        (
            {"rule_id": "SKY-C304", "kind": "structure", "value": 80, "threshold": 50},
            "80 lines (limit 50)",
        ),
        (
            {"rule_id": "SKY-L028", "kind": "structure", "value": 9, "threshold": 6},
            "9 return statements (limit 6)",
        ),
        (
            {
                "rule_id": "SKY-L029",
                "kind": "quality",
                "value": "retry",
                "threshold": 0,
                "message": "Boolean positional parameter 'retry' is a readability trap.",
            },
            "true/false positional parameter; make it keyword-only",
        ),
        (
            {"rule_id": "SKY-C401", "kind": "clone", "value": "type2 1.00"},
            "same structure, 100% similar",
        ),
        (
            {"rule_id": "SKY-C401", "kind": "clone", "value": "type3 0.91"},
            "near copy, 91% similar",
        ),
        (
            {
                "rule_id": "SKY-L001",
                "kind": "logic",
                "value": "mutable",
                "threshold": 0,
                "message": "Mutable default argument detected.",
            },
            "Mutable default argument detected.",
        ),
        (
            {"rule_id": "SKY-Q302", "kind": "nesting", "value": 6, "threshold": 4},
            "Nesting depth 6 (limit 4)",
        ),
    ],
)
def test_quality_detail_says_what_was_measured(finding, detail):
    assert _quality_detail(finding)[2] == detail
    assert "(max " not in _quality_detail(finding)[2]


@pytest.mark.parametrize("kind", ["complexity", "nesting", "structure", "clone"])
def test_quality_detail_preserves_message_when_measurement_is_missing(kind):
    finding = {"kind": kind, "rule_id": "SKY-C303", "message": "Original finding"}
    assert _quality_detail(finding)[2] == "Original finding"
    assert _quality_detail({"kind": kind})[2] == "Measurement unavailable"


def test_quality_detail_preserves_zero_measurement():
    assert _quality_detail({"kind": "complexity", "value": 0, "threshold": 0})[2] == (
        "Complexity: 0 (limit 0)"
    )


@pytest.mark.parametrize("similarity", ["nan", "inf", "-inf", "1.1", "-0.1"])
def test_quality_detail_does_not_invent_invalid_clone_percentage(similarity):
    assert _quality_detail({"kind": "clone", "value": f"type2 {similarity}"})[2] == (
        "same structure"
    )


def _scan_result(root):
    return {
        "analysis_summary": {"total_files": 3},
        "danger": [
            {
                "rule_id": "SKY-D290",
                "severity": "HIGH",
                "message": (
                    "Workflow uses pull_request_target; avoid running untrusted "
                    "PR content with a privileged token."
                ),
                "file": str(root / ".github" / "workflows" / "skylos.yml"),
                "line": 6,
                "symbol": "<module>",
                "ai_authored": False,
            }
        ],
        "quality": [
            {
                "rule_id": "SKY-C303",
                "kind": "structure",
                "name": "test_partial_refund_settles_half_even_in_minor_units",
                "value": 8,
                "threshold": 5,
                "message": "Function has 8 required arguments (limit: 5).",
                "file": str(root / "tests" / "test_refunds.py"),
                "basename": "test_refunds.py",
                "line": 62,
            }
        ],
        "unused_functions": [
            {
                "name": "UTCDateTime.process_bind_param",
                "file": str(root / "acme_payments" / "db" / "base.py"),
                "line": 28,
                "confidence": 60,
                "dead_code_reason_tags": ["no_refs", "not_exported"],
            }
        ],
        "architecture_metrics": {"advisory_count": 18},
    }


@pytest.mark.parametrize("width", [80, 100, 160])
def test_tables_keep_rule_ids_locations_and_messages_readable(
    tmp_path, monkeypatch, width
):
    monkeypatch.chdir(tmp_path)
    output = StringIO()
    console = Console(
        file=output,
        force_terminal=False,
        color_system=None,
        width=width,
        theme=_skylos_console_theme(),
    )

    render_results(console, _scan_result(tmp_path), copy_badge=False)

    rendered = output.getvalue()
    lines = rendered.splitlines()
    for whole in (
        "SKY-D290",
        "SKY-C303",
        ".github/workflows/skylos.yml:6",
        "tests/test_refunds.py:62",
        "acme_payments/db/base.py:28",
    ):
        assert any(whole in line for line in lines), whole
    # The message keeps a readable width instead of one word per line.
    assert "Workflow uses pull_request_target;" in rendered
    assert "UTCDateTime.process_bind_param" in rendered
    assert "…" not in rendered
    assert "8 arguments (limit 5)" in rendered
    assert "Line count" not in rendered
    assert max(len(line) for line in lines) <= width


def test_architecture_advisories_say_how_to_list_them():
    output = StringIO()
    console = Console(
        file=output,
        force_terminal=False,
        color_system=None,
        width=120,
        theme=_skylos_console_theme(),
    )

    render_results(
        console,
        {
            "analysis_summary": {"total_files": 1},
            "architecture_metrics": {"advisory_count": 18},
        },
        copy_badge=False,
    )

    rendered = " ".join(output.getvalue().split())
    assert "Architecture advisories: 18" in rendered
    assert "add --format concise" in rendered


def test_long_custom_rule_id_keeps_message_and_location_at_80_columns():
    output = StringIO()
    console = Console(
        file=output, width=80, color_system=None, theme=_skylos_console_theme()
    )
    rule_id = "CUSTOM-" + "A" * 100
    message = "Full message with meaningful readable details."
    location = "src/customer_application/service.py:27"
    render_results(
        console,
        {
            "custom_rules": [
                {
                    "rule_id": rule_id,
                    "severity": "HIGH",
                    "message": message,
                    "file": location.rsplit(":", 1)[0],
                    "line": 27,
                }
            ]
        },
        copy_badge=False,
    )

    rendered = output.getvalue()
    rows = [line.split("│") for line in rendered.splitlines() if line.startswith("│")]
    rule_cells = "".join(row[2].strip() for row in rows if len(row) >= 5)
    message_cells = " ".join(row[3].strip() for row in rows if len(row) >= 5)
    assert rule_id in rule_cells
    assert message in message_cells
    assert location in message_cells
    assert "…" not in rendered
    assert max(map(len, rendered.splitlines())) <= 80
