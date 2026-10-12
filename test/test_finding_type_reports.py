"""Presentation groups advice without changing findings, severity or grades."""

from copy import deepcopy
from io import StringIO
import json

import pytest
from rich.console import Console
from rich.table import Table
from unittest.mock import Mock

from skylos.cli import _skylos_console_theme
from skylos.reporting.finding_types import summarize_finding_types
from skylos.ui.rich_report import _finding_view, render_results
from skylos.ui.terminal_report import collect_pretty_findings, render_pretty_results


def _result():
    return {
        "analysis_summary": {"total_files": 3},
        "quality": [
            {
                "rule_id": "SKY-C303",
                "severity": "HIGH",
                "message": "ADVICE-FIRST",
                "file": "a.py",
                "line": 5,
            },
            {
                "rule_id": "SKY-C303",
                "severity": "LOW",
                "message": "ADVICE-SECOND",
                "file": "a.py",
                "line": 7,
            },
            {
                "rule_id": "SKY-C303",
                "severity": "LOW",
                "message": "ADVICE-THIRD",
                "file": "b.py",
                "line": 9,
            },
            {
                "rule_id": "SKY-L001",
                "severity": "LOW",
                "message": "DEFECT-MESSAGE",
                "file": "c.py",
                "line": 3,
            },
        ],
        "danger": [
            {
                "rule_id": "SKY-D211",
                "severity": "CRITICAL",
                "message": "REVIEW-MESSAGE",
                "file": "c.py",
                "line": 4,
            }
        ],
        "grade": {
            "overall": {"score": 71, "letter": "C"},
            "categories": {},
            "scanned_categories": [],
        },
    }


def _render(renderer, result, width, **options):
    output = StringIO()
    console = Console(
        file=output, width=width, color_system=None, theme=_skylos_console_theme()
    )
    if renderer is render_results:
        options["copy_badge"] = False
    renderer(console, result, **options)
    return output.getvalue()


@pytest.mark.parametrize(
    "renderer", [render_results, render_pretty_results], ids=["tables", "pretty"]
)
@pytest.mark.parametrize("width", [80, 120])
@pytest.mark.parametrize("expanded", [False, True], ids=["grouped", "expanded"])
def test_grouping_keeps_complete_counts_types_severity_and_result(
    renderer, width, expanded
):
    result = _result()
    original = json.dumps(result, sort_keys=True)
    output = _render(renderer, result, width, expand_advice=expanded)
    normalized = " ".join(output.split())

    assert "1 defect · 1 review · 3 advice in 1 group" in normalized
    assert (
        output.index("DEFECT-MESSAGE")
        < output.index("REVIEW-MESSAGE")
        < output.index("SKY-C303")
    )
    assert "Type" in output and "Severity" in output
    assert "LOW" in output and "CRITICAL" in output and "HIGH" in output
    assert "c.py:3" in output and "c.py:4" in output
    if expanded:
        for message in ("ADVICE-FIRST", "ADVICE-SECOND", "ADVICE-THIRD"):
            assert message in output
        assert output.count("SKY-C303") == 3
        for location in ("a.py:5", "a.py:7", "b.py:9"):
            assert location in output
    else:
        assert output.count("SKY-C303") == 1
        assert "ADVICE-FIRST" not in output
        assert "a.py (2)" in output and "b.py (1)" in output
        assert "--expand-advice" in output and "--format json" in output
        assert "Count" in output and "Top files" in output
    assert max(map(len, output.splitlines())) <= width
    assert json.dumps(result, sort_keys=True) == original


def test_repeated_canonical_rows_are_not_lost_and_mirrors_are_not_displayed_twice():
    repeated = {
        "rule_id": "SKY-L001",
        "severity": "HIGH",
        "file": "a.py",
        "line": 1,
        "message": "Repeated defect",
    }
    other_evidence = {**repeated, "evidence": "a different source"}
    result = {
        "quality": [repeated, repeated, other_evidence],
        "code_health": [deepcopy(repeated)],
    }

    assert summarize_finding_types(result)["defect"] == 3
    assert len(_finding_view(result, "defect")["quality"]) == 3
    assert len(collect_pretty_findings(result)) == 3
    for renderer in (render_results, render_pretty_results):
        output = _render(renderer, result, 120)
        assert output.count("Repeated defect") == 3


@pytest.mark.parametrize(
    "renderer", [render_results, render_pretty_results], ids=["tables", "pretty"]
)
def test_complete_headline_and_grade_scope_survive_display_limit(renderer):
    result = _result()
    result["analysis_summary"]["grade_includes_filtered_findings"] = True
    output = _render(renderer, result, 120, limit=1)

    assert "1 defect · 1 review · 3 advice in 1 group" in " ".join(output.split())
    assert (
        "Grade includes all analyzed findings, including those outside this display."
        in output
    )
    assert result["grade"]["overall"] == {"score": 71, "letter": "C"}


@pytest.mark.parametrize(
    "renderer", [render_results, render_pretty_results], ids=["tables", "pretty"]
)
def test_long_messages_and_literal_paths_are_accessible_at_80_columns(renderer):
    message = " ".join(["full meaningful diagnostic detail"] * 8) + " LASTDETAILTOKEN"
    result = {
        "quality": [
            {
                "rule_id": "SKY-L001",
                "severity": "HIGH",
                "message": message,
                "file": "src/[bold]app.py",
                "line": 27,
            }
        ]
    }
    original = deepcopy(result)
    output = _render(renderer, result, 80)

    assert "LASTDETAILTOKEN" in output
    assert "src/[bold]app.py:27" in output
    assert "…" not in output
    assert max(map(len, output.splitlines())) <= 80
    assert result == original


def test_tree_includes_types_severity_and_all_finding_categories():
    result = {
        "custom_rules": [
            {
                "rule_id": "CUSTOM-A",
                "severity": "HIGH",
                "message": "Custom message",
                "file": "custom.py",
                "line": 2,
            }
        ],
        "circular_dependencies": [
            {
                "rule_id": "SKY-CIRC",
                "severity": "MEDIUM",
                "message": "Cycle message",
                "file": "circle.py",
                "line": 3,
            }
        ],
        "unused_fixtures": [{"name": "fixture_name", "file": "test_a.py", "line": 4}],
        "unused_exports": [{"name": "export_name", "file": "a.ts", "line": 5}],
        "quality": [
            {
                "rule_id": "SKY-C303",
                "severity": "LOW",
                "message": "Advice message",
                "file": "a.py",
                "line": 6,
            }
        ],
    }
    original = deepcopy(result)
    output = _render(render_results, result, 80, tree=True, expand_advice=True)
    for text in (
        "Custom message",
        "Cycle message",
        "fixture_name",
        "export_name",
        "Advice message",
        "custom.py:2",
        "circle.py:3",
        "test_a.py:4",
        "a.ts:5",
        "a.py:6",
    ):
        assert text in output
    assert "Type: Review  Severity: HIGH" in output
    assert "Type: Advice  Severity: LOW" in output
    assert max(map(len, output.splitlines())) <= 80
    assert result == original


def test_advice_group_retains_literal_file_markup_and_all_files_in_expanded_view():
    result = {
        "quality": [
            {
                "rule_id": "SKY-C303",
                "severity": "LOW",
                "message": f"message-{i}",
                "file": f"folder/[bold]file{i}.py",
                "line": i + 1,
            }
            for i in range(5)
        ]
    }
    for renderer in (render_results, render_pretty_results):
        grouped = _render(renderer, result, 120)
        assert "folder/[bold]file0.py" in grouped
        assert "+2 more files" in grouped
        expanded = _render(renderer, result, 120, expand_advice=True)
        for i in range(5):
            assert f"folder/[bold]file{i}.py:{i + 1}" in expanded
            assert f"message-{i}" in expanded


@pytest.mark.parametrize(
    "section",
    [
        "analysis_errors",
        "danger",
        "reliability",
        "ai_defects",
        "secrets",
        "quality",
        "circular_dependencies",
        "custom_rules",
        "dependency_vulnerabilities",
        "publisher_change_findings",
        "unused_functions",
        "unused_imports",
        "unused_parameters",
        "unused_variables",
        "unused_classes",
        "unused_files",
        "unused_fixtures",
        "unused_exports",
    ],
)
def test_every_finding_table_has_type_and_severity(section):
    console = Mock()
    result = {
        section: [
            {
                "rule_id": "CUSTOM-REVIEW",
                "name": "sample",
                "severity": "CRITICAL",
                "message": "Finding detail",
                "file": "a.py",
                "line": 2,
            }
        ]
    }
    render_results(console, result, copy_badge=False, expand_advice=True)
    tables = [
        call.args[0]
        for call in console.print.call_args_list
        if call.args and isinstance(call.args[0], Table)
    ]

    assert len(tables) == 1
    columns = {column.header: list(column._cells) for column in tables[0].columns}
    assert columns["Type"] == ["Review"]
    assert columns["Severity"] == ["CRITICAL"]
    assert "Finding detail" in columns["Message"][0]
    assert columns["Location"] == ["a.py:2"]


def test_signals_and_code_health_are_visible_without_duplication():
    defect = {
        "rule_id": "SKY-L001",
        "severity": "LOW",
        "message": "Code health defect",
        "file": "a.py",
        "line": 1,
    }
    signal = {
        "rule_id": "SKY-C303",
        "severity": "LOW",
        "message": "Architecture advice",
        "file": "b.py",
        "line": 2,
    }
    result = {
        "code_health": [defect],
        "architecture_metrics": {"advisories": [{"signals": [signal]}]},
    }
    for renderer in (render_results, render_pretty_results):
        output = _render(renderer, result, 120, expand_advice=True)
        assert "1 defect · 0 review · 1 advice in 1 group" in " ".join(output.split())
        assert output.count("Code health defect") == 1
        assert output.count("Architecture advice") == 1


def test_pretty_advice_uses_layout_newlines_and_keeps_rule_ids_at_80_columns():
    result = {
        "quality": [
            {
                "rule_id": "SKY-C303",
                "severity": "LOW",
                "message": "Advice",
                "file": f"src/service{i}.py",
                "line": i + 1,
            }
            for i in range(2)
        ]
        + [
            {
                "rule_id": "SKY-C304",
                "severity": "LOW",
                "message": "Advice",
                "file": "src/service2.py",
                "line": 3,
            }
        ]
    }
    output = _render(render_pretty_results, result, 80)
    assert output.count("SKY-C303") == 1
    assert output.count("SKY-C304") == 1
    assert "\\x0a" not in output
    assert max(map(len, output.splitlines())) <= 80


def test_pretty_keeps_confidence_verification_and_provenance():
    finding = {
        "rule_id": "SKY-D211",
        "severity": "HIGH",
        "message": "Review SQL",
        "file": "a.py",
        "line": 1,
        "confidence": 95,
        "symbol": "Order.save",
        "ai_authored": True,
        "ai_agent": "coding-agent",
        "verification": {
            "verdict": "VERIFIED",
            "evidence": {"chain": [{"fn": "view"}, {"fn": "save"}]},
        },
    }
    output = _render(render_pretty_results, {"danger": [finding]}, 80)
    for context in (
        "Confidence: 95%",
        "Symbol: Order.save",
        "AI: coding-agent",
        "Verified: VERIFIED",
        "Proof: view -> save",
    ):
        assert context in output
