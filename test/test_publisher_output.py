"""Publisher history is a review signal across scan output formats."""

from types import SimpleNamespace

from rich.console import Console

from skylos import cli
from skylos.reporting.sarif import SarifExporter
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results
from skylos.ui.tui import prepare_category_data


def _publisher_result():
    return {
        "analysis_summary": {"total_files": 0},
        "dependency_vulnerabilities": [],
        "publisher_change_findings": [
            {
                "rule_id": "SKY-SCA-NPM-PUB001",
                "severity": "WARN",
                "message": "bob first published example after a 210-day release gap",
                "file": "package-lock.json",
                "line": 8,
                "metadata": {
                    "package_name": "example",
                    "package_version": "2.0.0",
                    "previous_publisher": "alice",
                    "new_publisher": "bob",
                    "dormancy_days": 210,
                },
            }
        ],
    }


def _console():
    return Console(
        record=True,
        width=180,
        force_terminal=False,
        theme=cli._skylos_console_theme(),
    )


def test_publisher_review_is_visible_in_concise_without_failing_exit():
    result = _publisher_result()
    assert cli._format_concise_results(result) == (
        "package-lock.json:8  SKY-SCA-NPM-PUB001  "
        "bob first published example after a 210-day release gap\n"
    )
    assert cli._has_concise_findings(result) is False
    args = SimpleNamespace(gate=False, force=False)
    assert cli._concise_scan_exit_code(result, {}, args) == 0


def test_publisher_review_respects_rule_and_display_filters():
    result = _publisher_result()
    selected = cli._apply_rule_selection(result, ["SKY-SCA-NPM-PUB001"])
    assert selected["publisher_change_findings"] == result["publisher_change_findings"]
    assert (
        cli._apply_rule_selection(result, ["SKY-D211"])["publisher_change_findings"]
        == []
    )

    shown = cli._apply_display_filters(
        result, severity="medium", category="publisher_change"
    )
    assert len(shown["publisher_change_findings"]) == 1
    hidden = cli._apply_display_filters(result, severity="high")
    assert hidden["publisher_change_findings"] == []

    args = SimpleNamespace(select=["SKY-SCA-NPM-PUB001"], sca=False)
    cli._apply_selected_rule_analysis_flags(args)
    assert args.sca is True
    assert args.scan_publisher_changes is True


def test_publisher_review_has_distinct_pretty_and_rich_sections():
    result = _publisher_result()

    pretty_console = _console()
    render_pretty_results(pretty_console, result)
    pretty = pretty_console.export_text()
    assert "0 issues · 1 review signal" in pretty
    assert "WARN  SKY-SCA-NPM-PUB001" in pretty
    assert "Publisher review" in pretty

    rich_console = _console()
    render_results(rich_console, result, copy_badge=False)
    rich = rich_console.export_text()
    assert "npm Publisher Changes (review only)" in rich
    assert "example@2.0.0" in rich
    assert "alice → bob" in rich
    assert "210 days" in rich
    assert "Dependency Vulnerabilities (SCA)" not in rich


def test_publisher_review_has_distinct_tui_category():
    data = prepare_category_data(_publisher_result())
    columns, rows, raw = data["publisher_review"]

    assert columns == ["Package", "Publisher", "Release gap", "File:Line"]
    assert rows == [("example@2.0.0", "alice → bob", "210 days", "package-lock.json:8")]
    assert raw[0]["rule_id"] == "SKY-SCA-NPM-PUB001"
    assert data["dependencies"][1] == []


def test_incomplete_publisher_review_is_visible_without_findings():
    result = {
        "analysis_summary": {
            "total_files": 0,
            "publisher_change_scan": {
                "status": "unavailable",
                "warnings": ["ca9 0.6.0 or newer is required"],
            },
        },
        "publisher_change_findings": [],
    }

    pretty_console = _console()
    render_pretty_results(pretty_console, result)
    assert "npm publisher review incomplete: ca9 0.6.0 or newer is required" in (
        pretty_console.export_text()
    )

    rich_console = _console()
    render_results(rich_console, result, copy_badge=False)
    assert "npm publisher review incomplete: ca9 0.6.0 or newer is required" in (
        rich_console.export_text()
    )


def test_publisher_sarif_is_review_note_without_security_score():
    finding = dict(_publisher_result()["publisher_change_findings"][0])
    finding["category"] = "PUBLISHER_CHANGE"
    sarif = SarifExporter([finding]).generate()["runs"][0]
    rule = sarif["tool"]["driver"]["rules"][0]
    exported = sarif["results"][0]

    assert rule["id"] == "SKY-SCA-NPM-PUB001"
    assert rule["shortDescription"]["text"] == (
        "Review npm publisher change after release dormancy"
    )
    assert "security-severity" not in rule["properties"]
    assert exported["level"] == "note"
    assert exported["properties"]["review_only"] is True
    assert exported["properties"]["category"] == "PUBLISHER_CHANGE"
    assert exported["properties"]["skylos_metadata"]["new_publisher"] == "bob"
