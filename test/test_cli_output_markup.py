"""Finding text is printed literally: Rich must never read it as markup.

A message like "No [tool.skylos.gate] policy..." used to lose its brackets
because Rich parsed `[tool.skylos.gate]` as a style tag.
"""

import json
import logging
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

import skylos.cli as cli
from skylos.cli import _skylos_console_theme
from skylos.commands.clean_cmd import _print_dry_run_plan
from skylos.core.gatekeeper import _handle_advisory_gate, _handle_incomplete_gate
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results

MESSAGE = "No [tool.skylos.gate] policy and a [bold] word stay literal."
NAME = "[bold]helper"
PATH = "app/[tool.skylos.gate].py"


def _console():
    return Console(
        record=True, width=400, theme=_skylos_console_theme(), color_system=None
    )


def _result():
    finding = {"file": PATH, "line": 3, "severity": "HIGH", "message": MESSAGE}
    return {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": NAME, "file": PATH, "line": 3, "confidence": 90}],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [{**finding, "rule_id": "SKY-D211", "symbol": "[bold]fn"}],
        "secrets": [{**finding, "rule_id": "SKY-S101", "provider": "[red]x"}],
        "quality": [
            {
                **finding,
                "rule_id": "SKY-R103",
                "kind": "repo_policy",
                "name": "[tool.skylos.gate]",
                "basename": "pyproject.toml",
            }
        ],
        "custom_rules": [{**finding, "rule_id": "CUSTOM-1"}],
        "dependency_vulnerabilities": [
            {
                **finding,
                "rule_id": "SKY-SCA",
                "metadata": {
                    "package_name": "[bold]pkg",
                    "package_version": "1.0",
                    "display_id": "GHSA-[x]",
                },
            }
        ],
        "grade": {
            "overall": {"score": 40, "letter": "F"},
            "categories": {
                "quality": {
                    "score": 40,
                    "letter": "F",
                    "weight": 0.25,
                    "key_issue": "[tool.skylos.gate] missing",
                }
            },
            "scanned_categories": ["quality"],
        },
    }


@pytest.mark.parametrize("tree", [False, True], ids=["table", "tree"])
def test_rich_report_prints_finding_text_literally(tree):
    console = _console()

    render_results(console, _result(), tree=tree, copy_badge=False)

    text = console.export_text()
    assert MESSAGE in text
    assert NAME in text
    assert "[tool.skylos.gate] missing" in text
    assert "No  policy" not in text


def test_rich_table_prints_paths_symbols_and_packages_literally():
    console = _console()

    render_results(console, _result(), copy_badge=False)

    text = console.export_text()
    assert f"{PATH}:3" in text
    assert "[bold]fn" in text
    assert "[red]x" in text
    assert "[bold]pkg@1.0" in text
    assert "GHSA-[x]" in text


def test_tree_prints_paths_literally():
    console = _console()

    render_results(console, _result(), tree=True, copy_badge=False)

    assert PATH in console.export_text()


def test_quality_table_help_shows_the_config_table_name():
    console = _console()

    render_results(console, _result(), copy_badge=False)

    assert "tune in [tool.skylos] (complexity" in console.export_text()


def test_pretty_report_prints_finding_text_literally():
    console = _console()

    render_pretty_results(console, _result())

    assert MESSAGE in console.export_text()


@pytest.mark.parametrize("handler", [_handle_advisory_gate, _handle_incomplete_gate])
def test_gate_reasons_print_literally(handler):
    console = _console()

    handler(console, [MESSAGE])

    assert MESSAGE in console.export_text()


def test_clean_dry_run_prints_names_and_paths_literally():
    console = _console()
    findings = [
        {"file": PATH, "line": 3, "type": "function", "name": NAME, "confidence": 90}
    ]

    _print_dry_run_plan(console, findings, "remove")

    text = console.export_text()
    assert PATH in text
    assert f"L3 function {NAME} (90%)" in text


def _empty_result():
    return {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }


@pytest.mark.parametrize(
    "extra_args, expected_level",
    [([], logging.WARNING), (["--verbose"], None)],
    ids=["default", "verbose"],
)
def test_rich_scan_hides_analyzer_info_logs_unless_verbose(
    monkeypatch, extra_args, expected_level
):
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", ".", "--no-provenance", *extra_args]
    )
    fake_logger = Mock()
    fake_logger.console = Mock()
    analyzer_logger = logging.getLogger("Skylos")
    original_level = analyzer_logger.level
    observed = {}

    def fake_analyze(*args, **kwargs):
        observed["analyzer_level"] = analyzer_logger.level
        return json.dumps(_empty_result())

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress"),
        patch("skylos.cli.run_analyze", side_effect=fake_analyze),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results"),
        patch("skylos.cli.print_badge"),
    ):
        try:
            cli.main()
        except SystemExit:
            pass

    assert observed["analyzer_level"] == (
        original_level if expected_level is None else expected_level
    )
    assert analyzer_logger.level == original_level
