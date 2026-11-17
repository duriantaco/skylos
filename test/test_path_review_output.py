"""Unresolved paths remain findings and are explained separately from safety."""

import copy
import json
from datetime import datetime, timezone
from io import StringIO

import pytest
from rich.console import Console

from skylos.analyzer import analyze
from skylos.cli import _skylos_console_theme
from skylos.core.gatekeeper import check_gate
from skylos.reporting.path_display import path_review_lines, path_review_summary
from skylos.reporting.report_page import render_report
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results


def _finding(status="unknown", *, rule="SKY-D215", line=7, file="app.py"):
    return {
        "rule_id": rule,
        "file": file,
        "line": line,
        "col": 4,
        "symbol": "reader",
        "severity": "HIGH",
        "message": "Path requires review; the caller input is unresolved.",
        "metadata": {
            "path_provenance": {
                "version": 1,
                "status": status,
                status: [["app.py:4 caller callback is external", "app.py:7 sink"]],
            }
        },
    }


def _result(*findings):
    return {
        "danger": list(findings),
        "suppressed": [_finding("safe")],
        "analysis_summary": {"total_files": 1, "grade_categories": ["security"]},
    }


def test_summary_counts_only_unresolved_reported_path_findings():
    result = _result(
        _finding(),
        _finding("incomplete", rule="SKY-D324"),
        _finding("untrusted", rule="SKY-D325"),
        _finding("unknown", rule="SKY-D211"),
    )
    before = copy.deepcopy(result)
    receipt = path_review_summary(result["danger"])
    assert receipt["unresolved_count"] == 2
    assert receipt["by_status"] == {"unknown": 1, "incomplete": 1}
    assert receipt["by_rule"] == {"SKY-D215": 1, "SKY-D324": 1}
    assert len(receipt["examples"]) == 2
    assert receipt["examples"][0]["reason"] == "app.py:4 caller callback is external"
    assert "not proof of safety" in receipt["scope"]
    assert result == before
    config = {"gate": {"max_security": 0}}
    before_gate = check_gate(result, config)
    result["analysis_summary"]["path_review"] = receipt
    assert before_gate[0] is False
    assert check_gate(result, config) == before_gate
    assert json.loads(json.dumps(receipt)) == receipt


def test_review_examples_and_untrusted_text_are_bounded():
    findings = [_finding(line=i + 1) for i in range(10)]
    findings[0]["file"] = "\x1b[31mapp.py\x00"
    findings[0]["metadata"]["path_provenance"]["unknown"][0][0] = (
        "\x1b[31m" + "missing source " * 100
    )
    receipt = path_review_summary(findings)
    assert receipt["unresolved_count"] == 10
    assert len(receipt["examples"]) == 3
    assert all(len(example["reason"]) <= 300 for example in receipt["examples"])
    assert "\x1b" not in receipt["examples"][0]["file"]
    assert "\x00" not in receipt["examples"][0]["file"]
    assert "\x1b" not in receipt["examples"][0]["reason"]


def test_malformed_or_unproven_metadata_does_not_claim_a_review_or_safety():
    findings = [None, "text", {"rule_id": []}, _finding("untrusted"), _finding("safe")]
    malformed = _finding()
    malformed["metadata"]["path_provenance"]["status"] = {}
    findings.append(malformed)
    assert path_review_summary(findings)["unresolved_count"] == 0
    assert path_review_lines({"danger": findings}) == []


@pytest.mark.parametrize("output", ["rich", "pretty"])
def test_human_output_names_uncertainty_and_the_missing_caller_edge(output, tmp_path):
    result = _result(_finding(file=str(tmp_path / "app.py")))
    before = copy.deepcopy(result)
    buffer = StringIO()
    console = Console(
        file=buffer, width=200, color_system=None, theme=_skylos_console_theme()
    )
    if output == "rich":
        render_results(console, result, root_path=tmp_path, copy_badge=False)
    else:
        render_pretty_results(console, result, root_path=tmp_path)
    rendered = buffer.getvalue()
    assert "1 path finding needs review: caller/source unresolved" in rendered
    assert "safety is not established" in rendered
    assert "SKY-D215 app.py:7: app.py:4 caller callback is external" in rendered
    assert "metadata.path_provenance with --format json" in rendered
    assert "Path requires review" in rendered
    assert result == before


@pytest.mark.parametrize("output", ["md", "html"])
def test_standalone_report_preserves_review_count_and_gap(output):
    result = _result(_finding(), _finding("incomplete", rule="SKY-D325", line=12))
    before = copy.deepcopy(result)
    rendered = render_report(
        result, report_format=output, now=datetime(2026, 11, 17, tzinfo=timezone.utc)
    )
    assert "2 path findings need review: caller/source unresolved" in rendered
    assert "safety is not established" in rendered
    assert "app.py:4 caller callback is external" in rendered
    assert "metadata.path_provenance with --format json" in rendered
    assert result == before


def test_analyzer_json_exposes_unresolved_paths_without_target_execution(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "app.py").write_text(
        "raise RuntimeError('inspected source must not execute')\n"
        "from pathlib import Path\n"
        "def reader(path):\n"
        "    return Path(path).read_text()\n",
        encoding="utf-8",
    )
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )
    unresolved = [
        row
        for row in result.get("danger", [])
        if (row.get("metadata", {}).get("path_provenance") or {}).get("status")
        == "unknown"
    ]
    assert unresolved
    receipt = result["analysis_summary"]["path_review"]
    assert receipt["unresolved_count"] == len(unresolved)
    assert receipt["by_status"]["unknown"] == len(unresolved)
    assert receipt["examples"]
    assert not result.get("analysis_errors")
