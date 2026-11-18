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


def test_standard_http_guard_is_reviewable_in_reports_and_compact_upload():
    from skylos.api._payloads import _compact_provenance

    guarded = _finding("conditional_http_guard")
    proof = guarded["metadata"]["path_provenance"]
    proof["input_trust"] = "untrusted"
    proof["guarded_http"] = [["app.py:4 HTTP input", "app.py:8 filename check"]]
    proof["validation_uncertainty"] = {
        "status": "unverified",
        "check": "filename_filter_body",
        "assumption": "standard_http_string_decoding",
        "steps": ["app.py:4 filename filter applied"],
    }
    assert _compact_provenance(proof)["validation_uncertainty"] == proof["validation_uncertainty"]
    assert _compact_provenance(proof)["guarded_http"] == proof["guarded_http"]
    assert _compact_provenance(proof)["input_trust"] == "untrusted"
    result = _result(guarded, _finding("untrusted", line=15))
    summary = path_review_summary(result["danger"])
    assert summary["unresolved_count"] == 1
    assert summary["by_status"]["conditional_http_guard"] == 1
    assert "Filename checks conditional on standard HTTP decoding (1)." in path_review_lines(result)


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
    result = _result(
        _finding(file=str(tmp_path / "app.py")),
        _finding("incomplete", line=9, file=str(tmp_path / "app.py")),
    )
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
    assert "2 path findings need review: caller/source unresolved" in rendered
    assert "Unknown sources or callers (1) · Incomplete traces (1)" in rendered
    assert "Exploitability remains unconfirmed." in rendered
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


@pytest.mark.parametrize("output", ["html", "md"])
def test_report_links_all_review_rows_with_their_evidence(tmp_path, output):
    from skylos.reporting.listing import LISTING_VERSION

    marked = []
    for number in range(1, 6):
        path = str(tmp_path / f"review-{number}.py")
        row = _finding("unknown", line=number + 100, file=path)
        row["language"] = "python"
        row["listing"] = {
            "version": LISTING_VERSION,
            "listed": False,
            "reason": "path-needs-review",
        }
        row["metadata"]["path_provenance"].update(
            complete_project=True,
            disposition="needs_review",
            unknown=[
                [
                    f"review-{number}.py:{number} <script> [link](https://bad.example) | source unresolved"
                ]
            ],
        )
        marked.append(row)
    listed = _finding("untrusted", line=10, file=str(tmp_path / "actual.py"))
    result = _result(*marked, listed)
    original = copy.deepcopy(result)
    report = render_report(result, output, project_root=tmp_path)
    assert result == original
    assert "Path findings needing review (5)" in report
    assert "#path-findings-needing-review" in report
    if output == "html":
        section = report.partition('id="path-findings-needing-review"')[2].partition(
            "</table>"
        )[0]
        assert "<script>" not in section
        assert "&lt;script&gt;" in section
        assert "<th>Reason</th>" in section
    else:
        section = report.partition("## Path findings needing review")[2].partition(
            "## Gate"
        )[0]
        assert "[link](" not in section
        assert "<script>" not in section
        assert "| Rule | Reason |" in section
    for number in range(1, 6):
        assert f"review-{number}.py" in section
        assert str(number + 100) in section
    assert "source unresolved" in section
    assert str(tmp_path) not in section
    assert "SKY-D215" in section
    assert "actual.py" not in section


def _review_only_report(tmp_path, count=2):
    from skylos.reporting.advice_policy import apply_advice_policy
    from skylos.reporting.assessment import compute_assessment

    rows = []
    for line in range(10, 10 + count):
        row = _finding(line=line)
        row["metadata"]["path_provenance"].update(
            complete_project=True, disposition="needs_review"
        )
        rows.append(row)
    result = _result(*rows)
    result["suppressed"] = []
    result["analysis_summary"].update(
        comparison_scope={
            "kind": "repository_root",
            "complete_repository": True,
            "changed_files_only": False,
            "excluded_folders": [],
        },
        resolution_scope_limited=False,
        analysis_error_count=0,
    )
    result["analysis_errors"] = []
    result["assessment"] = compute_assessment(result)
    return apply_advice_policy(result, project_root=tmp_path)


def test_path_review_assessment_and_coverage_match_the_retained_scan(tmp_path):
    from skylos.api._scan_coverage import scan_coverage_receipt
    from skylos.reporting.assessment import compute_assessment
    from skylos.reporting.assessment_display import assessment_rows, closing_summary
    from skylos.reporting.issue_summary import issue_summary

    def coverage(result):
        return scan_coverage_receipt(
            result, analyzer_owned=True, analysis_mode="static"
        )

    result = _review_only_report(tmp_path)
    assert compute_assessment(result) == result["assessment"]
    risk = result["assessment"]["risk"]
    assert risk["status"] == risk["categories"]["security"]["status"] == "unknown"
    assert risk["finding_count"] == 0
    assert risk["path_review_count"] == 2
    assert (
        "2 path checks need review"
        in dict(assessment_rows(result["assessment"]))["Risk"]
    )
    assert "2 additional path checks need review" in closing_summary(result)
    assert issue_summary(result)["path_review_count"] == 2
    assert result["advice_visibility"]["omitted_checks"] == 0
    assert coverage(result)["complete"] is True

    # Either changing the persisted assessment or losing its raw row invalidates
    # the coverage proof used when resolving previous findings.
    changed = copy.deepcopy(result)
    changed["assessment"]["risk"].pop("path_review_count")
    assert coverage(changed)["complete"] is False
    result["danger"].pop()
    assert coverage(result)["complete"] is False


def test_review_gate_and_verdict_use_raw_findings_for_every_limit(tmp_path):
    from skylos.core.gatekeeper import build_summary_markdown
    from skylos.reporting.top_risks import scan_verdict

    result = _review_only_report(tmp_path)
    assert [row["severity"] for row in result["danger"]] == ["HIGH", "HIGH"]
    for limit, status in ((0, "not_ready"), (1, "not_ready"), (2, "review")):
        config = {"gate": {"max_security": limit, "max_high": 5}}
        passed, reasons = check_gate(result, config)
        assert passed is (limit == 2)
        assert scan_verdict(result, config=config)["status"] == status
        summary = build_summary_markdown(result, passed, reasons)
        assert "The gate includes 2 path findings awaiting review." in summary
        assert "hidden from the list as low-risk" not in summary


@pytest.mark.parametrize("output", ["html", "md", "rich", "pretty", "llm"])
def test_review_only_human_output_never_claims_absence(tmp_path, output):
    result = _review_only_report(tmp_path, 1)
    if output in ("html", "md"):
        rendered = render_report(result, output, project_root=tmp_path)
        assert "Path findings needing review (1)" in rendered
    elif output == "llm":
        from skylos.reporting.llm_report import _generate_llm_report

        rendered = _generate_llm_report(result, tmp_path)
        assert "1 additional path check needs review" in rendered
        assert "No findings." not in rendered
    else:
        buffer = StringIO()
        console = Console(
            file=buffer, width=160, color_system=None, theme=_skylos_console_theme()
        )
        if output == "rich":
            render_results(console, result, root_path=tmp_path, copy_badge=False)
        else:
            render_pretty_results(console, result, root_path=tmp_path)
        rendered = buffer.getvalue()
        assert "1 path finding needs review" in rendered
    if output != "llm":
        assert "app.py" in rendered and "SKY-D215" in rendered
    assert "No findings to display" not in rendered
    assert "No risk findings" not in rendered
