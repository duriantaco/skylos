"""LLM report complexity entries retain both original checks and their evidence."""

import copy
import json
import re

import pytest

from skylos.reporting.finding_types import annotate_finding_types
from skylos.reporting.llm_report import (
    _collect_llm_report_findings,
    _generate_llm_report,
)


def _finding(rule, *, line=12, name="app.process", severity="MEDIUM"):
    cognitive = rule == "SKY-Q306"
    return {
        "rule_id": rule,
        "severity": severity,
        "type": "function",
        "kind": "complexity",
        "name": name,
        "simple_name": name.rsplit(".", 1)[-1],
        "file": "missing.py",
        "line": line,
        "value": 22 if cognitive else 14,
        "threshold": 15 if cognitive else 10,
        "message": "Simplify nested logic." if cognitive else "Split branches.",
        "evidence": {"branches": ["first", "second"], "rule": rule},
    }


def _records(report):
    return [
        json.loads(value)
        for value in re.findall(
            r"Record:\n```json\n(.*?)\n```", report, flags=re.DOTALL
        )
    ]


def test_default_report_counts_functions_and_discloses_original_checks(tmp_path):
    result = {
        "quality": [
            _finding("SKY-Q306"),
            _finding("SKY-Q301"),
            _finding("SKY-Q306", line=30, name="app.other"),
        ]
    }

    report = _generate_llm_report(result, tmp_path)

    # The lone cognitive score is measured, not listed, by default.
    assert "0 defects · 0 review · 1 advice entry (2 findings) in 1 group." in report
    assert "1 optional advice finding (1 function metrics without two agreeing" in report
    assert "SKY-Q301 + SKY-Q306: 1 advice entry in 1 file — Function complexity" in report
    assert "each original record for grouped metric checks" in report
    assert _records(report) == []


def test_expanded_report_has_one_heading_both_scores_and_both_original_records(
    tmp_path,
):
    cyclomatic = _finding("SKY-Q301", severity="LOW")
    cognitive = _finding("SKY-Q306", severity="HIGH")
    result = {"quality": [cognitive, cyclomatic]}

    report = _generate_llm_report(result, tmp_path, expand_advice=True)

    assert report.count("\n## ") == 1
    assert "## 1. SKY-Q301 + SKY-Q306 | MEDIUM | Quality\n" in report
    assert "Name: app.process\n" in report
    assert report.count("Type: Advice") == 1
    assert "SKY-Q301: Cyclomatic complexity: 14 (threshold: 10)" in report
    assert "SKY-Q306: Cognitive complexity: 22 (threshold: 15)" in report
    assert "Split branches." in report and "Simplify nested logic." in report
    assert _records(report) == [
        {**finding, "finding_type": "advice"} for finding in (cyclomatic, cognitive)
    ]
    assert "_complexity_display" not in report
    assert "Advice groups" not in report


@pytest.mark.parametrize("expand_advice", [False, True])
def test_render_keeps_raw_findings_grades_and_gates_unchanged(tmp_path, expand_advice):
    result = {
        "quality": [_finding("SKY-Q301"), _finding("SKY-Q306")],
        "grade": {"overall": "B", "complexity": 71},
        "gate": {"failed": True, "blocking_count": 2, "reasons": ["quality"]},
    }
    # Already classified CLI results must remain unchanged too.
    annotate_finding_types(result)
    expected = copy.deepcopy(result)

    _generate_llm_report(result, tmp_path, expand_advice=expand_advice)

    assert result == expected
    assert json.loads(json.dumps(result)) == expected


@pytest.mark.parametrize("rule", ["SKY-Q301", "SKY-Q306"])
def test_unpaired_complexity_report_keeps_original_rule_and_record(tmp_path, rule):
    finding = _finding(rule)
    result = {"quality": [finding]}

    # One metric alone is listed with --all-advice.
    compact = _generate_llm_report(result, tmp_path, all_advice=True)
    expanded = _generate_llm_report(
        result, tmp_path, expand_advice=True, all_advice=True
    )

    assert "0 defects · 0 review · 1 advice in 1 group." in compact
    assert f"{rule}: 1 advice entry in 1 file" in compact
    assert f"## 1. {rule} | MEDIUM | Quality\n" in expanded
    assert " + " not in expanded
    assert _records(expanded) == [{**finding, "finding_type": "advice"}]


def test_custom_checks_reusing_complexity_ids_stay_individual_review_records(
    tmp_path,
):
    findings = [_finding("SKY-Q301"), _finding("SKY-Q306")]
    result = {"custom_rules": findings}

    report = _generate_llm_report(result, tmp_path)

    assert "0 defects · 2 review · 0 advice in 0 groups." in report
    assert report.count("Type: Review") == 2
    assert "SKY-Q301 + SKY-Q306" not in report
    assert _records(report) == [
        {**finding, "finding_type": "review"} for finding in findings
    ]


def test_evidence_variants_are_not_dropped_by_expanded_report(tmp_path):
    first = _finding("SKY-Q301")
    variant = copy.deepcopy(first)
    variant["evidence"]["branches"] = ["different branch"]
    cognitive = _finding("SKY-Q306")
    result = {"quality": [first, variant, cognitive]}

    report = _generate_llm_report(result, tmp_path, expand_advice=True)

    assert report.count("Type: Advice") == 3
    assert "3 advice in 1 group." in report
    assert _records(report) == [
        {**finding, "finding_type": "advice"} for finding in (first, variant, cognitive)
    ]


def test_raw_llm_collector_keeps_both_checks_and_original_objects():
    findings = [_finding("SKY-Q306"), _finding("SKY-Q301")]

    collected = _collect_llm_report_findings({"quality": findings})

    assert collected == [(finding, "Quality") for finding in findings]
    assert all(row[0] is original for row, original in zip(collected, findings))
    assert all("_complexity_display" not in finding for finding in findings)
