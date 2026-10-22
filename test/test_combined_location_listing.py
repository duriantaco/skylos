"""One listed issue per function location; every measure stays in the report."""

from copy import deepcopy
import io
import json

import pytest
from rich.console import Console

from skylos.cli import _apply_rule_selection
from skylos.core.gatekeeper import check_gate
from skylos.reporting.advice_policy import apply_advice_policy, prepare_advice_view
from skylos.reporting.listing import listed_result
from skylos.ui.terminal_report import render_pretty_results


def _metric(rule, value, threshold, severity, line=10, name="build"):
    return {
        "rule_id": rule,
        "file": "/app/service.py",
        "line": line,
        "severity": severity,
        "name": name,
        "value": value,
        "threshold": threshold,
        "message": f"{rule} is {value} (threshold: {threshold}).",
    }


def _function(line=10, name="build"):
    return [
        _metric("SKY-Q301", 11, 10, "WARN", line, name),
        _metric("SKY-Q306", 22, 15, "MEDIUM", line, name),
        _metric("SKY-C304", 219, 50, "HIGH", line, name),
    ]


def _listing(result):
    found = {}
    for row in result["quality"]:
        found[(row["line"], row["rule_id"])] = row["listing"]
    return found


def _quality_count(result, config):
    passed, reasons = check_gate(result, config)
    for reason in reasons:
        text = str(reason)
        if "quality issue" in text:
            return passed, text
    return passed, ""


def test_most_severe_measure_leads_and_the_others_point_at_it(tmp_path):
    raw = {"quality": _function()}
    before = deepcopy(raw)
    result = apply_advice_policy(raw, project_root=tmp_path)

    assert raw == before
    marks = _listing(result)
    assert marks[(10, "SKY-C304")]["listed"] is True
    assert marks[(10, "SKY-C304")]["combines"] == [
        {"rule_id": "SKY-Q301", "line": 10},
        {"rule_id": "SKY-Q306", "line": 10},
    ]
    lead = {"rule_id": "SKY-C304", "file": "/app/service.py", "line": 10}
    for rule in ("SKY-Q301", "SKY-Q306"):
        assert marks[(10, rule)]["listed"] is False
        assert marks[(10, rule)]["reason"] == "combined"
        assert marks[(10, rule)]["lead"] == lead
    assert len(result["quality"]) == 3
    assert json.loads(json.dumps(result)) == result


def test_counts_name_the_location_once_and_keep_every_record(tmp_path):
    result = apply_advice_policy(
        {"quality": _function(10, "build") + _function(40, "render")},
        project_root=tmp_path,
    )
    summary = result["analysis_summary"]
    assert summary["quality_count"] == 6
    assert summary["listed_quality_count"] == 2
    visibility = result["advice_visibility"]
    assert visibility["combined_checks"] == 4
    assert visibility["omitted_checks"] == 0


def test_gate_counts_one_issue_per_function_unless_a_rule_is_enforced(tmp_path):
    result = apply_advice_policy({"quality": _function()}, project_root=tmp_path)
    passed, text = _quality_count(result, {"gate": {"max_quality": 0}})
    assert passed is False
    assert "1 quality issue" in text
    enforced = {"gate": {"max_quality": 0, "rules": ["SKY-Q301"]}}
    passed, text = _quality_count(result, enforced)
    assert passed is False
    assert "2 quality issue" in text


def test_terminal_view_still_shows_every_measure_in_one_entry(tmp_path):
    result = apply_advice_policy({"quality": _function()}, project_root=tmp_path)
    view, visibility = prepare_advice_view(result)
    rules = sorted(row["rule_id"] for row in view["quality"])
    assert rules == ["SKY-C304", "SKY-Q301", "SKY-Q306"]
    assert visibility.omitted_checks == 0
    buffer = io.StringIO()
    console = Console(file=buffer, width=200, color_system=None, force_terminal=False)
    render_pretty_results(console, result, expand_advice=True)
    text = buffer.getvalue()
    for value in ("219", "22", "11"):
        assert value in text


def test_all_advice_lists_every_measure(tmp_path):
    result = apply_advice_policy(
        {"quality": _function()}, project_root=tmp_path, all_advice=True
    )
    for listing in _listing(result).values():
        assert listing["listed"] is True
        assert "lead" not in listing
        assert "combines" not in listing


def test_measures_at_different_locations_stay_separate(tmp_path):
    rows = _function()
    rows[1] = _metric("SKY-Q306", 22, 15, "MEDIUM", 11, "build")
    result = apply_advice_policy({"quality": rows}, project_root=tmp_path)
    for listing in _listing(result).values():
        assert listing["reason"] != "combined"


def test_repeated_measure_at_one_location_is_not_combined(tmp_path):
    rows = _function() + [_metric("SKY-C304", 230, 50, "HIGH")]
    result = apply_advice_policy({"quality": rows}, project_root=tmp_path)
    reasons = [row["listing"]["reason"] for row in result["quality"]]
    assert "combined" not in reasons


@pytest.mark.parametrize(
    "selected_rule,required_annotations",
    [("SKY-Q301", False), ("SKY-T102", True)],
)
def test_explicit_rule_survives_grouping_and_selection(
    tmp_path, selected_rule, required_annotations
):
    if required_annotations:
        rows = []
        for rule in ("SKY-T101", "SKY-T102"):
            row = _metric(rule, 1, 0, "LOW")
            row["annotation_evidence"] = {
                "version": 1,
                "required": True,
                "source": "annotation_policy",
            }
            rows.append(row)
    else:
        rows = _function()
    raw = {"quality": rows}
    before = deepcopy(raw)
    result = apply_advice_policy(
        raw, project_root=tmp_path, explicit_rules=[selected_rule]
    )
    assert raw == before
    assert len(result["quality"]) == len(rows)
    selected = _apply_rule_selection(result, [selected_rule])

    assert len(selected["quality"]) == 1
    mark = selected["quality"][0]["listing"]
    assert mark["listed"] is True
    assert mark["reason"] == "explicit_rule"
    assert "lead" not in mark
    assert selected["analysis_summary"]["listed_quality_count"] == 1
    passed, text = _quality_count(selected, {"gate": {"max_quality": 0}})
    assert passed is False
    assert "1 quality issue" in text


@pytest.mark.parametrize(
    "variant", [{"evidence": {"source": "different"}}, {"severity": "CRITICAL"}]
)
def test_group_marks_preserve_distinct_records_and_equal_mirrors(tmp_path, variant):
    rows = _function()
    risk_variant = {**deepcopy(rows[0]), **variant}
    raw = {
        "quality": rows,
        "danger": [risk_variant],
        "code_health": [deepcopy(rows[1])],
    }
    before = deepcopy(raw)
    result = apply_advice_policy(raw, project_root=tmp_path)

    assert raw == before
    assert result["danger"][0]["listing"]["listed"] is True
    assert result["danger"][0]["listing"]["reason"] == "default"
    assert "lead" not in result["danger"][0]["listing"]
    assert listed_result(result)["danger"] == result["danger"]
    assert result["quality"][1]["listing"]["reason"] == "combined"
    assert result["code_health"][0]["listing"] == result["quality"][1]["listing"]
    assert result["analysis_summary"]["listed_quality_count"] == 1


def test_supported_id_alias_retains_canonical_group_references(tmp_path):
    rows = _function()
    for row in rows:
        row["id"] = row.pop("rule_id")
    raw = {"quality": rows}
    before = deepcopy(raw)
    result = apply_advice_policy(raw, project_root=tmp_path)

    assert raw == before
    marks = {}
    for row in result["quality"]:
        marks[row["id"]] = row["listing"]
    lead = {"rule_id": "SKY-C304", "file": "/app/service.py", "line": 10}
    for rule in ("SKY-Q301", "SKY-Q306"):
        assert marks[rule]["listed"] is False
        assert marks[rule]["lead"] == lead
    assert marks["SKY-C304"]["listed"] is True
    assert marks["SKY-C304"]["combines"] == [
        {"rule_id": "SKY-Q301", "line": 10},
        {"rule_id": "SKY-Q306", "line": 10},
    ]
    assert result["analysis_summary"]["quality_count"] == 3
    assert result["analysis_summary"]["listed_quality_count"] == 1
