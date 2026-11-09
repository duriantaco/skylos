"""Cleanup queues retain detector evidence, visibility and incomplete coverage."""

from copy import deepcopy

import pytest

from skylos.cleanup import build_cleanup_plan


def _report(**sections):
    return {
        "analysis_summary": {
            "total_files": 2,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "ai_verification": {"state": "complete"},
        },
        "analysis_errors": [],
        **sections,
    }


def _finding(rule="SKY-L033", **values):
    return {
        "rule_id": rule,
        "file": "app.py",
        "line": 8,
        "name": "process",
        "severity": "MEDIUM",
        "message": "Statement has no effect",
        **values,
    }


def test_queue_ranks_defects_and_retains_original_evidence(tmp_path):
    review = _finding(
        "SKY-L012", severity="CRITICAL", evidence={"reference": "missing"}
    )
    defect = _finding(evidence={"expression": "value"})
    raw = _report(ai_defects=[review], quality=[defect])
    before = deepcopy(raw)
    plan = build_cleanup_plan(raw, project_root=tmp_path, top=1)
    assert plan["status"] == "ready"
    assert plan["tasks"][0]["rule_id"] == "SKY-L012"
    assert plan["tasks"][0]["finding"] == review
    assert plan["tasks"][0]["evidence"] == {"reference": "missing"}
    assert plan["tasks"][0]["finding_type"] == "review"
    assert plan["counts"]["tasks"] == 2
    assert plan["counts"]["shown_tasks"] == 1
    assert raw == before


def test_metrics_and_style_stay_advice_and_marks_are_respected(tmp_path):
    listed = _finding("SKY-L037", message="Simplify bool", severity="LOW")
    optional = _finding("SKY-L038", message="Use conversion flag", severity="LOW")
    optional["listing"] = {"version": 1, "listed": False, "reason": "measurement"}
    listed["listing"] = {"version": 1, "listed": True, "reason": "evidence"}
    raw = _report(quality=[listed, optional], listing_policy_version=1)
    before = deepcopy(raw)
    focused = build_cleanup_plan(raw, project_root=tmp_path)
    expanded = build_cleanup_plan(raw, project_root=tmp_path, all_advice=True)
    assert focused["tasks"] == expanded["tasks"] == []
    assert [row["rule_id"] for row in focused["advisories"]] == ["SKY-L037"]
    assert focused["counts"]["optional_advice"] == 1
    assert len(expanded["advisories"]) == 2
    assert expanded["counts"]["optional_advice"] == 0
    assert expanded["advisories"][1]["finding"]["listing"]["listed"] is False
    assert raw == before


def test_mirrors_count_once_but_distinct_evidence_is_preserved(tmp_path):
    first = _finding("SKY-L012", evidence={"binding": "first"})
    second = _finding("SKY-L012", evidence={"binding": "second"})
    raw = _report(quality=[first], ai_defects=[deepcopy(first), second])
    plan = build_cleanup_plan(raw, project_root=tmp_path)
    assert len(plan["tasks"]) == 2
    assert len({task["id"] for task in plan["tasks"]}) == 2
    reordered = _report(ai_defects=[second, deepcopy(first)], quality=[first])
    assert [task["id"] for task in plan["tasks"]] == [
        task["id"]
        for task in build_cleanup_plan(reordered, project_root=tmp_path)["tasks"]
    ]


def test_dead_code_is_review_work_never_an_automatic_delete(tmp_path):
    raw = _report(
        unused_functions=[
            {
                "name": "plugin_entry",
                "file": str(tmp_path / "app.py"),
                "line": 2,
                "confidence": 90,
            }
        ]
    )
    task = build_cleanup_plan(raw, project_root=tmp_path)["tasks"][0]
    assert task["rule_id"] == "SKY-U001"
    assert task["finding_type"] == "review"
    assert task["file"] == "app.py"
    assert "dynamic use" in task["action"]
    assert task["finding"]["confidence"] == 90


@pytest.mark.parametrize(
    "change",
    [
        {"analysis_errors": [{"kind": "syntax_error", "file": "app.py"}]},
        {
            "analysis_summary": {
                "total_files": 0,
                "grade_categories": ["quality", "ai_defects", "dead_code"],
            }
        },
        {"analysis_summary": {"total_files": 1, "grade_categories": ["dead_code"]}},
        {"analysis_summary": {"total_files": 1}},
        {
            "analysis_summary": {
                "total_files": 1,
                "grade_categories": ["quality", "ai_defects", "dead_code"],
                "ai_verification": {
                    "state": "incomplete",
                    "missing_checks": ["python_local_api_reference"],
                },
            }
        },
    ],
)
def test_empty_or_failed_scan_never_becomes_a_clear_queue(tmp_path, change):
    raw = {**_report(), **change}
    plan = build_cleanup_plan(raw, project_root=tmp_path)
    assert plan["status"] == "incomplete"
    assert plan["limitations"]
    assert plan["analysis_errors"] == raw["analysis_errors"]
    assert plan["analysis_summary"] == raw["analysis_summary"]


@pytest.mark.parametrize(
    "raw", [None, [], {}, _report(quality=["bad"]), _report(quality={})]
)
def test_malformed_reports_cannot_silently_drop_evidence(tmp_path, raw):
    with pytest.raises(ValueError):
        build_cleanup_plan(raw, project_root=tmp_path)


@pytest.mark.parametrize(
    "sections",
    [
        {"publisher_change_findings": ["broken"]},
        {"architecture_metrics": {"advisories": {}}},
        {"architecture_metrics": {"advisories": [{"signals": [None]}]}},
    ],
)
def test_malformed_mirrors_and_architecture_are_rejected(tmp_path, sections):
    with pytest.raises(ValueError):
        build_cleanup_plan(_report(**sections), project_root=tmp_path)


@pytest.mark.parametrize("coverage", [None, [], {}, {"state": "unknown"}])
def test_missing_ai_coverage_cannot_be_clear(tmp_path, coverage):
    raw = _report()
    raw["analysis_summary"]["ai_verification"] = coverage
    assert build_cleanup_plan(raw, project_root=tmp_path)["status"] == "incomplete"


def test_observation_ids_preserve_literal_whitespace_in_evidence(tmp_path):
    first = _finding(evidence={"literal": "a b"})
    second = _finding(evidence={"literal": "a  b"})
    plan = build_cleanup_plan(_report(quality=[first, second]), project_root=tmp_path)
    assert len({task["id"] for task in plan["tasks"]}) == 2


def test_incomplete_scan_keeps_available_tasks(tmp_path):
    raw = _report(quality=[_finding()], analysis_errors=[{"kind": "worker_crash"}])
    plan = build_cleanup_plan(raw, project_root=tmp_path)
    assert plan["status"] == "incomplete"
    assert plan["counts"]["tasks"] == 1


def test_empty_complete_queue_is_clear_but_optional_advice_remains_counted(tmp_path):
    raw = _report(quality=[_finding("SKY-L038")])
    raw["quality"][0]["listing"] = {
        "version": 1,
        "listed": False,
        "reason": "measurement",
    }
    raw["listing_policy_version"] = 1
    plan = build_cleanup_plan(raw, project_root=tmp_path)
    assert plan["status"] == "clear"
    assert plan["counts"]["optional_advice"] == 1


def test_imported_security_rows_do_not_become_quality_tasks(tmp_path):
    plan = build_cleanup_plan(
        _report(danger=[_finding("SKY-D201")]), project_root=tmp_path
    )
    assert plan["scope"] == ["quality", "ai_defects", "dead_code"]
    assert plan["counts"]["tasks"] == 0
