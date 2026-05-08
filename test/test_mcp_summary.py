from __future__ import annotations

from skylos_mcp.server import (
    _architecture_payload,
    _health_score_payload,
    _make_summary,
)


def test_make_summary_includes_workspace_report_when_present():
    result = {
        "analysis_summary": {"total_files": 1, "monorepo_detected": True},
        "workspaces": {
            "root_package": {"name": "@repo/root"},
            "packages": [{"name": "@repo/app"}],
            "diagnostics": [],
        },
    }

    summary = _make_summary(result)

    assert summary["analysis_summary"]["monorepo_detected"] is True
    assert summary["workspaces"]["root_package"]["name"] == "@repo/root"


def test_make_summary_omits_empty_workspace_report():
    result = {
        "analysis_summary": {"total_files": 1},
        "workspaces": {
            "root_package": None,
            "packages": [],
            "diagnostics": [],
        },
    }

    summary = _make_summary(result)

    assert "workspaces" not in summary


def test_architecture_payload_filters_architecture_findings():
    result = {
        "analysis_summary": {"quality_count": 2},
        "architecture_metrics": {"layer_policy": {"violation_count": 1}},
        "quality": [
            {"rule_id": "SKY-Q805", "kind": "architecture", "name": "domain"},
            {"rule_id": "SKY-L014", "kind": "logic", "name": "password"},
        ],
    }

    payload = _architecture_payload(result)

    assert payload["architecture_metrics"]["layer_policy"]["violation_count"] == 1
    assert [finding["rule_id"] for finding in payload["findings"]] == ["SKY-Q805"]


def test_health_score_payload_summarizes_counts_and_grade():
    result = {
        "analysis_summary": {
            "quality_count": 3,
            "danger_count": 1,
            "secrets_count": 0,
            "sca_count": 2,
        },
        "grade": {
            "overall": {"score": 88, "letter": "B+"},
            "categories": {
                "quality": {
                    "score": 82,
                    "letter": "B-",
                    "key_issue": "Architecture layer violation",
                },
                "secrets": {
                    "score": 100,
                    "letter": "A+",
                    "key_issue": "No secrets found",
                },
            },
        },
        "unused_functions": [{"name": "old"}],
        "architecture_metrics": {
            "layer_policy": {"violation_count": 1},
            "system_metrics": {"architecture_fitness": 0.91},
        },
    }

    payload = _health_score_payload(result)

    assert payload["grade"]["overall"]["letter"] == "B+"
    assert payload["counts"]["dead_code"] == 1
    assert payload["counts"]["architecture_policy_violations"] == 1
    assert payload["architecture_fitness"] == 0.91
    assert payload["top_issues"] == [
        {"category": "quality", "key_issue": "Architecture layer violation"}
    ]
