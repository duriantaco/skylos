from __future__ import annotations

from skylos_mcp.server import _make_summary


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
