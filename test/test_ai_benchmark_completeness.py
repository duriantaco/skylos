"""Clean benchmark credit requires proof that the relevant checks ran."""

import pytest

from skylos.benchmarks.ai_code_defects import run_manifest


MANIFEST = "benchmarks/ai_code_defects/manifest.json"


@pytest.mark.parametrize("case", ["clean-generated-code", "clean-typescript-local-api-surface"])
@pytest.mark.parametrize("report", [
    {"findings": []},
    {"status": "incomplete", "coverage": {"state": "incomplete", "checks": []}, "findings": []},
    {"status": "pass", "coverage": {"state": "complete", "checks": []}, "findings": []},
])
def test_empty_or_incomplete_reports_do_not_earn_clean_credit(case, report):
    summary = run_manifest(MANIFEST, selected_cases={case}, verify_func=lambda *a, **k: report)
    assert summary["pass_count"] == 0
    assert summary["failure_count"] == 1
    assert summary["scores"]["weighted_pass_rate"] == 0
    assert summary["scores"]["absence_guard"] == 0
    assert summary["score_available"] is False
    assert any(f["failure_type"] == "verification" for f in summary["cases"][0]["failures"])


def test_complete_applicable_checks_earn_clean_credit():
    summary = run_manifest(
        MANIFEST, selected_cases={"clean-typescript-local-api-surface"},
        verify_func=lambda *a, **k: {
            "status": "pass", "findings": [],
            "coverage": {"state": "complete", "checks": [
                {"id": "typescript_local_api_surface", "outcome": "pass"},
            ]},
        },
    )
    assert summary["pass_count"] == 1


def test_explicit_unsupported_contract_is_preserved_as_incomplete():
    summary = run_manifest(
        MANIFEST, selected_cases={"rust-local-api-unsupported"},
        verify_func=lambda *a, **k: {
            "status": "incomplete", "findings": [],
            "coverage": {"state": "incomplete", "checks": [
                {"id": "rust_workspace_api_surface", "outcome": "incomplete"},
            ]},
        },
    )
    assert summary["pass_count"] == 1
    assert summary["cases"][0]["status"] == "incomplete"
    assert summary["cases"][0]["coverage_state"] == "incomplete"
    assert summary["cases"][0]["scored"] is False
    assert summary["score_available"] is False
    assert summary["scores"]["absence_guard"] == 0


def test_static_benchmark_explicitly_disables_behavior_comparison():
    seen = []

    def verify(*args, **kwargs):
        seen.append(kwargs["behavior_comparison"])
        return {"findings": []}

    run_manifest(MANIFEST, selected_cases={"clean-generated-code"}, verify_func=verify)
    assert seen == [False]
