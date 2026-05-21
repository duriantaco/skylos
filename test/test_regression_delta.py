import pytest
from pathlib import Path

from scripts.regression_delta import _safe_workspace_json, compare


def _corpus_summary(failures=None):
    failures = failures or {}
    return {
        "failure_count": sum(len(items) for items in failures.values()),
        "cases": [
            {
                "id": case_id,
                "failures": [
                    {
                        "category": category,
                        "mode": mode,
                        "expected": expected,
                        "found": ["actual"],
                    }
                    for category, mode, expected in items
                ],
            }
            for case_id, items in failures.items()
        ],
    }


def _quality_summary(
    *,
    failure_count=0,
    overall_score=100.0,
    taxonomy=None,
    failures=None,
):
    failures = failures or {}
    taxonomy = taxonomy or {"precision_guard": 100.0, "maintainability": 100.0}
    return {
        "failure_count": failure_count
        or sum(len(items) for items in failures.values()),
        "scores": {"overall_score": overall_score},
        "taxonomy": {
            label: {"weighted_score": score} for label, score in taxonomy.items()
        },
        "cases": [
            {
                "id": case_id,
                "failures": [
                    {
                        "failure_type": failure_type,
                        "category": category,
                        "mode": mode,
                        "expected": expected,
                        "found": ["actual"],
                    }
                    for failure_type, category, mode, expected in items
                ],
            }
            for case_id, items in failures.items()
        ],
    }


def _agent_review_summary(
    *,
    failure_count=0,
    overall_score=100.0,
    recall=1.0,
    absence_guard=1.0,
    avg_tokens_per_case=1000.0,
    total_elapsed_seconds=10.0,
    security_scorecard=None,
    failures=None,
):
    failures = failures or {}
    security_scorecard = security_scorecard or {"sql_injection": 100.0}
    return {
        "failure_count": failure_count
        or sum(len(items) for items in failures.values()),
        "avg_tokens_per_case": avg_tokens_per_case,
        "total_elapsed_seconds": total_elapsed_seconds,
        "scores": {
            "overall_score": overall_score,
            "recall": recall,
            "absence_guard": absence_guard,
        },
        "security_scorecard": {
            label: {"weighted_score": score}
            for label, score in security_scorecard.items()
        },
        "cases": [
            {
                "id": case_id,
                "failures": [
                    {
                        "failure_type": failure_type,
                        "category": category,
                        "mode": mode,
                        "expected": expected,
                        "found": ["actual"],
                    }
                    for failure_type, category, mode, expected in items
                ],
            }
            for case_id, items in failures.items()
        ],
    }


def test_corpus_no_change_passes():
    summary = _corpus_summary({"known-case": [("quality", "present", "SKY-Q301")]})

    passed, lines = compare("corpus", summary, summary)

    assert passed is True
    assert "No corpus regression detected." in lines


def test_corpus_new_failure_fails():
    base = _corpus_summary()
    head = _corpus_summary({"new-case": [("unused_functions", "absent", "handler")]})

    passed, lines = compare("corpus", base, head)

    assert passed is False
    assert any("failure count increased" in line for line in lines)
    assert any("new-case" in line for line in lines)


def test_corpus_removed_failure_passes():
    base = _corpus_summary({"known-case": [("unused_functions", "absent", "handler")]})
    head = _corpus_summary()

    passed, lines = compare("corpus", base, head)

    assert passed is True
    assert "No corpus regression detected." in lines


def test_quality_failure_count_increase_fails():
    base = _quality_summary(failure_count=0)
    head = _quality_summary(
        failures={"quality-case": [("expectation", "quality", "present", "SKY-L006")]}
    )

    passed, lines = compare("quality", base, head)

    assert passed is False
    assert any("failure count increased" in line for line in lines)
    assert any("quality-case" in line for line in lines)


def test_quality_overall_score_drop_fails():
    base = _quality_summary(overall_score=100.0)
    head = _quality_summary(overall_score=99.0)

    passed, lines = compare("quality", base, head)

    assert passed is False
    assert any("overall score dropped" in line for line in lines)


def test_quality_taxonomy_score_drop_fails():
    base = _quality_summary(taxonomy={"precision_guard": 100.0})
    head = _quality_summary(taxonomy={"precision_guard": 95.0})

    passed, lines = compare("quality", base, head)

    assert passed is False
    assert any("taxonomy 'precision_guard' score dropped" in line for line in lines)


def test_quality_score_improvement_passes():
    base = _quality_summary(overall_score=95.0, taxonomy={"precision_guard": 95.0})
    head = _quality_summary(overall_score=100.0, taxonomy={"precision_guard": 100.0})

    passed, lines = compare("quality", base, head)

    assert passed is True
    assert "No quality benchmark regression detected." in lines


def test_agent_review_no_regression_passes_with_token_warning():
    base = _agent_review_summary(avg_tokens_per_case=1000.0)
    head = _agent_review_summary(avg_tokens_per_case=1200.0)

    passed, lines = compare("agent_review", base, head)

    assert passed is True
    assert "No agent-review benchmark regression detected." in lines
    assert any("avg tokens/case increased more than 15%" in line for line in lines)


def test_agent_review_score_drop_fails():
    base = _agent_review_summary(overall_score=100.0)
    head = _agent_review_summary(overall_score=95.0)

    passed, lines = compare("agent_review", base, head)

    assert passed is False
    assert any("overall score dropped" in line for line in lines)


def test_agent_review_new_failure_fails():
    base = _agent_review_summary()
    head = _agent_review_summary(
        failures={"repo-clean-service": [("expectation", "security", "absent", "x")]}
    )

    passed, lines = compare("agent_review", base, head)

    assert passed is False
    assert any("new failing agent-review expectations" in line for line in lines)
    assert any("repo-clean-service" in line for line in lines)


def test_agent_review_security_score_drop_fails():
    base = _agent_review_summary(security_scorecard={"sql_injection": 100.0})
    head = _agent_review_summary(security_scorecard={"sql_injection": 80.0})

    passed, lines = compare("agent_review", base, head)

    assert passed is False
    assert any("security class 'sql_injection' score dropped" in line for line in lines)


def test_json_inputs_must_be_workspace_local_filenames():
    workspace = Path.cwd().resolve()

    assert _safe_workspace_json("head.json", workspace).name == "head.json"

    with pytest.raises(ValueError, match="workspace-local"):
        _safe_workspace_json("../head.json", workspace)

    with pytest.raises(ValueError, match=".json"):
        _safe_workspace_json("head.txt", workspace)
