from __future__ import annotations

import json
from pathlib import Path

import pytest

import skylos.benchmarks.ai_code_defects as benchmark
from skylos.benchmarks.ai_code_defects import (
    AI_CODE_DEFECT_TAXONOMY,
    format_summary,
    load_manifest,
    run_manifest,
    validate_manifest,
)


MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent
    / "benchmarks"
    / "ai_code_defects"
    / "manifest.json"
)


def test_checked_in_ai_code_defect_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert {case["id"] for case in cases} == {
        "hallucinated-reference",
        "incomplete-generation",
        "dependency-version-hallucination",
    }
    labels = set()
    for case in cases:
        for label in case["taxonomy"]:
            labels.add(label)
    assert labels <= set(AI_CODE_DEFECT_TAXONOMY)


def test_ai_code_defect_runner_scores_expectations(monkeypatch):
    seen = []

    def fake_verify(case_path, **kwargs):
        seen.append((Path(case_path).name, kwargs))
        if "hallucinated_reference" in str(case_path):
            return {
                "findings": [
                    {
                        "rule_id": "SKY-L012",
                        "vibe_category": "hallucinated_reference",
                    }
                ]
            }
        if "incomplete_generation" in str(case_path):
            return {
                "findings": [
                    {
                        "rule_id": "SKY-L026",
                        "vibe_category": "incomplete_generation",
                    }
                ]
            }
        return {
            "findings": [
                {
                    "rule_id": "SKY-D225",
                    "vibe_category": "dependency_hallucination",
                }
            ]
        }

    ticks = iter([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7])
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(MANIFEST_PATH, verify_func=fake_verify)

    assert summary["case_count"] == 3
    assert summary["pass_count"] == 3
    assert summary["failure_count"] == 0
    assert summary["scores"]["overall_score"] == pytest.approx(100.0)
    assert seen[2][1]["include_dependency_hallucinations"] is True


def test_ai_code_defect_runner_empty_selection_runs_all_cases(monkeypatch):
    seen = []

    def fake_verify(case_path, **_kwargs):
        seen.append(Path(case_path).name)
        return {
            "findings": [
                {
                    "rule_id": "SKY-L012",
                    "vibe_category": "hallucinated_reference",
                },
                {
                    "rule_id": "SKY-L026",
                    "vibe_category": "incomplete_generation",
                },
                {
                    "rule_id": "SKY-D225",
                    "vibe_category": "dependency_hallucination",
                },
            ]
        }

    summary = run_manifest(MANIFEST_PATH, selected_cases=None, verify_func=fake_verify)

    assert summary["case_count"] == 3
    assert seen == [
        "hallucinated_reference",
        "incomplete_generation",
        "dependency_version_hallucination",
    ]


def test_ai_code_defect_runner_seeds_dependency_status_cache():
    cache_payloads = []
    prepared_paths = []

    def fake_verify(case_path, **_kwargs):
        prepared_path = Path(case_path)
        prepared_paths.append(prepared_path)
        cache_path = prepared_path / ".skylos" / "cache" / "dependency_versions.json"
        cache_payloads.append(json.loads(cache_path.read_text(encoding="utf-8")))
        return {
            "findings": [
                {
                    "rule_id": "SKY-D225",
                    "vibe_category": "dependency_hallucination",
                }
            ]
        }

    summary = run_manifest(
        MANIFEST_PATH,
        selected_cases={"dependency-version-hallucination"},
        verify_func=fake_verify,
    )

    assert summary["case_count"] == 1
    assert summary["pass_count"] == 1
    assert cache_payloads[0]["schema_version"] == 1
    assert cache_payloads[0]["statuses"] == {
        "npm:left-pad:99.99.99": "missing_version"
    }
    assert not prepared_paths[0].exists()


def test_ai_code_defect_runner_reports_missing_expectation(monkeypatch):
    def fake_verify(_case_path, **_kwargs):
        return {"findings": []}

    summary = run_manifest(
        MANIFEST_PATH,
        selected_cases={"hallucinated-reference"},
        verify_func=fake_verify,
    )

    assert summary["case_count"] == 1
    assert summary["failure_count"] == 1
    assert summary["cases"][0]["failures"][0]["mode"] == "present"


def test_format_summary_includes_case_statuses():
    summary = {
        "pass_count": 1,
        "failure_count": 1,
        "scores": {
            "overall_score": 75.0,
            "recall": 0.5,
            "absence_guard": 1.0,
        },
        "cases": [
            {"id": "good", "failures": []},
            {"id": "bad", "failures": [{"failure_type": "expectation"}]},
        ],
    }

    rendered = format_summary(summary)

    assert "AI-code defect benchmark score: 75.0/100" in rendered
    assert "- good: PASS" in rendered
    assert "- bad: FAIL" in rendered


def test_validate_manifest_rejects_unknown_taxonomy(tmp_path):
    fixture = tmp_path / "case.py"
    fixture.write_text("pass\n", encoding="utf-8")
    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-taxonomy",
                "path": "case.py",
                "taxonomy": ["unknown"],
                "importance": "high",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                },
                "expect": {
                    "present": [{"rule_id": "SKY-L012"}],
                    "absent": [],
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown taxonomy"):
        validate_manifest(load_manifest(manifest_path), manifest_path)
