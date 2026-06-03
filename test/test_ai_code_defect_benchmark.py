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


EXPECTED_CASE_IDS = {
    "hallucinated-reference",
    "repo-local-phantom-reference",
    "multiple-phantom-references",
    "incomplete-generation",
    "unfinished-generated-class",
    "api-signature-hallucination",
    "dependency-package-hallucination",
    "dependency-version-hallucination",
    "go-module-version-hallucination",
    "clean-generated-code",
}


EXPECTED_CASE_PATH_NAMES = [
    "hallucinated_reference",
    "repo_local_phantom_reference",
    "multiple_phantom_references",
    "incomplete_generation",
    "unfinished_generated_class",
    "api_signature_hallucination",
    "dependency_package_hallucination",
    "dependency_version_hallucination",
    "go_module_version_hallucination",
    "clean_generated_code",
]


def _finding(rule_id, vibe_category, *, message="", file_path="app.py"):
    return {
        "rule_id": rule_id,
        "vibe_category": vibe_category,
        "message": message,
        "range": {"file": file_path},
    }


def _fake_findings_for_case(case_path):
    case_name = Path(case_path).name
    if case_name == "hallucinated_reference":
        return [
            _finding("SKY-L012", "hallucinated_reference"),
        ]
    if case_name == "repo_local_phantom_reference":
        return [
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                file_path="app/views.py",
            ),
        ]
    if case_name == "multiple_phantom_references":
        return [
            _finding("SKY-L012", "hallucinated_reference"),
            _finding("SKY-L012", "hallucinated_reference"),
            _finding("SKY-L012", "hallucinated_reference"),
        ]
    if case_name == "incomplete_generation":
        return [
            _finding("SKY-L026", "incomplete_generation"),
        ]
    if case_name == "unfinished_generated_class":
        return [
            _finding("SKY-L026", "incomplete_generation"),
            _finding("SKY-L026", "incomplete_generation"),
            _finding("SKY-L026", "incomplete_generation"),
        ]
    if case_name == "api_signature_hallucination":
        return [
            _finding(
                "SKY-D224",
                "api_signature_hallucination",
                message="Installed package 'requests' does not expose requests.fetch_json",
            ),
            _finding(
                "SKY-D224",
                "api_signature_hallucination",
                message="Installed package 'requests' does not expose requests.open_stream",
            ),
        ]
    if case_name == "dependency_package_hallucination":
        return [
            _finding(
                "SKY-D222",
                "dependency_hallucination",
                message="Hallucinated npm dependency skylos-ai-ghost-sdk",
            ),
        ]
    if case_name == "dependency_version_hallucination":
        return [
            _finding("SKY-D225", "dependency_hallucination"),
        ]
    if case_name == "go_module_version_hallucination":
        return [
            _finding(
                "SKY-D225",
                "dependency_hallucination",
                message="github.com/gin-gonic/gin@99.99.99 does not exist",
            ),
        ]
    return []


def test_checked_in_ai_code_defect_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert {case["id"] for case in cases} == EXPECTED_CASE_IDS
    labels = set()
    for case in cases:
        for label in case["taxonomy"]:
            labels.add(label)
    assert labels <= set(AI_CODE_DEFECT_TAXONOMY)


def test_ai_code_defect_runner_scores_expectations(monkeypatch):
    seen = []

    def fake_verify(case_path, **kwargs):
        seen.append((Path(case_path).name, kwargs))
        return {"findings": _fake_findings_for_case(case_path)}

    ticks = iter(
        [
            0.0,
            0.1,
            0.2,
            0.3,
            0.4,
            0.5,
            0.6,
            0.7,
            0.8,
            0.9,
            1.0,
            1.1,
            1.2,
            1.3,
            1.4,
            1.5,
            1.6,
            1.7,
            1.8,
            1.9,
            2.0,
            2.1,
        ]
    )
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(MANIFEST_PATH, verify_func=fake_verify)

    assert summary["case_count"] == 10
    assert summary["pass_count"] == 10
    assert summary["failure_count"] == 0
    assert summary["scores"]["overall_score"] == pytest.approx(100.0)

    danger_case_names = {
        "api_signature_hallucination",
        "dependency_package_hallucination",
        "dependency_version_hallucination",
        "go_module_version_hallucination",
        "clean_generated_code",
    }
    for case_name, kwargs in seen:
        if case_name not in danger_case_names:
            continue
        assert kwargs["include_dependency_hallucinations"] is True


def test_ai_code_defect_runner_empty_selection_runs_all_cases(monkeypatch):
    seen = []

    def fake_verify(case_path, **_kwargs):
        seen.append(Path(case_path).name)
        return {"findings": _fake_findings_for_case(case_path)}

    summary = run_manifest(MANIFEST_PATH, selected_cases=None, verify_func=fake_verify)

    assert summary["case_count"] == 10
    assert seen == EXPECTED_CASE_PATH_NAMES


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
