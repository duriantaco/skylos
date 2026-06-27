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
    "range-scoped-mixed-edit",
    "file-scoped-multi-module",
    "assertion-weakening",
    "incomplete-generation",
    "unfinished-generated-class",
    "api-signature-hallucination",
    "api-keyword-hallucination",
    "dependency-package-hallucination",
    "compound-ai-failure-edit",
    "compound-api-range-scope",
    "dependency-version-hallucination",
    "go-module-version-hallucination",
    "mixed-manifest-hallucinations",
    "nested-manifest-workspace",
    "clean-dependency-manifest",
    "clean-api-signature",
    "clean-range-scope",
    "clean-generated-code",
}


EXPECTED_CASE_PATH_NAMES = [
    "hallucinated_reference",
    "repo_local_phantom_reference",
    "multiple_phantom_references",
    "range_scoped_mixed_edit",
    "file_scoped_multi_module",
    "assertion_weakening",
    "incomplete_generation",
    "unfinished_generated_class",
    "api_signature_hallucination",
    "api_keyword_hallucination",
    "dependency_package_hallucination",
    "compound_ai_failure_edit",
    "compound_ai_failure_edit",
    "dependency_version_hallucination",
    "go_module_version_hallucination",
    "mixed_manifest_hallucinations",
    "nested_manifest_workspace",
    "clean_dependency_manifest",
    "clean_api_signature",
    "range_scoped_mixed_edit",
    "clean_generated_code",
]


def _finding(
    rule_id,
    vibe_category,
    *,
    message="",
    file_path="app.py",
    start_line=1,
    category="quality",
    severity="CRITICAL",
    ai_likelihood="high",
):
    return {
        "rule_id": rule_id,
        "vibe_category": vibe_category,
        "ai_likelihood": ai_likelihood,
        "message": message,
        "range": {
            "file": file_path,
            "start_line": start_line,
            "end_line": start_line,
        },
        "severity": severity,
        "category": category,
    }


def _fake_findings_for_case(case_path, scan_kwargs=None):
    if scan_kwargs is None:
        scan_kwargs = {}

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
    if case_name == "range_scoped_mixed_edit":
        if scan_kwargs.get("line_range") == "1:3":
            return []
        return [
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                message="Call to 'sanitize_input()' but this function is never defined.",
                start_line=12,
                category="ai_defect",
            ),
        ]
    if case_name == "file_scoped_multi_module":
        return [
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                message="Call to 'validate_token()' but this function is never defined.",
                file_path="app/routes.py",
                start_line=2,
            ),
        ]
    if case_name == "assertion_weakening":
        return [
            _finding(
                "SKY-A101",
                "assertion_weakening",
                message="Specific assertion was replaced with a broad truthiness/null check",
                file_path="tests/test_payments.py",
                start_line=12,
                category="ai_defect",
                severity="MEDIUM",
                ai_likelihood="medium",
            ),
        ]
    if case_name == "incomplete_generation":
        return [
            _finding(
                "SKY-L026",
                "incomplete_generation",
                severity="MEDIUM",
                ai_likelihood="medium",
            ),
        ]
    if case_name == "unfinished_generated_class":
        return [
            _finding(
                "SKY-L026",
                "incomplete_generation",
                severity="MEDIUM",
                ai_likelihood="medium",
            ),
            _finding(
                "SKY-L026",
                "incomplete_generation",
                severity="MEDIUM",
                ai_likelihood="medium",
            ),
            _finding(
                "SKY-L026",
                "incomplete_generation",
                severity="MEDIUM",
                ai_likelihood="medium",
            ),
        ]
    if case_name == "api_signature_hallucination":
        return [
            _finding(
                "SKY-D224",
                "api_signature_hallucination",
                message="Installed package 'requests' does not expose requests.fetch_json",
                category="ai_defect",
                severity="HIGH",
            ),
            _finding(
                "SKY-D224",
                "api_signature_hallucination",
                message="Installed package 'requests' does not expose requests.open_stream",
                category="ai_defect",
                severity="HIGH",
            ),
        ]
    if case_name == "api_keyword_hallucination":
        return [
            _finding(
                "SKY-D224",
                "api_signature_hallucination",
                message="Installed package 'requests' rejects keyword retry_policy",
                start_line=6,
                category="ai_defect",
                severity="HIGH",
            ),
            _finding(
                "SKY-D224",
                "api_signature_hallucination",
                message="Installed package 'requests' rejects keyword json_body",
                start_line=15,
                category="ai_defect",
                severity="HIGH",
            ),
        ]
    if case_name == "dependency_package_hallucination":
        return [
            _finding(
                "SKY-D222",
                "dependency_hallucination",
                message="Hallucinated npm dependency skylos-ai-ghost-sdk",
                category="ai_defect",
            ),
        ]
    if case_name == "compound_ai_failure_edit":
        is_api_range_scope = scan_kwargs.get("file") == "app.py"
        if scan_kwargs.get("line_range") != "6:8":
            is_api_range_scope = False
        if is_api_range_scope:
            return [
                _finding(
                    "SKY-D224",
                    "api_signature_hallucination",
                    message=(
                        "Installed package 'requests' does not expose "
                        "requests.fetch_json"
                    ),
                    start_line=6,
                    category="ai_defect",
                    severity="HIGH",
                ),
            ]
        return [
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                message="Call to 'validate_token()' but this function is never defined.",
                start_line=5,
            ),
            _finding(
                "SKY-L026",
                "incomplete_generation",
                start_line=14,
                severity="MEDIUM",
                ai_likelihood="medium",
            ),
            _finding(
                "SKY-D224",
                "api_signature_hallucination",
                message="Installed package 'requests' does not expose requests.fetch_json",
                start_line=6,
                category="ai_defect",
                severity="HIGH",
            ),
            _finding(
                "SKY-D222",
                "dependency_hallucination",
                message="Hallucinated npm dependency skylos-compound-ghost-sdk",
                category="ai_defect",
            ),
            _finding(
                "SKY-D225",
                "dependency_hallucination",
                message="Hallucinated npm dependency version left-pad@99.99.99",
                category="ai_defect",
                severity="HIGH",
            ),
        ]
    if case_name == "nested_manifest_workspace":
        return [
            _finding(
                "SKY-D222",
                "dependency_hallucination",
                message="Hallucinated npm dependency skylos-nested-ghost-sdk",
                file_path="packages/api/package.json",
                category="ai_defect",
            ),
            _finding(
                "SKY-D225",
                "dependency_hallucination",
                message="Hallucinated npm dependency version left-pad@99.99.99",
                file_path="packages/api/package.json",
                category="ai_defect",
                severity="HIGH",
            ),
        ]
    if case_name == "dependency_version_hallucination":
        return [
            _finding(
                "SKY-D225",
                "dependency_hallucination",
                category="ai_defect",
                severity="HIGH",
            ),
        ]
    if case_name == "go_module_version_hallucination":
        return [
            _finding(
                "SKY-D225",
                "dependency_hallucination",
                message="github.com/gin-gonic/gin@99.99.99 does not exist",
                category="ai_defect",
                severity="HIGH",
            ),
        ]
    if case_name == "mixed_manifest_hallucinations":
        return [
            _finding(
                "SKY-D222",
                "dependency_hallucination",
                message="Hallucinated npm dependency skylos-enterprise-agent",
                category="ai_defect",
            ),
            _finding(
                "SKY-D225",
                "dependency_hallucination",
                message="Hallucinated npm dependency version left-pad@99.99.99",
                category="ai_defect",
                severity="HIGH",
            ),
            _finding(
                "SKY-D222",
                "dependency_hallucination",
                message="Hallucinated npm dependency skylos-agent-testkit",
                category="ai_defect",
            ),
        ]
    if case_name == "clean_api_signature":
        return []
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
        return {"findings": _fake_findings_for_case(case_path, kwargs)}

    ticks = iter(range(100))
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(MANIFEST_PATH, verify_func=fake_verify)

    assert summary["case_count"] == 21
    assert summary["pass_count"] == 21
    assert summary["failure_count"] == 0
    assert summary["scores"]["overall_score"] == pytest.approx(100.0)

    dependency_hallucination_case_names = {
        "api_signature_hallucination",
        "api_keyword_hallucination",
        "dependency_package_hallucination",
        "compound_ai_failure_edit",
        "dependency_version_hallucination",
        "go_module_version_hallucination",
        "mixed_manifest_hallucinations",
        "nested_manifest_workspace",
        "clean_dependency_manifest",
        "clean_api_signature",
        "clean_generated_code",
    }
    for case_name, kwargs in seen:
        if case_name not in dependency_hallucination_case_names:
            continue
        assert kwargs["include_dependency_hallucinations"] is True


def test_ai_code_defect_runner_empty_selection_runs_all_cases(monkeypatch):
    seen = []

    def fake_verify(case_path, **_kwargs):
        seen.append(Path(case_path).name)
        return {"findings": _fake_findings_for_case(case_path, _kwargs)}

    summary = run_manifest(MANIFEST_PATH, selected_cases=None, verify_func=fake_verify)

    assert summary["case_count"] == 21
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


def test_ai_code_defect_runner_isolates_dependency_hallucination_cases_without_status_cache():
    prepared_paths = []

    def fake_verify(case_path, **_kwargs):
        prepared_path = Path(case_path)
        prepared_paths.append(prepared_path)
        cache_path = prepared_path / ".skylos" / "cache" / "dependency_versions.json"
        assert not cache_path.exists()
        return {"findings": []}

    summary = run_manifest(
        MANIFEST_PATH,
        selected_cases={"clean-api-signature"},
        verify_func=fake_verify,
    )

    assert summary["case_count"] == 1
    assert summary["pass_count"] == 1
    assert prepared_paths
    assert prepared_paths[0].parent.name.startswith("skylos-ai-defect-")
    assert not prepared_paths[0].exists()


def test_ai_code_defect_runner_prepares_git_baseline():
    prepared_paths = []

    def fake_verify(case_path, **kwargs):
        prepared_path = Path(case_path)
        prepared_paths.append(prepared_path)
        assert (prepared_path / ".git").is_dir()
        test_file = prepared_path / "tests" / "test_payments.py"
        current = test_file.read_text(encoding="utf-8")
        assert "assert result is not None" in current
        assert kwargs["file"] == "tests/test_payments.py"
        assert kwargs["include_dependency_hallucinations"] is False
        return {"findings": _fake_findings_for_case(case_path, kwargs)}

    summary = run_manifest(
        MANIFEST_PATH,
        selected_cases={"assertion-weakening"},
        verify_func=fake_verify,
    )

    assert summary["case_count"] == 1
    assert summary["pass_count"] == 1
    assert prepared_paths
    assert prepared_paths[0].parent.name.startswith("skylos-ai-defect-")
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
    failure_modes = set()
    for failure in summary["cases"][0]["failures"]:
        failure_modes.add(failure["mode"])
    assert "present" in failure_modes


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


def test_validate_manifest_rejects_legacy_danger_scan_flag(tmp_path):
    fixture = tmp_path / "case.py"
    fixture.write_text("pass\n", encoding="utf-8")
    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "legacy-danger",
                "path": "case.py",
                "taxonomy": ["dependency_hallucination"],
                "importance": "high",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                },
                "scan": {"danger": True},
                "expect": {
                    "present": [{"rule_id": "SKY-D222"}],
                    "absent": [],
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="scan\\.danger"):
        validate_manifest(load_manifest(manifest_path), manifest_path)
