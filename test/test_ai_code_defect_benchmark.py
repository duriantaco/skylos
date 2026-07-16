from __future__ import annotations

import json
from pathlib import Path

import pytest

import skylos.benchmarks.ai_code_defects as benchmark
from skylos.benchmarks.ai_code_defects import (
    AI_CODE_DEFECT_TAXONOMY,
    BENCHMARK_LANGUAGES,
    format_summary,
    load_manifest,
    run_manifest,
    validate_manifest,
)
from skylos.verify_change import verify_change_path


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
    "bad-test-expected-broadening",
    "clean-test-expected-change",
    "incomplete-generation",
    "unfinished-generated-class",
    "api-signature-hallucination",
    "api-keyword-hallucination",
    "dependency-package-hallucination",
    "compound-ai-failure-edit",
    "compound-api-range-scope",
    "repo-level-security-regression",
    "slopsquat-dependency",
    "disabled-security-control",
    "missing-auth-route",
    "clean-auth-route",
    "async-swallowed-error",
    "clean-async-error-handling",
    "clean-repo-level-security",
    "dependency-version-hallucination",
    "go-module-version-hallucination",
    "mixed-manifest-hallucinations",
    "nested-manifest-workspace",
    "contract-phantom-helper",
    "contract-route-guard-missing",
    "contract-route-guard-clean",
    "contract-dependency-manifest",
    "contract-dependency-clean",
    "clean-dependency-manifest",
    "clean-api-signature",
    "clean-dynamic-api-surface",
    "clean-range-scope",
    "typescript-local-api-hallucination",
    "clean-typescript-local-api-surface",
    "go-local-api-hallucination",
    "clean-go-local-api-surface",
    "java-local-api-hallucination",
    "clean-java-local-api-surface",
    "clean-generated-code",
}


EXPECTED_CASE_PATH_NAMES = [
    "hallucinated_reference",
    "repo_local_phantom_reference",
    "multiple_phantom_references",
    "range_scoped_mixed_edit",
    "file_scoped_multi_module",
    "assertion_weakening",
    "bad_test_expected_broadening",
    "clean_test_expected_change",
    "incomplete_generation",
    "unfinished_generated_class",
    "api_signature_hallucination",
    "api_keyword_hallucination",
    "dependency_package_hallucination",
    "compound_ai_failure_edit",
    "compound_ai_failure_edit",
    "dependency_version_hallucination",
    "repo_level_security_regression",
    "slopsquat_dependency",
    "disabled_security_control",
    "missing_auth_route",
    "clean_auth_route",
    "async_swallowed_error",
    "clean_async_error_handling",
    "clean_repo_level_security",
    "go_module_version_hallucination",
    "mixed_manifest_hallucinations",
    "nested_manifest_workspace",
    "contract_phantom_helper",
    "contract_route_guard_missing",
    "contract_route_guard_clean",
    "contract_dependency_manifest",
    "contract_dependency_clean",
    "clean_dependency_manifest",
    "clean_api_signature",
    "clean_dynamic_api_surface",
    "range_scoped_mixed_edit",
    "typescript_local_api_hallucination",
    "clean_typescript_local_api_surface",
    "go_local_api_hallucination",
    "clean_go_local_api_surface",
    "java_local_api_hallucination",
    "clean_java_local_api_surface",
    "clean_generated_code",
]


@pytest.mark.parametrize(
    ("fixture", "expected_status", "check_id", "expected_outcome"),
    [
        (
            "go_local_api_hallucination",
            "fail",
            "go_workspace_api_surface",
            "fail",
        ),
        (
            "clean_go_local_api_surface",
            "pass",
            "go_workspace_api_surface",
            "pass",
        ),
        (
            "java_local_api_hallucination",
            "fail",
            "java_workspace_api_surface",
            "fail",
        ),
        (
            "clean_java_local_api_surface",
            "pass",
            "java_workspace_api_surface",
            "pass",
        ),
    ],
)
def test_checked_in_local_api_benchmarks_assert_verification_contract(
    monkeypatch,
    fixture,
    expected_status,
    check_id,
    expected_outcome,
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    payload = verify_change_path(
        MANIFEST_PATH.parent / "fixtures" / fixture,
        project_context=True,
        include_dependency_hallucinations=False,
    )

    assert payload["status"] == expected_status
    assert payload["coverage"]["state"] == "complete"
    check = next(
        item for item in payload["coverage"]["checks"] if item["id"] == check_id
    )
    assert check["outcome"] == expected_outcome
    assert check["finding_count"] == (1 if expected_outcome == "fail" else 0)


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
    contract_clause=None,
    metadata=None,
):
    finding = {
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
    if contract_clause is not None:
        finding["contract_clause"] = contract_clause
    if metadata is not None:
        finding["metadata"] = metadata
    return finding


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
    if case_name == "bad_test_expected_broadening":
        return [
            _finding(
                "SKY-A101",
                "assertion_weakening",
                message="Specific expected value was replaced with a broad matcher",
                file_path="tests/test_auth.py",
                start_line=9,
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
                metadata={
                    "dependency_truth_state": "missing_package",
                    "dependency_truth_source": "registry",
                    "dependency_source": "manifest",
                },
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
    if case_name == "repo_level_security_regression":
        return [
            _finding(
                "SKY-D205",
                "",
                message="Untrusted deserialization via pickle.loads",
                start_line=12,
                category="security",
                severity="CRITICAL",
            ),
            _finding(
                "SKY-D211",
                "",
                message="Possible SQL injection: tainted or string-built query.",
                start_line=8,
                category="security",
                severity="CRITICAL",
            ),
        ]
    if case_name == "slopsquat_dependency":
        return [
            _finding(
                "SKY-D222",
                "dependency_hallucination",
                message="Suspicious PyPI dependency reqeusts looks like requests",
                category="ai_defect",
                severity="HIGH",
                metadata={
                    "dependency_truth_state": "suspicious_existing",
                    "dependency_truth_source": "registry+lookalike",
                    "dependency_source": "manifest",
                },
            ),
        ]
    if case_name == "disabled_security_control":
        return [
            _finding(
                "SKY-L011",
                "disabled_security_control",
                message="TLS verification disabled in generated HTTP call.",
                start_line=5,
                severity="HIGH",
                ai_likelihood="medium",
            ),
        ]
    if case_name == "missing_auth_route":
        return [
            _finding(
                "SKY-F102",
                "missing_auth_guard",
                message="Mutating route has no obvious auth or permission guard.",
                start_line=7,
                severity="MEDIUM",
                ai_likelihood="medium",
            ),
        ]
    if case_name == "async_swallowed_error":
        return [
            _finding(
                "SKY-L030",
                "swallowed_error",
                message="Async handler catches broad 'Exception' and swallows it.",
                start_line=4,
                severity="MEDIUM",
                ai_likelihood="medium",
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
    if case_name == "contract_phantom_helper":
        return [
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                message="Call to verify_acme_tenant() is never defined.",
                file_path="app.py",
                category="ai_defect",
                contract_clause="ai.phantom_symbols.names",
            ),
        ]
    if case_name == "contract_route_guard_missing":
        return [
            _finding(
                "SKY-A105",
                "missing_contract_guardrail",
                message="Route is missing @login_required.",
                file_path="apps/api/routes.py",
                category="ai_defect",
                severity="HIGH",
                contract_clause="security.routes.require_any_decorator",
            ),
        ]
    if case_name == "contract_route_guard_clean":
        return []
    if case_name == "contract_dependency_manifest":
        return [
            _finding(
                "SKY-D222",
                "dependency_hallucination",
                message="Hallucinated npm dependency skylos-contract-ghost-sdk",
                file_path="package.json",
                category="ai_defect",
                contract_clause="ai.dependencies.reject_nonexistent_packages",
            ),
            _finding(
                "SKY-D225",
                "dependency_hallucination",
                message="Hallucinated npm dependency version left-pad@99.99.99",
                file_path="package.json",
                category="ai_defect",
                severity="HIGH",
                contract_clause="ai.dependencies.reject_impossible_versions",
            ),
        ]
    if case_name == "contract_dependency_clean":
        return []
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
    if case_name == "typescript_local_api_hallucination":
        return [
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                file_path="src/app.ts",
                metadata={
                    "language": "typescript",
                    "reference_kind": "named_import",
                },
            ),
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                file_path="src/app.ts",
                metadata={
                    "language": "typescript",
                    "reference_kind": "named_import",
                },
            ),
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                file_path="src/app.ts",
                metadata={
                    "language": "typescript",
                    "reference_kind": "namespace_member",
                },
            ),
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                file_path="src/app.ts",
                metadata={
                    "language": "typescript",
                    "reference_kind": "commonjs_destructure",
                },
            ),
        ]
    if case_name == "go_local_api_hallucination":
        return [
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                file_path="cmd/app/main.go",
                metadata={
                    "language": "go",
                    "reference_kind": "package_selector",
                },
            )
        ]
    if case_name == "java_local_api_hallucination":
        return [
            _finding(
                "SKY-L012",
                "hallucinated_reference",
                file_path="src/demo/app/App.java",
                metadata={
                    "language": "java",
                    "reference_kind": "static_member",
                },
            )
        ]
    return []


def _fake_result_for_case(case_path, scan_kwargs=None):
    findings = _fake_findings_for_case(case_path, scan_kwargs)
    contracts = {
        "go_local_api_hallucination": (
            "fail",
            "go_workspace_api_surface",
            "fail",
        ),
        "clean_go_local_api_surface": (
            "pass",
            "go_workspace_api_surface",
            "pass",
        ),
        "java_local_api_hallucination": (
            "fail",
            "java_workspace_api_surface",
            "fail",
        ),
        "clean_java_local_api_surface": (
            "pass",
            "java_workspace_api_surface",
            "pass",
        ),
    }
    contract = contracts.get(Path(case_path).name)
    if contract is None:
        return {"findings": findings}
    status, check_id, outcome = contract
    return {
        "status": status,
        "findings": findings,
        "coverage": {
            "state": "complete",
            "checks": [{"id": check_id, "outcome": outcome}],
        },
    }


def test_checked_in_ai_code_defect_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert {case["id"] for case in cases} == EXPECTED_CASE_IDS
    assert all(case.get("language") in BENCHMARK_LANGUAGES for case in cases)
    labels = set()
    for case in cases:
        for label in case["taxonomy"]:
            labels.add(label)
    assert labels <= set(AI_CODE_DEFECT_TAXONOMY)


def test_ai_code_defect_dependency_status_cache_normalizes_present_alias(tmp_path):
    case_path = tmp_path / "case"
    case_path.mkdir()

    benchmark._write_dependency_status_cache(
        case_path,
        [
            {
                "ecosystem": "npm",
                "name": "realpkg",
                "version": "1.2.3",
                "status": "exists",
            }
        ],
    )

    cache_path = case_path / benchmark.VERSION_CACHE_PATH
    payload = json.loads(cache_path.read_text(encoding="utf-8"))

    assert payload["statuses"] == {"npm:realpkg:1.2.3": "present"}


def test_ai_code_defect_dependency_status_cache_normalizes_package_identity(tmp_path):
    case_path = tmp_path / "case"
    case_path.mkdir()

    benchmark._write_dependency_status_cache(
        case_path,
        [
            {
                "ecosystem": "PyPI",
                "name": "Requests_HTML",
                "version": "1.2.3",
                "status": "missing_package",
            }
        ],
    )

    cache_path = case_path / benchmark.VERSION_CACHE_PATH
    payload = json.loads(cache_path.read_text(encoding="utf-8"))

    assert payload["statuses"] == {"PyPI:requests-html:1.2.3": "missing_package"}


def test_ai_code_defect_runner_scores_expectations(monkeypatch):
    seen = []

    def fake_verify(case_path, **kwargs):
        seen.append((Path(case_path).name, kwargs))
        return _fake_result_for_case(case_path, kwargs)

    ticks = iter(range(100))
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(MANIFEST_PATH, verify_func=fake_verify)

    assert summary["case_count"] == 43
    assert summary["pass_count"] == 43
    assert summary["failure_count"] == 0
    assert summary["scores"]["overall_score"] == pytest.approx(100.0)
    assert summary["metadata"]["languages"]["labelled_cases"] == 43
    assert summary["metadata"]["languages"]["coverage_rate"] == 1.0

    dependency_hallucination_case_names = {
        "api_signature_hallucination",
        "api_keyword_hallucination",
        "dependency_package_hallucination",
        "compound_ai_failure_edit",
        "dependency_version_hallucination",
        "slopsquat_dependency",
        "go_module_version_hallucination",
        "mixed_manifest_hallucinations",
        "nested_manifest_workspace",
        "clean_dependency_manifest",
        "clean_api_signature",
        "clean_dynamic_api_surface",
        "clean_generated_code",
    }
    for case_name, kwargs in seen:
        if case_name not in dependency_hallucination_case_names:
            continue
        assert kwargs["include_dependency_hallucinations"] is True

    security_case_names = {
        "repo_level_security_regression",
        "clean_repo_level_security",
    }
    for case_name, kwargs in seen:
        assert kwargs["include_security_findings"] is (
            case_name in security_case_names
        )

    contract_case_names = {
        "contract_phantom_helper",
        "contract_route_guard_missing",
        "contract_route_guard_clean",
        "contract_dependency_manifest",
        "contract_dependency_clean",
    }
    for case_name, kwargs in seen:
        if case_name not in contract_case_names:
            continue
        assert kwargs["contract_path"] == ".skylos/ai-contract.yml"


def test_ai_code_defect_runner_empty_selection_runs_all_cases(monkeypatch):
    seen = []

    def fake_verify(case_path, **_kwargs):
        seen.append(Path(case_path).name)
        return _fake_result_for_case(case_path, _kwargs)

    summary = run_manifest(MANIFEST_PATH, selected_cases=None, verify_func=fake_verify)

    assert summary["case_count"] == 43
    assert seen == EXPECTED_CASE_PATH_NAMES


def test_ai_code_defect_runner_seeds_dependency_status_cache():
    cache_payloads = []
    prepared_paths = []

    def fake_verify(case_path, **_kwargs):
        prepared_path = Path(case_path)
        prepared_paths.append(prepared_path)
        cache_path = prepared_path / ".skylos" / "cache" / "dependency_versions.json"
        cache_payloads.append(
            json.loads(
                cache_path.read_text(encoding="utf-8")  # skylos: ignore[SKY-D215] benchmark temp fixture path
            )
        )
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


def test_ai_code_defect_runner_isolates_security_cases():
    prepared_paths = []

    def fake_verify(case_path, **kwargs):
        prepared_path = Path(case_path)
        prepared_paths.append(prepared_path)
        assert prepared_path.parent.name.startswith("skylos-ai-defect-")
        assert kwargs["include_security_findings"] is True
        return {"findings": _fake_findings_for_case(case_path, kwargs)}

    summary = run_manifest(
        MANIFEST_PATH,
        selected_cases={"repo-level-security-regression"},
        verify_func=fake_verify,
    )

    assert summary["case_count"] == 1
    assert summary["pass_count"] == 1
    assert prepared_paths
    assert not prepared_paths[0].exists()


def test_ai_code_defect_runner_prepares_git_baseline():
    prepared_paths = []

    def fake_verify(case_path, **kwargs):
        prepared_path = Path(case_path)
        prepared_paths.append(prepared_path)
        assert (prepared_path / ".git").is_dir()
        test_file = prepared_path / "tests" / "test_payments.py"
        current = test_file.read_text(encoding="utf-8")  # skylos: ignore[SKY-D215] benchmark temp fixture path
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


def test_ai_code_defect_runner_enforces_verification_contract():
    def fake_verify(_case_path, **_kwargs):
        return {
            "status": "incomplete",
            "findings": [],
            "coverage": {
                "state": "incomplete",
                "checks": [
                    {
                        "id": "java_workspace_api_surface",
                        "outcome": "incomplete",
                    }
                ],
            },
        }

    summary = run_manifest(
        MANIFEST_PATH,
        selected_cases={"clean-java-local-api-surface"},
        verify_func=fake_verify,
    )

    assert summary["failure_count"] == 1
    modes = {failure["mode"] for failure in summary["cases"][0]["failures"]}
    assert modes == {"check_outcome", "coverage_state", "status"}


def test_ai_code_defect_runner_matches_metadata_expectations(monkeypatch, tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                        {
                            "id": "metadata-case",
                            "path": "case",
                            "taxonomy": ["dependency_hallucination"],
                            "importance": "critical",
                            "source": {
                                "repo": "https://example.com/repo",
                                "license": "MIT",
                            },
                            "scan": {},
                        "expect": {
                            "present": [
                                {
                                    "rule_id": "SKY-D222",
                                    "metadata": {
                                        "dependency_truth_state": "missing_package",
                                        "dependency_source": "manifest",
                                    },
                                }
                            ],
                            "absent": [],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    def fake_verify(_case_path, **_kwargs):
        return {
            "findings": [
                _finding(
                    "SKY-D222",
                    "dependency_hallucination",
                    metadata={
                        "dependency_truth_state": "missing_package",
                        "dependency_source": "manifest",
                    },
                )
            ]
        }

    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: 1)

    summary = run_manifest(manifest, verify_func=fake_verify)

    assert summary["pass_count"] == 1
    assert summary["failure_count"] == 0


def test_ai_code_defect_runner_exports_challenge_metadata(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "app.py").write_text(
        "import requests\n"
        "requests.fetch_json('https://example.test')\n",
        encoding="utf-8",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "id": "challenge-case",
                        "path": "case",
                        "taxonomy": ["api_signature_hallucination"],
                        "importance": "high",
                        "source": {
                            "repo": "https://example.com/repo",
                            "license": "MIT",
                        },
                        "scan": {},
                        "expect": {
                            "present": [{"rule_id": "SKY-D224"}],
                            "absent": [],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def fake_verify(_case_path, **_kwargs):
        return {
            "findings": [
                _finding(
                    "SKY-D224",
                    "api_signature_hallucination",
                    message=(
                        "Installed package 'requests' does not expose "
                        "requests.fetch_json"
                    ),
                    file_path="app.py",
                    start_line=2,
                    category="ai_defect",
                    severity="HIGH",
                )
            ]
        }

    def challenge(probes, prompt):
        assert len(probes) == 1
        assert "Use this Chain-of-Verification" in prompt
        return {
            "decisions": [
                {
                    "id": 1,
                    "verdict": "ACCEPTED",
                    "reason": "deterministic finding remains supported",
                    "static_proof": "",
                    "proof_kind": "",
                    "proof_lines": [],
                }
            ]
        }

    summary = run_manifest(manifest, verify_func=fake_verify, challenge_func=challenge)

    assert summary["pass_count"] == 1
    case_challenge = summary["cases"][0]["metadata"]["challenge"]
    assert case_challenge["deterministic_findings_retained"] is True
    assert case_challenge["outcome_counts"]["accepted"] == 1
    assert summary["metadata"]["challenge"]["outcome_counts"]["accepted"] == 1


def test_ai_code_defect_runner_records_external_comparison_request_without_runner(
    tmp_path,
):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "id": "comparison-case",
                        "path": "case",
                        "taxonomy": ["dependency_hallucination"],
                        "importance": "high",
                        "source": {
                            "repo": "https://example.com/repo",
                            "license": "MIT",
                        },
                        "scan": {},
                        "expect": {
                            "present": [],
                            "absent": [{"rule_id": "SKY-D222"}],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def fake_verify(_case_path, **_kwargs):
        return {"findings": []}

    summary = run_manifest(
        manifest,
        verify_func=fake_verify,
        comparison_tools=["semgrep"],
    )

    case_comparison = summary["cases"][0]["metadata"]["external_comparisons"]
    top_comparison = summary["metadata"]["external_comparisons"]
    assert case_comparison["requested_tools"] == ["semgrep"]
    assert case_comparison["executed"] is False
    assert case_comparison["reason"] == "no_comparison_runner"
    assert case_comparison["results"] == []
    assert top_comparison["requested_tools"] == ["semgrep"]
    assert top_comparison["executed_case_count"] == 0
    assert top_comparison["skipped_case_count"] == 1


def test_ai_code_defect_runner_uses_external_comparison_runner(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "id": "comparison-case",
                        "path": "case",
                        "taxonomy": ["dependency_hallucination"],
                        "importance": "high",
                        "source": {
                            "repo": "https://example.com/repo",
                            "license": "MIT",
                        },
                        "scan": {},
                        "expect": {
                            "present": [],
                            "absent": [{"rule_id": "SKY-D222"}],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    calls = []

    def fake_verify(_case_path, **_kwargs):
        return {"findings": []}

    def compare(tool_name, case_path, case):
        calls.append((tool_name, Path(case_path).name, case["id"]))
        return {
            "finding_count": 0,
            "status": "installed",
            "tool": "spoofed-tool",
        }

    summary = run_manifest(
        manifest,
        verify_func=fake_verify,
        comparison_tools=["semgrep"],
        comparison_func=compare,
    )

    assert calls == [("semgrep", "case", "comparison-case")]
    case_comparison = summary["cases"][0]["metadata"]["external_comparisons"]
    top_comparison = summary["metadata"]["external_comparisons"]
    assert case_comparison["executed"] is True
    assert case_comparison["results"] == [
        {
            "tool": "semgrep",
            "finding_count": 0,
            "status": "installed",
        }
    ]
    assert top_comparison["executed_case_count"] == 1
    assert top_comparison["result_count"] == 1
    assert top_comparison["tool_result_counts"] == {"semgrep": 1}


def test_ai_code_defect_runner_reports_evidence_and_runtime_metrics(
    monkeypatch,
    tmp_path,
):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "id": "metrics-case",
                        "path": "case",
                        "taxonomy": ["dependency_hallucination"],
                        "importance": "high",
                        "source": {
                            "repo": "https://example.com/repo",
                            "license": "MIT",
                        },
                        "scan": {},
                        "expect": {
                            "present": [{"rule_id": "SKY-D222"}],
                            "absent": [],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def fake_verify(_case_path, **_kwargs):
        return {
            "findings": [
                {
                    "rule_id": "SKY-D222",
                    "vibe_category": "dependency_hallucination",
                    "message": "missing package",
                    "range": {
                        "file": "package.json",
                        "start_line": 1,
                        "end_line": 1,
                    },
                    "severity": "HIGH",
                    "category": "ai_defect",
                    "evidence_contract": {
                        "schema_version": 1,
                        "proof_state": "candidate",
                        "sources": ["package.json"],
                        "sinks": [],
                        "symbols": ["ghost@1.0.0"],
                        "traces": ["package.json:1"],
                        "limitations": [],
                    },
                }
            ]
        }

    ticks = iter([10.0, 11.0, 13.0, 15.0])
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(manifest, verify_func=fake_verify)

    evidence = summary["metadata"]["evidence_contracts"]
    runtime = summary["metadata"]["runtime"]
    assert evidence["finding_count"] == 1
    assert evidence["with_contract"] == 1
    assert evidence["coverage_rate"] == 1.0
    assert evidence["proof_states"] == {"candidate": 1}
    assert runtime["case_count"] == 1
    assert runtime["mean_seconds"] == 2.0
    assert summary["cases"][0]["evidence_contracts"]["with_contract"] == 1


def test_ai_code_defect_runtime_metadata_uses_nearest_rank_p95():
    cases = [{"elapsed_seconds": float(index)} for index in range(1, 32)]

    runtime = benchmark._runtime_metadata(cases)

    assert runtime["case_count"] == 31
    assert runtime["p95_seconds"] == 30.0


def test_validate_manifest_rejects_invalid_metadata_expectation(tmp_path):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                        {
                            "id": "bad-metadata",
                            "path": "case",
                            "taxonomy": ["dependency_hallucination"],
                            "importance": "critical",
                            "source": {
                                "repo": "https://example.com/repo",
                                "license": "MIT",
                            },
                            "scan": {},
                        "expect": {
                            "present": [
                                {
                                    "rule_id": "SKY-D222",
                                    "metadata": {"dependency_truth_state": 123},
                                }
                            ],
                            "absent": [],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="metadata.dependency_truth_state"):
        validate_manifest(load_manifest(manifest_path), manifest_path)


def test_format_summary_includes_case_statuses():
    summary = {
        "pass_count": 1,
        "failure_count": 1,
        "scores": {
            "overall_score": 75.0,
            "recall": 0.5,
            "absence_guard": 1.0,
        },
        "metadata": {
            "evidence_contracts": {
                "finding_count": 2,
                "with_contract": 1,
                "coverage_rate": 0.5,
            },
            "runtime": {
                "mean_seconds": 1.25,
                "p95_seconds": 2.5,
            },
            "challenge": {
                "outcome_counts": {
                    "accepted": 1,
                    "refuted": 0,
                    "uncertain": 1,
                }
            },
            "external_comparisons": {
                "requested_tools": ["semgrep"],
                "executed_case_count": 1,
                "result_count": 1,
            },
        },
        "cases": [
            {"id": "good", "failures": []},
            {"id": "bad", "failures": [{"failure_type": "expectation"}]},
        ],
    }

    rendered = format_summary(summary)

    assert "AI-code defect benchmark score: 75.0/100" in rendered
    assert "AI-code defect evidence-contract coverage: 0.50 (1/2)" in rendered
    assert "AI-code defect benchmark runtime: mean 1.25s, p95 2.50s" in rendered
    assert "AI-code defect challenge outcomes: accepted=1, refuted=0, uncertain=1" in rendered
    assert "AI-code defect external comparisons: semgrep, executed cases 1, results 1" in rendered
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


def test_validate_manifest_rejects_non_boolean_dependency_hallucination_flag(
    tmp_path,
):
    fixture = tmp_path / "case.py"
    fixture.write_text("pass\n", encoding="utf-8")
    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-dependency-flag",
                "path": "case.py",
                "taxonomy": ["dependency_hallucination"],
                "importance": "high",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                },
                "scan": {"dependency_hallucinations": "false"},
                "expect": {
                    "present": [{"rule_id": "SKY-D222"}],
                    "absent": [],
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="scan\\.dependency_hallucinations"):
        validate_manifest(load_manifest(manifest_path), manifest_path)
