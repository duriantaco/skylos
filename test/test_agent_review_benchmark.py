import json
from pathlib import Path

import pytest
import skylos.agent_review_benchmark as benchmark
from skylos.agent_review_benchmark import (
    ALLOWED_SCAN_ISSUE_TYPES,
    AGENT_REVIEW_TAXONOMY,
    SECURITY_BENCHMARK_CLASSES,
    format_summary,
    load_manifest,
    prepare_case_scan,
    run_manifest,
    validate_manifest,
)
from skylos.llm.schemas import AnalysisResult


MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent / "agent_review_benchmarks" / "manifest.json"
)


def test_checked_in_agent_review_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert len(cases) >= 24
    assert {case["id"] for case in cases} >= {
        "complexity-hotspot",
        "inconsistent-return",
        "empty-error-handler",
        "clean-module",
        "cross-file-sql-injection",
        "flask-handler-security",
        "flask-getter-shell",
        "flask-ssrf",
        "flask-path-traversal",
        "flask-upload-traversal",
        "jwt-insecure-decode",
        "fastapi-query-ssrf",
        "flask-open-redirect",
        "flask-reflected-xss",
        "flask-pickle-deserialization",
        "flask-archive-extraction",
        "debt-hotspot-service",
        "repo-clean-service",
    }

    labels = {label for case in cases for label in case["taxonomy"]}
    assert labels <= set(AGENT_REVIEW_TAXONOMY)
    security_labels = {
        label
        for case in cases
        for label in case.get("security_classes", [])
    }
    assert security_labels <= set(SECURITY_BENCHMARK_CLASSES)
    assert security_labels >= {
        "sql_injection",
        "command_injection",
        "ssrf",
        "path_traversal",
        "file_upload",
        "auth_bypass",
        "open_redirect",
        "xss",
        "deserialization",
        "archive_extraction",
    }


def test_agent_review_runner_reports_symbol_and_budget_failures(tmp_path, monkeypatch):
    fixture = tmp_path / "fixture.py"
    fixture.write_text("def demo():\n    return 1\n", encoding="utf-8")

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-agent-case",
                "path": "fixture.py",
                "taxonomy": ["control_flow"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "test only",
                },
                "budget": {"max_seconds": 0.5},
                "expect": {"present": {"quality": ["demo"]}, "absent": {}},
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(
        benchmark,
        "_scan_case",
        lambda case_path, model, api_key, provider, base_url, case=None: {
            "finding_count": 0,
            "symbols": [],
            "summary": "No issues found",
            "tokens_used": 17,
        },
    )

    ticks = iter([0.0, 1.0])
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(manifest_path, model="gpt-4.1", api_key="KEY")

    assert summary["failure_count"] == 2
    assert summary["total_tokens_used"] == 17
    failures = summary["cases"][0]["failures"]
    assert {failure["failure_type"] for failure in failures} == {
        "expectation",
        "budget",
    }


def test_format_summary_includes_agent_metrics():
    summary = {
        "case_count": 1,
        "pass_count": 1,
        "failure_count": 0,
        "model": "gpt-4.1",
        "total_elapsed_seconds": 0.25,
        "scores": {
            "overall_score": 100.0,
            "recall": 1.0,
            "absence_guard": 1.0,
            "latency_score": 1.0,
        },
        "total_tokens_used": 99,
        "avg_tokens_per_case": 99.0,
        "security_scorecard": {
            "sql_injection": {
                "description": SECURITY_BENCHMARK_CLASSES["sql_injection"],
                "case_count": 1,
                "pass_count": 1,
                "failed_case_count": 0,
                "pass_rate": 1.0,
                "weighted_score": 100.0,
            }
        },
        "cases": [
            {
                "id": "empty-error-handler",
                "importance": "critical",
                "security_classes": [],
                "elapsed_seconds": 0.25,
                "scores": {"overall_score": 100.0},
                "tokens_used": 99,
                "symbols": ["parse_payload"],
                "failures": [],
            }
        ],
    }

    rendered = format_summary(summary)

    assert "Agent review benchmark score: 100.0/100" in rendered
    assert "Agent review benchmark model: gpt-4.1" in rendered
    assert "Agent review benchmark total tokens: 99" in rendered
    assert "sql_injection: cases=1 pass=1 fail=0 score=100.0" in rendered
    assert "symbols: parse_payload" in rendered


def test_run_manifest_builds_security_scorecard(tmp_path, monkeypatch):
    first = tmp_path / "pickle_case.py"
    second = tmp_path / "archive_case.py"
    first.write_text("def restore_session():\n    return 1\n", encoding="utf-8")
    second.write_text("def extract_bundle():\n    return 1\n", encoding="utf-8")

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "pickle-case",
                "path": "pickle_case.py",
                "taxonomy": ["security"],
                "security_classes": ["deserialization", "archive_extraction"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "test only",
                },
                "budget": {"max_seconds": 1.0},
                "expect": {"present": {"security": ["restore_session"]}, "absent": {}},
            },
            {
                "id": "archive-case",
                "path": "archive_case.py",
                "taxonomy": ["security"],
                "security_classes": ["archive_extraction"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "test only",
                },
                "budget": {"max_seconds": 1.0},
                "expect": {"present": {"security": ["extract_bundle"]}, "absent": {}},
            },
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(
        benchmark,
        "_scan_case",
        lambda case_path, model, api_key, provider, base_url, case=None: {
            "finding_count": 1 if case["id"] == "pickle-case" else 0,
            "symbols": ["restore_session"] if case["id"] == "pickle-case" else [],
            "summary": "ok",
            "tokens_used": 11,
            "reviewed_files": [str(case_path)],
        },
    )

    ticks = iter([0.0, 0.1, 0.2, 0.3])
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(manifest_path, model="gpt-4.1", api_key="KEY")

    assert summary["pass_count"] == 1
    assert summary["failure_count"] == 1
    assert summary["security_scorecard"]["deserialization"] == {
        "description": SECURITY_BENCHMARK_CLASSES["deserialization"],
        "case_count": 1,
        "pass_count": 1,
        "failed_case_count": 0,
        "pass_rate": 1.0,
        "weighted_score": 100.0,
    }
    assert summary["security_scorecard"]["archive_extraction"] == {
        "description": SECURITY_BENCHMARK_CLASSES["archive_extraction"],
        "case_count": 2,
        "pass_count": 1,
        "failed_case_count": 1,
        "pass_rate": 0.5,
        "weighted_score": 75.0,
    }


def test_precision_guard_allows_expected_positive_findings(tmp_path, monkeypatch):
    fixture = tmp_path / "fixture.py"
    fixture.write_text("def restore_session():\n    return 1\n", encoding="utf-8")

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "mixed-security-case",
                "path": "fixture.py",
                "taxonomy": ["security", "precision_guard"],
                "security_classes": ["deserialization"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "test only",
                },
                "budget": {"max_seconds": 1.0},
                "expect": {
                    "present": {"security": ["restore_session"]},
                    "absent": {"security": ["restore_session_safe"]},
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(
        benchmark,
        "_scan_case",
        lambda case_path, model, api_key, provider, base_url, case=None: {
            "finding_count": 1,
            "symbols": ["restore_session"],
            "summary": "Found 1 issue",
            "tokens_used": 13,
            "reviewed_files": [str(case_path)],
        },
    )

    ticks = iter([0.0, 0.1])
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(manifest_path, model="gpt-4.1", api_key="KEY")

    assert summary["pass_count"] == 1
    assert summary["failure_count"] == 0
    assert summary["cases"][0]["failures"] == []
    assert summary["cases"][0]["scores"]["overall_score"] == 100.0


def test_precision_guard_still_rejects_findings_for_clean_case(tmp_path, monkeypatch):
    fixture = tmp_path / "fixture.py"
    fixture.write_text("def normalize_name():\n    return 'ok'\n", encoding="utf-8")

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "clean-precision-case",
                "path": "fixture.py",
                "taxonomy": ["precision_guard"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "test only",
                },
                "budget": {"max_seconds": 1.0},
                "expect": {
                    "present": {},
                    "absent": {"quality": ["normalize_name"]},
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(
        benchmark,
        "_scan_case",
        lambda case_path, model, api_key, provider, base_url, case=None: {
            "finding_count": 1,
            "symbols": ["normalize_name"],
            "summary": "Found 1 issue",
            "tokens_used": 13,
            "reviewed_files": [str(case_path)],
        },
    )

    ticks = iter([0.0, 0.1])
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(manifest_path, model="gpt-4.1", api_key="KEY")

    assert summary["pass_count"] == 0
    assert summary["failure_count"] == 2
    assert {failure["mode"] for failure in summary["cases"][0]["failures"]} == {
        "absent",
        "precision_guard",
    }
def test_prepare_case_scan_directory_selects_repo_files(tmp_path):
    proj = tmp_path / "case"
    tests = proj / "tests"
    proj.mkdir()
    tests.mkdir()

    app = proj / "app.py"
    service = proj / "service.py"
    misc = proj / "misc.py"
    test_service = tests / "test_service.py"

    app.write_text("from service import handle\n", encoding="utf-8")
    service.write_text(
        "def handle(flag, mode, retries=0, emit_metrics=False, include_pending=False):\n"
        "    if flag:\n"
        "        return 1\n"
        "    if mode == 'slow':\n"
        "        return 2\n"
        "    if retries:\n"
        "        return 3\n"
        "    if emit_metrics:\n"
        "        return 4\n"
        "    if include_pending:\n"
        "        return 5\n"
        "    return 0\n",
        encoding="utf-8",
    )
    misc.write_text("VALUE = 1\n", encoding="utf-8")
    test_service.write_text(
        "from service import handle\n\n"
        "def test_handle():\n"
        "    assert handle(True, 'fast') == 1\n",
        encoding="utf-8",
    )

    prepared = prepare_case_scan(proj, max_files=3)

    reviewed = {Path(path).name for path in prepared["files"]}
    assert "app.py" in reviewed
    assert "service.py" in reviewed
    assert prepared["full_file_review"] is True
    assert str(service.resolve()) in prepared["repo_context_map"]


def test_scan_case_passes_issue_types_into_analyzer(tmp_path, monkeypatch):
    fixture = tmp_path / "app.py"
    fixture.write_text("def run_tool():\n    return 1\n", encoding="utf-8")

    monkeypatch.setattr(
        benchmark,
        "prepare_case_scan",
        lambda case_path, max_files=benchmark.DEFAULT_SCAN_MAX_FILES: {
            "project_root": tmp_path,
            "files": [fixture],
            "repo_context_map": {},
            "full_file_review": True,
        },
    )

    seen: dict[str, object] = {}

    class FakeAnalyzer:
        def __init__(self, config):
            seen["config"] = config

        def analyze_files(self, files, defs_map=None, static_findings=None, issue_types=None):
            seen["files"] = list(files)
            seen["issue_types"] = list(issue_types or [])
            return AnalysisResult(findings=[], summary="No issues found", tokens_used=0)

    monkeypatch.setattr(benchmark, "SkylosLLM", FakeAnalyzer)

    result = benchmark._scan_case(
        fixture,
        model="gpt-4.1",
        api_key="KEY",
        provider=None,
        base_url=None,
        case={"scan": {"issue_types": ["security_audit"]}},
    )

    assert result["finding_count"] == 0
    assert seen["files"] == [fixture]
    assert seen["issue_types"] == ["security_audit"]


def test_validate_manifest_rejects_unknown_scan_issue_type(tmp_path):
    fixture = tmp_path / "fixture.py"
    fixture.write_text("def demo():\n    return 1\n", encoding="utf-8")

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-scan-mode",
                "path": "fixture.py",
                "taxonomy": ["security"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "test only",
                },
                "scan": {"issue_types": ["security_audit", "not_a_mode"]},
                "expect": {"present": {}, "absent": {}},
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        validate_manifest(load_manifest(manifest_path), manifest_path)

    assert "unsupported scan.issue_types value" in str(exc.value)
    for allowed in ALLOWED_SCAN_ISSUE_TYPES:
        assert allowed in str(exc.value)


def test_validate_manifest_rejects_unknown_security_class(tmp_path):
    fixture = tmp_path / "fixture.py"
    fixture.write_text("def demo(user_input):\n    return user_input\n", encoding="utf-8")

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-security-class",
                "path": "fixture.py",
                "taxonomy": ["security"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "test only",
                },
                "security_classes": ["not_a_class"],
                "expect": {"present": {"security": ["demo"]}, "absent": {}},
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        validate_manifest(load_manifest(manifest_path), manifest_path)

    assert "unknown security class" in str(exc.value)
    for allowed in SECURITY_BENCHMARK_CLASSES:
        assert allowed in str(exc.value)


def test_validate_manifest_requires_security_class_for_positive_security_case(tmp_path):
    fixture = tmp_path / "fixture.py"
    fixture.write_text("def demo(user_input):\n    return user_input\n", encoding="utf-8")

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "missing-security-class",
                "path": "fixture.py",
                "taxonomy": ["security"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "test only",
                },
                "expect": {"present": {"security": ["demo"]}, "absent": {}},
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        validate_manifest(load_manifest(manifest_path), manifest_path)

    assert "must declare security_classes" in str(exc.value)
