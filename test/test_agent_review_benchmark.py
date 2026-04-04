import json
from pathlib import Path

import skylos.agent_review_benchmark as benchmark
from skylos.agent_review_benchmark import (
    AGENT_REVIEW_TAXONOMY,
    format_summary,
    load_manifest,
    prepare_case_scan,
    run_manifest,
    validate_manifest,
)


MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent / "agent_review_benchmarks" / "manifest.json"
)


def test_checked_in_agent_review_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert len(cases) >= 13
    assert {case["id"] for case in cases} >= {
        "complexity-hotspot",
        "inconsistent-return",
        "empty-error-handler",
        "clean-module",
        "cross-file-sql-injection",
        "debt-hotspot-service",
        "repo-clean-service",
    }

    labels = {label for case in cases for label in case["taxonomy"]}
    assert labels <= set(AGENT_REVIEW_TAXONOMY)


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
        "cases": [
            {
                "id": "empty-error-handler",
                "importance": "critical",
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
    assert "symbols: parse_payload" in rendered


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
