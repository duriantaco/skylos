import json
from pathlib import Path

import skylos.quality_benchmark as benchmark
from skylos.quality_benchmark import (
    QUALITY_TAXONOMY,
    format_summary,
    load_manifest,
    run_manifest,
    validate_manifest,
)


MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent / "quality_benchmarks" / "manifest.json"
)


def test_checked_in_quality_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert len(cases) >= 6
    assert {case["id"] for case in cases} >= {
        "complexity-hotspot",
        "long-function",
        "argument-overload",
        "inconsistent-return",
        "empty-error-handler",
        "clean-module",
    }

    labels = {label for case in cases for label in case["taxonomy"]}
    assert labels <= set(QUALITY_TAXONOMY)


def test_checked_in_quality_benchmark_passes():
    summary = run_manifest(MANIFEST_PATH)

    assert summary["case_count"] >= 6
    assert summary["failure_count"] == 0, format_summary(summary)
    assert summary["scores"]["overall_score"] >= 95.0, format_summary(summary)


def test_runner_reports_present_and_budget_failures(tmp_path, monkeypatch):
    case_dir = tmp_path / "inconsistent_case"
    case_dir.mkdir()
    (case_dir / "demo.py").write_text(
        "def demo(flag):\n    return flag\n", encoding="utf-8"
    )

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-quality-case",
                "path": "inconsistent_case",
                "description": "Synthetic benchmark failure case.",
                "taxonomy": ["control_flow"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "Test-only fixture.",
                },
                "budget": {"max_seconds": 0.5},
                "expect": {
                    "present": {"quality": ["SKY-L006"]},
                    "absent": {},
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(
        benchmark,
        "_scan_case",
        lambda case_path, scan=None: {
            "quality": [],
            "unused_functions": [],
            "unused_imports": [],
        },
    )

    ticks = iter([0.0, 1.0])
    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: next(ticks))

    summary = run_manifest(manifest_path)

    assert summary["failure_count"] == 2
    failures = summary["cases"][0]["failures"]
    assert {failure["failure_type"] for failure in failures} == {
        "expectation",
        "budget",
    }
    assert summary["scores"]["overall_score"] < 50.0


def test_format_summary_includes_taxonomy_and_metrics():
    summary = {
        "case_count": 1,
        "failure_count": 0,
        "total_elapsed_seconds": 0.25,
        "scores": {
            "overall_score": 100.0,
            "presence_recall": 1.0,
            "absence_guard": 1.0,
            "latency_score": 1.0,
        },
        "taxonomy": {
            "complexity": {
                "description": QUALITY_TAXONOMY["complexity"],
                "case_count": 1,
                "weighted_score": 100.0,
                "failure_count": 0,
            }
        },
        "cases": [
            {
                "id": "complexity-hotspot",
                "importance": "critical",
                "elapsed_seconds": 0.25,
                "scores": {"overall_score": 100.0},
                "failures": [],
            }
        ],
    }

    rendered = format_summary(summary)

    assert "Quality benchmark score: 100.0/100" in rendered
    assert "complexity: cases=1 score=100.0 failures=0" in rendered
    assert "PASS complexity-hotspot [critical]" in rendered
