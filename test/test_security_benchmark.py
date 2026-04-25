import json
from pathlib import Path

import skylos.security_benchmark as benchmark
from skylos.security_benchmark import (
    SECURITY_TAXONOMY,
    format_summary,
    load_manifest,
    run_manifest,
    validate_manifest,
)


MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent / "benchmarks/security" / "manifest.json"
)


def test_checked_in_security_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert len(cases) >= 6
    assert {case["id"] for case in cases} >= {
        "sql-tainted-param",
        "sql-constant-format",
        "ssrf-tainted-host",
        "ssrf-fixed-host-path",
        "subprocess-alias-shell",
        "yaml-safeloader-positional",
    }

    labels = {label for case in cases for label in case["taxonomy"]}
    assert labels <= set(SECURITY_TAXONOMY)


def test_checked_in_security_benchmark_passes():
    summary = run_manifest(MANIFEST_PATH)

    assert summary["case_count"] >= 6
    assert summary["failure_count"] == 0, format_summary(summary)
    assert summary["counts"]["false_positives"] == 0, format_summary(summary)
    assert summary["counts"]["false_negatives"] == 0, format_summary(summary)
    assert summary["scores"]["precision"] == 1.0, format_summary(summary)
    assert summary["scores"]["recall"] == 1.0, format_summary(summary)


def test_runner_reports_false_positive_and_false_negative(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "app.py").write_text("def demo():\n    return 1\n", encoding="utf-8")

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-security-case",
                "path": "case",
                "description": "Synthetic security benchmark failure case.",
                "taxonomy": ["sql_injection", "precision_guard"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "Test-only fixture.",
                },
                "budget": {"max_seconds": 1.0},
                "expect": {
                    "present": {"danger": ["SKY-D211"]},
                    "absent": {"danger": ["SKY-D216"]},
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
            "danger": [{"rule_id": "SKY-D216", "message": "SSRF"}]
        },
    )

    summary = run_manifest(manifest_path)

    assert summary["failure_count"] == 2
    assert summary["counts"] == {
        "true_positives": 0,
        "false_positives": 1,
        "false_negatives": 1,
        "true_negatives": 0,
    }
    failures = summary["cases"][0]["failures"]
    assert {failure["mode"] for failure in failures} == {"present", "absent"}


def test_format_summary_includes_security_metrics():
    summary = {
        "case_count": 1,
        "failure_count": 0,
        "total_elapsed_seconds": 0.25,
        "counts": {
            "true_positives": 1,
            "false_positives": 0,
            "false_negatives": 0,
            "true_negatives": 1,
        },
        "scores": {
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "absence_guard": 1.0,
            "latency_score": 1.0,
            "overall_score": 100.0,
        },
        "taxonomy": {
            "sql_injection": {
                "description": SECURITY_TAXONOMY["sql_injection"],
                "case_count": 1,
                "weighted_score": 100.0,
                "failure_count": 0,
                "true_positives": 1,
                "false_positives": 0,
                "false_negatives": 0,
                "true_negatives": 1,
            }
        },
        "cases": [
            {
                "id": "sql-tainted-param",
                "importance": "critical",
                "elapsed_seconds": 0.25,
                "scores": {"overall_score": 100.0},
                "true_positives": 1,
                "false_positives": 0,
                "false_negatives": 0,
                "true_negatives": 1,
                "failures": [],
            }
        ],
    }

    rendered = format_summary(summary)

    assert "Security benchmark counts: TP=1 FP=0 FN=0 TN=1" in rendered
    assert "Security benchmark metrics: precision=1.0 recall=1.0 f1=1.0" in rendered
    assert "sql_injection: cases=1 score=100.0 failures=0 TP=1 FP=0 FN=0 TN=1" in rendered
