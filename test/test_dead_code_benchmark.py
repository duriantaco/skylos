import json
import subprocess
from pathlib import Path

import skylos.dead_code_benchmark as benchmark
from skylos.analyzer import analyze
from skylos.dead_code_benchmark import (
    DEAD_CODE_TAXONOMY,
    format_summary,
    load_external_targets,
    load_manifest,
    run_manifest,
    validate_external_targets,
    validate_manifest,
)


MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent / "benchmarks/dead_code" / "manifest.json"
)
EXTERNAL_TARGETS_PATH = (
    Path(__file__).resolve().parent.parent
    / "benchmarks/dead_code"
    / "external_targets.json"
)


def test_checked_in_dead_code_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert len(cases) >= 3
    assert {case["id"] for case in cases} >= {
        "basic-unused-symbols",
        "fastapi-route-used",
        "dynamic-registry-used",
    }

    labels = {label for case in cases for label in case["taxonomy"]}
    assert labels <= set(DEAD_CODE_TAXONOMY)


def test_checked_in_external_targets_validate():
    manifest = load_external_targets(EXTERNAL_TARGETS_PATH)
    targets = validate_external_targets(manifest, EXTERNAL_TARGETS_PATH)

    assert {target["id"] for target in targets} >= {"skylos-demo"}
    labels = {label for target in targets for label in target["taxonomy"]}
    assert labels <= set(DEAD_CODE_TAXONOMY)


def test_checked_in_dead_code_benchmark_passes():
    summary = run_manifest(MANIFEST_PATH)

    assert summary["case_count"] >= 3
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
                "id": "bad-dead-code-case",
                "path": "case",
                "description": "Synthetic dead-code benchmark failure case.",
                "taxonomy": ["basic_detection", "precision_guard"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "Test-only fixture.",
                },
                "expect": {
                    "unused": [
                        {"kind": "function", "file": "app.py", "symbol": "missing"}
                    ],
                    "used": [
                        {"kind": "function", "file": "app.py", "symbol": "used"}
                    ],
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(
        benchmark,
        "_scan_case",
        lambda case_path, case: {
            "unused_functions": [
                {"file": str(case_path / "app.py"), "simple_name": "used"}
            ]
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
    assert {failure["mode"] for failure in failures} == {"unused", "used"}


def test_format_summary_includes_dead_code_metrics():
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
            "basic_detection": {
                "description": DEAD_CODE_TAXONOMY["basic_detection"],
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
                "id": "basic-unused-symbols",
                "importance": "critical",
                "elapsed_seconds": 0.25,
                "scores": {"overall_score": 100.0},
                "true_positives": 1,
                "false_positives": 0,
                "false_negatives": 0,
                "true_negatives": 1,
                "unlabeled_finding_count": 0,
                "unlabeled_findings": [],
                "failures": [],
            }
        ],
    }

    rendered = format_summary(summary)

    assert "Dead-code benchmark counts: TP=1 FP=0 FN=0 TN=1" in rendered
    assert "Dead-code benchmark metrics: precision=1.0 recall=1.0 f1=1.0" in rendered
    assert "basic_detection: cases=1 score=100.0 failures=0 TP=1 FP=0 FN=0 TN=1" in rendered


def test_vulture_scanner_scores_against_manifest(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "app.py").write_text(
        "def unused_helper():\n    return 1\n"
        "def used_helper():\n    return 2\n"
        "RESULT = used_helper()\n",
        encoding="utf-8",
    )
    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "vulture-comparison-case",
                "path": "case",
                "description": "Synthetic competitor scanner benchmark case.",
                "taxonomy": ["basic_detection", "precision_guard"],
                "importance": "critical",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "Test-only fixture.",
                },
                "scan": {"confidence": 0},
                "expect": {
                    "unused": [
                        {
                            "kind": "function",
                            "file": "app.py",
                            "symbol": "unused_helper",
                        }
                    ],
                    "used": [
                        {
                            "kind": "function",
                            "file": "app.py",
                            "symbol": "used_helper",
                        }
                    ],
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr(benchmark.shutil, "which", lambda name: "/usr/bin/vulture")

    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["/usr/bin/vulture", "."]
        return subprocess.CompletedProcess(
            cmd,
            3,
            stdout="app.py:1: unused function 'unused_helper' (60% confidence)\n",
            stderr="",
        )

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)

    summary = run_manifest(manifest_path, scanner="vulture")

    assert summary["scanner"] == "vulture"
    assert summary["failure_count"] == 0, format_summary(summary)
    assert summary["counts"] == {
        "true_positives": 1,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 1,
    }


def test_same_external_import_in_another_file_does_not_rescue_unused_local_import(tmp_path):
    (tmp_path / "unused_import.py").write_text(
        "from datetime import datetime\n", encoding="utf-8"
    )
    (tmp_path / "used_import.py").write_text(
        "from datetime import datetime\n"
        "def now():\n"
        "    return datetime.utcnow()\n",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_imports = {
        (Path(item["file"]).name, item["simple_name"])
        for item in result.get("unused_imports", [])
    }

    assert ("unused_import.py", "datetime") in unused_imports
    assert ("used_import.py", "datetime") not in unused_imports
