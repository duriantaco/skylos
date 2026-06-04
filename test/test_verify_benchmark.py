from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "verify_benchmark.py"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("verify_benchmark_script", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verify_benchmark_default_manifest_uses_public_benchmark_name():
    module = _load_script_module()

    assert module.DEFAULT_MANIFEST.name == "manifest.json"
    assert module.DEFAULT_MANIFEST.parent.name == "verify_benchmark"
    assert module.DEFAULT_MANIFEST.exists()


def test_verify_benchmark_tool_environment_defaults_to_single_worker(monkeypatch):
    module = _load_script_module()

    monkeypatch.delenv("SKYLOS_JOBS", raising=False)
    env = module._tool_environment()

    assert env["SKYLOS_JOBS"] == "1"


def test_verify_benchmark_tool_environment_preserves_explicit_worker_count(monkeypatch):
    module = _load_script_module()

    monkeypatch.setenv("SKYLOS_JOBS", "4")
    env = module._tool_environment()

    assert env["SKYLOS_JOBS"] == "4"


def test_verify_benchmark_report_uses_public_script_name():
    module = _load_script_module()
    summary = {
        "name": "Skylos Verify Benchmark v0.1",
        "description": "Neutral-label benchmark.",
        "methodology_sources": [],
        "case_count": 1,
        "passed_count": 1,
        "failed_count": 0,
        "expected_findings": 1,
        "matched_findings": 1,
        "false_negatives": 0,
        "false_positives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "elapsed_seconds": 0.1,
        "cases": [
            {
                "id": "case",
                "passed": True,
                "expected_count": 1,
                "matched_count": 1,
                "finding_count": 1,
                "missed": [],
                "unexpected": [],
                "forbidden": [],
            }
        ],
    }

    rendered = module.format_report(summary)

    assert "# Verify Benchmark Report" in rendered
    assert "python scripts/verify_benchmark.py" in rendered
    assert "skylos-verify-benchmark-report.md" in rendered
    legacy_title = "Verify " + "Blind"
    assert legacy_title not in rendered
