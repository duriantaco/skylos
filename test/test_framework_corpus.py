import json
from pathlib import Path

import skylos.benchmarks.framework_corpus as framework_corpus
from skylos.benchmarks.framework_corpus import (
    format_summary,
    load_manifest,
    run_manifest,
    validate_manifest,
)


MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent
    / "benchmarks"
    / "framework_corpus"
    / "manifest.json"
)


def _write_manifest(tmp_path, manifest):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def _sample_manifest():
    return {
        "version": 1,
        "targets": [
            {
                "id": "demo",
                "repo": "https://github.com/example/demo",
                "ref": "0123456789abcdef",
                "checkout": "demo",
                "license": "MIT",
                "scan_paths": ["pkg"],
                "baseline": {
                    "counts": {
                        "unused_functions": 1,
                        "unused_imports": 0,
                    },
                    "max_delta": 0,
                },
                "expect": {
                    "present": [
                        {
                            "category": "unused_functions",
                            "file": "pkg/app.py",
                            "symbol": "stale",
                        }
                    ],
                    "absent": [
                        {
                            "category": "unused_functions",
                            "file": "pkg/app.py",
                            "symbol": "live",
                        }
                    ],
                },
            }
        ],
    }


def test_checked_in_framework_corpus_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    targets = validate_manifest(manifest, MANIFEST_PATH)

    assert {target["id"] for target in targets} >= {
        "fastapi",
        "starlette",
        "pydantic",
        "typer",
        "click",
    }


def test_framework_corpus_skips_missing_checkout_by_default(tmp_path):
    manifest_path = _write_manifest(tmp_path, _sample_manifest())

    summary = run_manifest(manifest_path, checkout_root=tmp_path / "checkouts")

    assert summary["target_count"] == 0
    assert summary["skipped_target_count"] == 1
    assert summary["failure_count"] == 0
    assert summary["skipped_targets"][0]["id"] == "demo"


def test_framework_corpus_can_require_checkouts(tmp_path):
    manifest_path = _write_manifest(tmp_path, _sample_manifest())

    summary = run_manifest(
        manifest_path,
        checkout_root=tmp_path / "checkouts",
        require_checkouts=True,
    )

    assert summary["target_count"] == 1
    assert summary["failure_count"] == 1
    assert summary["targets"][0]["status"] == "fail"
    assert "missing_checkout" in format_summary(summary)


def test_framework_corpus_passes_baseline_and_expectations(tmp_path, monkeypatch):
    checkout = tmp_path / "checkouts" / "demo" / "pkg"
    checkout.mkdir(parents=True)
    (checkout / "app.py").write_text("def stale():\n    pass\n", encoding="utf-8")
    manifest_path = _write_manifest(tmp_path, _sample_manifest())

    def fake_scan_target(target, target_path):
        return {
            "unused_functions": [
                {
                    "file": str(target_path / "pkg" / "app.py"),
                    "simple_name": "stale",
                }
            ],
            "unused_imports": [],
        }

    monkeypatch.setattr(framework_corpus, "_scan_target", fake_scan_target)

    summary = run_manifest(manifest_path, checkout_root=tmp_path / "checkouts")

    assert summary["target_count"] == 1
    assert summary["pass_count"] == 1
    assert summary["failure_count"] == 0, format_summary(summary)
    assert summary["targets"][0]["counts"]["unused_functions"] == 1


def test_framework_corpus_reports_count_and_anchor_drift(tmp_path, monkeypatch):
    checkout = tmp_path / "checkouts" / "demo" / "pkg"
    checkout.mkdir(parents=True)
    (checkout / "app.py").write_text("def stale():\n    pass\n", encoding="utf-8")
    manifest = _sample_manifest()
    manifest["targets"][0]["baseline"]["counts"]["unused_functions"] = 0
    manifest["targets"][0]["expect"]["absent"][0]["symbol"] = "stale"
    manifest_path = _write_manifest(tmp_path, manifest)

    def fake_scan_target(target, target_path):
        return {
            "unused_functions": [
                {
                    "file": str(target_path / "pkg" / "app.py"),
                    "simple_name": "stale",
                }
            ]
        }

    monkeypatch.setattr(framework_corpus, "_scan_target", fake_scan_target)

    summary = run_manifest(manifest_path, checkout_root=tmp_path / "checkouts")

    assert summary["target_count"] == 1
    assert summary["failure_count"] == 2
    failure_types = {
        failure["failure_type"]
        for failure in summary["targets"][0]["failures"]
    }
    assert failure_types == {"baseline_count", "expectation"}
