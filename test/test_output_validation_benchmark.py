from collections import Counter
from pathlib import Path

import pytest

from benchmarks.output_validation import benchmark


MANIFEST = (
    Path(__file__).resolve().parents[1] / "benchmarks/output_validation/manifest.json"
)


def test_checked_in_manifest_has_source_anchored_labels():
    cases = benchmark.validate_manifest(benchmark.load_manifest(MANIFEST), MANIFEST)
    paths = [path for case in cases for path in case["paths"]]

    assert len(cases) == 20
    assert len(paths) == 22
    assert Counter(path["label"] for path in paths) == {
        "safe": 8,
        "unsafe": 13,
        "unknown": 1,
    }
    assert Counter(case["cohort"] for case in cases) == {
        "pilot": 13,
        "adversarial": 7,
    }
    assert all(path["source_location"].startswith("app.py:") for path in paths)
    assert all(path["use_location"].startswith("app.py:") for path in paths)


def test_score_keeps_false_passes_alarms_unknowns_and_misses_distinct():
    rows = [
        {"label": "unsafe", "candidate": {"prediction": "safe"}},
        {"label": "safe", "candidate": {"prediction": "unsafe"}},
        {"label": "safe", "candidate": {"prediction": "unknown"}},
        {"label": "unsafe", "candidate": {"prediction": "missed"}},
        {"label": "unsafe", "candidate": {"prediction": "unsafe"}},
        {"label": "unknown", "candidate": {"prediction": "unknown"}},
        {"label": "unknown", "candidate": {"prediction": "safe"}},
    ]

    counts = benchmark._score(rows, "candidate")

    assert counts["false_passes"] == 1
    assert counts["false_alarms"] == 1
    assert counts["unknown_on_known"] == 1
    assert counts["discovery_misses"] == 1
    assert counts["correct_known"] == 1
    assert counts["unknown_label_reported"] == 1
    assert counts["unknown_overclaims"] == 1
    assert counts["known_total"] == 5


def test_manifest_rejects_a_path_without_a_source_anchor(tmp_path):
    fixture = tmp_path / "fixtures" / "case"
    fixture.mkdir(parents=True)
    (fixture / "app.py").write_text(
        "def answer():\n    return None  # ov-use: result\n", encoding="utf-8"
    )
    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-anchor",
                "fixture": "fixtures/case",
                "paths": [
                    {
                        "id": "response-to-result",
                        "call": "response",
                        "use": "result",
                        "label": "unsafe",
                        "reason": "The source marker is absent.",
                    }
                ],
            }
        ],
    }

    with pytest.raises(ValueError, match="Missing call/use marker"):
        benchmark.validate_manifest(manifest, tmp_path / "manifest.json")


def test_static_runner_can_scan_missing_external_helper():
    summary = benchmark.run_manifest(MANIFEST, case_id="external-validator")

    assert summary["case_count"] == 1
    assert summary["path_count"] == 1
    assert summary["baseline"]["discovery_misses"] == 0
    assert summary["candidate"]["discovery_misses"] == 0
    assert summary["paths"][0]["label"] == "unknown"


def test_baseline_exposes_function_scoped_false_passes():
    summary = benchmark.run_manifest(MANIFEST, cohort="pilot")

    assert summary["baseline"]["false_passes"] == 7
    assert summary["baseline"]["false_alarms"] == 0
    assert summary["baseline"]["discovery_misses"] == 0
    assert summary["scan_elapsed_seconds"] >= 0


def test_flow_verdict_fixes_false_passes_and_keeps_clean_paths():
    summary = benchmark.run_manifest(MANIFEST, cohort="pilot")
    candidate = summary["candidate"]

    assert candidate["correct_known"] == candidate["known_total"] == 13
    assert candidate["false_passes"] == 0
    assert candidate["false_alarms"] == 0
    assert candidate["unknown_on_known"] == 0
    assert candidate["discovery_misses"] == 0
    assert candidate["unknown_label_reported"] == candidate["unknown_label_total"] == 1
    assert summary["evidence_alignment"]["both_match"] == summary["path_count"] == 14
    assert summary["defense_mismatches"] == 0


def test_adversarial_cohort_has_no_false_pass_and_limits_unknowns():
    summary = benchmark.run_manifest(MANIFEST, cohort="adversarial")
    candidate = summary["candidate"]

    assert summary["case_count"] == 7
    assert summary["path_count"] == 8
    assert summary["baseline"]["false_passes"] == 2
    assert candidate["false_passes"] == 0
    assert candidate["false_alarms"] == 0
    assert candidate["discovery_misses"] == 0
    assert candidate["unknown_on_known"] <= 1
    assert candidate["correct_known"] >= 7
    assert candidate["safe_total"] == 3
    assert candidate["safe_retention"] == 1.0
    assert summary["evidence_alignment"]["both_match"] == 8
    assert summary["defense_mismatches"] == 0

    parsed_get = next(
        path for path in summary["paths"] if path["case"] == "parsed-get-answer"
    )
    assert parsed_get["label"] == "safe"
    assert parsed_get["candidate"]["prediction"] == "safe"
