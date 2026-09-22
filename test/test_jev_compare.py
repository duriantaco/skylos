from __future__ import annotations

import copy
import hashlib
import json

import pytest

from skylos.benchmarks._jev_dead_code_dataset import _digest, prepare_batches
from skylos.benchmarks._jev_dead_code_types import JevBenchmarkError
from skylos.benchmarks.jev_compare import compare_jev_to_scanner


def _label(
    label_id: str, expectation: str, category: str, *, symbol: str | None = None
) -> dict:
    return {
        "id": label_id,
        "expectation": expectation,
        "category": category,
        "match": {"path": "module.py", "symbol": symbol or label_id.replace("-", "_")},
    }


def _fixture(tmp_path, *, omit_javascript_neutral: bool = False):
    manifest = {
        "schema_version": "skylos-golden-benchmark/v1",
        "suite": "dead_code",
        "split": "dev",
        "label_state": "frozen",
        "cases": [
            {
                "id": "python-case",
                "languages": ["python"],
                "label_coverage": "closed",
                "source": {"local_path": "fixtures/python"},
                "labels": [
                    _label("corrected", "should_not_report", "live_function"),
                    _label("regressed", "should_report", "unused_function"),
                    _label(
                        "both-correct",
                        "should_report",
                        "unused_function",
                        symbol="unused_both_correct",
                    ),
                    _label("both-wrong", "should_not_report", "live_function"),
                ],
            },
            {
                "id": "javascript-case",
                "languages": ["javascript"],
                "label_coverage": "closed",
                "source": {"local_path": "fixtures/javascript"},
                "labels": [
                    _label(
                        "abstain-right",
                        "should_not_report",
                        "live_variable",
                        symbol=(
                            "abstain_right"
                            if omit_javascript_neutral
                            else "unused_abstain_right"
                        ),
                    ),
                    _label("abstain-wrong", "should_not_report", "live_variable"),
                ],
            },
        ],
    }
    path = tmp_path / "manifests" / "manifest.json"
    path.parent.mkdir()
    raw = json.dumps(manifest)
    path.write_text(raw, encoding="utf-8")
    for case in manifest["cases"]:
        source = tmp_path / case["source"]["local_path"]
        source.mkdir(parents=True)
        content = "\n".join(
            f"def {label['match']['symbol']}():\n    pass\n" for label in case["labels"]
        )
        (source / "module.py").write_text(content, encoding="utf-8")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    scanner = {
        "suite": "dead_code",
        "split": "dev",
        "label_state": "frozen",
        "tool": "skylos",
        "ok": True,
        "case_count": 2,
        "skipped_case_count": 0,
        "skipped_cases": [],
        "cases": [
            {
                "case_id": case["id"],
                "languages": case["languages"],
                "unlabeled_finding_count": 2 if case["id"] == "python-case" else 0,
                "labels": [
                    {
                        "label_id": label["id"],
                        "expectation": label["expectation"],
                        "matched": label["id"]
                        in {
                            "corrected",
                            "regressed",
                            "both-correct",
                            "both-wrong",
                            "abstain-wrong",
                        },
                    }
                    for label in case["labels"]
                ],
            }
            for case in manifest["cases"]
        ],
    }
    predicted = {
        "corrected": ("used", 0.9),
        "regressed": ("used", 0.9),
        "both-correct": ("unused", 0.8),
        "both-wrong": ("unused", 0.9),
        "abstain-right": ("used", 0.79),
        "abstain-wrong": ("abstain", 0.9),
    }
    planned = prepare_batches(path)
    batches = []
    for batch in planned:
        predictions = []
        for question in batch.questions:
            decision, confidence = predicted[question.label_id]
            predictions.append(
                {
                    "label_id": question.label_id,
                    "case_id": batch.case_id,
                    "arm": batch.arm,
                    "expected": question.expected,
                    "predicted": decision,
                    "confidence": confidence,
                    "target": {
                        "file": question.file,
                        "symbol": question.symbol,
                        "line": question.line,
                    },
                }
            )
        batches.append(
            {
                "case_id": batch.case_id,
                "arm": batch.arm,
                "status": "ok",
                "request_digest": batch.request_digest,
                "decision_count": len(predictions),
                "predictions": predictions,
            }
        )
    report = {
        "schema_version": 2,
        "benchmark": "jev_dead_code",
        "status": "complete",
        "manifest_digest": digest,
        "manifest_metadata": {
            "format": "skylos-golden-benchmark/v1",
            "split": "dev",
            "label_state": "frozen",
        },
        "planned_request_count": len(batches),
        "completed_request_count": len(batches),
        "planned_requests": [
            {
                "case_id": batch.case_id,
                "arm": batch.arm,
                "request_digest": batch.request_digest,
            }
            for batch in planned
        ],
        "batches": batches,
    }
    report["report_digest"] = _digest(report)
    return path, report, scanner


def _seal(report):
    report["report_digest"] = _digest(
        {key: value for key, value in report.items() if key != "report_digest"}
    )


def test_comparison_joins_labels_and_reports_outcomes(tmp_path):
    path, report, scanner = _fixture(tmp_path)
    result = compare_jev_to_scanner(report, scanner, path)

    counts = result["summary"]["counts"]
    assert counts["labels"] == 6
    assert all(
        counts[outcome] == 1
        for outcome in (
            "jev_corrected_scanner",
            "jev_regressed_scanner",
            "both_correct",
            "both_wrong",
            "jev_abstained_scanner_correct",
            "jev_abstained_scanner_wrong",
        )
    )
    assert counts["scanner_errors"] == 3
    assert counts["jev_decided_errors"] == 2
    assert counts["scanner_unsafe_removals"] == 3
    assert counts["jev_unsafe_removals"] == 1
    assert counts["scanner_unlabeled_findings"] == 2
    assert "frozen labels only" in result["comparison_scope"]
    summary = result["summary"]
    assert summary["confusion"] == {
        "scanner": {
            "true_positives": 2,
            "false_positives": 3,
            "false_negatives": 0,
            "true_negatives": 1,
        },
        "jev_decided": {
            "true_positives": 1,
            "false_positives": 1,
            "false_negatives": 1,
            "true_negatives": 1,
        },
        "jev_abstentions": {"unused": 0, "used": 2},
    }
    assert summary["metric_denominators"] == {
        "scanner": {
            "precision": 5,
            "recall": 2,
            "false_positive_rate": 4,
            "accuracy": 6,
        },
        "jev_decided": {
            "precision": 2,
            "recall": 2,
            "false_positive_rate": 2,
            "accuracy": 4,
            "coverage": 6,
        },
        "jev_all_labels": {"precision": 2, "recall": 2, "false_positive_rate": 4},
    }
    assert summary["metrics"] == {
        "jev_coverage": 0.6667,
        "scanner_accuracy": 0.5,
        "jev_decided_accuracy": 0.5,
        "scanner": {
            "precision": 0.4,
            "recall": 1.0,
            "f1": 0.5714,
            "false_positive_rate": 0.75,
        },
        "jev_decided": {
            "precision": 0.5,
            "recall": 0.5,
            "f1": 0.5,
            "false_positive_rate": 0.5,
        },
        "jev_all_labels": {
            "precision": 0.5,
            "recall": 0.5,
            "f1": 0.5,
            "false_positive_rate": 0.25,
        },
    }
    assert result["by_case"]["python-case"]["counts"]["labels"] == 4
    assert result["by_language"]["javascript"]["counts"]["jev_abstained"] == 2
    assert result["by_category"]["unused_function"]["counts"]["labels"] == 2
    assert result["by_category"]["unused_function"]["confusion"]["jev_decided"] == {
        "true_positives": 1,
        "false_positives": 0,
        "false_negatives": 1,
        "true_negatives": 0,
    }
    assert (
        result["by_category"]["unused_function"]["metrics"]["jev_decided"]["recall"]
        == 0.5
    )
    assert (
        result["by_language"]["javascript"]["metrics"]["jev_decided"]["recall"] is None
    )
    assert [label["label_id"] for label in result["labels"]] == [
        "abstain-right",
        "abstain-wrong",
        "both-correct",
        "both-wrong",
        "corrected",
        "regressed",
    ]


def test_threshold_is_inclusive_and_arm_is_selectable(tmp_path):
    path, report, scanner = _fixture(tmp_path)
    result = compare_jev_to_scanner(
        report, scanner, path, threshold=0.79, arm="neutralized"
    )
    assert result["arm"] == "neutralized"
    assert result["summary"]["counts"]["jev_abstained"] == 1
    result = compare_jev_to_scanner(report, scanner, path, threshold=0.8)
    by_id = {label["label_id"]: label for label in result["labels"]}
    assert by_id["both-correct"]["jev_predicted"] == "unused"
    assert by_id["abstain-right"]["jev_predicted"] == "abstain"


def test_all_label_recall_includes_abstained_unused_labels(tmp_path):
    path, report, scanner = _fixture(tmp_path)
    regressed = next(
        item
        for item in report["batches"][0]["predictions"]
        if item["label_id"] == "regressed"
    )
    regressed["predicted"] = "abstain"
    _seal(report)
    summary = compare_jev_to_scanner(report, scanner, path)["summary"]
    assert summary["confusion"]["jev_abstentions"] == {"unused": 1, "used": 2}
    assert summary["metric_denominators"]["jev_decided"]["recall"] == 1
    assert summary["metric_denominators"]["jev_all_labels"]["recall"] == 2
    assert summary["metrics"]["jev_decided"]["recall"] == 1.0
    assert summary["metrics"]["jev_all_labels"]["recall"] == 0.5


def test_original_comparison_allows_optional_neutralized_arm(tmp_path):
    path, report, scanner = _fixture(tmp_path, omit_javascript_neutral=True)
    assert report["planned_request_count"] == 3
    assert (
        compare_jev_to_scanner(report, scanner, path)["summary"]["counts"]["labels"]
        == 6
    )
    with pytest.raises(JevBenchmarkError, match="neutralized arm is unavailable"):
        compare_jev_to_scanner(report, scanner, path, arm="neutralized")


@pytest.mark.parametrize("threshold", [-0.1, 1.1, float("nan"), True])
def test_invalid_threshold_fails(tmp_path, threshold):
    path, report, scanner = _fixture(tmp_path)
    with pytest.raises(JevBenchmarkError, match="threshold"):
        compare_jev_to_scanner(report, scanner, path, threshold=threshold)


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda report, scanner: report.update(status="incomplete"), "complete"),
        (
            lambda report, scanner: report.update(manifest_digest="wrong"),
            "manifest digest",
        ),
        (
            lambda report, scanner: report["manifest_metadata"].update(split="holdout"),
            "split",
        ),
        (lambda report, scanner: scanner.update(split="holdout"), "split"),
        (lambda report, scanner: scanner["cases"][0]["labels"].pop(), "label set"),
        (
            lambda report, scanner: scanner["cases"][0]["labels"].append(
                copy.deepcopy(scanner["cases"][0]["labels"][0])
            ),
            "duplicate scanner label",
        ),
        (
            lambda report, scanner: report["batches"][0]["predictions"].pop(),
            "decision count",
        ),
        (lambda report, scanner: report["batches"].pop(), "request counts"),
        (
            lambda report, scanner: report["batches"][0]["predictions"][0][
                "target"
            ].update(symbol="other"),
            "target differs",
        ),
    ],
)
def test_mismatched_or_incomplete_inputs_fail_closed(tmp_path, change, message):
    path, report, scanner = _fixture(tmp_path)
    change(report, scanner)
    _seal(report)
    with pytest.raises(JevBenchmarkError, match=message):
        compare_jev_to_scanner(report, scanner, path)


def test_report_digest_detects_tampering(tmp_path):
    path, report, scanner = _fixture(tmp_path)
    report["batches"][0]["predictions"][0]["predicted"] = "unused"
    with pytest.raises(JevBenchmarkError, match="report digest"):
        compare_jev_to_scanner(report, scanner, path)


def test_schema_two_requires_report_digest(tmp_path):
    path, report, scanner = _fixture(tmp_path)
    del report["report_digest"]
    with pytest.raises(JevBenchmarkError, match="requires a report digest"):
        compare_jev_to_scanner(report, scanner, path)


def test_changed_fixture_source_fails_even_with_unchanged_manifest(tmp_path):
    path, report, scanner = _fixture(tmp_path)
    source = tmp_path / "fixtures" / "python" / "module.py"
    source.write_text(
        source.read_text(encoding="utf-8") + "\ndef added():\n    pass\n",
        encoding="utf-8",
    )
    with pytest.raises(
        JevBenchmarkError, match="request digests differ from current fixture sources"
    ):
        compare_jev_to_scanner(report, scanner, path)


@pytest.mark.parametrize(
    "change, message",
    [
        (
            lambda report: report["planned_requests"][0].update(request_digest="wrong"),
            "planned request digests differ",
        ),
        (
            lambda report: report["batches"][0].update(request_digest="wrong"),
            "batch request digests differ",
        ),
        (
            lambda report: report.pop("planned_requests"),
            "Jev planned requests must be a list",
        ),
    ],
)
def test_request_provenance_is_required_and_exact(tmp_path, change, message):
    path, report, scanner = _fixture(tmp_path)
    change(report)
    _seal(report)
    with pytest.raises(JevBenchmarkError, match=message):
        compare_jev_to_scanner(report, scanner, path)


def test_selected_case_sets_must_match(tmp_path):
    path, report, scanner = _fixture(tmp_path)
    scanner["cases"].pop()
    scanner["case_count"] = 1
    with pytest.raises(JevBenchmarkError, match="target case sets differ"):
        compare_jev_to_scanner(report, scanner, path)
