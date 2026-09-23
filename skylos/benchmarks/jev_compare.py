"""Offline, label-by-label comparison of Jev and a golden dead-code run.

The corpus runner's summary does not contain a manifest digest. We therefore
bind the Jev report to the manifest bytes and check every selected scanner
case and label against that same frozen manifest. This does not prove which
manifest bytes the scanner originally used, but prevents an accidental join
on a merely similar set of label IDs.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from skylos.benchmarks._jev_dead_code_dataset import (
    _digest,
    _manifest_text,
    prepare_batches_with_snapshot,
)
from skylos.benchmarks._jev_dead_code_golden import (
    GOLDEN_SCHEMA,
    normalize_golden_cases,
)
from skylos.benchmarks._jev_dead_code_types import JevBenchmarkError


COMPARISON_SCHEMA_VERSION = 1
OUTCOMES = (
    "jev_corrected_scanner",
    "jev_regressed_scanner",
    "both_correct",
    "both_wrong",
    "jev_abstained_scanner_correct",
    "jev_abstained_scanner_wrong",
)
EXPECTATIONS = {"should_report": "unused", "should_not_report": "used"}
DECISIONS = {"unused", "used", "abstain"}


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise JevBenchmarkError(f"{field} must be an object")
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise JevBenchmarkError(f"{field} must be a list")
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise JevBenchmarkError(f"{field} must be a non-empty string")
    return value


def _count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise JevBenchmarkError(f"{field} must be a non-negative integer")
    return value


def _manifest_index(manifest_path: str | Path) -> tuple[dict[str, Any], str]:
    manifest_text = _manifest_text(manifest_path)
    digest = hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()
    try:
        manifest = _object(json.loads(manifest_text), "manifest")
    except json.JSONDecodeError as exc:
        raise JevBenchmarkError("benchmark manifest is not valid JSON") from exc
    if manifest.get("schema_version") != GOLDEN_SCHEMA:
        raise JevBenchmarkError("comparison requires a golden benchmark manifest")
    if not isinstance(manifest.get("split"), str) or not manifest["split"]:
        raise JevBenchmarkError("golden benchmark split must be non-empty")
    # Validates frozen labels, closed coverage, and globally unique case/label IDs.
    normalize_golden_cases(manifest, manifest_path)
    cases: dict[str, Any] = {}
    for case in manifest["cases"]:
        case_id = case["id"]
        languages = case.get("languages")
        if (
            not isinstance(languages, list)
            or not languages
            or any(not isinstance(lang, str) or not lang for lang in languages)
            or len(languages) != len(set(languages))
        ):
            raise JevBenchmarkError(f"golden case {case_id} has invalid languages")
        labels = {}
        for label in case["labels"]:
            labels[label["id"]] = label
        cases[case_id] = {"languages": languages, "labels": labels}
    return {"split": manifest["split"], "cases": cases}, digest


def _validate_provenance(
    report: dict[str, Any],
    scanner: dict[str, Any],
    manifest: dict[str, Any],
    manifest_digest: str,
) -> str:
    if report.get("benchmark") != "jev_dead_code":
        raise JevBenchmarkError("not a Jev dead-code report")
    if report.get("status") != "complete":
        raise JevBenchmarkError("Jev report must be complete")
    if report.get("manifest_digest") != manifest_digest:
        raise JevBenchmarkError("Jev report manifest digest does not match")
    metadata = _object(report.get("manifest_metadata"), "Jev manifest metadata")
    if (
        metadata.get("format") != GOLDEN_SCHEMA
        or metadata.get("split") != manifest["split"]
        or metadata.get("label_state") != "frozen"
    ):
        raise JevBenchmarkError("Jev report manifest split or state does not match")
    schema_version = _count(report.get("schema_version"), "Jev report schema version")
    reported_digest = report.get("report_digest")
    if schema_version >= 2 and not isinstance(reported_digest, str):
        raise JevBenchmarkError("Jev schema 2 report requires a report digest")
    if reported_digest is not None:
        without_digest = {
            key: value for key, value in report.items() if key != "report_digest"
        }
        if reported_digest != _digest(without_digest):
            raise JevBenchmarkError("Jev report digest does not match its contents")
    if (
        scanner.get("suite") != "dead_code"
        or scanner.get("split") != manifest["split"]
        or scanner.get("label_state") != "frozen"
        or scanner.get("ok") is not True
    ):
        raise JevBenchmarkError(
            "scanner summary split, state, or status does not match"
        )
    tool = _identifier(scanner.get("tool"), "scanner summary tool")
    if tool != "skylos":
        raise JevBenchmarkError("comparison requires a Skylos scanner summary")
    if _count(scanner.get("skipped_case_count"), "skipped case count") != 0:
        raise JevBenchmarkError("scanner summary has skipped cases")
    if _list(scanner.get("skipped_cases"), "skipped cases"):
        raise JevBenchmarkError("scanner summary has skipped cases")
    return tool


def _scanner_index(
    summary: dict[str, Any], manifest: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], int]:
    cases = _list(summary.get("cases"), "scanner cases")
    if len(cases) != _count(summary.get("case_count"), "scanner case count"):
        raise JevBenchmarkError("scanner case count does not match case records")
    found: dict[str, dict[str, Any]] = {}
    unlabeled_count = 0
    for raw_case in cases:
        case = _object(raw_case, "scanner case")
        case_id = _identifier(case.get("case_id"), "scanner case ID")
        if case_id in found:
            raise JevBenchmarkError(f"duplicate scanner case ID: {case_id}")
        expected_case = manifest["cases"].get(case_id)
        if expected_case is None:
            raise JevBenchmarkError(f"unknown scanner case ID: {case_id}")
        if case.get("languages") != expected_case["languages"]:
            raise JevBenchmarkError(f"scanner languages differ for case: {case_id}")
        unlabeled_count += _count(
            case.get("unlabeled_finding_count"),
            f"scanner case {case_id} unlabeled finding count",
        )
        labels: dict[str, Any] = {}
        for raw_label in _list(case.get("labels"), f"scanner case {case_id} labels"):
            label = _object(raw_label, "scanner label")
            label_id = _identifier(label.get("label_id"), "scanner label ID")
            if label_id in labels:
                raise JevBenchmarkError(f"duplicate scanner label ID: {label_id}")
            source = expected_case["labels"].get(label_id)
            if source is None:
                raise JevBenchmarkError(f"unknown scanner label ID: {label_id}")
            if label.get("expectation") != source["expectation"]:
                raise JevBenchmarkError(f"scanner expectation differs for: {label_id}")
            if not isinstance(label.get("matched"), bool):
                raise JevBenchmarkError(
                    f"scanner matched value is invalid for: {label_id}"
                )
            labels[label_id] = label
        if set(labels) != set(expected_case["labels"]):
            raise JevBenchmarkError(f"scanner label set differs for case: {case_id}")
        found[case_id] = labels
    if not found:
        raise JevBenchmarkError("scanner summary has no compared cases")
    return found, unlabeled_count


def _jev_index(
    report: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, dict[str, dict[str, Any]]]:
    batches = _list(report.get("batches"), "Jev batches")
    planned = _count(report.get("planned_request_count"), "planned Jev request count")
    completed = _count(
        report.get("completed_request_count"), "completed Jev request count"
    )
    if len(batches) != planned or completed != planned:
        raise JevBenchmarkError("Jev report request counts are incomplete")
    found: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for raw_batch in batches:
        batch = _object(raw_batch, "Jev batch")
        case_id = _identifier(batch.get("case_id"), "Jev batch case ID")
        arm = batch.get("arm")
        if case_id not in manifest["cases"] or arm not in ("original", "neutralized"):
            raise JevBenchmarkError("Jev batch has an unknown case or arm")
        if arm in found[case_id]:
            raise JevBenchmarkError(f"duplicate Jev batch for {case_id}/{arm}")
        if batch.get("status") != "ok":
            raise JevBenchmarkError("Jev report contains an unsuccessful batch")
        predictions: dict[str, Any] = {}
        raw_predictions = _list(batch.get("predictions"), "Jev predictions")
        if len(raw_predictions) != _count(
            batch.get("decision_count"), "Jev decision count"
        ):
            raise JevBenchmarkError(
                "Jev batch decision count does not match predictions"
            )
        for raw_prediction in raw_predictions:
            prediction = _object(raw_prediction, "Jev prediction")
            label_id = _identifier(prediction.get("label_id"), "Jev label ID")
            if label_id in predictions:
                raise JevBenchmarkError(f"duplicate Jev label ID: {label_id}")
            source = manifest["cases"][case_id]["labels"].get(label_id)
            if source is None:
                raise JevBenchmarkError(f"unknown Jev label ID: {label_id}")
            expected = EXPECTATIONS[source["expectation"]]
            if (
                prediction.get("case_id") != case_id
                or prediction.get("arm") != arm
                or prediction.get("expected") != expected
            ):
                raise JevBenchmarkError(
                    f"Jev prediction identity differs for: {label_id}"
                )
            target = _object(prediction.get("target"), "Jev prediction target")
            match = source["match"]
            if (
                target.get("file") != match["path"]
                or target.get("symbol") != match["symbol"]
                or target.get("line") != match.get("line")
            ):
                raise JevBenchmarkError(
                    f"Jev prediction target differs for: {label_id}"
                )
            if prediction.get("predicted") not in DECISIONS:
                raise JevBenchmarkError(f"Jev prediction is invalid for: {label_id}")
            confidence = prediction.get("confidence")
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not math.isfinite(confidence)
                or not 0 <= confidence <= 1
            ):
                raise JevBenchmarkError(f"Jev confidence is invalid for: {label_id}")
            predictions[label_id] = prediction
        if set(predictions) != set(manifest["cases"][case_id]["labels"]):
            raise JevBenchmarkError(f"Jev label set differs for case: {case_id}")
        found[case_id][arm] = predictions
    if any("original" not in arms for arms in found.values()):
        raise JevBenchmarkError("Jev report is missing an original arm")
    return found


def _request_digest_index(records: list[Any], field: str) -> dict[tuple[str, str], str]:
    indexed = {}
    for raw_record in records:
        record = _object(raw_record, field)
        case_id = _identifier(record.get("case_id"), f"{field} case ID")
        arm = record.get("arm")
        if arm not in ("original", "neutralized"):
            raise JevBenchmarkError(f"{field} has an unknown arm")
        key = (case_id, arm)
        if key in indexed:
            raise JevBenchmarkError(f"duplicate {field} for {case_id}/{arm}")
        indexed[key] = _identifier(record.get("request_digest"), f"{field} digest")
    return indexed


def _verify_prepared_requests(
    report: dict[str, Any],
    manifest_path: str | Path,
    manifest_digest: str,
    selected_cases: set[str],
) -> None:
    """Bind an offline comparison to the current fixture bytes and prompt."""
    planned, fresh_digest, _metadata = prepare_batches_with_snapshot(
        manifest_path, selected_cases
    )
    if fresh_digest != manifest_digest:
        raise JevBenchmarkError("benchmark manifest changed during comparison")
    expected = {(batch.case_id, batch.arm): batch.request_digest for batch in planned}
    if len(expected) != len(planned):
        raise JevBenchmarkError(
            "prepared Jev requests contain duplicate case/arm pairs"
        )
    if len(planned) != _count(
        report.get("planned_request_count"), "planned Jev request count"
    ):
        raise JevBenchmarkError(
            "Jev planned requests differ from current fixture sources"
        )
    reported_batches = _request_digest_index(
        _list(report.get("batches"), "Jev batches"), "Jev batch"
    )
    if reported_batches != expected:
        raise JevBenchmarkError(
            "Jev batch request digests differ from current fixture sources"
        )
    planned_records = report.get("planned_requests")
    if (
        _count(report.get("schema_version"), "Jev report schema version") >= 2
        or planned_records is not None
    ):
        reported_plan = _request_digest_index(
            _list(planned_records, "Jev planned requests"), "Jev planned request"
        )
        if reported_plan != expected:
            raise JevBenchmarkError(
                "Jev planned request digests differ from current fixture sources"
            )


def _outcome(expected: str, scanner: str, jev: str) -> str:
    scanner_correct = scanner == expected
    if jev == "abstain":
        return (
            "jev_abstained_scanner_correct"
            if scanner_correct
            else "jev_abstained_scanner_wrong"
        )
    jev_correct = jev == expected
    if jev_correct and not scanner_correct:
        return "jev_corrected_scanner"
    if scanner_correct and not jev_correct:
        return "jev_regressed_scanner"
    return "both_correct" if jev_correct else "both_wrong"


def _confusion(labels: list[dict[str, Any]], prediction_key: str) -> dict[str, int]:
    counts = {
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 0,
    }
    buckets = {
        ("unused", "unused"): "true_positives",
        ("used", "unused"): "false_positives",
        ("used", "used"): "true_negatives",
        ("unused", "used"): "false_negatives",
    }
    for item in labels:
        prediction = item[prediction_key]
        if prediction != "abstain":
            counts[buckets[(item["expected"], prediction)]] += 1
    return counts


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _classification_metrics(
    confusion: dict[str, int],
    *,
    unused_total: int | None = None,
    used_total: int | None = None,
) -> tuple[dict[str, float | None], dict[str, int]]:
    tp = confusion["true_positives"]
    fp = confusion["false_positives"]
    fn = confusion["false_negatives"]
    tn = confusion["true_negatives"]
    denominators = {
        "precision": tp + fp,
        "recall": tp + fn if unused_total is None else unused_total,
        "false_positive_rate": fp + tn if used_total is None else used_total,
    }
    raw_precision = (
        tp / denominators["precision"] if denominators["precision"] else None
    )
    raw_recall = tp / denominators["recall"] if denominators["recall"] else None
    precision = round(raw_precision, 4) if raw_precision is not None else None
    recall = round(raw_recall, 4) if raw_recall is not None else None
    fpr = _ratio(fp, denominators["false_positive_rate"])
    if raw_precision is None or raw_recall is None:
        f1 = None
    else:
        f1 = (
            round(2 * raw_precision * raw_recall / (raw_precision + raw_recall), 4)
            if raw_precision + raw_recall
            else 0.0
        )
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
    }, denominators


def _summarize(labels: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {outcome: 0 for outcome in OUTCOMES}
    for item in labels:
        counts[item["outcome"]] += 1
    total = len(labels)
    abstained = (
        counts["jev_abstained_scanner_correct"] + counts["jev_abstained_scanner_wrong"]
    )
    decided = total - abstained
    scanner_confusion = _confusion(labels, "scanner_predicted")
    jev_confusion = _confusion(labels, "jev_predicted")
    abstained_unused = sum(
        item["expected"] == "unused" and item["jev_predicted"] == "abstain"
        for item in labels
    )
    abstained_used = abstained - abstained_unused
    scanner_errors = (
        scanner_confusion["false_positives"] + scanner_confusion["false_negatives"]
    )
    jev_errors = jev_confusion["false_positives"] + jev_confusion["false_negatives"]
    counts.update(
        {
            "labels": total,
            "jev_abstained": abstained,
            "scanner_errors": scanner_errors,
            "jev_decided_errors": jev_errors,
            "net_corrections": counts["jev_corrected_scanner"]
            - counts["jev_regressed_scanner"],
            "scanner_unsafe_removals": scanner_confusion["false_positives"],
            "jev_unsafe_removals": jev_confusion["false_positives"],
        }
    )
    scanner_metrics, scanner_denominators = _classification_metrics(scanner_confusion)
    jev_decided_metrics, jev_decided_denominators = _classification_metrics(
        jev_confusion
    )
    jev_all_metrics, jev_all_denominators = _classification_metrics(
        jev_confusion,
        unused_total=sum(item["expected"] == "unused" for item in labels),
        used_total=sum(item["expected"] == "used" for item in labels),
    )
    metrics = {
        "jev_coverage": round(decided / total, 4) if total else 0.0,
        "scanner_accuracy": round((total - scanner_errors) / total, 4)
        if total
        else None,
        "jev_decided_accuracy": round((decided - jev_errors) / decided, 4)
        if decided
        else None,
        "scanner": scanner_metrics,
        "jev_decided": jev_decided_metrics,
        "jev_all_labels": jev_all_metrics,
    }
    return {
        "counts": counts,
        "confusion": {
            "scanner": scanner_confusion,
            "jev_decided": jev_confusion,
            "jev_abstentions": {"unused": abstained_unused, "used": abstained_used},
        },
        "metric_denominators": {
            "scanner": {**scanner_denominators, "accuracy": total},
            "jev_decided": {
                **jev_decided_denominators,
                "accuracy": decided,
                "coverage": total,
            },
            "jev_all_labels": jev_all_denominators,
        },
        "metrics": metrics,
    }


def compare_jev_to_scanner(
    jev_report: dict[str, Any],
    scanner_summary: dict[str, Any],
    manifest_path: str | Path,
    *,
    threshold: float = 0.8,
    arm: str = "original",
) -> dict[str, Any]:
    """Compare an offline Jev report to a Skylos golden-corpus summary.

    Raises ``JevBenchmarkError`` on incomplete runs, provenance mismatch, or
    any non-identical selected case/label set. Confidence below ``threshold``
    becomes an abstention; the threshold is inclusive.
    """
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or not 0 <= threshold <= 1
    ):
        raise JevBenchmarkError("comparison threshold must be between 0 and 1")
    if arm not in ("original", "neutralized"):
        raise JevBenchmarkError("comparison arm must be original or neutralized")
    report = _object(jev_report, "Jev report")
    scanner = _object(scanner_summary, "scanner summary")
    manifest, digest = _manifest_index(manifest_path)
    tool = _validate_provenance(report, scanner, manifest, digest)
    scanner_cases, unlabeled_count = _scanner_index(scanner, manifest)
    jev_cases = _jev_index(report, manifest)
    if set(scanner_cases) != set(jev_cases):
        raise JevBenchmarkError("Jev and scanner target case sets differ")
    _verify_prepared_requests(report, manifest_path, digest, set(scanner_cases))
    if arm == "neutralized" and any(
        "neutralized" not in jev_cases[case_id] for case_id in scanner_cases
    ):
        raise JevBenchmarkError(
            "neutralized arm is unavailable for one or more selected cases"
        )
    labels = []
    for case_id in sorted(scanner_cases):
        source_case = manifest["cases"][case_id]
        for label_id in sorted(source_case["labels"]):
            source = source_case["labels"][label_id]
            expected = EXPECTATIONS[source["expectation"]]
            matched = scanner_cases[case_id][label_id]["matched"]
            scanner_predicted = "unused" if matched else "used"
            prediction = jev_cases[case_id][arm][label_id]
            predicted = prediction["predicted"]
            confidence = float(prediction["confidence"])
            jev_predicted = predicted if confidence >= threshold else "abstain"
            labels.append(
                {
                    "label_id": label_id,
                    "case_id": case_id,
                    "languages": list(source_case["languages"]),
                    "category": source["category"],
                    "expected": expected,
                    "scanner_predicted": scanner_predicted,
                    "jev_predicted": jev_predicted,
                    "jev_raw_predicted": predicted,
                    "jev_confidence": confidence,
                    "outcome": _outcome(expected, scanner_predicted, jev_predicted),
                }
            )
    by_case = {}
    by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in labels:
        by_case.setdefault(item["case_id"], []).append(item)
        for language in item["languages"]:
            by_language[language].append(item)
        by_category[item["category"]].append(item)
    summary = _summarize(labels)
    summary["counts"]["scanner_unlabeled_findings"] = unlabeled_count
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "benchmark": "jev_dead_code_comparison",
        "manifest_digest": digest,
        "split": manifest["split"],
        "scanner": tool,
        "arm": arm,
        "threshold": float(threshold),
        "comparison_scope": (
            "Metrics and outcomes cover frozen labels only. Scanner unlabeled "
            "findings are counted separately and may be additional false positives "
            "when strict unlabeled scoring is enabled. Jev confusion excludes "
            "abstentions; all-label recall counts abstained unused labels in its "
            "denominator, and all-label false-positive rate counts abstained used "
            "labels in its denominator. Undefined metric denominators yield null."
        ),
        "summary": summary,
        "by_case": {key: _summarize(value) for key, value in sorted(by_case.items())},
        "by_language": {
            key: _summarize(value) for key, value in sorted(by_language.items())
        },
        "by_category": {
            key: _summarize(value) for key, value in sorted(by_category.items())
        },
        "labels": labels,
    }
