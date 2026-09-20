from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skylos.benchmarks._jev_dead_code_dataset import (
    JEV_ENDPOINT,
    JEV_MODEL,
    PROMPT_VERSION,
    _digest,
    manifest_digest,
    manifest_metadata,
    prompt_digest,
)


REPORT_SCHEMA_VERSION = 1
INPUT_PRICE_PER_MILLION_USD = 0.042
PRICE_OBSERVED_ON = "2026-09-20"
DEFAULT_THRESHOLDS = (0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95)


def _decision_bucket(item: dict[str, Any], threshold: float) -> str:
    expected = item["expected"]
    predicted = item["predicted"]
    if predicted == "abstain" or float(item["confidence"]) < threshold:
        return f"abstained_{expected}"
    return {
        ("unused", "unused"): "true_positives",
        ("unused", "used"): "false_positives",
        ("used", "unused"): "false_negatives",
        ("used", "used"): "true_negatives",
    }[(predicted, expected)]


def _threshold_score(
    predictions: list[dict[str, Any]],
    threshold: float,
) -> dict[str, Any]:
    counts = {
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 0,
        "abstained_unused": 0,
        "abstained_used": 0,
    }
    for item in predictions:
        counts[_decision_bucket(item, threshold)] += 1
    abstentions = counts["abstained_unused"] + counts["abstained_used"]
    decided = len(predictions) - abstentions
    removal_total = counts["true_positives"] + counts["false_positives"]
    actual_unused = sum(item["expected"] == "unused" for item in predictions)
    correct = counts["true_positives"] + counts["true_negatives"]
    return {
        "threshold": threshold,
        "counts": counts,
        "abstentions": abstentions,
        "abstentions_by_expected": {
            "unused": counts["abstained_unused"],
            "used": counts["abstained_used"],
        },
        "coverage": round(decided / len(predictions), 4) if predictions else 0.0,
        "decided_accuracy": round(correct / decided, 4) if decided else None,
        "unused_precision": (
            round(counts["true_positives"] / removal_total, 4)
            if removal_total
            else None
        ),
        "unused_recall": (
            round(counts["true_positives"] / actual_unused, 4)
            if actual_unused
            else None
        ),
        "unsafe_removal_count": counts["false_positives"],
    }


def _calibration(predictions: list[dict[str, Any]]) -> dict[str, Any]:
    if not predictions:
        return {"brier_unused": None, "mean_log_loss": None}
    squared = []
    losses = []
    for item in predictions:
        probability = float(item["probabilities"]["unreferenced"])
        actual = 1.0 if item["expected"] == "unused" else 0.0
        squared.append((probability - actual) ** 2)
        target_choice = "unreferenced" if actual else "retained"
        target_probability = max(float(item["probabilities"][target_choice]), 1e-12)
        losses.append(-math.log(target_probability))
    return {
        "brier_unused": round(sum(squared) / len(squared), 6),
        "mean_log_loss": round(sum(losses) / len(losses), 6),
    }


def _arm_summary(predictions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "decision_count": len(predictions),
        "predicted": {
            label: sum(item["predicted"] == label for item in predictions)
            for label in ("unused", "used", "abstain")
        },
        "calibration": _calibration(predictions),
        "thresholds": [
            _threshold_score(predictions, threshold) for threshold in DEFAULT_THRESHOLDS
        ],
    }


def _paired_consistency(predictions: list[dict[str, Any]]) -> dict[str, Any]:
    indexed = {
        (item["case_id"], item["question_id"], item["arm"]): item
        for item in predictions
    }
    pairs = []
    for key, original in indexed.items():
        case_id, question_id, arm = key
        if arm != "original":
            continue
        neutral = indexed.get((case_id, question_id, "neutralized"))
        if neutral is not None:
            pairs.append((original, neutral))
    same = sum(left["predicted"] == right["predicted"] for left, right in pairs)
    return {
        "pair_count": len(pairs),
        "same_decision_count": same,
        "decision_consistency": round(same / len(pairs), 4) if pairs else None,
    }


def score_predictions(predictions: list[dict[str, Any]]) -> dict[str, Any]:
    arms = {
        arm: _arm_summary([item for item in predictions if item["arm"] == arm])
        for arm in ("original", "neutralized")
    }
    return {"arms": arms, "paired": _paired_consistency(predictions)}


def _duration_stats(batches: list[dict[str, Any]], field: str) -> dict[str, Any]:
    values = sorted(
        float(batch[field])
        for batch in batches
        if batch.get("status") == "ok" and field in batch
    )
    if not values:
        return {"mean": None, "p50": None, "p95": None, "max": None}

    def nearest_rank(fraction: float) -> float:
        index = max(0, math.ceil(fraction * len(values)) - 1)
        return round(values[index], 6)

    return {
        "mean": round(sum(values) / len(values), 6),
        "p50": nearest_rank(0.5),
        "p95": nearest_rank(0.95),
        "max": round(values[-1], 6),
    }


def _latency_summary(batches: list[dict[str, Any]]) -> dict[str, Any]:
    completed = [batch for batch in batches if batch.get("status") == "ok"]
    return {
        "sample_count": len(completed),
        "percentile_method": "nearest_rank",
        "request_seconds": _duration_stats(batches, "request_elapsed_seconds"),
        "local_contract_validation_seconds": _duration_stats(
            batches, "local_contract_validation_seconds"
        ),
        "total_seconds": _duration_stats(batches, "elapsed_seconds"),
        "request_includes": [
            "network",
            "typesafe_service",
            "response_download",
            "json_decode",
        ],
        "server_constrained_generation_isolated": False,
    }


def _successful_predictions(batches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for batch in batches
        for item in batch.get("predictions", [])
        if batch.get("status") == "ok"
    ]


def _usage_summary(batches: list[dict[str, Any]]) -> dict[str, int]:
    return {
        field: sum(int(batch.get("usage", {}).get(field, 0)) for batch in batches)
        for field in ("input_tokens", "output_tokens")
    }


def build_report(
    manifest_path: str | Path,
    batches: list[dict[str, Any]],
    planned_count: int,
) -> dict[str, Any]:
    predictions = _successful_predictions(batches)
    usage = _usage_summary(batches)
    complete = len(batches) == planned_count and all(
        batch.get("status") == "ok" for batch in batches
    )
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "benchmark": "jev_dead_code",
        "status": "complete" if complete else "incomplete",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "manifest": str(Path(manifest_path).expanduser().absolute()),
        "manifest_digest": manifest_digest(manifest_path),
        "manifest_metadata": manifest_metadata(manifest_path),
        "endpoint": JEV_ENDPOINT,
        "requested_model": JEV_MODEL,
        "prompt_version": PROMPT_VERSION,
        "prompt_digest": prompt_digest(),
        "ground_truth_sent_to_model": False,
        "source_stored_in_report": False,
        "planned_request_count": planned_count,
        "completed_request_count": sum(
            batch.get("status") == "ok" for batch in batches
        ),
        "usage": usage,
        "estimated_input_cost_usd": round(
            usage["input_tokens"] * INPUT_PRICE_PER_MILLION_USD / 1_000_000,
            6,
        ),
        "pricing_basis": {
            "input_usd_per_million_tokens": INPUT_PRICE_PER_MILLION_USD,
            "observed_on": PRICE_OBSERVED_ON,
            "informational_only": True,
        },
        "elapsed_seconds": round(
            sum(float(batch.get("elapsed_seconds", 0.0)) for batch in batches), 4
        ),
        "latency": _latency_summary(batches),
        "summary": score_predictions(predictions),
        "batches": batches,
    }
    report["report_digest"] = _digest(report)
    return report


def format_plan(plan: dict[str, Any]) -> str:
    metadata = plan["manifest_metadata"]
    lines = [
        "Jev dead-code benchmark plan (no network used)",
        f"Model: {plan['model']} (pinned)",
        f"Ground truth: {metadata['format']}",
    ]
    if metadata["split"] is not None:
        lines.append(
            f"Split: {metadata['split']} ({metadata['label_state']} labels)"
        )
    lines.extend(
        [
            f"Cases: {plan['case_count']}",
            f"Ground-truth symbols: {plan['ground_truth_count']} "
            f"({plan['unused_count']} unused, {plan['used_count']} used)",
            (
                f"Blind decisions: {plan['decision_count']} across "
                f"{plan['request_count']} requests"
            ),
            "Arms: original identifiers, label-signal-neutralized identifiers",
        ]
    )
    return "\n".join(lines)


def _threshold_at(summary: dict[str, Any], threshold: float) -> dict[str, Any]:
    for item in summary["thresholds"]:
        if item["threshold"] == threshold:
            return item
    raise KeyError(threshold)


def format_report(report: dict[str, Any]) -> str:
    lines = [
        f"Jev dead-code benchmark: {report['status']}",
        f"Model: {report['requested_model']}",
        (
            f"Requests: {report['completed_request_count']}/"
            f"{report['planned_request_count']}"
        ),
    ]
    for arm in ("original", "neutralized"):
        arm_summary = report["summary"]["arms"][arm]
        score = _threshold_at(arm_summary, 0.8)
        lines.append(
            f"{arm}: coverage={score['coverage']} accuracy={score['decided_accuracy']} "
            f"unused_precision={score['unused_precision']} "
            f"unsafe_removals={score['unsafe_removal_count']} at confidence>=0.8"
        )
    paired = report["summary"]["paired"]
    latency = report["latency"]
    lines.extend(
        [
            f"Identifier-neutralization consistency: {paired['decision_consistency']}",
            "Request latency seconds: "
            f"p50={latency['request_seconds']['p50']} "
            f"p95={latency['request_seconds']['p95']}",
            "Local contract validation seconds: "
            f"p50={latency['local_contract_validation_seconds']['p50']} "
            f"p95={latency['local_contract_validation_seconds']['p95']}",
            f"Input tokens: {report['usage']['input_tokens']}",
            f"Estimated input cost: ${report['estimated_input_cost_usd']:.6f} "
            f"(informational price observed {PRICE_OBSERVED_ON})",
        ]
    )
    errors = [batch for batch in report["batches"] if batch["status"] == "error"]
    for item in errors:
        lines.append(f"ERROR {item['case_id']} [{item['arm']}]: {item['error']}")
    return "\n".join(lines)
