from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FEEDBACK_DIR = Path.home() / ".skylos"
FEEDBACK_FILE = FEEDBACK_DIR / "feedback.json"

DEFAULT_WEIGHTS = {
    "same_file_attr": 1.0,
    "same_pkg_attr": 0.3,
    "global_attr": 0.1,
}

MIN_WEIGHT = 0.02
MAX_WEIGHT = 2.0
MIN_OBSERVATIONS = 5


@dataclass
class HeuristicObservation:
    heuristic_type: str
    is_spurious: bool
    function_name: str = ""
    project: str = ""


@dataclass
class FeedbackData:
    observations: dict[str, dict[str, int]] = field(default_factory=dict)
    tuned_weights: dict[str, float] = field(default_factory=dict)
    total_runs: int = 0

    def to_dict(self) -> dict:
        return {
            "observations": self.observations,
            "tuned_weights": self.tuned_weights,
            "total_runs": self.total_runs,
        }

    @classmethod
    def from_dict(cls, data: dict) -> FeedbackData:
        return cls(
            observations=data.get("observations", {}),
            tuned_weights=data.get("tuned_weights", {}),
            total_runs=data.get("total_runs", 0),
        )


def load_feedback() -> FeedbackData:
    if not FEEDBACK_FILE.exists():
        return FeedbackData()
    try:
        data = json.loads(FEEDBACK_FILE.read_text(encoding="utf-8"))
        return FeedbackData.from_dict(data)
    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Failed to load feedback: {e}")
        return FeedbackData()


def save_feedback(data: FeedbackData) -> None:
    try:
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
        FEEDBACK_FILE.write_text(
            json.dumps(data.to_dict(), indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        logger.warning(f"Failed to save feedback: {e}")


def record_verification_results(
    verification_result: dict[str, Any],
) -> FeedbackData:
    feedback = load_feedback()

    for finding in verification_result.get("verified_findings", []):
        verdict = finding.get("_llm_verdict", "")
        heuristic_refs = finding.get("heuristic_refs", {})

        if not heuristic_refs:
            continue
        if verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
            continue

        for htype in heuristic_refs:
            if htype not in feedback.observations:
                feedback.observations[htype] = {"real": 0, "spurious": 0, "uncertain": 0}

            if verdict == "TRUE_POSITIVE":
                feedback.observations[htype]["spurious"] += 1
            elif verdict == "FALSE_POSITIVE":
                feedback.observations[htype]["real"] += 1

    for new_dead in verification_result.get("new_dead_code", []):
        heuristic_refs = new_dead.get("heuristic_refs", {})
        for htype in heuristic_refs:
            if htype not in feedback.observations:
                feedback.observations[htype] = {"real": 0, "spurious": 0, "uncertain": 0}
            feedback.observations[htype]["spurious"] += 1

    feedback.total_runs += 1

    feedback.tuned_weights = compute_tuned_weights(feedback)

    save_feedback(feedback)
    return feedback


def compute_tuned_weights(feedback: FeedbackData) -> dict[str, float]:

    tuned = {}

    for htype, default_w in DEFAULT_WEIGHTS.items():
        obs = feedback.observations.get(htype, {})
        real = obs.get("real", 0)
        spurious = obs.get("spurious", 0)
        total = real + spurious

        if total < MIN_OBSERVATIONS:
            tuned[htype] = default_w
            continue

        accuracy = real / total
        new_weight = default_w * accuracy
        new_weight = max(MIN_WEIGHT, min(MAX_WEIGHT, new_weight))

        tuned[htype] = round(new_weight, 4)

    return tuned


def get_tuned_weights() -> dict[str, float]:
    feedback = load_feedback()
    weights = dict(DEFAULT_WEIGHTS)
    weights.update(feedback.tuned_weights)
    return weights


def get_feedback_summary() -> dict[str, Any]:
    feedback = load_feedback()

    summary = {
        "total_runs": feedback.total_runs,
        "heuristic_types": {},
    }

    for htype in DEFAULT_WEIGHTS:
        obs = feedback.observations.get(htype, {})
        real = obs.get("real", 0)
        spurious = obs.get("spurious", 0)
        total = real + spurious

        default_w = DEFAULT_WEIGHTS[htype]
        tuned_w = feedback.tuned_weights.get(htype, default_w)

        summary["heuristic_types"][htype] = {
            "observations": total,
            "real": real,
            "spurious": spurious,
            "accuracy_pct": round(100 * real / total, 1) if total > 0 else None,
            "default_weight": default_w,
            "tuned_weight": tuned_w,
            "weight_change_pct": round(100 * (tuned_w - default_w) / default_w, 1) if default_w > 0 else 0,
        }

    return summary


def reset_feedback() -> None:
    if FEEDBACK_FILE.exists():
        FEEDBACK_FILE.unlink()
