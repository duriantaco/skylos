from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from skylos.research.dead_code.ablation import AblationResult, run_ablation
from skylos.research.dead_code.evidence import CandidateClassification


class GroundTruthLabel(StrEnum):
    ALIVE = "alive"
    DEAD = "dead"


class ScoreOutcome(StrEnum):
    TRUE_POSITIVE = "tp"
    FALSE_POSITIVE = "fp"
    FALSE_NEGATIVE = "fn"
    TRUE_NEGATIVE = "tn"
    ABSTAIN = "abstain"
    MISSING = "missing"


@dataclass(frozen=True)
class GroundTruthCase:
    qualified_name: str
    expected: GroundTruthLabel
    file: str | None = None
    note: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "GroundTruthCase":
        qname = str(raw.get("qualified_name") or raw.get("qname") or "").strip()
        if not qname:
            raise ValueError("ground-truth case is missing qualified_name")
        return cls(
            qualified_name=qname,
            expected=_parse_expected_label(raw.get("expected")),
            file=str(raw["file"]) if raw.get("file") else None,
            note=str(raw.get("note") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "qualified_name": self.qualified_name,
            "expected": self.expected.value,
        }
        if self.file:
            payload["file"] = self.file
        if self.note:
            payload["note"] = self.note
        return payload


@dataclass(frozen=True)
class GroundTruthManifest:
    name: str
    cases: tuple[GroundTruthCase, ...]
    description: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "GroundTruthManifest":
        cases_raw = raw.get("cases")
        if not isinstance(cases_raw, list):
            raise ValueError("ground-truth manifest must contain a cases list")
        cases = tuple(GroundTruthCase.from_dict(item) for item in cases_raw)
        seen: set[str] = set()
        for case in cases:
            if case.qualified_name in seen:
                raise ValueError(
                    f"duplicate ground-truth case: {case.qualified_name}"
                )
            seen.add(case.qualified_name)
        return cls(
            name=str(raw.get("name") or "unnamed"),
            description=str(raw.get("description") or ""),
            cases=cases,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "cases": [case.to_dict() for case in self.cases],
        }
        if self.description:
            payload["description"] = self.description
        return payload


@dataclass(frozen=True)
class ScoredCase:
    qualified_name: str
    expected: GroundTruthLabel
    predicted: CandidateClassification | None
    outcome: ScoreOutcome
    file: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "qualified_name": self.qualified_name,
            "expected": self.expected.value,
            "predicted": self.predicted.value if self.predicted else None,
            "outcome": self.outcome.value,
        }
        if self.file:
            payload["file"] = self.file
        if self.note:
            payload["note"] = self.note
        return payload


@dataclass(frozen=True)
class ScoreSummary:
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0
    abstain: int = 0
    missing: int = 0
    extra: int = 0

    @property
    def precision(self) -> float | None:
        denominator = self.true_positive + self.false_positive
        if denominator == 0:
            return None
        return self.true_positive / denominator

    @property
    def recall(self) -> float | None:
        denominator = self.true_positive + self.false_negative
        if denominator == 0:
            return None
        return self.true_positive / denominator

    @property
    def f1(self) -> float | None:
        precision = self.precision
        recall = self.recall
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    @property
    def accuracy(self) -> float | None:
        correct = self.true_positive + self.true_negative
        total = correct + self.false_positive + self.false_negative
        if total == 0:
            return None
        return correct / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "positive_class": GroundTruthLabel.DEAD.value,
            "tp": self.true_positive,
            "fp": self.false_positive,
            "fn": self.false_negative,
            "tn": self.true_negative,
            "abstain": self.abstain,
            "missing": self.missing,
            "extra": self.extra,
            "precision": _rounded(self.precision),
            "recall": _rounded(self.recall),
            "f1": _rounded(self.f1),
            "accuracy": _rounded(self.accuracy),
        }

    def with_extra_as_false_positive(self) -> "ScoreSummary":
        return ScoreSummary(
            true_positive=self.true_positive,
            false_positive=self.false_positive + self.extra,
            false_negative=self.false_negative,
            true_negative=self.true_negative,
            abstain=self.abstain,
            missing=self.missing,
            extra=self.extra,
        )


@dataclass(frozen=True)
class ScoringResult:
    variant: str
    manifest: GroundTruthManifest
    project_root: Path
    cases: tuple[ScoredCase, ...]
    extra_predictions: tuple[str, ...] = field(default_factory=tuple)

    @property
    def summary(self) -> ScoreSummary:
        counts = {
            ScoreOutcome.TRUE_POSITIVE: 0,
            ScoreOutcome.FALSE_POSITIVE: 0,
            ScoreOutcome.FALSE_NEGATIVE: 0,
            ScoreOutcome.TRUE_NEGATIVE: 0,
            ScoreOutcome.ABSTAIN: 0,
            ScoreOutcome.MISSING: 0,
        }
        for case in self.cases:
            counts[case.outcome] += 1
        return ScoreSummary(
            true_positive=counts[ScoreOutcome.TRUE_POSITIVE],
            false_positive=counts[ScoreOutcome.FALSE_POSITIVE],
            false_negative=counts[ScoreOutcome.FALSE_NEGATIVE],
            true_negative=counts[ScoreOutcome.TRUE_NEGATIVE],
            abstain=counts[ScoreOutcome.ABSTAIN],
            missing=counts[ScoreOutcome.MISSING],
            extra=len(self.extra_predictions),
        )

    @property
    def binary_no_report_summary(self) -> ScoreSummary:
        """Treat abstain/missing as a negative report decision."""
        counts = {
            "true_positive": 0,
            "false_positive": 0,
            "false_negative": 0,
            "true_negative": 0,
            "abstain": 0,
            "missing": 0,
            "extra": len(self.extra_predictions),
        }
        for case in self.cases:
            if case.outcome == ScoreOutcome.TRUE_POSITIVE:
                counts["true_positive"] += 1
            elif case.outcome == ScoreOutcome.FALSE_POSITIVE:
                counts["false_positive"] += 1
            elif case.outcome == ScoreOutcome.FALSE_NEGATIVE:
                counts["false_negative"] += 1
            elif case.outcome == ScoreOutcome.TRUE_NEGATIVE:
                counts["true_negative"] += 1
            elif case.expected == GroundTruthLabel.DEAD:
                counts["false_negative"] += 1
                if case.outcome == ScoreOutcome.ABSTAIN:
                    counts["abstain"] += 1
                else:
                    counts["missing"] += 1
            else:
                counts["true_negative"] += 1
                if case.outcome == ScoreOutcome.ABSTAIN:
                    counts["abstain"] += 1
                else:
                    counts["missing"] += 1
        return ScoreSummary(**counts)

    def to_dict(self) -> dict[str, Any]:
        summary = self.summary
        binary_summary = self.binary_no_report_summary
        return {
            "variant": self.variant,
            "project_root": str(self.project_root),
            "manifest": self.manifest.to_dict(),
            "summary": summary.to_dict(),
            "closed_world_summary": summary.with_extra_as_false_positive().to_dict(),
            "binary_no_report_summary": binary_summary.to_dict(),
            "closed_world_binary_no_report_summary": (
                binary_summary.with_extra_as_false_positive().to_dict()
            ),
            "cases": [case.to_dict() for case in self.cases],
            "extra_predictions": list(self.extra_predictions),
        }


def _resolved_manifest_file(path: str | Path) -> Path:
    """Normalise a caller-supplied manifest path before reading it.

    Manifest paths arrive from command-line arguments.  Resolving collapses
    ``..`` segments and symlinks, and the result must be an existing regular
    file, so a traversal-style argument cannot steer the read at a directory
    or a device node.
    """
    resolved = Path(path).expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"ground-truth manifest is not a regular file: {resolved}")
    return resolved


def load_manifest(path: str | Path) -> GroundTruthManifest:
    manifest_path = _resolved_manifest_file(path)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("ground-truth manifest must be a JSON object")
    return GroundTruthManifest.from_dict(raw)


def score_ablation(
    project_root: str | Path,
    manifest: GroundTruthManifest,
    *,
    variant: str,
) -> ScoringResult:
    result = run_ablation(project_root, variant=variant)
    return score_ablation_result(result, manifest)


def score_ablation_result(
    result: AblationResult,
    manifest: GroundTruthManifest,
) -> ScoringResult:
    cases_by_qname = {case.qualified_name: case for case in manifest.cases}
    scored: list[ScoredCase] = []

    for expected_case in manifest.cases:
        symbol = result.symbols.get(expected_case.qualified_name)
        predicted = result.classify(expected_case.qualified_name) if symbol else None
        scored.append(
            ScoredCase(
                qualified_name=expected_case.qualified_name,
                expected=expected_case.expected,
                predicted=predicted,
                outcome=_outcome(expected_case.expected, predicted),
                file=expected_case.file,
                note=expected_case.note,
            )
        )

    extra = tuple(
        sorted(
            qname
            for qname in set(result.symbols) - set(cases_by_qname)
            if _prediction_is_dead(result.classify(qname))
        )
    )
    return ScoringResult(
        variant=result.variant.value,
        manifest=manifest,
        project_root=result.project_root,
        cases=tuple(scored),
        extra_predictions=extra,
    )


def _parse_expected_label(raw: Any) -> GroundTruthLabel:
    value = str(raw or "").strip().lower()
    aliases = {
        "live": GroundTruthLabel.ALIVE,
        "alive": GroundTruthLabel.ALIVE,
        "reachable": GroundTruthLabel.ALIVE,
        "used": GroundTruthLabel.ALIVE,
        "dead": GroundTruthLabel.DEAD,
        "likely_dead": GroundTruthLabel.DEAD,
        "validated_dead": GroundTruthLabel.DEAD,
        "unreachable": GroundTruthLabel.DEAD,
        "unused": GroundTruthLabel.DEAD,
    }
    if value not in aliases:
        raise ValueError(f"unsupported expected label: {raw!r}")
    return aliases[value]


def _prediction_is_dead(
    predicted: CandidateClassification | None,
) -> bool | None:
    if predicted is None:
        return None
    if predicted == CandidateClassification.UNCERTAIN:
        return None
    return predicted in {
        CandidateClassification.DEAD,
        CandidateClassification.LIKELY_DEAD,
        CandidateClassification.VALIDATED_DEAD,
    }


def _outcome(
    expected: GroundTruthLabel,
    predicted: CandidateClassification | None,
) -> ScoreOutcome:
    predicted_dead = _prediction_is_dead(predicted)
    if predicted is None:
        return ScoreOutcome.MISSING
    if predicted_dead is None:
        return ScoreOutcome.ABSTAIN
    expected_dead = expected == GroundTruthLabel.DEAD
    if expected_dead and predicted_dead:
        return ScoreOutcome.TRUE_POSITIVE
    if not expected_dead and predicted_dead:
        return ScoreOutcome.FALSE_POSITIVE
    if expected_dead and not predicted_dead:
        return ScoreOutcome.FALSE_NEGATIVE
    return ScoreOutcome.TRUE_NEGATIVE


def _rounded(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 6)
