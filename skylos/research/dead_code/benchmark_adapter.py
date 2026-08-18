from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
from pathlib import Path
from time import perf_counter
from typing import Any, Iterable

from skylos.research.dead_code.ablation import (
    AblationResult,
    ResearchVariant,
    run_ablation,
)
from skylos.research.dead_code.evidence import SymbolKey
from skylos.research.dead_code.scoring import (
    GroundTruthCase,
    GroundTruthLabel,
    GroundTruthManifest,
    ScoreSummary,
    ScoringResult,
    score_ablation_result,
)


@dataclass(frozen=True)
class SkippedBenchmarkLabel:
    case_id: str
    label_id: str
    reason: str
    expectation: str = ""
    category: str = ""
    path: str = ""
    symbol: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "label_id": self.label_id,
            "reason": self.reason,
            "expectation": self.expectation,
            "category": self.category,
            "path": self.path,
            "symbol": self.symbol,
        }


@dataclass(frozen=True)
class SkippedBenchmarkCase:
    case_id: str
    reason: str
    languages: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "reason": self.reason,
            "languages": list(self.languages),
        }


@dataclass(frozen=True)
class EvaluatedBenchmarkCase:
    case_id: str
    case_root: Path
    source_path: str
    manifest: GroundTruthManifest
    skipped_labels: tuple[SkippedBenchmarkLabel, ...]
    ablations: dict[str, AblationResult] = field(default_factory=dict)
    scores: dict[str, ScoringResult] = field(default_factory=dict)
    runtimes: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "source_path": self.source_path,
            "case_root": str(self.case_root),
            "scored_label_count": len(self.manifest.cases),
            "skipped_label_count": len(self.skipped_labels),
            "runtime_seconds": {
                variant: _rounded_seconds(seconds)
                for variant, seconds in sorted(self.runtimes.items())
            },
            "manifest": self.manifest.to_dict(),
            "skipped_labels": [label.to_dict() for label in self.skipped_labels],
            "scores": {
                variant: score.to_dict() for variant, score in sorted(self.scores.items())
            },
        }


@dataclass(frozen=True)
class BenchmarkEvaluation:
    benchmark_root: Path
    source_manifest: Path
    suite: str
    split: str
    cases: tuple[EvaluatedBenchmarkCase, ...]
    skipped_cases: tuple[SkippedBenchmarkCase, ...]
    variants: tuple[str, ...]

    def aggregate_summary(self) -> dict[str, Any]:
        return {
            variant: _aggregate_variant(self.cases, variant).to_dict()
            for variant in self.variants
        }

    def closed_world_aggregate_summary(self) -> dict[str, Any]:
        return {
            variant: _aggregate_variant(
                self.cases,
                variant,
                extra_as_false_positive=True,
            ).to_dict()
            for variant in self.variants
        }

    def binary_no_report_aggregate_summary(self) -> dict[str, Any]:
        return {
            variant: _aggregate_variant(
                self.cases,
                variant,
                binary_no_report=True,
            ).to_dict()
            for variant in self.variants
        }

    def closed_world_binary_no_report_aggregate_summary(self) -> dict[str, Any]:
        return {
            variant: _aggregate_variant(
                self.cases,
                variant,
                binary_no_report=True,
                extra_as_false_positive=True,
            ).to_dict()
            for variant in self.variants
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_root": str(self.benchmark_root),
            "source_manifest": str(self.source_manifest),
            "suite": self.suite,
            "split": self.split,
            "scope": {
                "languages": ["python"],
                "symbol_kinds": ["class", "function", "method", "variable"],
                "positive_class": GroundTruthLabel.DEAD.value,
                "unsupported_labels_are_skipped": True,
            },
            "variants": list(self.variants),
            "aggregate": self.aggregate_summary(),
            "closed_world_aggregate": self.closed_world_aggregate_summary(),
            "binary_no_report_aggregate": self.binary_no_report_aggregate_summary(),
            "closed_world_binary_no_report_aggregate": (
                self.closed_world_binary_no_report_aggregate_summary()
            ),
            "runtime_seconds": {
                variant: _rounded_seconds(
                    sum(case.runtimes.get(variant, 0.0) for case in self.cases)
                )
                for variant in self.variants
            },
            "case_count": len(self.cases),
            "skipped_case_count": len(self.skipped_cases),
            "cases": [case.to_dict() for case in self.cases],
            "skipped_cases": [case.to_dict() for case in self.skipped_cases],
        }


def evaluate_benchmark_manifest(
    benchmark_root: str | Path,
    manifest_path: str | Path,
    *,
    variants: Iterable[str] | None = None,
) -> BenchmarkEvaluation:
    root = Path(benchmark_root).resolve()
    manifest_file = Path(manifest_path)
    if not manifest_file.is_absolute():
        manifest_file = root / manifest_file
    manifest_file = manifest_file.resolve()
    manifest = _read_json(manifest_file)
    variant_values = tuple(variants or [variant.value for variant in ResearchVariant])

    evaluated_cases: list[EvaluatedBenchmarkCase] = []
    skipped_cases: list[SkippedBenchmarkCase] = []

    for case in manifest.get("cases", []):
        case_id = str(case.get("id") or "")
        languages = tuple(str(language) for language in case.get("languages", []))
        if "python" not in languages:
            skipped_cases.append(
                SkippedBenchmarkCase(
                    case_id=case_id,
                    reason="unsupported_language_for_current_research_adapter",
                    languages=languages,
                )
            )
            continue

        source_path = str(case.get("source", {}).get("local_path") or "")
        case_root = (root / source_path).resolve()
        if not case_root.exists():
            skipped_cases.append(
                SkippedBenchmarkCase(
                    case_id=case_id,
                    reason="missing_source_path",
                    languages=languages,
                )
            )
            continue

        ablations: dict[str, AblationResult] = {}
        runtimes: dict[str, float] = {}
        for variant in variant_values:
            started = perf_counter()
            ablations[variant] = run_ablation(case_root, variant=variant)
            runtimes[variant] = perf_counter() - started
        graph_symbols = next(iter(ablations.values())).symbols if ablations else {}
        research_manifest, skipped_labels = _ground_truth_manifest_for_case(
            case,
            case_root,
            graph_symbols.values(),
        )
        if not research_manifest.cases:
            skipped_cases.append(
                SkippedBenchmarkCase(
                    case_id=case_id,
                    reason="no_supported_labels",
                    languages=languages,
                )
            )
            continue

        scores = {
            variant: score_ablation_result(ablation, research_manifest)
            for variant, ablation in ablations.items()
        }
        evaluated_cases.append(
            EvaluatedBenchmarkCase(
                case_id=case_id,
                case_root=case_root,
                source_path=source_path,
                manifest=research_manifest,
                skipped_labels=tuple(skipped_labels),
                ablations=ablations,
                scores=scores,
                runtimes=runtimes,
            )
        )

    return BenchmarkEvaluation(
        benchmark_root=root,
        source_manifest=manifest_file,
        suite=str(manifest.get("suite") or ""),
        split=str(manifest.get("split") or ""),
        cases=tuple(evaluated_cases),
        skipped_cases=tuple(skipped_cases),
        variants=variant_values,
    )


def _confined_output_dir(output_dir: str | Path, benchmark_root: Path) -> Path:
    """Resolve a result directory and confine it to the benchmark artifact.

    ``--results-dir`` is caller supplied, and every retained result belongs
    under the benchmark root that produced it.  Resolving first, then
    requiring containment, keeps a traversal-style argument from writing
    outside the artifact tree.
    """
    resolved = Path(output_dir).expanduser().resolve()
    confine_to = Path(benchmark_root).expanduser().resolve()
    if resolved != confine_to and not resolved.is_relative_to(confine_to):
        raise ValueError(
            f"refusing to write results outside the benchmark root {confine_to}: "
            f"{resolved}"
        )
    return resolved


def write_benchmark_evaluation(
    evaluation: BenchmarkEvaluation,
    output_dir: str | Path,
) -> Path:
    root = _confined_output_dir(output_dir, evaluation.benchmark_root)
    root.mkdir(parents=True, exist_ok=True)
    _write_json(root / "summary.json", evaluation.to_dict())

    subset = {
        "name": f"{evaluation.suite}.{evaluation.split}.python-classes-functions-methods-variables",
        "source_manifest": str(evaluation.source_manifest),
        "cases": [
            {
                "case_id": case.case_id,
                "source_path": case.source_path,
                "manifest": case.manifest.to_dict(),
                "skipped_labels": [
                    skipped.to_dict() for skipped in case.skipped_labels
                ],
            }
            for case in evaluation.cases
        ],
        "skipped_cases": [case.to_dict() for case in evaluation.skipped_cases],
    }
    _write_json(root / "research_subset_manifest.json", subset)

    for case in evaluation.cases:
        for variant, ablation in case.ablations.items():
            _write_json(
                root / "raw" / case.case_id / f"{variant}.json",
                ablation.to_dict(),
            )
        for variant, score in case.scores.items():
            _write_json(
                root / "scores" / case.case_id / f"{variant}.json",
                score.to_dict(),
            )

    return root


def default_result_dir(
    benchmark_root: str | Path,
    *,
    source_manifest: str | Path,
    timestamp: datetime | None = None,
) -> Path:
    root = Path(benchmark_root).resolve()
    stamp = (timestamp or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    stem = Path(source_manifest).name.replace(".json", "")
    return root / "results" / "local" / "research_dead_code" / stem / stamp


def _ground_truth_manifest_for_case(
    case: dict[str, Any],
    case_root: Path,
    symbols: Iterable[SymbolKey],
) -> tuple[GroundTruthManifest, list[SkippedBenchmarkLabel]]:
    case_id = str(case.get("id") or "unnamed")
    labels = case.get("labels", [])
    ground_truth: list[GroundTruthCase] = []
    skipped: list[SkippedBenchmarkLabel] = []
    used_qnames: set[str] = set()
    symbol_list = tuple(symbols)

    for label in labels:
        match = label.get("match", {})
        if not isinstance(match, dict):
            match = {}
        expectation = str(label.get("expectation") or "")
        expected = _expected_label(expectation)
        path = str(match.get("path") or "")
        simple_symbol = str(match.get("symbol") or "")
        if expected is None:
            skipped.append(
                _skipped_label(case_id, label, "unsupported_expectation")
            )
            continue
        if not path or not simple_symbol:
            skipped.append(
                _skipped_label(case_id, label, "missing_path_or_symbol_match")
            )
            continue

        matching_symbols = _matching_symbols(
            symbol_list,
            case_root,
            path=path,
            simple_symbol=simple_symbol,
            line=match.get("line"),
        )
        if not matching_symbols:
            skipped.append(_skipped_label(case_id, label, "unsupported_symbol_kind"))
            continue
        if len(matching_symbols) > 1:
            skipped.append(_skipped_label(case_id, label, "ambiguous_symbol_match"))
            continue

        symbol = matching_symbols[0]
        if symbol.qualified_name in used_qnames:
            skipped.append(_skipped_label(case_id, label, "duplicate_symbol_label"))
            continue
        used_qnames.add(symbol.qualified_name)
        ground_truth.append(
            GroundTruthCase(
                qualified_name=symbol.qualified_name,
                expected=expected,
                file=symbol.repo_relative_file(case_root),
                note=str(label.get("review", {}).get("reason") or ""),
            )
        )

    return (
        GroundTruthManifest(
            name=case_id,
            description=f"Research-scoped labels for benchmark case {case_id}.",
            cases=tuple(ground_truth),
        ),
        skipped,
    )


def _matching_symbols(
    symbols: Iterable[SymbolKey],
    case_root: Path,
    *,
    path: str,
    simple_symbol: str,
    line: Any,
) -> list[SymbolKey]:
    candidates: list[SymbolKey] = []
    for symbol in symbols:
        if symbol.kind not in {"class", "function", "method", "variable"}:
            continue
        if not _path_matches(path, symbol.repo_relative_file(case_root)):
            continue
        if symbol.qualified_name.rsplit(".", 1)[-1] != simple_symbol:
            continue
        if not _line_matches(line, symbol.line):
            continue
        candidates.append(symbol)
    return candidates


def _expected_label(expectation: str) -> GroundTruthLabel | None:
    if expectation == "should_report":
        return GroundTruthLabel.DEAD
    if expectation == "should_not_report":
        return GroundTruthLabel.ALIVE
    return None


def _skipped_label(
    case_id: str,
    label: dict[str, Any],
    reason: str,
) -> SkippedBenchmarkLabel:
    match = label.get("match", {})
    if not isinstance(match, dict):
        match = {}
    return SkippedBenchmarkLabel(
        case_id=case_id,
        label_id=str(label.get("id") or ""),
        reason=reason,
        expectation=str(label.get("expectation") or ""),
        category=str(label.get("category") or ""),
        path=str(match.get("path") or ""),
        symbol=str(match.get("symbol") or ""),
    )


def _aggregate_variant(
    cases: Iterable[EvaluatedBenchmarkCase],
    variant: str,
    *,
    extra_as_false_positive: bool = False,
    binary_no_report: bool = False,
) -> ScoreSummary:
    totals = {
        "true_positive": 0,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 0,
        "abstain": 0,
        "missing": 0,
        "extra": 0,
    }
    for case in cases:
        score = case.scores.get(variant)
        if score is None:
            continue
        summary = score.binary_no_report_summary if binary_no_report else score.summary
        if extra_as_false_positive:
            summary = summary.with_extra_as_false_positive()
        totals["true_positive"] += summary.true_positive
        totals["false_positive"] += summary.false_positive
        totals["false_negative"] += summary.false_negative
        totals["true_negative"] += summary.true_negative
        totals["abstain"] += summary.abstain
        totals["missing"] += summary.missing
        totals["extra"] += summary.extra
    return ScoreSummary(**totals)


def _path_matches(expected: str, actual: str) -> bool:
    expected_norm = expected.replace("\\", "/").lower()
    actual_norm = actual.replace("\\", "/").lower()
    return actual_norm == expected_norm or actual_norm.endswith("/" + expected_norm)


def _line_matches(expected: Any, actual: int) -> bool:
    if expected in (None, "", []):
        return True
    try:
        expected_int = int(expected)
    except (TypeError, ValueError):
        return False
    return abs(expected_int - int(actual)) <= 2


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _rounded_seconds(value: float) -> float:
    return round(value, 6)
