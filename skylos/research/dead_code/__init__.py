"""Research-only dead-code analysis primitives."""

from skylos.research.dead_code.ablation import (
    AblationResult,
    ResearchVariant,
    run_ablation,
)
from skylos.research.dead_code.benchmark_adapter import (
    BenchmarkEvaluation,
    EvaluatedBenchmarkCase,
    SkippedBenchmarkCase,
    SkippedBenchmarkLabel,
    default_result_dir,
    evaluate_benchmark_manifest,
    write_benchmark_evaluation,
)
from skylos.research.dead_code.evidence import (
    CandidateClassification,
    EvidenceEvent,
    EvidenceKind,
    EvidenceLedger,
    SymbolKey,
)
from skylos.research.dead_code.root_inference import RootInferenceConfig, infer_roots
from skylos.research.dead_code.reachability import (
    FunctionGraph,
    ReachabilityResult,
    analyze_reachability,
    build_function_graph,
)
from skylos.research.dead_code.roots import InferredRoot, RootKind, RootSet
from skylos.research.dead_code.scoring import (
    GroundTruthCase,
    GroundTruthLabel,
    GroundTruthManifest,
    ScoreOutcome,
    ScoreSummary,
    ScoredCase,
    ScoringResult,
    load_manifest,
    score_ablation,
    score_ablation_result,
)

__all__ = [
    "AblationResult",
    "BenchmarkEvaluation",
    "CandidateClassification",
    "EvidenceEvent",
    "EvidenceKind",
    "EvidenceLedger",
    "EvaluatedBenchmarkCase",
    "FunctionGraph",
    "GroundTruthCase",
    "GroundTruthLabel",
    "GroundTruthManifest",
    "InferredRoot",
    "ReachabilityResult",
    "ResearchVariant",
    "RootInferenceConfig",
    "RootKind",
    "RootSet",
    "ScoreOutcome",
    "ScoreSummary",
    "ScoredCase",
    "ScoringResult",
    "SkippedBenchmarkCase",
    "SkippedBenchmarkLabel",
    "SymbolKey",
    "analyze_reachability",
    "build_function_graph",
    "default_result_dir",
    "evaluate_benchmark_manifest",
    "infer_roots",
    "load_manifest",
    "run_ablation",
    "score_ablation",
    "score_ablation_result",
    "write_benchmark_evaluation",
]
