from __future__ import annotations

from dataclasses import dataclass, field

from .dead_code_verifier import Verdict


VERIFICATION_MODE_PRODUCTION = "production"

VERIFICATION_MODE_JUDGE_ALL = "judge_all"

VALID_VERIFICATION_MODES = {
    VERIFICATION_MODE_PRODUCTION,
    VERIFICATION_MODE_JUDGE_ALL,
}


@dataclass
class EdgeResolution:
    caller: str
    callee: str
    is_real: bool
    reason: str


@dataclass
class SurvivorVerdict:
    name: str
    full_name: str
    file: str
    line: int
    heuristic_refs: dict
    verdict: Verdict
    rationale: str
    original_confidence: int
    suggested_confidence: int


@dataclass
class SuppressionDecision:
    code: str
    rationale: str
    evidence: list[str] = field(default_factory=list)
    hard: bool = False


@dataclass
class VerifyStats:
    total_findings: int = 0
    verified_true_positive: int = 0
    verified_false_positive: int = 0
    deterministic_suppressed: int = 0
    uncertain: int = 0
    suppression_challenged: int = 0
    suppression_reclassified_dead: int = 0
    survivors_challenged: int = 0
    survivors_reclassified_dead: int = 0
    entry_points_discovered: int = 0
    edges_resolved: int = 0
    edges_spurious: int = 0
    haiku_prefiltered: int = 0
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    elapsed_seconds: float = 0.0
