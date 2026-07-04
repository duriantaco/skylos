from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ACCEPTED_OUTCOME = "accepted"
REFUTED_OUTCOME = "refuted"
UNCERTAIN_OUTCOME = "uncertain"

ACCEPTED_VERDICTS = {"ACCEPTED", "SUPPORTED", "TRUE_POSITIVE", "REAL"}
REFUTED_VERDICT = "REFUTED"
UNCERTAIN_VERDICT = "UNCERTAIN"

DECISIONS_FIELD = "decisions"
ID_FIELD = "id"
VERDICT_FIELD = "verdict"
REASON_FIELD = "reason"
STATIC_PROOF_FIELD = "static_proof"
PROOF_KIND_FIELD = "proof_kind"
PROOF_LINES_FIELD = "proof_lines"


@dataclass(frozen=True)
class AIDefectChallengeProbe:
    id: int
    rule_id: str
    category: str
    severity: str
    file: str
    line: int
    message: str
    symbol: str = ""
    evidence_contract: dict[str, Any] | None = None
    code_context: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "symbol": self.symbol,
            "evidence_contract": _json_dict(self.evidence_contract),
            "code_context": self.code_context,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class AIDefectChallengeDecision:
    id: int
    verdict: str
    reason: str = ""
    static_proof: str = ""
    proof_kind: str = ""
    proof_lines: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "verdict": self.verdict,
            "reason": self.reason,
            "static_proof": self.static_proof,
            "proof_kind": self.proof_kind,
            "proof_lines": list(self.proof_lines),
        }


@dataclass(frozen=True)
class AIDefectChallengeOutcome:
    probe: AIDefectChallengeProbe
    outcome: str
    reason: str = ""
    static_proof: str = ""
    proof_kind: str = ""
    proof_lines: tuple[int, ...] = ()
    suppression_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe": self.probe.to_dict(),
            "outcome": self.outcome,
            "reason": self.reason,
            "static_proof": self.static_proof,
            "proof_kind": self.proof_kind,
            "proof_lines": list(self.proof_lines),
            "suppression_allowed": self.suppression_allowed,
        }


def _json_dict(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return dict(value)
