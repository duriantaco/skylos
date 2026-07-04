from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from skylos.llm.schemas import normalize_json_response_text

from .ai_defect_challenge_models import (
    ACCEPTED_OUTCOME,
    ACCEPTED_VERDICTS,
    DECISIONS_FIELD,
    ID_FIELD,
    PROOF_KIND_FIELD,
    PROOF_LINES_FIELD,
    REASON_FIELD,
    REFUTED_OUTCOME,
    REFUTED_VERDICT,
    STATIC_PROOF_FIELD,
    UNCERTAIN_OUTCOME,
    UNCERTAIN_VERDICT,
    VERDICT_FIELD,
    AIDefectChallengeDecision,
    AIDefectChallengeOutcome,
    AIDefectChallengeProbe,
)
from .ai_defect_challenge_proof import StaticProofDetector

logger = logging.getLogger(__name__)


def normalize_ai_defect_challenge_decisions(
    response: Any,
    *,
    expected_count: int,
) -> list[AIDefectChallengeDecision]:
    decisions = _parse_decisions(response)
    decision_map = {
        decision.id: decision
        for decision in decisions
        if 1 <= decision.id <= expected_count
    }
    normalized = []
    for index in range(1, expected_count + 1):
        normalized.append(
            decision_map.get(
                index,
                AIDefectChallengeDecision(
                    id=index,
                    verdict=UNCERTAIN_VERDICT,
                    reason="Challenge response omitted this candidate.",
                ),
            )
        )
    return normalized


def apply_ai_defect_challenge_decisions(
    probes: list[AIDefectChallengeProbe],
    decisions: list[AIDefectChallengeDecision],
    *,
    proof_detector: StaticProofDetector | None = None,
    project_root: str | Path = ".",
) -> list[AIDefectChallengeOutcome]:
    proof_detector = proof_detector or StaticProofDetector()
    decision_map = {decision.id: decision for decision in decisions}
    outcomes = []
    for probe in probes:
        decision = decision_map.get(
            probe.id,
            AIDefectChallengeDecision(
                id=probe.id,
                verdict=UNCERTAIN_VERDICT,
                reason="Challenge response omitted this candidate.",
            ),
        )
        outcomes.append(
            _decision_to_outcome(
                probe,
                decision,
                proof_detector=proof_detector,
                project_root=project_root,
            )
        )
    return outcomes


def challenge_outcome_counts(
    outcomes: list[AIDefectChallengeOutcome],
) -> dict[str, int]:
    counts = {
        "challenged": len(outcomes),
        ACCEPTED_OUTCOME: 0,
        REFUTED_OUTCOME: 0,
        UNCERTAIN_OUTCOME: 0,
        "suppression_allowed": 0,
    }
    for outcome in outcomes:
        if outcome.outcome in {
            ACCEPTED_OUTCOME,
            REFUTED_OUTCOME,
            UNCERTAIN_OUTCOME,
        }:
            counts[outcome.outcome] += 1
        if outcome.suppression_allowed:
            counts["suppression_allowed"] += 1
    return counts


def build_ai_defect_challenge_metadata(
    *,
    findings: list[dict[str, Any]],
    outcomes: list[AIDefectChallengeOutcome],
    skipped_count: int,
) -> dict[str, Any]:
    counts = challenge_outcome_counts(outcomes)
    counts["skipped"] = skipped_count
    return {
        "challenge": {
            "schema_version": 1,
            "finding_count": len(findings),
            "outcome_counts": counts,
            "outcomes": [outcome.to_dict() for outcome in outcomes],
            "deterministic_findings_retained": True,
        }
    }


def _decision_to_outcome(
    probe: AIDefectChallengeProbe,
    decision: AIDefectChallengeDecision,
    *,
    proof_detector: StaticProofDetector,
    project_root: str | Path,
) -> AIDefectChallengeOutcome:
    verdict = decision.verdict.strip().upper()
    if verdict in ACCEPTED_VERDICTS:
        return _accepted_outcome(probe, decision)
    if verdict == REFUTED_VERDICT:
        return _refuted_or_uncertain_outcome(
            probe,
            decision,
            proof_detector=proof_detector,
            project_root=project_root,
        )
    return _uncertain_outcome(probe, decision)


def _accepted_outcome(
    probe: AIDefectChallengeProbe,
    decision: AIDefectChallengeDecision,
) -> AIDefectChallengeOutcome:
    return AIDefectChallengeOutcome(
        probe=probe,
        outcome=ACCEPTED_OUTCOME,
        reason=decision.reason,
        static_proof=decision.static_proof,
        proof_kind=decision.proof_kind,
        proof_lines=decision.proof_lines,
        suppression_allowed=False,
    )


def _refuted_or_uncertain_outcome(
    probe: AIDefectChallengeProbe,
    decision: AIDefectChallengeDecision,
    *,
    proof_detector: StaticProofDetector,
    project_root: str | Path,
) -> AIDefectChallengeOutcome:
    if proof_detector.allows_refutation(probe, decision, project_root=project_root):
        return AIDefectChallengeOutcome(
            probe=probe,
            outcome=REFUTED_OUTCOME,
            reason=decision.reason,
            static_proof=decision.static_proof,
            proof_kind=decision.proof_kind,
            proof_lines=decision.proof_lines,
            suppression_allowed=True,
        )
    return AIDefectChallengeOutcome(
        probe=probe,
        outcome=UNCERTAIN_OUTCOME,
        reason=decision.reason or "REFUTED verdict omitted static proof.",
        static_proof=decision.static_proof,
        proof_kind=decision.proof_kind,
        proof_lines=decision.proof_lines,
        suppression_allowed=False,
    )


def _uncertain_outcome(
    probe: AIDefectChallengeProbe,
    decision: AIDefectChallengeDecision,
) -> AIDefectChallengeOutcome:
    return AIDefectChallengeOutcome(
        probe=probe,
        outcome=UNCERTAIN_OUTCOME,
        reason=decision.reason,
        static_proof=decision.static_proof,
        proof_kind=decision.proof_kind,
        proof_lines=decision.proof_lines,
        suppression_allowed=False,
    )


def _parse_decisions(response: Any) -> list[AIDefectChallengeDecision]:
    if response is None:
        return []
    if isinstance(response, list):
        raw_decisions = response
    elif isinstance(response, dict):
        raw_decisions = response.get(DECISIONS_FIELD)
    elif isinstance(response, str):
        raw_decisions = _parse_json_decisions(response)
    else:
        return []

    if not isinstance(raw_decisions, list):
        return []
    decisions = []
    for item in raw_decisions:
        decision = _normalize_decision(item)
        if decision is not None:
            decisions.append(decision)
    return decisions


def _parse_json_decisions(response: str) -> Any:
    try:
        payload = json.loads(normalize_json_response_text(response))
    except json.JSONDecodeError as exc:
        logger.warning("AI-defect challenge response was invalid JSON: %s", exc)
        return []
    if isinstance(payload, dict):
        return payload.get(DECISIONS_FIELD)
    return []


def _normalize_decision(item: Any) -> AIDefectChallengeDecision | None:
    if not isinstance(item, dict):
        return None
    try:
        decision_id = int(item.get(ID_FIELD))
    except (TypeError, ValueError):
        return None
    proof_lines = tuple(_positive_ints(item.get(PROOF_LINES_FIELD)))
    return AIDefectChallengeDecision(
        id=decision_id,
        verdict=str(item.get(VERDICT_FIELD) or UNCERTAIN_VERDICT).upper(),
        reason=str(item.get(REASON_FIELD) or ""),
        static_proof=str(item.get(STATIC_PROOF_FIELD) or ""),
        proof_kind=str(item.get(PROOF_KIND_FIELD) or ""),
        proof_lines=proof_lines,
    )


def _positive_ints(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    lines = []
    for item in value:
        try:
            line = int(item)
        except (TypeError, ValueError):
            continue
        if line >= 1:
            lines.append(line)
    return lines
