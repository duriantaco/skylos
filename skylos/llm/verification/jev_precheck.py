"""Route or judge static dead-code candidates with optional Jev evidence.

The legacy precheck only skips the broad verifier for confident agreement.
Judge mode also accepts confident retained answers as final suppressions.
Neither mode authorizes automatic fixes.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from .runtime import VerificationRuntime


def _valid_confidence(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and 0.0 <= number <= 1.0 else None


def run_jev_precheck_phase(
    ctx: VerificationRuntime,
    to_verify: list[dict],
    *,
    project_root: Path,
    jev_judge: bool = False,
    jev_only: bool = False,
) -> list[dict]:
    if jev_only and not jev_judge:
        raise ValueError("jev_only requires jev_judge")
    if not to_verify:
        return to_verify

    from skylos.llm.jev_triage import (
        MIN_AGREEMENT_CONFIDENCE,
        MIN_JUDGE_CONFIDENCE,
        triage_findings,
    )

    threshold = MIN_JUDGE_CONFIDENCE if jev_judge else MIN_AGREEMENT_CONFIDENCE

    with ctx.phase(
        "jev_precheck",
        {"candidate_count": len(to_verify), "judge": jev_judge},
    ) as phase_step:
        try:
            decisions = ctx.run_tool(
                "jev_precheck",
                lambda: triage_findings(
                    project_root,
                    to_verify,
                    min_confidence=threshold,
                ),
                input_summary={
                    "candidate_count": len(to_verify),
                    "min_confidence": threshold,
                },
                output_summary=lambda result: {"decision_count": len(result)},
            )
        except Exception as exc:
            ctx.log(f"Jev precheck unavailable ({type(exc).__name__}); using LLM")
            decisions = None

        if not isinstance(decisions, list) or len(decisions) != len(to_verify):
            decisions = [{} for _ in to_verify]

        remaining = []
        for finding, decision in zip(to_verify, decisions):
            for key in (
                "_jev_agreed",
                "_jev_judged_retained",
                "_jev_status",
                "_jev_choice",
                "_jev_confidence",
                "_jev_choice_probability",
                "_jev_unverified",
            ):
                finding.pop(key, None)
            if jev_only:
                # A reused candidate must not inherit an old LLM verdict when
                # Jev cannot decide; no LLM runs in this mode to replace it.
                finding.pop("_llm_verdict", None)
                finding.pop("_llm_rationale", None)
                finding["_verified_by_llm"] = False
            if not isinstance(decision, dict):
                decision = {}
            status = decision.get("status")
            choice = decision.get("choice")
            confidence = _valid_confidence(decision.get("confidence"))
            probability = _valid_confidence(decision.get("choice_probability"))
            confident = confidence is not None and confidence >= threshold
            if jev_judge:
                confident = (
                    confident and probability is not None and probability >= threshold
                )
            if status == "agreed" and choice == "unreferenced" and confident:
                finding["_jev_agreed"] = True
                finding["_jev_status"] = "agreed"
                finding["_jev_choice"] = choice
                finding["_jev_confidence"] = confidence
                if probability is not None:
                    finding["_jev_choice_probability"] = probability
                if jev_judge:
                    # A Jev verdict is not an LLM verdict and must not become
                    # eligible for the existing LLM-approved fix path.
                    finding.pop("_llm_verdict", None)
                    finding.pop("_llm_rationale", None)
                    finding["_verified_by_llm"] = False
                    finding["_source"] = "jev_dead_code_verifier"
                ctx.stats.jev_agreed += 1
                ctx.record_decision(
                    "jev_precheck",
                    "jev_judged_unused" if jev_judge else "skipped_broad_llm",
                    finding,
                    {
                        "choice": choice,
                        "confidence": confidence,
                        "choice_probability": probability,
                    },
                )
                continue

            if (
                jev_judge
                and status == "disagreed"
                and choice == "retained"
                and confident
            ):
                finding["_jev_judged_retained"] = True
                finding["_jev_status"] = "disagreed"
                finding["_jev_choice"] = choice
                finding["_jev_confidence"] = confidence
                finding["_jev_choice_probability"] = probability
                # FALSE_POSITIVE is the verifier's existing suppression
                # interop field. Provenance remains Jev, never an LLM claim.
                finding["_llm_verdict"] = "FALSE_POSITIVE"
                finding["_llm_rationale"] = (
                    "Jev found the symbol retained by a live use"
                )
                finding["_verified_by_llm"] = False
                finding["_source"] = "jev_dead_code_verifier"
                finding["_suppression_hard"] = True
                finding["_adjusted_confidence"] = 20
                ctx.stats.jev_disagreed += 1
                ctx.stats.jev_judged_retained += 1
                ctx.stats.verified_false_positive += 1
                ctx.record_decision(
                    "jev_precheck",
                    "jev_judged_retained",
                    finding,
                    {
                        "choice": choice,
                        "confidence": confidence,
                        "choice_probability": probability,
                    },
                )
                continue

            if status == "disagreed" and choice == "retained" and confident:
                normalized = "disagreed"
                ctx.stats.jev_disagreed += 1
            elif status == "uncertain" and choice in {
                "retained",
                "unreferenced",
                "insufficient_evidence",
            }:
                normalized = "uncertain"
                ctx.stats.jev_uncertain += 1
            else:
                normalized = "unavailable"
                ctx.stats.jev_unavailable += 1
            finding["_jev_status"] = normalized
            if choice in {"retained", "unreferenced", "insufficient_evidence"}:
                finding["_jev_choice"] = choice
            if confidence is not None:
                finding["_jev_confidence"] = confidence
            if probability is not None:
                finding["_jev_choice_probability"] = probability
            if jev_only:
                finding["_jev_unverified"] = True
                ctx.stats.uncertain += 1
            remaining.append(finding)
            ctx.record_decision(
                "jev_precheck",
                "jev_unverified" if jev_only else "sent_to_broad_llm",
                finding,
                {"status": normalized, "choice": finding.get("_jev_choice")},
            )

        if jev_only:
            ctx.log(
                f"Jev only: {ctx.stats.jev_agreed} judged unused, "
                f"{ctx.stats.jev_judged_retained} judged retained, "
                f"{len(remaining)} left unverified"
            )
        elif jev_judge:
            ctx.log(
                f"Jev judge: {ctx.stats.jev_agreed} judged unused, "
                f"{ctx.stats.jev_judged_retained} judged retained, "
                f"{len(remaining)} sent to broad LLM"
            )
        else:
            ctx.log(
                f"Jev precheck: {ctx.stats.jev_agreed} agreed/skipped, "
                f"{len(remaining)} sent to broad LLM"
            )
        phase_step.set_output_summary(
            agreed=ctx.stats.jev_agreed,
            disagreed=ctx.stats.jev_disagreed,
            judged_retained=ctx.stats.jev_judged_retained,
            uncertain=ctx.stats.jev_uncertain,
            unavailable=ctx.stats.jev_unavailable,
            sent_to_broad_llm=0 if jev_only else len(remaining),
            unverified=len(remaining) if jev_only else 0,
        )
    return remaining
