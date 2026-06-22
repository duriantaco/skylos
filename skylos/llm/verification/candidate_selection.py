from __future__ import annotations

from typing import Any

from skylos.llm.dead_code_verifier import Verdict, _parse_confidence, _parse_int

from .runtime import VerificationRuntime


def run_candidate_selection_phase(
    ctx: VerificationRuntime,
    findings: list[dict],
    discovered_eps: list[Any],
    *,
    max_verify: int,
    confidence_range: tuple[int, int],
    judge_all_mode: bool,
) -> list[dict]:
    with ctx.phase(
        "candidate_selection",
        {
            "finding_count": len(findings),
            "max_verify": max_verify,
            "confidence_low": confidence_range[0],
            "confidence_high": confidence_range[1],
        },
    ) as phase_step:
        lo, hi = confidence_range
        to_verify = []
        for finding in findings:
            if _should_judge_candidate(finding, judge_all_mode, lo, hi):
                _select_judged_candidate(
                    ctx,
                    finding,
                    discovered_eps,
                    judge_all_mode,
                    to_verify,
                )
            else:
                _mark_candidate_skipped(finding, hi)

        to_verify = to_verify[:max_verify]
        _record_candidate_selection_decisions(ctx, findings, to_verify)
        phase_step.set_output_summary(
            to_verify=len(to_verify),
            deterministic_suppressed=ctx.stats.deterministic_suppressed,
            verified_false_positive=ctx.stats.verified_false_positive,
        )
    return to_verify


def _should_judge_candidate(
    finding: dict,
    judge_all_mode: bool,
    confidence_low: int,
    confidence_high: int,
) -> bool:
    conf = _parse_confidence(finding.get("confidence", 60))
    refs = _parse_int(finding.get("references", 0))
    return refs == 0 and (judge_all_mode or confidence_low <= conf <= confidence_high)


def _select_judged_candidate(
    ctx: VerificationRuntime,
    finding: dict,
    discovered_eps: list[Any],
    judge_all_mode: bool,
    to_verify: list[dict],
) -> None:
    matched_ep = _find_discovered_entry_point(finding, discovered_eps)
    if matched_ep is not None:
        _handle_discovered_entry_point(ctx, finding, matched_ep, judge_all_mode, to_verify)
        return
    _handle_deterministic_candidate(ctx, finding, judge_all_mode, to_verify)


def _find_discovered_entry_point(finding: dict, discovered_eps: list[Any]) -> Any | None:
    full_name = finding.get("full_name", finding.get("name", ""))
    return next((ep for ep in discovered_eps if ep.name == full_name), None)


def _handle_discovered_entry_point(
    ctx: VerificationRuntime,
    finding: dict,
    matched_ep: Any,
    judge_all_mode: bool,
    to_verify: list[dict],
) -> None:
    if judge_all_mode:
        finding["_judge_discovered_entry_point"] = (
            f"{matched_ep.source}: {matched_ep.reason}"
        )
        ctx.ops.record_prefilter_fact(
            finding,
            code="discovered_entry_point",
            rationale="Project configuration references this symbol as an entry point",
            evidence=[f"source={matched_ep.source}", f"reason={matched_ep.reason}"],
        )
        to_verify.append(finding)
        return

    finding["_llm_verdict"] = Verdict.FALSE_POSITIVE.value
    finding["_llm_rationale"] = "Discovered as entry point in project config"
    finding["_verified_by_llm"] = True
    finding["_adjusted_confidence"] = 20
    ctx.stats.verified_false_positive += 1


def _handle_deterministic_candidate(
    ctx: VerificationRuntime,
    finding: dict,
    judge_all_mode: bool,
    to_verify: list[dict],
) -> None:
    decision = _run_deterministic_suppression(ctx, finding)
    if decision is None:
        to_verify.append(finding)
        return
    if judge_all_mode and not decision.hard:
        ctx.ops.record_prefilter_fact(
            finding,
            code=decision.code,
            rationale=decision.rationale,
            evidence=decision.evidence,
        )
        to_verify.append(finding)
        return
    _apply_deterministic_suppression(ctx, finding, decision)


def _run_deterministic_suppression(ctx: VerificationRuntime, finding: dict) -> Any:
    return ctx.run_tool(
        "deterministic_suppression",
        lambda finding=finding: ctx.ops.deterministic_suppress(
            finding,
            ctx.source_cache,
            project_root=ctx.grep_root,
            repo_facts=ctx.repo_facts,
            defs_map=ctx.defs_map,
            grep_cache=ctx.grep_cache,
        ),
        input_summary={
            "name": finding.get("full_name") or finding.get("name"),
            "file": finding.get("file"),
            "type": finding.get("type"),
        },
        output_summary=lambda result: {
            "suppressed": result is not None,
            "code": result.code if result is not None else None,
            "hard": bool(result.hard) if result is not None else None,
        },
    )


def _apply_deterministic_suppression(
    ctx: VerificationRuntime,
    finding: dict,
    decision: Any,
) -> None:
    finding["_llm_verdict"] = Verdict.FALSE_POSITIVE.value
    finding["_llm_rationale"] = decision.rationale
    finding["_suppression_reason"] = decision.code
    finding["_suppression_evidence"] = list(decision.evidence)
    finding["_suppression_hard"] = bool(decision.hard)
    finding["_deterministically_suppressed"] = True
    finding["_verified_by_llm"] = False
    finding["_adjusted_confidence"] = 20
    ctx.stats.deterministic_suppressed += 1


def _mark_candidate_skipped(finding: dict, confidence_high: int) -> None:
    conf = _parse_confidence(finding.get("confidence", 60))
    refs = _parse_int(finding.get("references", 0))
    if refs > 0:
        finding["_llm_verdict"] = "SKIPPED_HAS_REFS"
        finding["_llm_rationale"] = f"Has {refs} references"
    elif conf > confidence_high:
        finding["_llm_verdict"] = "SKIPPED_HIGH_CONF"
        finding["_llm_rationale"] = "High confidence from static; skipped LLM"
    else:
        finding["_llm_verdict"] = "SKIPPED_LOW_CONF"
        finding["_llm_rationale"] = "Below threshold"


def _record_candidate_selection_decisions(
    ctx: VerificationRuntime,
    findings: list[dict],
    to_verify: list[dict],
) -> None:
    to_verify_ids = {id(finding) for finding in to_verify}
    for finding in findings:
        verdict = str(finding.get("_llm_verdict") or "")
        ctx.record_decision(
            "candidate_selection",
            _candidate_selection_code(finding, verdict, to_verify_ids),
            finding,
            {"verdict": verdict or None},
        )


def _candidate_selection_code(
    finding: dict,
    verdict: str,
    to_verify_ids: set[int],
) -> str:
    if id(finding) in to_verify_ids:
        return "sent_to_llm"
    if finding.get("_deterministically_suppressed"):
        return "deterministically_suppressed"
    if verdict == Verdict.FALSE_POSITIVE.value:
        return "discovered_entry_point"
    if verdict == "SKIPPED_HAS_REFS":
        return "skipped_has_refs"
    if verdict == "SKIPPED_HIGH_CONF":
        return "skipped_high_confidence"
    if verdict == "SKIPPED_LOW_CONF":
        return "skipped_low_confidence"
    return "candidate_unresolved"
