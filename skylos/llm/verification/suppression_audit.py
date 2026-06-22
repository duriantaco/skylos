from __future__ import annotations

from typing import Any

from skylos.llm.dead_code_verifier import Verdict

from .runtime import VerificationRuntime


def run_suppression_audit_phase(
    ctx: VerificationRuntime,
    findings: list[dict],
    *,
    enable_suppression_challenge: bool,
    max_suppression_audit: int,
) -> None:
    with ctx.phase(
        "suppression_audit",
        {
            "enabled": enable_suppression_challenge,
            "max_suppression_audit": max_suppression_audit,
        },
    ) as phase_step:
        start_calls = ctx.stats.llm_calls
        start_reclassified = ctx.stats.suppression_reclassified_dead
        suppression_candidates: list[dict] = []

        if enable_suppression_challenge:
            suppression_candidates = _suppression_audit_candidates(
                ctx,
                findings,
                max_suppression_audit,
            )
            _audit_suppression_candidates(ctx, suppression_candidates)
            _record_suppression_audit_decisions(ctx, suppression_candidates)

        phase_step.set_output_summary(
            audited=len(suppression_candidates),
            llm_calls=ctx.stats.llm_calls - start_calls,
            reclassified_dead=(
                ctx.stats.suppression_reclassified_dead - start_reclassified
            ),
        )


def _suppression_audit_candidates(
    ctx: VerificationRuntime,
    findings: list[dict],
    max_suppression_audit: int,
) -> list[dict]:
    candidates = [
        finding
        for finding in findings
        if ctx.ops.should_audit_suppression(finding)
    ][:max_suppression_audit]
    ctx.stats.suppression_challenged = len(candidates)
    return candidates


def _audit_suppression_candidates(
    ctx: VerificationRuntime,
    suppression_candidates: list[dict],
) -> None:
    if not suppression_candidates:
        return
    ctx.check_llm_budget(len(suppression_candidates), "suppression_audit")
    ctx.log(
        "Pass 3: Auditing "
        f"{len(suppression_candidates)} FALSE_POSITIVE decisions "
        "for false negatives..."
    )
    for finding in suppression_candidates:
        result = _run_suppression_audit(ctx, finding)
        ctx.add_llm_calls(1)
        _apply_suppression_audit_result(ctx, finding, result)


def _run_suppression_audit(ctx: VerificationRuntime, finding: dict) -> Any:
    return ctx.run_tool(
        "suppression_audit",
        lambda finding=finding: ctx.ops.audit_suppressed_finding(
            ctx.agent,
            finding,
            ctx.defs_map,
            ctx.source_cache,
            project_root=ctx.grep_root,
            repo_facts=ctx.repo_facts,
        ),
        input_summary={
            "name": finding.get("full_name") or finding.get("name"),
            "file": finding.get("file"),
        },
        output_summary=lambda result: {
            "verdict": result.verdict.value,
            "adjusted_confidence": result.adjusted_confidence,
        },
    )


def _apply_suppression_audit_result(
    ctx: VerificationRuntime,
    finding: dict,
    result: Any,
) -> None:
    finding["_suppression_audited"] = True
    finding["_suppression_audit_verdict"] = result.verdict.value
    finding["_suppression_audit_rationale"] = result.rationale

    if result.verdict == Verdict.TRUE_POSITIVE:
        _reopen_suppressed_finding(ctx, finding, result)
    elif result.verdict == Verdict.FALSE_POSITIVE:
        _confirm_suppressed_finding(finding)


def _reopen_suppressed_finding(
    ctx: VerificationRuntime,
    finding: dict,
    result: Any,
) -> None:
    finding["_llm_verdict"] = Verdict.TRUE_POSITIVE.value
    finding["_llm_rationale"] = f"[suppression-audit] {result.rationale}"
    finding["_verified_by_llm"] = True
    finding["_adjusted_confidence"] = result.adjusted_confidence
    finding["_llm_challenged"] = True
    finding["_suppression_reopened"] = True

    if finding.get("_deterministically_suppressed"):
        _overrule_deterministic_suppression(ctx, finding)
    else:
        ctx.stats.verified_false_positive -= 1

    ctx.stats.verified_true_positive += 1
    ctx.stats.suppression_reclassified_dead += 1


def _overrule_deterministic_suppression(
    ctx: VerificationRuntime,
    finding: dict,
) -> None:
    ctx.stats.deterministic_suppressed -= 1
    finding["_deterministically_suppressed"] = False
    if finding.get("_suppression_reason"):
        finding["_suppression_overruled_reason"] = finding.get("_suppression_reason")
        finding.pop("_suppression_reason", None)
    if finding.get("_suppression_evidence"):
        finding["_suppression_overruled_evidence"] = finding.get("_suppression_evidence")
        finding.pop("_suppression_evidence", None)


def _confirm_suppressed_finding(finding: dict) -> None:
    if finding.get("_deterministically_suppressed"):
        finding["_verified_by_llm"] = True


def _record_suppression_audit_decisions(
    ctx: VerificationRuntime,
    suppression_candidates: list[dict],
) -> None:
    for finding in suppression_candidates:
        ctx.record_decision(
            "suppression_audit",
            _suppression_audit_decision_code(finding),
            finding,
            {"verdict": finding.get("_suppression_audit_verdict")},
        )


def _suppression_audit_decision_code(finding: dict) -> str:
    if finding.get("_suppression_reopened"):
        return "suppression_reopened"
    if finding.get("_suppression_audited"):
        return "suppression_confirmed"
    return "suppression_pending"
