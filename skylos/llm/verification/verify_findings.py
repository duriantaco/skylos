from __future__ import annotations

from typing import Any

from skylos.llm.dead_code_verifier import Verdict, _parse_int

from .runtime import VerificationRuntime


def run_verify_findings_phase(
    ctx: VerificationRuntime,
    to_verify: list[dict],
    *,
    batch_mode: bool,
) -> None:
    with ctx.phase(
        "verify_findings",
        {"candidate_count": len(to_verify), "batch_mode": batch_mode},
    ) as phase_step:
        start = _verification_phase_start(ctx)
        reverify_candidate_count = 0

        if batch_mode and len(to_verify) > 1:
            batch_results = _run_batch_verification(ctx, to_verify)
            ctx.add_llm_calls(_batch_verification_llm_calls(batch_results))
            _apply_verification_results(ctx, to_verify, batch_results)
            reverify_candidates = _rich_reverify_candidates(ctx, to_verify)
            reverify_candidate_count = len(reverify_candidates)
            _run_rich_reverification(ctx, reverify_candidates)
        else:
            _run_individual_verification(ctx, to_verify)

        _record_verify_decisions(ctx, to_verify)
        _set_verify_output_summary(ctx, phase_step, start, reverify_candidate_count)


def _verification_phase_start(ctx: VerificationRuntime) -> dict[str, int]:
    return {
        "llm_calls": ctx.stats.llm_calls,
        "true_positive": ctx.stats.verified_true_positive,
        "false_positive": ctx.stats.verified_false_positive,
        "uncertain": ctx.stats.uncertain,
    }


def _run_batch_verification(ctx: VerificationRuntime, to_verify: list[dict]) -> list[Any]:
    planned_verify_calls = ctx.ops.estimate_batches(
        to_verify,
        ctx.defs_map,
        ctx.source_cache,
        repo_facts=ctx.repo_facts,
    )
    ctx.check_llm_budget(planned_verify_calls, "batch_verify")
    ctx.log(
        f"Pass 2: Batch-verifying {len(to_verify)} findings "
        f"({planned_verify_calls} LLM calls)..."
    )
    return ctx.run_tool(
        "batch_verify",
        lambda: ctx.ops.batch_verify_findings(
            ctx.agent,
            to_verify,
            ctx.defs_map,
            ctx.source_cache,
            project_root=ctx.grep_root,
            repo_facts=ctx.repo_facts,
        ),
        input_summary={
            "candidate_count": len(to_verify),
            "planned_llm_calls": planned_verify_calls,
        },
        output_summary=lambda result: {"result_count": len(result)},
    )


def _batch_verification_llm_calls(batch_results: list[Any]) -> int:
    skipped_refs_rationale = "Has " "{references} references; skipped"
    verified_count = len(
        [
            result
            for result in batch_results
            if result.rationale
            != skipped_refs_rationale.format(
                references=_parse_int(result.finding.get("references", 0))
            )
        ]
    )
    return max(1, (verified_count + 4) // 5)


def _apply_verification_results(
    ctx: VerificationRuntime,
    findings: list[dict],
    results: list[Any],
) -> None:
    for finding, result in zip(findings, results):
        _apply_verification_result(ctx, finding, result)


def _apply_verification_result(
    ctx: VerificationRuntime,
    finding: dict,
    result: Any,
) -> None:
    finding["_llm_verdict"] = result.verdict.value
    finding["_llm_rationale"] = result.rationale
    finding["_verified_by_llm"] = result.verdict != Verdict.UNCERTAIN
    finding["_original_confidence"] = result.original_confidence
    finding["_adjusted_confidence"] = result.adjusted_confidence

    if result.verdict == Verdict.TRUE_POSITIVE:
        ctx.stats.verified_true_positive += 1
    elif result.verdict == Verdict.FALSE_POSITIVE:
        ctx.stats.verified_false_positive += 1
        finding["_llm_challenged"] = True
    else:
        ctx.stats.uncertain += 1


def _rich_reverify_candidates(
    ctx: VerificationRuntime,
    findings: list[dict],
) -> list[dict]:
    return [
        finding
        for finding in findings
        if finding.get("_llm_verdict") == "TRUE_POSITIVE"
        and _finding_has_rich_context(ctx, finding)
    ]


def _finding_has_rich_context(ctx: VerificationRuntime, finding: dict) -> bool:
    ctx_text = ctx.ops.build_graph_context(
        finding,
        ctx.defs_map,
        ctx.source_cache,
        project_root=ctx.grep_root,
        repo_facts=ctx.repo_facts,
        grep_cache=ctx.grep_cache,
    )
    lower_context = ctx_text.lower()
    rich_markers = (
        "Inheritance Context",
        "CONFIRMED",
        "cast(",
        "pragma: no cover",
        "Collectible pytest test class: yes",
        "MkDocs hook registration: yes",
        "Definition side effect: yes",
        "Repo-relative file path references",
    )
    return "class_usage" in lower_context or any(
        marker in ctx_text for marker in rich_markers
    )


def _run_rich_reverification(
    ctx: VerificationRuntime,
    reverify_candidates: list[dict],
) -> None:
    if not reverify_candidates:
        return
    ctx.check_llm_budget(len(reverify_candidates), "reverify_findings")
    ctx.log(
        "  Re-verifying "
        f"{len(reverify_candidates)} batch TPs with rich evidence "
        "(individual mode)..."
    )
    for finding in reverify_candidates:
        result = _run_graph_verify(ctx, finding, mode="reverify")
        ctx.add_llm_calls(1)
        _apply_reverify_result(ctx, finding, result)


def _run_graph_verify(ctx: VerificationRuntime, finding: dict, *, mode: str) -> Any:
    return ctx.run_tool(
        "graph_verify",
        lambda finding=finding: ctx.ops.verify_with_graph_context(
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
            "mode": mode,
        },
        output_summary=lambda result: {
            "verdict": result.verdict.value,
            "adjusted_confidence": result.adjusted_confidence,
        },
    )


def _apply_reverify_result(
    ctx: VerificationRuntime,
    finding: dict,
    result: Any,
) -> None:
    if result.verdict == Verdict.TRUE_POSITIVE:
        return

    finding["_llm_verdict"] = result.verdict.value
    finding["_llm_rationale"] = f"[re-verified] {result.rationale}"
    finding["_verified_by_llm"] = result.verdict != Verdict.UNCERTAIN
    finding["_adjusted_confidence"] = result.adjusted_confidence
    ctx.stats.verified_true_positive -= 1

    if result.verdict == Verdict.FALSE_POSITIVE:
        ctx.stats.verified_false_positive += 1
        finding["_llm_challenged"] = True
        ctx.log(f"    Flipped: {finding.get('full_name', '')} TP → FP")
    elif result.verdict == Verdict.UNCERTAIN:
        ctx.stats.uncertain += 1


def _run_individual_verification(
    ctx: VerificationRuntime,
    to_verify: list[dict],
) -> None:
    ctx.check_llm_budget(len(to_verify), "verify_findings")
    ctx.log(f"Pass 2: Verifying {len(to_verify)} findings with graph context...")
    for index, finding in enumerate(to_verify):
        result = _run_graph_verify(ctx, finding, mode="verify")
        ctx.add_llm_calls(1)
        _apply_verification_result(ctx, finding, result)
        if (index + 1) % 10 == 0:
            ctx.log(f"  Verified {index + 1}/{len(to_verify)}...")


def _record_verify_decisions(ctx: VerificationRuntime, to_verify: list[dict]) -> None:
    for finding in to_verify:
        verdict = str(finding.get("_llm_verdict") or "")
        ctx.record_decision(
            "verify_findings",
            _verify_decision_code(verdict),
            finding,
            {"verdict": verdict or None},
        )


def _verify_decision_code(verdict: str) -> str:
    if verdict == Verdict.TRUE_POSITIVE.value:
        return "verified_true_positive"
    if verdict == Verdict.FALSE_POSITIVE.value:
        return "verified_false_positive"
    if verdict == Verdict.UNCERTAIN.value:
        return "verified_uncertain"
    return "verification_unresolved"


def _set_verify_output_summary(
    ctx: VerificationRuntime,
    phase_step: Any,
    start: dict[str, int],
    reverify_candidate_count: int,
) -> None:
    phase_step.set_output_summary(
        llm_calls=ctx.stats.llm_calls - start["llm_calls"],
        verified_true_positive=(
            ctx.stats.verified_true_positive - start["true_positive"]
        ),
        verified_false_positive=(
            ctx.stats.verified_false_positive - start["false_positive"]
        ),
        uncertain=ctx.stats.uncertain - start["uncertain"],
        reverify_candidates=reverify_candidate_count,
    )
