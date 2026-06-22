from __future__ import annotations

import time
from typing import Any

from skylos.llm.dead_code_verifier import Verdict

from .runtime import VerificationRuntime


def run_propagate_alive_phase(
    ctx: VerificationRuntime,
    findings: list[dict],
) -> None:
    with ctx.phase("propagate_alive", {"finding_count": len(findings)}) as phase_step:
        fp_names, tp_findings = _partition_alive_findings(findings)
        findings_by_full_name = {
            finding.get("full_name", ""): finding for finding in findings
        }

        propagated = 0
        for finding in tp_findings:
            if _propagate_from_alive_callers(ctx, finding, fp_names):
                propagated += 1
                continue
            if _propagate_from_mutual_dependency(
                ctx,
                finding,
                fp_names,
                findings_by_full_name,
            ):
                propagated += 1

        if propagated:
            ctx.log(
                "  Transitive alive propagation: "
                f"{propagated} findings reclassified as FP"
            )
        phase_step.set_output_summary(
            true_positive_inputs=len(tp_findings),
            propagated=propagated,
        )


def _partition_alive_findings(findings: list[dict]) -> tuple[set[str], list[dict]]:
    fp_names = set()
    tp_findings = []
    for finding in findings:
        verdict = finding.get("_llm_verdict", "")
        full_name = finding.get("full_name", finding.get("name", ""))
        if verdict == "FALSE_POSITIVE":
            fp_names.add(full_name)
        elif verdict == "TRUE_POSITIVE":
            tp_findings.append(finding)
    return fp_names, tp_findings


def _propagate_from_alive_callers(
    ctx: VerificationRuntime,
    finding: dict,
    fp_names: set[str],
) -> bool:
    alive_callers = [
        caller for caller in finding.get("called_by", []) if caller in fp_names
    ]
    if not alive_callers:
        return False
    _mark_transitive_alive(
        ctx,
        finding,
        fp_names,
        reason=(
            "Transitive alive: called by "
            f"{alive_callers[0]} which is confirmed alive "
            "(FALSE_POSITIVE). Original rationale: "
            f"{finding.get('_llm_rationale', '')}"
        ),
        decision_detail={"alive_caller": alive_callers[0]},
    )
    return True


def _propagate_from_mutual_dependency(
    ctx: VerificationRuntime,
    finding: dict,
    fp_names: set[str],
    findings_by_full_name: dict[str, dict],
) -> bool:
    full_name = finding.get("full_name", finding.get("name", ""))
    for callee in finding.get("calls", []):
        other_finding = findings_by_full_name.get(callee)
        if other_finding is None or callee not in fp_names:
            continue
        if full_name in other_finding.get("called_by", []):
            _mark_transitive_alive(
                ctx,
                finding,
                fp_names,
                reason=(
                    "Transitive alive: mutual dependency with "
                    f"{callee} which is alive. Original rationale: "
                    f"{finding.get('_llm_rationale', '')}"
                ),
                decision_detail={"alive_callee": callee},
            )
            return True
    return False


def _mark_transitive_alive(
    ctx: VerificationRuntime,
    finding: dict,
    fp_names: set[str],
    *,
    reason: str,
    decision_detail: dict[str, Any],
) -> None:
    full_name = finding.get("full_name", finding.get("name", ""))
    finding["_llm_verdict"] = "FALSE_POSITIVE"
    finding["_llm_rationale"] = reason
    finding["_llm_challenged"] = True
    finding["_adjusted_confidence"] = 50
    fp_names.add(full_name)
    ctx.stats.verified_true_positive -= 1
    ctx.stats.verified_false_positive += 1
    ctx.record_decision(
        "propagate_alive",
        "transitive_alive",
        finding,
        decision_detail,
    )


def run_survivor_challenge_phase(
    ctx: VerificationRuntime,
    findings: list[dict],
    *,
    enable_survivor_challenge: bool,
    max_challenge: int,
    batch_mode: bool,
) -> list[dict[str, Any]]:
    new_dead = []
    with ctx.phase(
        "survivor_challenge",
        {
            "enabled": enable_survivor_challenge,
            "max_challenge": max_challenge,
            "batch_mode": batch_mode,
        },
    ) as phase_step:
        survivor_start_calls = ctx.stats.llm_calls
        survivor_start_reclassified = ctx.stats.survivors_reclassified_dead
        survivors: list[dict] = []
        local_on_emit_survivors: list[dict] = []

        if enable_survivor_challenge:
            ctx.log("Pass 4: Challenging survivors with heuristic refs...")
            local_on_emit_survivors = _run_local_survivor_scan(ctx, findings)
            _append_local_survivor_dead(ctx, local_on_emit_survivors, new_dead)
            survivors = _run_survivor_discovery(ctx, findings, max_challenge)
            _challenge_survivors(ctx, survivors, new_dead, batch_mode)

        phase_step.set_output_summary(
            local_reclassified=len(local_on_emit_survivors),
            survivors=len(survivors),
            new_dead=len(new_dead),
            llm_calls=ctx.stats.llm_calls - survivor_start_calls,
            reclassified_dead=(
                ctx.stats.survivors_reclassified_dead
                - survivor_start_reclassified
            ),
        )
    return new_dead


def _run_local_survivor_scan(
    ctx: VerificationRuntime,
    findings: list[dict],
) -> list[dict]:
    return ctx.run_tool(
        "survivor_local_scan",
        lambda: ctx.ops.find_local_on_emit_survivors(
            ctx.defs_map,
            findings,
            ctx.grep_root,
        ),
        input_summary={"finding_count": len(findings)},
        output_summary=lambda result: {"survivors": len(result)},
    )


def _append_local_survivor_dead(
    ctx: VerificationRuntime,
    local_on_emit_survivors: list[dict],
    new_dead: list[dict[str, Any]],
) -> None:
    if not local_on_emit_survivors:
        return
    ctx.stats.survivors_challenged += len(local_on_emit_survivors)
    ctx.stats.survivors_reclassified_dead += len(local_on_emit_survivors)
    for survivor in local_on_emit_survivors:
        new_dead.append(_local_survivor_dead_finding(survivor))
        ctx.record_decision(
            "survivor_challenge",
            "local_survivor_reclassified",
            survivor,
            {"source": "registry_survivor_challenge"},
        )
    ctx.log(
        "  Reclassified "
        f"{len(local_on_emit_survivors)} local on/emit listeners as dead"
    )


def _local_survivor_dead_finding(survivor: dict) -> dict[str, Any]:
    owner = survivor.get("_registry_owner", "registry")
    event_name = survivor.get("_event_name", "")
    symbol_type = survivor.get("type", "function")
    return {
        "name": survivor["name"],
        "simple_name": survivor["simple_name"],
        "full_name": survivor["full_name"],
        "file": survivor["file"],
        "line": survivor["line"],
        "type": symbol_type,
        "confidence": min(95, int(survivor.get("confidence", 50) or 50) + 25),
        "references": 0,
        "message": f"Unused {symbol_type}: {survivor['name']}",
        "_category": "dead_code",
        "_llm_verdict": "TRUE_POSITIVE",
        "_llm_rationale": (
            f"Registered via @{owner}.on('{event_name}') but no "
            f"{owner}.emit('{event_name}') call exists in app/tests."
        ),
        "_source": "registry_survivor_challenge",
    }


def _run_survivor_discovery(
    ctx: VerificationRuntime,
    findings: list[dict],
    max_challenge: int,
) -> list[dict]:
    survivors = ctx.run_tool(
        "survivor_discovery",
        lambda: ctx.ops.find_survivors(ctx.defs_map, findings),
        input_summary={"finding_count": len(findings)},
        output_summary=lambda result: {"survivors": len(result)},
    )
    survivors = survivors[:max_challenge]
    ctx.stats.survivors_challenged += len(survivors)
    return survivors


def _challenge_survivors(
    ctx: VerificationRuntime,
    survivors: list[dict],
    new_dead: list[dict[str, Any]],
    batch_mode: bool,
) -> None:
    if not survivors:
        ctx.log("  No survivors with heuristic refs to challenge.")
        return

    survivor_cache = ctx.ops.build_source_cache([], ctx.defs_map, survivors)
    ctx.source_cache.update(survivor_cache)
    if batch_mode and len(survivors) > 1:
        _run_batch_survivor_challenge(ctx, survivors, new_dead)
    else:
        _run_individual_survivor_challenge(ctx, survivors, new_dead)
    ctx.log(
        f"  Challenged {len(survivors)}, "
        f"reclassified {ctx.stats.survivors_reclassified_dead} as dead"
    )


def _run_batch_survivor_challenge(
    ctx: VerificationRuntime,
    survivors: list[dict],
    new_dead: list[dict[str, Any]],
) -> None:
    planned_calls = max(1, (len(survivors) + 4) // 5)
    ctx.check_llm_budget(planned_calls, "survivor_challenge")
    batch_results = ctx.run_tool(
        "survivor_batch_challenge",
        lambda: ctx.ops.batch_challenge_survivors(
            ctx.agent,
            survivors,
            ctx.defs_map,
            ctx.source_cache,
        ),
        input_summary={
            "survivors": len(survivors),
            "planned_llm_calls": planned_calls,
        },
        output_summary=lambda result: {"result_count": len(result)},
    )
    ctx.add_llm_calls(planned_calls)
    for survivor, result in zip(survivors, batch_results):
        _append_llm_survivor_dead(ctx, survivor, result, new_dead)


def _run_individual_survivor_challenge(
    ctx: VerificationRuntime,
    survivors: list[dict],
    new_dead: list[dict[str, Any]],
) -> None:
    ctx.check_llm_budget(len(survivors), "survivor_challenge")
    for survivor in survivors:
        result = _run_survivor_challenge(ctx, survivor)
        ctx.add_llm_calls(1)
        _append_llm_survivor_dead(ctx, survivor, result, new_dead)


def _run_survivor_challenge(ctx: VerificationRuntime, survivor: dict) -> Any:
    return ctx.run_tool(
        "survivor_challenge",
        lambda survivor=survivor: ctx.ops.challenge_survivor(
            ctx.agent,
            survivor,
            ctx.defs_map,
            ctx.source_cache,
        ),
        input_summary={
            "name": survivor.get("full_name") or survivor.get("name"),
            "file": survivor.get("file"),
        },
        output_summary=lambda result: {
            "verdict": result.verdict.value,
            "suggested_confidence": result.suggested_confidence,
        },
    )


def _append_llm_survivor_dead(
    ctx: VerificationRuntime,
    survivor: dict,
    result: Any,
    new_dead: list[dict[str, Any]],
) -> None:
    if result.verdict != Verdict.TRUE_POSITIVE:
        return
    ctx.stats.survivors_reclassified_dead += 1
    new_dead.append(_llm_survivor_dead_finding(survivor, result))
    ctx.record_decision(
        "survivor_challenge",
        "llm_survivor_reclassified",
        survivor,
        {"source": "llm_survivor_challenge"},
    )


def _llm_survivor_dead_finding(survivor: dict, result: Any) -> dict[str, Any]:
    symbol_type = survivor.get("type", "function")
    return {
        "name": result.name,
        "full_name": result.full_name,
        "file": result.file,
        "line": result.line,
        "type": symbol_type,
        "confidence": result.suggested_confidence,
        "references": 0,
        "heuristic_refs": result.heuristic_refs,
        "message": f"Unused {symbol_type}: {result.name}",
        "_category": "dead_code",
        "_llm_verdict": "TRUE_POSITIVE",
        "_llm_rationale": result.rationale,
        "_source": "llm_survivor_challenge",
    }


def run_finalize_phase(
    ctx: VerificationRuntime,
    findings: list[dict],
    new_dead: list[dict[str, Any]],
    discovered_eps: list[Any],
    *,
    start_time: float,
    verification_mode: str,
) -> dict[str, Any]:
    with ctx.phase("finalize", {"finding_count": len(findings)}) as phase_step:
        ctx.stats.elapsed_seconds = round(time.time() - start_time, 1)

        try:
            usage = (
                getattr(ctx.agent.get_adapter(), "total_usage", {}) or {}
                if ctx.stats.llm_calls
                else {}
            )
        except (AttributeError, ImportError, RuntimeError, TypeError):
            usage = {}
        ctx.stats.prompt_tokens = int(usage.get("prompt_tokens") or 0)
        ctx.stats.completion_tokens = int(usage.get("completion_tokens") or 0)
        ctx.stats.total_tokens = int(usage.get("total_tokens") or 0)

        ctx.log(
            f"\nDone in {ctx.stats.elapsed_seconds}s "
            f"({ctx.stats.llm_calls} LLM calls)"
        )

        output = ctx.ops.build_verification_output(
            findings=findings,
            new_dead=new_dead,
            discovered_eps=discovered_eps,
            stats=ctx.stats,
            verification_mode=verification_mode,
        )

        ctx.ops.attach_feedback_summary(output, ctx.log)

        ctx.grep_cache.save(ctx.grep_root)
        phase_step.set_output_summary(
            verified_findings=len(output.get("verified_findings") or []),
            new_dead_code=len(output.get("new_dead_code") or []),
            total_llm_calls=ctx.stats.llm_calls,
            elapsed_seconds=ctx.stats.elapsed_seconds,
        )
    return output
