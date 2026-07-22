from __future__ import annotations

import logging
import os
from typing import Any

from skylos.llm.dead_code_verifier import Verdict, _parse_confidence
from skylos.llm.verification.llm import HAIKU_PREFILTER_MAX_BATCH

from .candidate_selection import run_candidate_selection_phase
from .runtime import VerificationOps, VerificationRuntime
from .suppression_audit import run_suppression_audit_phase
from .verify_findings import run_verify_findings_phase

logger = logging.getLogger(__name__)


def run_entry_discovery_phase(
    ctx: VerificationRuntime,
    *,
    enable_entry_discovery: bool,
) -> list[Any]:
    discovered_eps = []
    if not enable_entry_discovery:
        return discovered_eps

    with ctx.phase(
        "entry_discovery",
        {"definition_count": len(ctx.defs_map)},
    ) as phase_step:
        ctx.log("Pass 1: Discovering hidden entry points...")
        known_eps = []
        for name, info in ctx.defs_map.items():
            if isinstance(info, dict) and info.get("type") in (
                "function",
                "method",
            ):
                known_eps.append(name)

        known_eps = known_eps[:100]
        planned_llm_calls = ctx.ops.entry_discovery_planned_llm_calls(
            ctx.config_root,
            known_eps,
            ctx.repo_facts,
        )
        ctx.check_llm_budget(planned_llm_calls, "entry_discovery")
        discovered_eps = ctx.run_tool(
            "entry_discovery",
            lambda: ctx.ops.discover_entry_points(
                ctx.agent,
                ctx.config_root,
                known_eps,
            ),
            input_summary={"known_entry_points": len(known_eps)},
            output_summary=lambda result: {"entry_points": len(result)},
        )
        ctx.stats.entry_points_discovered = len(discovered_eps)
        ctx.add_llm_calls(planned_llm_calls)

        if discovered_eps:
            ctx.log(f"  Found {len(discovered_eps)} new entry points:")
            for ep in discovered_eps:
                ctx.log(f"    - {ep.name} (from {ep.source})")
        else:
            ctx.log("  No new entry points found.")
        phase_step.set_output_summary(
            entry_points=len(discovered_eps),
            planned_llm_calls=planned_llm_calls,
            llm_calls=planned_llm_calls,
        )
    return discovered_eps


def run_haiku_prefilter_phase(
    ctx: VerificationRuntime,
    to_verify: list[dict],
    *,
    config: Any,
) -> list[dict]:
    with ctx.phase("haiku_prefilter", {"candidate_count": len(to_verify)}) as phase_step:
        haiku_start_calls = ctx.stats.llm_calls
        exported_candidates = []
        dismissed_count = 0
        planned_haiku_calls = 0
        if to_verify:
            haiku_key = config.api_key or os.environ.get("ANTHROPIC_API_KEY")

            exported_candidates = [
                finding
                for finding in to_verify
                if finding.get("is_exported")
                and _parse_confidence(finding.get("confidence", 0)) >= 80
            ]
            if exported_candidates and haiku_key:
                planned_haiku_calls = max(
                    1,
                    (len(exported_candidates) + HAIKU_PREFILTER_MAX_BATCH - 1)
                    // HAIKU_PREFILTER_MAX_BATCH,
                )
                ctx.check_llm_budget(planned_haiku_calls, "haiku_prefilter")
                ctx.log(
                    "Pass 1.5: Haiku pre-filter for "
                    f"{len(exported_candidates)} exported symbols..."
                )
                try:
                    haiku_agent = ctx.ops.create_haiku_agent(haiku_key)
                    kept, dismissed = ctx.run_tool(
                        "haiku_prefilter",
                        lambda: ctx.ops.haiku_prefilter_exports(
                            haiku_agent,
                            exported_candidates,
                            ctx.source_cache,
                        ),
                        input_summary={
                            "exported_candidates": len(exported_candidates),
                            "planned_llm_calls": planned_haiku_calls,
                        },
                        output_summary=lambda result: {
                            "kept": len(result[0]),
                            "dismissed": len(result[1]),
                        },
                    )
                    ctx.stats.haiku_prefiltered = len(dismissed)
                    ctx.stats.verified_false_positive += len(dismissed)
                    ctx.add_llm_calls(planned_haiku_calls)
                    dismissed_count = len(dismissed)
                    dismissed_set = {id(finding) for finding in dismissed}
                    for finding in dismissed:
                        ctx.record_decision(
                            "haiku_prefilter",
                            "haiku_public_api_dismissed",
                            finding,
                            {"verdict": Verdict.FALSE_POSITIVE.value},
                        )
                    to_verify = [
                        finding
                        for finding in to_verify
                        if id(finding) not in dismissed_set
                    ]
                    if dismissed:
                        ctx.log(
                            "  Haiku dismissed "
                            f"{len(dismissed)} exported symbols as public API"
                        )
                except Exception as exc:
                    logger.warning(f"Haiku pre-filter setup failed: {exc}")
        phase_step.set_output_summary(
            exported_candidates=len(exported_candidates),
            dismissed=dismissed_count,
            remaining_to_verify=len(to_verify),
            planned_llm_calls=planned_haiku_calls,
            llm_calls=ctx.stats.llm_calls - haiku_start_calls,
        )
    return to_verify
