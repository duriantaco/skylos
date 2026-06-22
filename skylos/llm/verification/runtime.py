from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class VerificationOps:
    discover_entry_points: Any
    entry_discovery_planned_llm_calls: Any
    record_prefilter_fact: Any
    deterministic_suppress: Any
    create_haiku_agent: Any
    haiku_prefilter_exports: Any
    estimate_batches: Any
    batch_verify_findings: Any
    build_graph_context: Any
    verify_with_graph_context: Any
    should_audit_suppression: Any
    audit_suppressed_finding: Any
    find_local_on_emit_survivors: Any
    find_survivors: Any
    build_source_cache: Any
    batch_challenge_survivors: Any
    challenge_survivor: Any
    build_verification_output: Any
    attach_feedback_summary: Any


@dataclass
class VerificationRuntime:
    agent: Any
    defs_map: dict[str, Any]
    grep_root: str
    config_root: Path
    grep_cache: Any
    source_cache: dict[str, str]
    repo_facts: Any
    stats: Any
    log: Any
    phase: Any
    check_llm_budget: Any
    record_decision: Any
    add_llm_calls: Any
    run_tool: Any
    ops: VerificationOps
