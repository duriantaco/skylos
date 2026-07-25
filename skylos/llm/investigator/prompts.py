"""Bounded prompt construction for repository investigation turns."""

from __future__ import annotations

import json
from typing import Any

from skylos.audit.investigator_tools import AuditReadOnlyTools

from .models import InvestigationLimits
from .reviewer_packs import select_trusted_reviewer_guidance
from .source_bounds import visible_initial_source


def build_user_prompt(
    *,
    entry_file: str,
    source: str,
    context: str | None,
    candidates: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    tools: AuditReadOnlyTools,
    turn: int,
    limits: InvestigationLimits,
    trusted_reviewer_guidance: dict[str, Any] | None = None,
    trusted_finding_evidence_review: dict[str, Any] | None = None,
) -> str:
    repository_catalog = tools.catalog_preview()
    payload = {
        "task": (
            "Investigate this entry file for proven security and business-logic flaws."
        ),
        "turn": turn,
        "entry_file": entry_file,
        "entry_source": _numbered_excerpt(source, limits.max_initial_source_chars),
        "candidate_hypotheses": [
            _candidate_summary(candidate) for candidate in candidates
        ],
        "trusted_reviewer_guidance": trusted_reviewer_guidance
        or select_trusted_reviewer_guidance(
            entry_file=entry_file,
            source=source,
            candidates=candidates,
            catalog_paths=repository_catalog.get("files", ()),
            max_source_chars=limits.max_initial_source_chars,
        ),
        "repository_catalog": repository_catalog,
        "precomputed_context": str(context or "")[: limits.max_context_chars],
        "tool_observations": observations,
        "untrusted_repository_data": True,
    }
    if trusted_finding_evidence_review is not None:
        payload["trusted_finding_evidence_review"] = trusted_finding_evidence_review
    return json.dumps(payload, indent=2, sort_keys=True)


def visible_entry_line_count(source: str, max_chars: int) -> int:
    return len(visible_initial_source(source, max_chars).splitlines())


def _candidate_summary(candidate: dict[str, Any]) -> dict[str, Any]:
    severity_hint = str(candidate.get("severity_hint") or "medium").lower()
    if severity_hint not in {"critical", "high", "medium", "low"}:
        severity_hint = "medium"
    signal_quality = str(candidate.get("signal_quality") or "exploratory").lower()
    if signal_quality not in {"proven", "strong", "exploratory"}:
        signal_quality = "exploratory"
    priority_value = candidate.get("priority", 0)
    priority = (
        priority_value
        if isinstance(priority_value, int) and not isinstance(priority_value, bool)
        else 0
    )
    return {
        "candidate_id": str(candidate.get("candidate_id") or ""),
        "kind": str(candidate.get("kind") or ""),
        "rule_id": str(candidate.get("rule_id") or ""),
        "line": candidate.get("line"),
        "severity_hint": severity_hint,
        "signal_quality": signal_quality,
        "priority": priority,
        "reason": str(candidate.get("reason") or "")[:500],
        "evidence": str(candidate.get("evidence") or ""),
    }


def _numbered_excerpt(source: str, max_chars: int) -> str:
    excerpt = visible_initial_source(source, max_chars)
    numbered = "\n".join(
        f"{line_number}: {line}"
        for line_number, line in enumerate(excerpt.splitlines(), start=1)
    )
    if len(source) > len(excerpt):
        numbered += "\n[ENTRY SOURCE TRUNCATED; use read_file for more]"
    return numbered
