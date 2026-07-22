"""Bounded prompt construction for repository investigation turns."""

from __future__ import annotations

import json
from typing import Any

from skylos.audit.investigator_tools import AuditReadOnlyTools

from .models import InvestigationLimits


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
) -> str:
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
        "repository_catalog": tools.catalog_preview(),
        "precomputed_context": str(context or "")[: limits.max_context_chars],
        "tool_observations": observations,
        "untrusted_repository_data": True,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def visible_entry_line_count(source: str, max_chars: int) -> int:
    return len(_visible_entry_source(source, max_chars).splitlines())


def _candidate_summary(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": str(candidate.get("candidate_id") or ""),
        "kind": str(candidate.get("kind") or ""),
        "rule_id": str(candidate.get("rule_id") or ""),
        "line": candidate.get("line"),
        "reason": str(candidate.get("reason") or "")[:500],
        "evidence": str(candidate.get("evidence") or ""),
    }


def _numbered_excerpt(source: str, max_chars: int) -> str:
    excerpt = _visible_entry_source(source, max_chars)
    numbered = "\n".join(
        f"{line_number}: {line}"
        for line_number, line in enumerate(excerpt.splitlines(), start=1)
    )
    if len(source) > len(excerpt):
        numbered += "\n[ENTRY SOURCE TRUNCATED; use read_file for more]"
    return numbered


def _visible_entry_source(source: str, max_chars: int) -> str:
    excerpt = source[:max_chars]
    if len(source) <= len(excerpt) or excerpt.endswith(("\n", "\r")):
        return excerpt
    lines = excerpt.splitlines(keepends=True)
    if not lines:
        return ""
    return "".join(lines[:-1])
