from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from skylos.core.api_symbol_truth import (
    SURFACE_KIND_PYTHON_MODULE,
    cached_api_symbol_surface,
)
from skylos.core.python_api_surface import python_environment_key
from skylos.core.safe_cache_io import read_text_no_symlink

from .ai_defect_challenge_models import (
    AIDefectChallengeDecision,
    AIDefectChallengeProbe,
)
from .ai_defect_challenge_probes import (
    MAX_CHALLENGE_CONTEXT_BYTES,
    _resolve_finding_file,
)

_API_KEYWORD_RE = re.compile(r"keyword\s+argument\s+'([^']+)'")

REFUTATION_PROOF_KINDS = {
    "api_signature_valid",
}


class StaticProofDetector:
    def allows_refutation(
        self,
        probe: AIDefectChallengeProbe,
        decision: AIDefectChallengeDecision,
        *,
        project_root: str | Path,
    ) -> bool:
        if not _has_required_static_proof(decision):
            return False
        if not _proof_lines_reference_probe(probe, decision.proof_lines):
            return False

        source_lines = _read_source_lines(_resolve_finding_file(project_root, probe.file))
        if source_lines is None:
            return False
        if not all(1 <= line <= len(source_lines) for line in decision.proof_lines):
            return False

        if decision.proof_kind == "api_signature_valid":
            return _api_signature_refutation_proven(
                probe,
                source_lines,
                project_root=project_root,
            )
        return False


def _has_required_static_proof(decision: AIDefectChallengeDecision) -> bool:
    if not decision.static_proof.strip():
        return False
    if decision.proof_kind not in REFUTATION_PROOF_KINDS:
        return False
    return bool(decision.proof_lines)


def _read_source_lines(source_path: Path) -> list[str] | None:
    source = read_text_no_symlink(
        source_path,
        max_bytes=MAX_CHALLENGE_CONTEXT_BYTES,
        encoding="utf-8",
    )
    if source is None:
        return None
    return source.splitlines()


def _proof_lines_reference_probe(
    probe: AIDefectChallengeProbe,
    proof_lines: tuple[int, ...],
) -> bool:
    return any(abs(line - probe.line) <= 3 for line in proof_lines)


def _api_signature_refutation_proven(
    probe: AIDefectChallengeProbe,
    source_lines: list[str],
    *,
    project_root: str | Path,
) -> bool:
    if probe.rule_id != "SKY-D224":
        return False
    symbol = probe.symbol.strip()
    if not symbol:
        return False
    parts = symbol.split(".")
    if len(parts) < 2:
        return False

    module_name = parts[0]
    member_parts = parts[1:]
    if not _source_mentions_symbol_leaf(source_lines, probe.line, member_parts[-1]):
        return False

    surface = cached_api_symbol_surface(
        project_root,
        SURFACE_KIND_PYTHON_MODULE,
        module_name,
        environment_key=python_environment_key(),
    )
    if surface is None:
        return False
    entry = _surface_symbol_entry(surface, member_parts)
    if not isinstance(entry, dict):
        return False

    keyword = _api_signature_keyword(probe.message)
    if keyword is None:
        return True
    if not _source_mentions_keyword(source_lines, probe.line, keyword):
        return False
    return _entry_accepts_keyword_strict(entry, keyword)


def _api_signature_keyword(message: str) -> str | None:
    match = _API_KEYWORD_RE.search(message)
    if match is None:
        return None
    keyword = match.group(1).strip()
    if not keyword:
        return None
    return keyword


def _source_mentions_symbol_leaf(
    source_lines: list[str],
    line: int,
    leaf: str,
) -> bool:
    if not leaf:
        return False
    start = max(0, line - 4)
    end = min(len(source_lines), line + 3)
    needle = f"{leaf}("
    return any(needle in source_lines[index] for index in range(start, end))


def _source_mentions_keyword(
    source_lines: list[str],
    line: int,
    keyword: str,
) -> bool:
    if not keyword:
        return False
    start = max(0, line - 4)
    end = min(len(source_lines), line + 3)
    needle = f"{keyword}="
    return any(needle in source_lines[index] for index in range(start, end))


def _surface_symbol_entry(
    surface: dict[str, Any],
    member_parts: list[str],
) -> dict[str, Any] | None:
    members = surface.get("members")
    if not isinstance(members, dict):
        return None

    current: dict[str, Any] | None = None
    for index, part in enumerate(member_parts):
        if current is None:
            entry = members.get(part)
        else:
            entry = _nested_surface_member(current, part)
        if not isinstance(entry, dict):
            return None
        if index == len(member_parts) - 1:
            return entry
        current = entry
    return None


def _nested_surface_member(entry: dict[str, Any], name: str) -> Any:
    for key in ("methods", "properties", "members"):
        values = entry.get(key)
        if isinstance(values, dict) and name in values:
            return values[name]
    return None


def _entry_accepts_keyword_strict(entry: dict[str, Any], keyword: str) -> bool:
    parameters = entry.get("parameters")
    if not isinstance(parameters, list) or not parameters:
        return False

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        kind = str(parameter.get("kind"))
        if kind == "VAR_KEYWORD":
            return True
        if parameter.get("name") != keyword:
            continue
        if kind in {"POSITIONAL_OR_KEYWORD", "KEYWORD_ONLY"}:
            return True
    return False
