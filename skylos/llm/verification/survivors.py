"""Second-pass checks for definitions that survive initial verification."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from ..dead_code_verifier import DeadCodeVerifierAgent, Verdict
from .llm import (
    BATCH_SURVIVOR_SYSTEM,
    MAX_BATCH_CONTEXT_CHARS,
    SURVIVOR_SYSTEM,
    SURVIVOR_USER,
    _call_llm_with_retry,
    _parse_batch_survivor_response,
)
from .types import SurvivorVerdict
from skylos.core.grep_verify import _run_grep

logger = logging.getLogger(__name__)


def _batch_challenge_survivors(
    agent: DeadCodeVerifierAgent,
    survivors: list[dict],
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
) -> list[SurvivorVerdict]:
    results = []
    batch = []
    batch_contexts = []
    batch_size = 0

    for surv in survivors:
        context = _build_survivor_context(surv, source_cache, defs_map)
        if _batch_would_overflow(batch, batch_size, context):
            results.extend(_challenge_survivor_batch(agent, batch, batch_contexts))
            batch = []
            batch_contexts = []
            batch_size = 0

        batch.append(surv)
        batch_contexts.append(context)
        batch_size += len(context)

    results.extend(_challenge_survivor_batch(agent, batch, batch_contexts))
    return results


def _batch_would_overflow(
    batch: list[dict],
    batch_size: int,
    context: str,
) -> bool:
    return bool(batch) and (
        batch_size + len(context) > MAX_BATCH_CONTEXT_CHARS or len(batch) >= 5
    )


def _challenge_survivor_batch(
    agent: DeadCodeVerifierAgent,
    batch: list[dict],
    batch_contexts: list[str],
) -> list[SurvivorVerdict]:
    if not batch:
        return []
    user_prompt = _build_batch_survivor_prompt(batch, batch_contexts)
    verdicts = _parse_batch_survivor_response(
        agent,
        BATCH_SURVIVOR_SYSTEM,
        user_prompt,
        len(batch),
    )
    return [
        _build_batch_survivor_verdict(survivor, verdict)
        for survivor, verdict in zip(batch, verdicts)
    ]


def _build_batch_survivor_prompt(
    batch: list[dict],
    batch_contexts: list[str],
) -> str:
    combined = "\n\n---\n\n".join(
        f"### Function {index + 1}: "
        f"`{survivor.get('full_name', survivor.get('name'))}`\n{context}"
        for index, (survivor, context) in enumerate(zip(batch, batch_contexts))
    )
    return (
        f"{combined}\n\nAssess all {len(batch)} functions above. "
        "Are their heuristic matches real or spurious? JSON array response:"
    )


def _build_batch_survivor_verdict(
    survivor: dict,
    verdict_data: dict,
) -> SurvivorVerdict:
    name = survivor.get("name", "unknown")
    confidence = survivor.get("confidence", 0)
    verdict, suggested = _survivor_verdict_values(verdict_data, confidence)
    return SurvivorVerdict(
        name=name,
        full_name=survivor.get("full_name", name),
        file=survivor.get("file", ""),
        line=survivor.get("line", 0),
        heuristic_refs=survivor.get("heuristic_refs", {}),
        verdict=verdict,
        rationale=verdict_data.get("rationale", ""),
        original_confidence=confidence,
        suggested_confidence=suggested,
    )


def _survivor_verdict_values(
    verdict_data: dict,
    confidence: int,
) -> tuple[Verdict, int]:
    if verdict_data.get("is_dead", False):
        return Verdict.TRUE_POSITIVE, min(95, confidence + 30)
    if verdict_data.get("heuristic_assessment", "uncertain") == "real":
        return Verdict.FALSE_POSITIVE, max(20, confidence - 20)
    return Verdict.UNCERTAIN, confidence


def _build_survivor_context(
    survivor: dict,
    source_cache: dict[str, str],
    defs_map: dict[str, Any],
) -> str:
    name = survivor.get("name", "")
    simple_name = survivor.get("simple_name", name.split(".")[-1])
    full_name = survivor.get("full_name", name)
    file_path = survivor.get("file", "")
    line = survivor.get("line", 0)
    snippet = _survivor_source_snippet(source_cache.get(file_path, ""), line)
    match_sites = _find_heuristic_match_sites(
        full_name,
        simple_name,
        source_cache,
        defs_map,
    )
    return (
        f"- File: `{file_path}:{line}`\n"
        f"- Heuristic refs: {json.dumps(survivor.get('heuristic_refs', {}))}\n"
        f"- Confidence: {survivor.get('confidence', 0)}\n\n"
        f"Source:\n{snippet}\n\n"
        f"Match sites:\n{match_sites}"
    )


def _survivor_source_snippet(source: str, line: int) -> str:
    if not source:
        return "(source not available)"
    lines = source.splitlines()
    start = max(0, line - 6)
    end = min(len(lines), line + 20)
    return "\n".join(f"{index + 1:4d} | {lines[index]}" for index in range(start, end))


def _find_heuristic_match_sites(
    name: str,
    simple_name: str,
    source_cache: dict[str, str],
    defs_map: dict[str, Any],
) -> str:
    sites = []
    search_attr = f".{simple_name}"

    for file_path, source in source_cache.items():
        lines = source.splitlines()
        for i, line_text in enumerate(lines):
            if search_attr in line_text and "def " not in line_text:
                sites.append(f"  {file_path}:{i + 1} | {line_text.strip()}")
                if len(sites) >= 15:
                    break
        if len(sites) >= 15:
            break

    if sites:
        return "\n".join(sites)
    else:
        return "  (no match sites found)"


def challenge_survivor(
    agent: DeadCodeVerifierAgent,
    defn_info: dict,
    defs_map: dict[str, Any],
    source_cache: dict[str, str],
) -> SurvivorVerdict:
    name = defn_info.get("name", "unknown")
    full_name = defn_info.get("full_name", name)
    simple_name = defn_info.get("simple_name", name.split(".")[-1])
    file_path = defn_info.get("file", "")
    line = defn_info.get("line", 0)
    kind = defn_info.get("type", "function")
    confidence = defn_info.get("confidence", 0)
    heuristic_refs = defn_info.get("heuristic_refs", {})

    source = source_cache.get(file_path, "")
    if source:
        source_lines = source.splitlines()
        start = max(0, line - 6)
        end = min(len(source_lines), line + 20)
        snippet = "\n".join(
            f"{i + 1:4d} | {source_lines[i]}" for i in range(start, end)
        )
    else:
        snippet = "(source not available)"

    match_sites = _find_heuristic_match_sites(
        full_name, simple_name, source_cache, defs_map
    )

    user = SURVIVOR_USER.format(
        full_name=full_name,
        file=file_path,
        line=line,
        kind=kind,
        confidence=confidence,
        heuristic_refs=json.dumps(heuristic_refs),
        source_snippet=snippet,
        match_sites=match_sites,
    )

    try:
        response = _call_llm_with_retry(agent, SURVIVOR_SYSTEM, user)
        if not response:
            raise ValueError("LLM call failed")
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
        if clean.endswith("```"):
            clean = clean.rsplit("```", 1)[0]
        clean = clean.strip()

        data = json.loads(clean)
        is_dead = data.get("is_dead", False)
        rationale = data.get("rationale", "")
        assessment = data.get("heuristic_assessment", "uncertain")

        if is_dead:
            verdict = Verdict.TRUE_POSITIVE
            suggested = min(95, confidence + 30)
        elif assessment == "real":
            verdict = Verdict.FALSE_POSITIVE
            suggested = max(20, confidence - 20)
        else:
            verdict = Verdict.UNCERTAIN
            suggested = confidence

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Survivor challenge failed for {name}: {e}")
        verdict = Verdict.UNCERTAIN
        rationale = f"LLM call failed: {e}"
        suggested = confidence

    return SurvivorVerdict(
        name=name,
        full_name=full_name,
        file=file_path,
        line=line,
        heuristic_refs=heuristic_refs,
        verdict=verdict,
        rationale=rationale,
        original_confidence=confidence,
        suggested_confidence=suggested,
    )


def _find_survivors(
    defs_map: dict[str, Any],
    already_flagged: list[dict],
) -> list[dict]:
    flagged_names = set()
    for f in already_flagged:
        flagged_names.add(f.get("full_name", f.get("name", "")))

    survivors = []
    for name, info in defs_map.items():
        if not isinstance(info, dict):
            continue
        if name in flagged_names:
            continue
        if info.get("type") not in ("function", "method"):
            continue

        heuristic_refs = info.get("heuristic_refs", {})
        if not heuristic_refs:
            continue

        refs = info.get("references", 0)
        if refs > 3:
            continue

        total_heuristic = sum(
            v if isinstance(v, (int, float)) else 0 for v in heuristic_refs.values()
        )
        if total_heuristic > 0:
            survivors.append(
                {
                    "name": name.split(".")[-1],
                    "full_name": name,
                    "simple_name": name.split(".")[-1],
                    "file": str(info.get("file", "")),
                    "line": info.get("line", 0),
                    "type": info.get("type", "function"),
                    "confidence": info.get("confidence", 50),
                    "heuristic_refs": heuristic_refs,
                    "references": refs,
                }
            )

    survivors.sort(
        key=lambda s: sum(
            v if isinstance(v, (int, float)) else 0
            for v in s.get("heuristic_refs", {}).values()
        ),
        reverse=True,
    )

    return survivors


_LOCAL_ON_DECORATOR_RE = re.compile(
    r"""@(?P<owner>[A-Za-z_][A-Za-z0-9_]*)\.on\(\s*(['"])(?P<event>[^'"]+)\2\s*\)"""
)


def _extract_local_on_listener_registration(
    file_path: str, line: int
) -> tuple[str, str] | None:
    try:
        with open(  # skylos: ignore[SKY-D215] analyzer reads current scan file
            file_path, "r", encoding="utf-8", errors="ignore"
        ) as source_file:
            source = source_file.read()
    except Exception as exc:
        logger.debug(
            "Unable to read listener registration source %s: %s",
            file_path,
            exc,
        )
        return None

    lines = source.splitlines()
    start = max(0, line - 6)
    end = max(0, line - 1)
    for idx in range(end - 1, start - 1, -1):
        text = lines[idx].strip()
        if not text:
            continue
        if not text.startswith("@"):
            break
        match = _LOCAL_ON_DECORATOR_RE.search(text)
        if match:
            return match.group("owner"), match.group("event")
    return None


def _supports_local_on_emit_registry(file_path: str, owner: str) -> bool:
    try:
        with open(  # skylos: ignore[SKY-D215] analyzer reads current scan file
            file_path, "r", encoding="utf-8", errors="ignore"
        ) as source_file:
            source = source_file.read()
    except Exception:
        return False

    if not re.search(rf"\bclass\s+{re.escape(owner)}\b", source):
        return False

    return bool(re.search(r"\bdef\s+emit\s*\(", source))


def _search_local_emit_sites(
    owner: str, event_name: str, project_root: str | Path
) -> list[str]:
    pattern = (
        re.escape(owner) + r"""\.emit\(\s*['"]""" + re.escape(event_name) + r"""['"]"""
    )
    matches: list[str] = []
    for subdir in ("app", "tests"):
        root = Path(project_root) / subdir
        if not root.exists():
            continue
        matches.extend(
            _run_grep(
                pattern,
                str(root),
                use_regex=True,
                include_globs=["*.py"],
                max_results=20,
            )
        )
    return matches[:20]


def _find_local_on_emit_survivors(
    defs_map: dict[str, Any],
    already_flagged: list[dict],
    project_root: str | Path,
) -> list[dict]:
    flagged_names = {f.get("full_name", f.get("name", "")) for f in already_flagged}
    survivors: list[dict] = []

    for name, info in defs_map.items():
        location = _local_on_emit_candidate_location(name, info, flagged_names)
        if location is None:
            continue
        file_path, line = location
        registration = _unmatched_local_on_registration(
            file_path,
            line,
            project_root,
        )
        if registration is None:
            continue
        owner, event_name = registration
        survivors.append(
            _local_on_emit_survivor(
                name,
                info,
                file_path=file_path,
                line=line,
                owner=owner,
                event_name=event_name,
            )
        )

    return survivors


def _local_on_emit_candidate_location(
    name: str,
    info: Any,
    flagged_names: set[str],
) -> tuple[str, int] | None:
    if not isinstance(info, dict) or name in flagged_names:
        return None
    if info.get("type") not in ("function", "method") or info.get("called_by"):
        return None
    file_path = str(info.get("file", "") or "")
    line = int(info.get("line", 0) or 0)
    if not file_path or line <= 0:
        return None
    return file_path, line


def _unmatched_local_on_registration(
    file_path: str,
    line: int,
    project_root: str | Path,
) -> tuple[str, str] | None:
    registration = _extract_local_on_listener_registration(file_path, line)
    if registration is None:
        return None
    owner, event_name = registration
    if not _supports_local_on_emit_registry(file_path, owner):
        return None
    if _search_local_emit_sites(owner, event_name, project_root):
        return None
    return owner, event_name


def _local_on_emit_survivor(
    name: str,
    info: dict[str, Any],
    *,
    file_path: str,
    line: int,
    owner: str,
    event_name: str,
) -> dict[str, Any]:
    simple_name = name.split(".")[-1]
    return {
        "name": simple_name,
        "full_name": name,
        "simple_name": simple_name,
        "file": file_path,
        "line": line,
        "type": info.get("type", "function"),
        "confidence": info.get("confidence", 50),
        "references": int(info.get("references", 0) or 0),
        "_registry_owner": owner,
        "_event_name": event_name,
    }
