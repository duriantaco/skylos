from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from .dead_code_verifier import DeadCodeVerifierAgent, Verdict
from .verify_llm import (
    BATCH_SURVIVOR_SYSTEM,
    MAX_BATCH_CONTEXT_CHARS,
    SURVIVOR_SYSTEM,
    SURVIVOR_USER,
    _call_llm_with_retry,
    _parse_batch_survivor_response,
)
from .verify_types import SurvivorVerdict
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

    def _flush_batch():
        nonlocal batch, batch_contexts, batch_size
        if not batch:
            return

        combined = "\n\n---\n\n".join(
            f"### Function {i + 1}: `{s.get('full_name', s.get('name'))}`\n{ctx}"
            for i, (s, ctx) in enumerate(zip(batch, batch_contexts))
        )
        user_prompt = (
            f"{combined}\n\nAssess all {len(batch)} functions above. "
            f"Are their heuristic matches real or spurious? JSON array response:"
        )

        verdicts = _parse_batch_survivor_response(
            agent, BATCH_SURVIVOR_SYSTEM, user_prompt, len(batch)
        )

        for surv, v_data in zip(batch, verdicts):
            name = surv.get("name", "unknown")
            full_name = surv.get("full_name", name)
            confidence = surv.get("confidence", 0)
            is_dead = v_data.get("is_dead", False)
            rationale = v_data.get("rationale", "")
            assessment = v_data.get("heuristic_assessment", "uncertain")

            if is_dead:
                verdict = Verdict.TRUE_POSITIVE
                suggested = min(95, confidence + 30)
            elif assessment == "real":
                verdict = Verdict.FALSE_POSITIVE
                suggested = max(20, confidence - 20)
            else:
                verdict = Verdict.UNCERTAIN
                suggested = confidence

            results.append(
                SurvivorVerdict(
                    name=name,
                    full_name=full_name,
                    file=surv.get("file", ""),
                    line=surv.get("line", 0),
                    heuristic_refs=surv.get("heuristic_refs", {}),
                    verdict=verdict,
                    rationale=rationale,
                    original_confidence=confidence,
                    suggested_confidence=suggested,
                )
            )

        batch = []
        batch_contexts = []
        batch_size = 0

    for surv in survivors:
        simple_name = surv.get("simple_name", surv.get("name", "").split(".")[-1])
        full_name = surv.get("full_name", surv.get("name", ""))
        file_path = surv.get("file", "")
        line = surv.get("line", 0)
        heuristic_refs = surv.get("heuristic_refs", {})

        source = source_cache.get(file_path, "")
        if source:
            slines = source.splitlines()
            start = max(0, line - 6)
            end = min(len(slines), line + 20)
            snippet = "\n".join(f"{i + 1:4d} | {slines[i]}" for i in range(start, end))
        else:
            snippet = "(source not available)"

        match_sites = _find_heuristic_match_sites(
            full_name, simple_name, source_cache, defs_map
        )

        ctx = (
            f"- File: `{file_path}:{line}`\n"
            f"- Heuristic refs: {json.dumps(heuristic_refs)}\n"
            f"- Confidence: {surv.get('confidence', 0)}\n\n"
            f"Source:\n{snippet}\n\n"
            f"Match sites:\n{match_sites}"
        )
        ctx_len = len(ctx)

        if batch and (
            batch_size + ctx_len > MAX_BATCH_CONTEXT_CHARS or len(batch) >= 5
        ):
            _flush_batch()

        batch.append(surv)
        batch_contexts.append(ctx)
        batch_size += ctx_len

    _flush_batch()
    return results


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
    except Exception:
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
        if not isinstance(info, dict):
            continue
        if name in flagged_names:
            continue
        if info.get("type") not in ("function", "method"):
            continue
        if info.get("called_by"):
            continue

        file_path = str(info.get("file", "") or "")
        line = int(info.get("line", 0) or 0)
        if not file_path or line <= 0:
            continue

        registration = _extract_local_on_listener_registration(file_path, line)
        if not registration:
            continue
        owner, event_name = registration

        if not _supports_local_on_emit_registry(file_path, owner):
            continue

        emit_sites = _search_local_emit_sites(owner, event_name, project_root)
        if emit_sites:
            continue

        survivors.append(
            {
                "name": name.split(".")[-1],
                "full_name": name,
                "simple_name": name.split(".")[-1],
                "file": file_path,
                "line": line,
                "type": info.get("type", "function"),
                "confidence": info.get("confidence", 50),
                "references": int(info.get("references", 0) or 0),
                "_registry_owner": owner,
                "_event_name": event_name,
            }
        )

    return survivors
