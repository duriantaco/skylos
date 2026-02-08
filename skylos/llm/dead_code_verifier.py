from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class VerificationResult:
    finding: dict
    verdict: Verdict = Verdict.UNCERTAIN
    rationale: str = ""
    original_confidence: int = 0
    adjusted_confidence: int = 0


CONFIDENCE_DELTA = {
    Verdict.TRUE_POSITIVE: +15,
    Verdict.FALSE_POSITIVE: -30,
    Verdict.UNCERTAIN: 0,
}
CONFIDENCE_CAP = 95
CONFIDENCE_FLOOR = 20


def apply_verdict(finding: dict, verdict: Verdict) -> int:
    raw = finding.get("confidence", 60)
    if isinstance(raw, str):
        raw = {"high": 85, "medium": 60, "low": 40}.get(raw.lower(), 60)
    delta = CONFIDENCE_DELTA[verdict]
    return max(CONFIDENCE_FLOOR, min(CONFIDENCE_CAP, raw + delta))


def _normalize_path(p) -> str:
    try:
        return str(Path(p).resolve())
    except Exception:
        return str(p)


def _parse_confidence(val) -> int:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        return {"high": 85, "medium": 60, "low": 40}.get(val.lower(), 60)
    return 60


def _parse_int(val, default=0) -> int:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val)
        except ValueError:
            return default
    return default


def build_verification_context(
    finding: dict,
    defs_map: dict[str, Any],
    source_lines: list[str] | None = None,
) -> str:
    name = finding.get("name", "unknown")
    full_name = finding.get("full_name", name)
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    kind = finding.get("type", finding.get("_category", "dead_code"))
    message = finding.get("message", "")
    refs = finding.get("references", 0)
    confidence = finding.get("confidence", "unknown")

    calls = finding.get("calls", [])
    called_by = finding.get("called_by", [])
    decorators = finding.get("decorators", [])
    is_lambda = finding.get("is_lambda", False)
    is_closure = finding.get("is_closure", False)
    closes_over = finding.get("closes_over", [])

    parts = []

    parts.append("## Static Analysis Verdict")
    parts.append(f"- Name: `{full_name}`")
    parts.append(f"- Type: {kind}")
    parts.append(f"- File: `{file_path}`")
    parts.append(f"- Line: {line}")
    parts.append(f"- Message: {message}")
    parts.append(f"- References found across entire project: {refs}")
    parts.append(f"- Static confidence: {confidence}")
    parts.append("")

    if source_lines:
        start = max(0, line - 11)
        end = min(len(source_lines), line + 10)
        parts.append("## Code Context")
        for i in range(start, end):
            marker = " >>> " if i == line - 1 else "     "
            if i < len(source_lines):
                parts.append(f"{i + 1:4d}{marker}{source_lines[i]}")
        parts.append("")

    parts.append("## Call Graph Evidence")
    if called_by:
        parts.append(f"- Called by: {', '.join(str(c) for c in called_by)}")
    else:
        parts.append("- Called by: NOBODY (0 callers across entire project)")
    if calls:
        parts.append(f"- Calls: {', '.join(str(c) for c in calls[:15])}")
    if decorators:
        parts.append(f"- Decorators: {', '.join(str(d) for d in decorators)}")
    if is_lambda:
        parts.append("- Is lambda: yes")
    if is_closure:
        parts.append("- Is closure: yes")
    if closes_over:
        parts.append(f"- Closes over: {', '.join(str(c) for c in closes_over)}")
    parts.append("")

    parts.append("## Cross-Reference (defs_map)")
    matched = None
    for def_name, def_info in defs_map.items():
        if isinstance(def_info, dict):
            if def_name == full_name or def_name.endswith(f".{name}"):
                matched = (def_name, def_info)
                break
    if matched:
        qname, info = matched
        parts.append(
            f"- Found in defs_map as: `{qname}` (type: {info.get('type', '?')})"
        )
    else:
        parts.append(f"- `{name}` not found in defs_map")
    parts.append("")

    parts.append("## Potential Alive Reasons to Consider")
    parts.append("- Dynamic dispatch: getattr(), globals(), __import__, importlib")
    parts.append("- Framework magic: Django signals, pytest fixtures, Flask routes")
    parts.append("- Plugin/registry: entry_points, plugin registries, click commands")
    parts.append("- Metaprogramming: metaclasses, __init_subclass__, type()")
    parts.append("- String refs: f-strings, format(), eval/exec")
    parts.append("- Public API: __all__, re-exported in __init__.py")
    parts.append("- Callback/handler: registered via string name elsewhere")

    return "\n".join(parts)


SYSTEM_PROMPT = """You are a dead-code verification expert. Your job is NOT to find dead code — \
static analysis has already done that. Your job is to VERIFY or CHALLENGE the static verdict.

Static analysis confirmed zero references and zero callers for this code across the entire project. \
Your task: determine if there is a plausible dynamic/framework/metaprogramming reason \
this code might still be reachable despite zero static references.

Be rigorous:
- TRUE_POSITIVE means you agree it's dead. Zero references, no dynamic escape hatch.
- FALSE_POSITIVE means you believe it's alive despite zero static refs. \
  You MUST cite a specific mechanism (e.g., "registered via entry_points in pyproject.toml", \
  "accessed via getattr in base class __init__", "decorator @app.route registers it").
- UNCERTAIN means you can't tell.

Respond with JSON only: {"verdict": "...", "rationale": "..."}"""

USER_PROMPT_TEMPLATE = """{context}

## Your Verdict
Based on the evidence above, is this truly dead code?

Respond with JSON:
{{"verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE" or "UNCERTAIN", "rationale": "1-2 sentence explanation citing specific mechanism if FALSE_POSITIVE"}}"""


class DeadCodeVerifierAgent:
    def __init__(self, config=None):
        if config is None:
            from skylos.llm.agents import AgentConfig

            config = AgentConfig()
        self.config = config
        self._adapter = None

    def get_adapter(self):
        if self._adapter is None:
            from skylos.llm.agents import create_llm_adapter

            self._adapter = create_llm_adapter(self.config)
        return self._adapter

    def _call_llm(self, system: str, user: str) -> str:
        if getattr(self.config, "stream", True):
            full = ""
            for chunk in self.get_adapter().stream(system, user):
                full += chunk
            return full
        else:
            return self.get_adapter().complete(system, user)

    def verify_single(
        self,
        finding: dict,
        defs_map: dict,
        source_cache: dict[str, str] | None = None,
    ) -> VerificationResult:
        raw_conf = _parse_confidence(finding.get("confidence", 60))
        refs = _parse_int(finding.get("references", 0))

        if refs > 0:
            return VerificationResult(
                finding=finding,
                verdict=Verdict.UNCERTAIN,
                rationale=f"Skipped: {refs} references exist (not zero-ref)",
                original_confidence=raw_conf,
                adjusted_confidence=raw_conf,
            )

        file_path = finding.get("file", "")
        normalized = _normalize_path(file_path)
        source_lines = None
        if source_cache:
            raw = source_cache.get(normalized) or source_cache.get(file_path)
            if isinstance(raw, str):
                source_lines = raw.splitlines()

        context = build_verification_context(finding, defs_map, source_lines)
        user_prompt = USER_PROMPT_TEMPLATE.format(context=context)

        try:
            response = self._call_llm(SYSTEM_PROMPT, user_prompt)
            clean = response.strip()
            if clean.startswith("```"):
                clean = clean.split("\n", 1)[-1]
            if clean.endswith("```"):
                clean = clean.rsplit("```", 1)[0]
            clean = clean.strip()

            data = json.loads(clean)
            verdict_str = data.get("verdict", "UNCERTAIN")
            try:
                verdict = Verdict(verdict_str)
            except (ValueError, KeyError):
                verdict = Verdict.UNCERTAIN
            rationale = data.get("rationale", "")
        except Exception as e:
            logger.warning(f"LLM verification failed for {finding.get('name')}: {e}")
            verdict = Verdict.UNCERTAIN
            rationale = f"LLM call failed: {e}"

        adjusted = apply_verdict(finding, verdict)

        return VerificationResult(
            finding=finding,
            verdict=verdict,
            rationale=rationale,
            original_confidence=raw_conf,
            adjusted_confidence=adjusted,
        )

    def verify_batch(
        self,
        findings: list[dict],
        defs_map: dict,
        source_cache: dict[str, str] | None = None,
        confidence_range: tuple[int, int] = (50, 85),
    ) -> list[VerificationResult]:
        results = []
        lo, hi = confidence_range

        for finding in findings:
            raw_conf = _parse_confidence(finding.get("confidence", 60))
            refs = _parse_int(finding.get("references", 0))

            if lo <= raw_conf <= hi and refs == 0:
                result = self.verify_single(finding, defs_map, source_cache)
            else:
                if raw_conf > hi:
                    v = Verdict.TRUE_POSITIVE
                    reason = "High confidence from static; skipped LLM verification"
                elif refs > 0:
                    v = Verdict.UNCERTAIN
                    reason = f"Has {refs} references; not a zero-ref candidate"
                else:
                    v = Verdict.UNCERTAIN
                    reason = "Below confidence threshold for verification"

                result = VerificationResult(
                    finding=finding,
                    verdict=v,
                    rationale=reason,
                    original_confidence=raw_conf,
                    adjusted_confidence=raw_conf,
                )

            results.append(result)

        return results

    def annotate_findings(
        self,
        findings: list[dict],
        defs_map: dict,
        source_cache: dict[str, str] | None = None,
        confidence_range: tuple[int, int] = (50, 85),
    ) -> list[dict]:
        results = self.verify_batch(findings, defs_map, source_cache, confidence_range)
        annotated = []

        for r in results:
            f = {**r.finding}
            f["_llm_verdict"] = r.verdict.value
            f["_llm_rationale"] = r.rationale
            f["_verified_by_llm"] = r.verdict != Verdict.UNCERTAIN
            f["_confidence_adjusted"] = r.adjusted_confidence

            if r.verdict == Verdict.FALSE_POSITIVE:
                f["_suppressed"] = True
                f["_suppressed_reason"] = f"LLM challenge: {r.rationale}"

            annotated.append(f)

        return annotated
