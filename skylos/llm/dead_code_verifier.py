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

    parts.append("## Dynamic Dispatch Pattern Examples (What to Look For)")
    parts.append("")
    parts.append("Pattern 1 - getattr() dispatch:")
    parts.append("```python")
    parts.append("def export_csv(data): ...")
    parts.append("def run_export(fmt):")
    parts.append("    handler = getattr(sys.modules[__name__], f'export_{fmt}')")
    parts.append("    # This CALLS export_csv dynamically when fmt='csv'")
    parts.append("    return handler(data)")
    parts.append("```")
    parts.append("→ If you see getattr() with a pattern matching the symbol name, mark FALSE_POSITIVE")
    parts.append("")
    parts.append("Pattern 2 - globals() dict access:")
    parts.append("```python")
    parts.append("def handle_create(payload): ...")
    parts.append("HANDLER_MAP = {action: globals()[f'handle_{action}'] for action in ['create', 'update']}")
    parts.append("# This REFERENCES handle_create dynamically")
    parts.append("```")
    parts.append("→ If you see globals()[...] with a pattern matching the symbol name, mark FALSE_POSITIVE")
    parts.append("")
    parts.append("Pattern 3 - __init_subclass__ registration:")
    parts.append("```python")
    parts.append("class Base:")
    parts.append("    def __init_subclass__(cls):")
    parts.append("        REGISTRY[cls.name] = cls  # Auto-registers subclasses")
    parts.append("class EmailHandler(Base):  # Gets auto-registered")
    parts.append("```")
    parts.append("→ If the symbol inherits from a class with __init_subclass__, mark FALSE_POSITIVE")
    parts.append("")

    if source_lines:
        max_lines = min(len(source_lines), 200)
        parts.append("## Full File Source (YOUR CODE TO ANALYZE)")
        parts.append(f"Showing {max_lines} of {len(source_lines)} lines. The flagged symbol is at line {line}.\n")
        for i in range(max_lines):
            marker = " >>> " if i == line - 1 else "     "
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

    parts.append("## Critical: Search for Dynamic Dispatch Evidence in Code Above")
    parts.append("The static analyzer already searched the ENTIRE project for:")
    parts.append("- All direct calls and references (found 0)")
    parts.append("- __all__ exports, re-exports in __init__.py")
    parts.append("- Decorator registrations visible in the AST")
    parts.append("")
    parts.append("SEARCH THE FULL FILE SOURCE ABOVE FOR THESE PATTERNS:")
    parts.append("")
    parts.append("1. getattr() or hasattr() calls:")
    parts.append(f"   Search for: getattr(.*{name}")
    parts.append(f"   Search for: getattr\\(.*['\\\"].*{name}")
    parts.append("")
    parts.append("2. globals() or locals() dict access:")
    parts.append(f"   Search for: globals\\(\\)\\[.*{name}")
    parts.append(f"   Search for: globals\\(\\)\\[.*f['\\\"].*{name}")
    parts.append("")
    parts.append("3. __init_subclass__ registration:")
    parts.append("   Search for: def __init_subclass__")
    parts.append(f"   Then check if class {name} inherits from a base with __init_subclass__")
    parts.append("")
    parts.append("4. Registry/Map access pattern (CRITICAL FOR DISPATCHER FUNCTIONS):")
    parts.append(f"   Does function `{name}` access a dict/map/registry variable?")
    parts.append("   Examples: HANDLER_MAP[key], _REGISTRY.get(name), registry[action]")
    parts.append("   If YES, search the file for where that dict/map is created:")
    parts.append("   - If populated by globals()[...] → FALSE_POSITIVE (dispatcher function)")
    parts.append("   - If populated by getattr(...) → FALSE_POSITIVE (dispatcher function)")
    parts.append("   - If populated by __init_subclass__ → FALSE_POSITIVE (registry accessor)")
    parts.append(f"   Example: `{name}` does `MAP.get(key)` and MAP is `{{k: globals()[f'handle_{{k}}']}}`")
    parts.append(f"            → This makes `{name}` a dispatcher → FALSE_POSITIVE")
    parts.append("")
    parts.append("5. String interpolation that builds function/class names:")
    parts.append(f"   Search for: f\\\"{{.*}}.*{name.lstrip('_')}\\\"")
    parts.append(f"   Search for: {{.*}}.format\\(.*{name.lstrip('_')}")
    parts.append("")
    parts.append("6. Framework decorators (Flask, FastAPI, Click, Pytest):")
    parts.append("   Look for @app.route, @router.get, @click.command, @pytest.fixture, etc.")
    parts.append("")
    parts.append("If you find ANY of these patterns in the code above, mark FALSE_POSITIVE.")
    parts.append("")
    parts.append("NOT valid reasons for FALSE_POSITIVE:")
    parts.append(
        "- The name starts with `_` (underscore prefix means private, not dynamically used)"
    )
    parts.append(
        "- It 'could theoretically' be called dynamically (speculation without evidence)"
    )
    parts.append(
        "- It 'might be' a test helper or utility (check the actual code context)"
    )
    parts.append(
        "- It 'looks like' a framework hook (verify against the actual decorators/imports)"
    )

    return "\n".join(parts)


SYSTEM_PROMPT = """\
You are verifying if code flagged as "unused" is actually dead or alive via dynamic dispatch.

Static analysis found ZERO direct references. Scan the source code for these patterns:

1. getattr() — Example: `getattr(module, f"export_{fmt}")` calls export_csv dynamically
2. globals()[] — Example: `globals()[f"handle_{action}"]` references handle_create dynamically
3. __init_subclass__ — Example: class inherits from base with `def __init_subclass__`
4. Dispatcher function — Function accesses a MAP/REGISTRY populated by patterns 1-3
   Example: `def dispatch(action): return HANDLER_MAP[action]`
            where `HANDLER_MAP = {a: globals()[f"handle_{a}"] for a in actions}`
            This makes `dispatch` a dispatcher function → FALSE_POSITIVE

VERDICT RULES:
- Pattern 1-3 found and matches flagged symbol → FALSE_POSITIVE
- Flagged symbol is a dispatcher that accesses registry from patterns 1-3 → FALSE_POSITIVE
- Otherwise → TRUE_POSITIVE

Respond with JSON: {"verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE", "rationale": "Line X: [pattern]"}\
"""

USER_PROMPT_TEMPLATE = """{context}

## Task: Scan the source code for dynamic dispatch

Flagged symbol: has 0 direct references.

Search the "Full File Source" above for these patterns:
1. "getattr(" — then check if it references the flagged symbol
2. "globals()[" — then check if it references the flagged symbol
3. "def __init_subclass__" — then check if the flagged symbol inherits from that class
4. Registry access — check if the flagged symbol accesses a dict/map populated by patterns 1-3
   Examples: HANDLER_MAP, _REGISTRY, registry dict

If you find ANY match → FALSE_POSITIVE (cite line number and pattern)
If you find NONE → TRUE_POSITIVE

JSON response: {{"verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE", "rationale": "..."}}\
"""


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

    def test_api_connection(self) -> tuple[bool, str]:
        try:
            response = self.get_adapter().complete(
                "You are a test assistant. Respond with exactly: OK",
                "Test"
            )

            response_lower = response.lower()
            if "error:" in response_lower or "quota" in response_lower or "exceeded" in response_lower:
                return False, f"API error: {response}"

            if "ratelimiterror" in response_lower or "unauthorized" in response_lower:
                return False, f"API authentication failed: {response}"

            if len(response.strip()) > 0:
                return True, "API connection successful"

            return False, "API returned empty response"

        except Exception as e:
            error_msg = str(e).lower()
            if "quota" in error_msg or "exceeded" in error_msg or "ratelimit" in error_msg:
                return False, f"API quota exceeded: {e}"
            elif "unauthorized" in error_msg or "authentication" in error_msg or "api key" in error_msg:
                return False, f"API authentication failed: {e}"
            else:
                return False, f"API connection failed: {e}"

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

            if finding.get("name") in ["export_csv", "handle_create", "EmailHandler"]:
                logger.warning(f"DEBUG RAW RESPONSE for {finding.get('name')}: {response[:500]}")

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

            if verdict == Verdict.TRUE_POSITIVE and finding.get("name") in ["export_csv", "handle_create", "EmailHandler"]:
                logger.info(f"DEBUG: LLM marked {finding.get('name')} as TRUE_POSITIVE")
                logger.info(f"DEBUG: Rationale: {rationale}")
                logger.info(f"DEBUG: Source lines provided: {len(source_lines) if source_lines else 0}")

        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse failed for {finding.get('name')}: {e}")
            verdict = Verdict.UNCERTAIN
            rationale = f"JSON parse failed: {e}"
        except Exception as e:
            error_msg = str(e).lower()
            if "ratelimiterror" in error_msg or "quota" in error_msg or "exceeded" in error_msg:
                logger.error(f"⚠️  LLM API QUOTA EXCEEDED - verification disabled: {e}")
                logger.error("Run 'skylos key' to configure a valid API key with credits")
            else:
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
            f["_original_confidence"] = r.original_confidence
            f["_adjusted_confidence"] = r.adjusted_confidence

            if r.verdict == Verdict.FALSE_POSITIVE:
                f["_llm_challenged"] = True
                f["_llm_challenge_reason"] = f"LLM challenge: {r.rationale}"

            annotated.append(f)

        return annotated
