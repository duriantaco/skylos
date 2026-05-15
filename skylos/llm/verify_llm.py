from __future__ import annotations

import json
import logging
import time

from .dead_code_verifier import DeadCodeVerifierAgent, Verdict

logger = logging.getLogger(__name__)


MAX_LLM_RETRIES = 3

RETRY_BACKOFF_BASE = 5

GRAPH_VERIFY_SYSTEM = """\
You are verifying if code flagged as "unused" is actually dead or alive.

You will receive:
1. The flagged symbol's source code
2. Call graph context (callers, callees)
3. Inheritance context (parent class overrides)
4. Search results: grep across the ENTIRE project (source, tests, docs, configs)
5. File context around matches (actual source code, not just grep snippets)

Your job: READ the evidence and REASON about whether each match is a real usage.

What counts as ALIVE (FALSE_POSITIVE):
- Called somewhere: .name() pattern in actual code (not just in the definition file)
- Imported and used in another file
- Overrides a confirmed parent class method (look for CONFIRMED in inheritance context)
- Used in cast() or bound in TypeVar
- Referenced by a Sphinx directive (:func:, autofunction) — documented public API
- Used via dynamic dispatch: getattr(obj, "name"), dict["name"], .do("name")
- Conditional import inside try/except ImportError — the symbol IS used in the guarded code path
- File or module path is referenced by a loader/CLI/config entry and the symbol is the runtime entry surface
- Explicit changelog/docs note that a symbol was reintroduced, restored, or kept as an alias/synonym for compatibility counts as ALIVE when the symbol remains a top-level API/type alias surface
- A pytest-collected test class/function is alive even without direct imports or calls
- A hook function registered in repo config (e.g. mkdocs hooks) is alive
- A class definition inside pytest.raises()/assertRaises() is executed for its side effect
- Parameters required by a callback/hook signature or by an interface/base-method signature are ALIVE even if unused inside the body
- Method on a class that substitutes/replaces a standard object (e.g. assigned to sys.stdout, \
used as a file-like object, wraps a socket) — standard protocol methods are called by the runtime
- Enum members (FOO, BAR) on a class inheriting from Enum/IntEnum — accessed via iteration, \
Choice(), or member lookup at runtime even without explicit references
- A public symbol (no underscore prefix) in an importable package that is documented in the \
project's docs/ directory (rst, md, or autodoc) is ALIVE — it exists for downstream consumers \
even if unused internally. Look for the public_api_docs search results.
- A symbol marked as exported (is_exported=true) is part of the package's public API. \
It exists for downstream consumers. Unless you find strong evidence it's truly orphaned \
(e.g., the entire module is dead), treat it as ALIVE.
- TypeScript/JS: imported via `import {{ X }}` or `require()`, used as JSX `<Component />`, \
exported via barrel `export {{ X }}`, used with decorator `@X`, or `implements Interface`
- Go: called as `package.Func()`, referenced in interface method signatures, struct field access
- Java: imported, annotated with @Override/@Bean/@Autowired, implements/extends
- Rust: imported via `use crate::`, referenced in `impl Trait for`, `#[derive(X)]`

What counts as DEAD (TRUE_POSITIVE):
- ZERO references anywhere in the project (only the definition itself found)
- Only referenced in docstrings, comments, or string descriptions — these are NOT usages
- Keyword argument values are NOT usages: fg="green" does NOT mean a variable named \
green is used
- TypeVar definitions like T = TypeVar("T") are NOT usages of T
- A class docstring mentioning a name is NOT a usage of that name
- Listed in __all__ but NOT imported or used anywhere — __all__ can be stale, but when \
combined with is_exported=true, treat __all__ membership as meaningful public API intent.
- TypeScript: only re-exported from index.ts but never actually consumed downstream
- Go: only referenced in _test.go files with Test* prefix (test-only symbol)

Decision rules:
- COMMIT to a verdict. Use UNCERTAIN only if evidence genuinely conflicts.
- If you see a real code usage (call, import, dispatch), it is FALSE_POSITIVE — full stop.
- If ZERO real code usages exist, it is TRUE_POSITIVE — full stop.
- Read the file context around each match to distinguish real code from comments/docs.
- __all__ alone is NOT enough to call something alive — but __all__ combined with is_exported=true IS strong evidence for ALIVE.
- A generic docs mention is not enough, but an explicit compatibility-retention note is strong evidence for ALIVE.
- If public_api_docs results show the symbol documented in docs/ AND the symbol is public \
(no underscore) in an importable package, it is FALSE_POSITIVE — library public API.

IMPORTANT: Respond with ONLY JSON. No explanations, no preamble.
{"verdict": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"UNCERTAIN", "rationale": "brief explanation"}\
"""

SUPPRESSION_AUDIT_SYSTEM = """\
You are auditing a prior ALIVE (FALSE_POSITIVE) decision for code flagged as "unused".

Your job is to catch FALSE NEGATIVES: cases where the earlier verifier or suppressor \
incorrectly decided the symbol was alive and removed a real dead-code finding.

You will receive:
1. The flagged symbol's source code and graph context
2. Search results and file context around matches
3. The prior FALSE_POSITIVE rationale and any suppression evidence

Decision standard:
- Return TRUE_POSITIVE if the prior "alive" story is weak, speculative, or unsupported by \
concrete runtime usage.
- Return FALSE_POSITIVE only if the evidence shows a real, defensible usage that keeps the \
symbol alive.
- Return UNCERTAIN only if the evidence genuinely conflicts.

Evidence that is NOT enough to keep something alive:
- Comments, docstrings, or plain string mentions
- Vague "might be dynamic" claims without a concrete dispatch/registration path
- Generic test mentions that do not execute or import the symbol
- File/module mentions without evidence the symbol is actually the runtime entry surface
- __all__ exports without real imports or usage

Evidence that IS enough to keep something alive:
- A public symbol (no underscore prefix) documented in docs/ (rst, md, autodoc) in an \
importable package — this is library public API for downstream consumers, even if unused internally

IMPORTANT: Respond with ONLY JSON. No explanations, no preamble.
{"verdict": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"UNCERTAIN", "rationale": "brief explanation"}\
"""

BATCH_VERIFY_SYSTEM = """\
You are verifying if multiple code symbols flagged as "unused" are actually dead or alive.

Each symbol includes: source code, call graph, inheritance info, and multi-strategy \
search results with file context. Definition-only matches have been pre-filtered — \
all grep results shown are USAGES, not the definition itself.

Your job: READ the evidence for each symbol and REASON about whether each match is a real usage.

What counts as ALIVE (FALSE_POSITIVE):
- Called somewhere: .name() pattern in actual code (not just in the definition file)
- Imported and used in another file
- Overrides a confirmed parent class method (look for CONFIRMED in inheritance context)
- Used in cast() or bound in TypeVar
- Referenced by a Sphinx directive (:func:, autofunction) — documented public API
- Used via dynamic dispatch: getattr(obj, "name"), dict["name"], .do("name")
- Conditional import inside try/except ImportError — the symbol IS used in the guarded code path
- File or module path is referenced by a loader/CLI/config entry and the symbol is the runtime entry surface
- Explicit changelog/docs note that a symbol was reintroduced, restored, or kept as an alias/synonym for compatibility counts as ALIVE when the symbol remains a top-level API/type alias surface
- A pytest-collected test class/function is alive even without direct imports or calls
- A hook function registered in repo config (e.g. mkdocs hooks) is alive
- A class definition inside pytest.raises()/assertRaises() is executed for its side effect
- Parameters required by a callback/hook signature or by an interface/base-method signature are ALIVE even if unused inside the body
- Method on a class that substitutes/replaces a standard object (e.g. assigned to sys.stdout, \
used as a file-like object, wraps a socket) — standard protocol methods are called by the runtime
- Enum members (FOO, BAR) on a class inheriting from Enum/IntEnum — accessed via iteration, \
Choice(), or member lookup at runtime even without explicit references
- A public symbol (no underscore prefix) in an importable package that is documented in the \
project's docs/ directory (rst, md, or autodoc) is ALIVE — it exists for downstream consumers \
even if unused internally. Look for the public_api_docs search results.
- A symbol marked as exported (is_exported=true) is part of the package's public API. \
It exists for downstream consumers. Unless you find strong evidence it's truly orphaned \
(e.g., the entire module is dead), treat it as ALIVE.

What counts as DEAD (TRUE_POSITIVE):
- ZERO references anywhere in the project (only the definition itself found)
- Only referenced in docstrings, comments, or string descriptions — these are NOT usages
- Keyword argument values are NOT usages: fg="green" does NOT mean a variable named \
green is used
- TypeVar definitions like T = TypeVar("T") are NOT usages of T
- A class docstring mentioning a name is NOT a usage of that name
- Listed in __all__ but NOT imported or used anywhere — __all__ can be stale, but when \
combined with is_exported=true, treat __all__ membership as meaningful public API intent.

Decision rules:
- COMMIT to a verdict. Use UNCERTAIN only if evidence genuinely conflicts.
- If you see a real code usage (call, import, dispatch), it is FALSE_POSITIVE — full stop.
- If ZERO real code usages exist, it is TRUE_POSITIVE — full stop.
- Read the file context around each match to distinguish real code from comments/docs.
- __all__ alone is NOT enough to call something alive — but __all__ combined with is_exported=true IS strong evidence for ALIVE.
- A generic docs mention is not enough, but an explicit compatibility-retention note is strong evidence for ALIVE.
- If public_api_docs results show the symbol documented in docs/ AND the symbol is public \
(no underscore) in an importable package, it is FALSE_POSITIVE — library public API.

IMPORTANT: You MUST respond with ONLY a JSON array. No explanations, no preamble.
[{"id": 1, "verdict": "TRUE_POSITIVE", "rationale": "..."}, {"id": 2, "verdict": "FALSE_POSITIVE", "rationale": "..."}]
"""

BATCH_SURVIVOR_SYSTEM = """\
You are checking if multiple functions are INCORRECTLY marked as alive by static \
analysis due to "heuristic attribute matches" (e.g. `obj.foo()` matching any \
function named `foo`).

For EACH function, determine if the heuristic matches are:
- REAL: the attribute access actually calls this specific function
- SPURIOUS: a different class/object has a method with the same name
- UNCERTAIN: cannot determine

IMPORTANT: You MUST respond with ONLY a JSON array. No explanations, no preamble, no markdown.
Output ONLY this format, nothing else:
[{"id": 1, "is_dead": true, "rationale": "...", "heuristic_assessment": "spurious"}, ...]
"""

MAX_BATCH_CONTEXT_CHARS = 50_000


def _is_error_response(response: str) -> bool:
    if response:
        lower = response.lower()
    else:
        lower = ""
    return any(
        marker in lower
        for marker in [
            "error:",
            "ratelimiterror",
            "rate_limit_error",
            "ratelimit",
            "unauthorized",
            "quota",
            "exceeded",
            "apiconnectionerror",
            "anthropicexception",
            "openaiexception",
            "no api key found",
            "set openai_api_key",
            "set anthropic_api_key",
            "timed out",
            "timeout",
        ]
    )


def _call_llm_with_retry(
    agent: DeadCodeVerifierAgent,
    system: str,
    user: str,
) -> str:
    for attempt in range(MAX_LLM_RETRIES):
        response = agent._call_llm(system, user)
        if not _is_error_response(response):
            return response
        if "rate_limit" in response.lower() or "ratelimit" in response.lower():
            wait = RETRY_BACKOFF_BASE * (2**attempt)
            logger.info(
                f"Rate limited, retrying in {wait}s (attempt {attempt + 1}/{MAX_LLM_RETRIES})"
            )
            time.sleep(wait)
        else:
            logger.warning(f"LLM returned error: {response[:200]}")
            return ""
    logger.warning(f"LLM rate limited after {MAX_LLM_RETRIES} retries")
    return ""


def _parse_batch_response(
    agent: DeadCodeVerifierAgent,
    system: str,
    user: str,
    expected_count: int,
) -> list[dict]:
    try:
        response = _call_llm_with_retry(agent, system, user)
        if not response:
            return [
                {"verdict": Verdict.UNCERTAIN, "rationale": "LLM call failed"}
            ] * expected_count

        logger.debug(f"Raw LLM response ({len(response)} chars): {response[:300]}")
        clean = _strip_markdown_fences(response)
        logger.debug(f"After strip_markdown_fences ({len(clean)} chars): {clean[:300]}")
        data = json.loads(clean)

        if isinstance(data, list):
            verdicts = []
            for i in range(expected_count):
                if i < len(data):
                    item = data[i]
                    verdict_str = item.get("verdict", "UNCERTAIN")
                    try:
                        verdict = Verdict(verdict_str)
                    except (ValueError, KeyError):
                        verdict = Verdict.UNCERTAIN
                    verdicts.append(
                        {
                            "verdict": verdict,
                            "rationale": item.get("rationale", ""),
                        }
                    )
                else:
                    verdicts.append(
                        {
                            "verdict": Verdict.UNCERTAIN,
                            "rationale": "Missing from batch response",
                        }
                    )
            return verdicts

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Batch verification parse failed: {e}")

    return [
        {"verdict": Verdict.UNCERTAIN, "rationale": "Batch parse failed"}
    ] * expected_count


def _parse_batch_survivor_response(
    agent: DeadCodeVerifierAgent,
    system: str,
    user: str,
    expected_count: int,
) -> list[dict]:
    try:
        response = _call_llm_with_retry(agent, system, user)
        if not response:
            return [
                {
                    "is_dead": False,
                    "rationale": "LLM call failed",
                    "heuristic_assessment": "uncertain",
                }
            ] * expected_count

        clean = _strip_markdown_fences(response)
        data = json.loads(clean)

        if isinstance(data, list):
            results = []
            for i in range(expected_count):
                if i < len(data):
                    results.append(data[i])
                else:
                    results.append(
                        {
                            "is_dead": False,
                            "rationale": "Missing",
                            "heuristic_assessment": "uncertain",
                        }
                    )
            return results

    except (json.JSONDecodeError, Exception) as e:
        logger.warning(f"Batch survivor parse failed: {e}")

    return [
        {
            "is_dead": False,
            "rationale": "Batch parse failed",
            "heuristic_assessment": "uncertain",
        }
    ] * expected_count


def _strip_markdown_fences(text: str) -> str:
    import re

    clean = text.strip()

    if clean.startswith("```"):
        clean = clean.split("\n", 1)[-1]
    if clean.endswith("```"):
        clean = clean.rsplit("```", 1)[0]
    clean = clean.strip()

    if clean and clean[0] in "[{":
        return clean

    match = re.search(r"\[[\s\S]*\]", clean)
    if match:
        return match.group(0)

    match = re.search(r"\{[\s\S]*\}", clean)
    if match:
        return match.group(0)

    return clean


SURVIVOR_SYSTEM = """\
You are checking if a function is INCORRECTLY marked as alive by static analysis.

The static analyzer gave this function a passing score because of "heuristic \
attribute matches" — meaning somewhere in the codebase, code like `obj.{name}()` \
was found, and the analyzer assumed it MIGHT call this function.

Your job: determine if those heuristic matches are REAL calls or SPURIOUS noise.

SPURIOUS example: `logger.info()` matches any function named `info` in the project.
REAL example: `self.handler.process()` where self.handler is an instance of HandlerClass.

Respond with JSON:
{{"is_dead": true/false, "rationale": "explanation", "heuristic_assessment": "real"|"spurious"|"uncertain"}}\
"""

SURVIVOR_USER = """\
- File: `{file}`
- Line: {line}
- Type: {kind}
- Static confidence: {confidence} (low = likely alive, high = likely dead)
- Heuristic refs that kept it alive: {heuristic_refs}

{source_snippet}

These are the attribute access sites that matched this function's name:
{match_sites}

Are the heuristic attribute matches REAL calls to this specific function, or \
SPURIOUS matches (e.g. a different class has a method with the same name)?

JSON response:\
"""

HAIKU_PREFILTER_SYSTEM = """\
You are a quick pre-filter for dead code analysis. For each symbol below, determine if it is \
a public API method meant to be called by external users of this package.

Answer YES if the symbol is clearly part of the public API (public method on a public class, \
exported in __init__.py or __all__, documented for external use).
Answer NO if the symbol appears to be internal implementation detail, private, or orphaned.

IMPORTANT: Respond with ONLY a JSON array. No explanations, no preamble.
[{"id": 1, "public_api": "YES", "reason": "brief reason"}, ...]
"""

HAIKU_PREFILTER_MAX_BATCH = 20
