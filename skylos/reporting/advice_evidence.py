"""Which built-in advice the scan lists by default, and the evidence it needs.

A threshold crossing is a measurement. The current default set retains:

* Python and JS/TS function metrics, when two complexity measures agree on
  the same function: cyclomatic and cognitive, or cognitive and nesting
  (historical small samples do not establish a precision guarantee);
* missing type annotations, as the annotation rule's typing-policy evidence
  decides (SKY-T101/T102 report only what the project's policy requires).

Style-only suggestions, including f-string conversions (SKY-L038), remain
optional even when the rewrite is equivalent.

Every other advice rule remains a complete, marked record and is counted under
``advice_visibility``; ``--all-advice`` lists it. Precision fixes do not promote
rules automatically. Promotion requires fresh independent labels on previously
unused repositories, targeting at least 50% useful findings. Missing or malformed
context evidence keeps otherwise eligible advice visible.
"""

from __future__ import annotations

PYTHON_SUFFIXES = (".py", ".pyi", ".pyw")
# Languages whose scanner records cognitive complexity (SKY-Q306).
COGNITIVE_SUFFIXES = (
    *PYTHON_SUFFIXES,
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
)
FUNCTION_METRIC_RULES = frozenset(
    {"SKY-Q301", "SKY-Q306", "SKY-C304", "SKY-Q302", "SKY-L028"}
)
# Pairs of complexity measures whose agreement marks hard-to-follow control flow.
CORROBORATING_PAIRS = (
    frozenset({"SKY-Q301", "SKY-Q306"}),
    frozenset({"SKY-Q306", "SKY-Q302"}),
)
ARCHITECTURE_METRIC_RULES = frozenset({"SKY-Q701", "SKY-Q702", "SKY-Q804", "SKY-Q806"})
TYPING_RULES = frozenset({"SKY-T101", "SKY-T102"})
PROVEN_IDIOM_RULES = frozenset()
DEFAULT_ADVICE_RULES = FUNCTION_METRIC_RULES | TYPING_RULES | PROVEN_IDIOM_RULES


def corroborated(rule_ids) -> bool:
    rules = set(rule_ids)
    return any(pair <= rules for pair in CORROBORATING_PAIRS)


def _finding_path(finding) -> str:
    for field in ("file", "file_path"):
        value = finding.get(field)
        if isinstance(value, str) and value:
            return value
    return ""


def is_gated_function_metric(category, finding, rule_id: str) -> bool:
    """Python and JS/TS record cognitive complexity, so their metrics are gated.

    Languages without that measure keep their function metrics visible.
    """
    return (
        category == "quality"
        and rule_id in FUNCTION_METRIC_RULES
        and _finding_path(finding).lower().endswith(COGNITIVE_SUFFIXES)
    )
