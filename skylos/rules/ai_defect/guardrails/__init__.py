"""Guardrail-tamper rules: a change that weakens the checks around it.

* SKY-A122: an AI code reviewer's instructions or settings changed.
* SKY-A125: a code-scanning platform's suppression marker added.

Both compare the base with the head and run in ``skylos done`` (the
``guardrail_tampering`` check) and in diff-aware scans (``--diff``,
``--diff-base`` and the PR gate), where they are reported as AI defects.
"""

from __future__ import annotations

from skylos.rules.ai_defect.guardrails.core import (
    GUARDRAIL_CLASS,
    GUARDRAIL_KIND,
    GUARDRAIL_RULES,
    RULE_REVIEWER_CONFIG,
    RULE_SCANNER_MARKER,
    FileChange,
    GuardrailFinding,
    GuardrailOutcome,
)
from skylos.rules.ai_defect.guardrails.scan import (
    changes_from_comparison,
    detect_guardrail_tampering,
    scan_git_changes,
)

__all__ = [
    "GUARDRAIL_CLASS",
    "GUARDRAIL_KIND",
    "GUARDRAIL_RULES",
    "RULE_REVIEWER_CONFIG",
    "RULE_SCANNER_MARKER",
    "FileChange",
    "GuardrailFinding",
    "GuardrailOutcome",
    "changes_from_comparison",
    "detect_guardrail_tampering",
    "scan_git_changes",
]
