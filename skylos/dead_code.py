from __future__ import annotations

from typing import Any

DEAD_CODE_RESULT_KEYS: tuple[str, ...] = (
    "unused_functions",
    "unused_classes",
    "unused_variables",
    "unused_imports",
    "unused_parameters",
)


def collect_dead_code_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for key in DEAD_CODE_RESULT_KEYS:
        for finding in result.get(key, []) or []:
            findings.append(dict(finding))
    return findings
