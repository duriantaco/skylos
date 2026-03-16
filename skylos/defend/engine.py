from __future__ import annotations

import copy

from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph
from skylos.defend.result import DefenseResult, DefenseScore, OpsScore
from skylos.defend.scoring import compute_defense_score, compute_ops_score
from skylos.defend.plugins import ALL_PLUGINS
from skylos.defend.plugin import DefensePlugin
from skylos.defend.policy import DefensePolicy


def run_defense_checks(
    integrations: list[LLMIntegration],
    graph: AIIntegrationGraph,
    *,
    policy: DefensePolicy | None = None,
    min_severity: str | None = None,
    owasp_filter: list[str] | None = None,
) -> tuple[list[DefenseResult], DefenseScore, OpsScore]:
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    min_sev_val = severity_order.get(min_severity, 0) if min_severity else 0

    plugins = _resolve_plugins(policy)
    results: list[DefenseResult] = []

    for integration in integrations:
        for plugin in plugins:
            if not plugin.applies_to(integration):
                continue

            if (
                owasp_filter
                and plugin.owasp_llm is not None
                and plugin.owasp_llm not in owasp_filter
            ):
                continue

            if severity_order.get(plugin.severity, 0) < min_sev_val:
                continue

            result = plugin.check(integration, graph)
            results.append(result)

    score = compute_defense_score(results)
    ops = compute_ops_score(results)
    return results, score, ops


def _resolve_plugins(policy: DefensePolicy | None) -> list[DefensePlugin]:
    if policy is None:
        return list(ALL_PLUGINS)

    active = []
    for plugin in ALL_PLUGINS:
        rule = policy.rules.get(plugin.id)
        if rule is not None:
            if not rule.get("enabled", True):
                continue
            if "severity" in rule:
                plugin = copy.copy(plugin)
                plugin.severity = rule["severity"]

        active.append(plugin)

    return active
