from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class CostControlsPlugin(DefensePlugin):
    id = "cost-controls"
    name = "Cost Controls"
    category = "ops"
    severity = "medium"
    owasp_llm = "LLM10"
    description = (
        "LLM API calls should set max_tokens to control costs "
        "and prevent unbounded token consumption"
    )
    remediation = (
        "Set max_tokens (or max_output_tokens) parameter in LLM API calls "
        "to cap response length and control costs."
    )

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        if integration.has_max_tokens:
            return self._pass(
                integration,
                integration.location,
                "max_tokens set on LLM call",
            )

        return self._fail(
            integration,
            integration.location,
            "No max_tokens set — unbounded token consumption",
        )
