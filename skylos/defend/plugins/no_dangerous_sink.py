from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class NoDangerousSinkPlugin(DefensePlugin):
    id = "no-dangerous-sink"
    name = "No Dangerous Output Sink"
    severity = "critical"
    owasp_llm = "LLM02"
    description = (
        "No dangerous sink (eval/exec/subprocess) detected in same scope as LLM call"
    )
    remediation = (
        "Remove dangerous sink from LLM call scope, or add output validation "
        "and sanitization before any dangerous operation."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return integration.integration_type != "mcp_server"

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        if not integration.output_sinks and not integration.output_sink_flows:
            return self._pass(
                integration,
                integration.location,
                "No dangerous sink detected in same scope as LLM call "
                "or reached by its output one call hop away",
            )

        parts = []
        if integration.output_sinks:
            sinks = ", ".join(integration.output_sinks)
            parts.append(
                f"Dangerous sink(s) detected in same scope as LLM call: {sinks}"
            )
        if integration.output_sink_flows:
            reached = "; ".join(integration.output_sink_flows)
            parts.append(
                f"Model output reaches a dangerous sink one call hop away: {reached}"
            )
        return self._fail(integration, integration.location, "; ".join(parts))
