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

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        if not integration.output_sinks:
            return self._pass(
                integration,
                integration.location,
                "No dangerous sink detected in same scope as LLM call",
            )

        sinks = ", ".join(integration.output_sinks)
        return self._fail(
            integration,
            integration.location,
            f"Dangerous sink(s) detected in same scope as LLM call: {sinks}",
        )
