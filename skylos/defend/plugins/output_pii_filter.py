from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class OutputPiiFilterPlugin(DefensePlugin):
    id = "output-pii-filter"
    name = "Output PII Filter"
    severity = "high"
    owasp_llm = "LLM06"
    description = (
        "LLM output returned to external users must pass through "
        "PII detection/redaction (presidio, scrubadub, or similar)"
    )
    remediation = (
        "Add PII detection and redaction between LLM response and user-facing output. "
        "Consider using presidio-analyzer, scrubadub, or a custom PII filter."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return bool(integration.input_sources)

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        if integration.has_pii_filter:
            return self._pass(
                integration,
                integration.location,
                "PII filtering detected on LLM output path",
            )

        return self._fail(
            integration,
            integration.location,
            "No PII filtering on LLM output returned to users",
        )
