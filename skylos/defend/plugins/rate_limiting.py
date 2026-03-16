from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class RateLimitingPlugin(DefensePlugin):
    id = "rate-limiting"
    name = "Rate Limiting"
    category = "ops"
    severity = "medium"
    owasp_llm = "LLM10"
    description = (
        "LLM endpoint handlers should have rate limiting middleware "
        "to prevent abuse and control costs"
    )
    remediation = (
        "Add rate limiting to LLM-powered endpoints using slowapi, "
        "flask-limiter, or similar middleware."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return bool(integration.input_sources)

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        if integration.has_rate_limiting:
            return self._pass(
                integration,
                integration.location,
                "Rate limiting detected on endpoint",
            )

        return self._fail(
            integration,
            integration.location,
            "No rate limiting on LLM endpoint",
        )
