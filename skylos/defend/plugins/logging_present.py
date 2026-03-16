from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class LoggingPresentPlugin(DefensePlugin):
    id = "logging-present"
    name = "Logging Present"
    category = "ops"
    severity = "medium"
    description = (
        "LLM calls should have input/output logging for observability "
        "(logging module, structlog, LangSmith, Helicone, etc.)"
    )
    remediation = (
        "Add logging around LLM calls to capture inputs and outputs. "
        "Use Python logging, structlog, or an LLM observability platform."
    )

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        if integration.has_logging:
            return self._pass(
                integration,
                integration.location,
                "Logging detected near LLM call",
            )

        return self._fail(
            integration,
            integration.location,
            "No logging detected around LLM call",
        )
