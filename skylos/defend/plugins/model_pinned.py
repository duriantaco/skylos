from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class ModelPinnedPlugin(DefensePlugin):
    id = "model-pinned"
    name = "Model Version Pinned"
    severity = "medium"
    owasp_llm = "LLM03"
    description = (
        "LLM API calls must use a pinned model version "
        "(e.g. gpt-4o-2024-08-06) rather than a floating alias"
    )
    remediation = (
        "Pin your model to a dated version (e.g. gpt-4o-2024-08-06, "
        "claude-sonnet-4-20250514) to prevent unexpected behavior changes."
    )

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        if not integration.model_value:
            return self._fail(
                integration,
                integration.location,
                "No model parameter found in LLM call",
            )

        if integration.model_pinned:
            return self._pass(
                integration,
                integration.location,
                f"Model pinned to {integration.model_value}",
            )

        return self._fail(
            integration,
            integration.location,
            f"Model uses floating alias '{integration.model_value}'",
        )
