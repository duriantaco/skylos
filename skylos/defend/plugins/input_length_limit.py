from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class InputLengthLimitPlugin(DefensePlugin):
    id = "input-length-limit"
    name = "Input Length Limited"
    severity = "low"
    owasp_llm = "LLM01"
    description = (
        "User input should have a length/size check before reaching the LLM call"
    )
    remediation = (
        "Add input length validation (e.g. len(input) check, [:N] slicing, "
        "or max_length validator) before the LLM call."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return bool(integration.input_sources)

    def check(self, integration: LLMIntegration, graph: AIIntegrationGraph) -> DefenseResult:
        if integration.has_input_length_limit:
            loc = integration.input_length_limit_location or integration.location
            return self._pass(
                integration,
                loc,
                f"Input length check at {loc}",
            )

        return self._fail(
            integration,
            integration.location,
            "Unbounded user input reaches LLM call",
        )
