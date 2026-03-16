from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class OutputValidationPlugin(DefensePlugin):
    id = "output-validation"
    name = "Output Validation Present"
    severity = "high"
    owasp_llm = "LLM02"
    description = (
        "LLM output must be parsed/validated before use "
        "(JSON parsing, schema validation, type checking)"
    )
    remediation = (
        "Add structured output validation using json.loads(), Pydantic model_validate(), "
        "or similar parsing before consuming LLM responses."
    )

    def check(self, integration: LLMIntegration, graph: AIIntegrationGraph) -> DefenseResult:
        if integration.has_output_validation:
            loc = integration.output_validation_location or integration.location
            return self._pass(
                integration,
                loc,
                f"Output validation present at {loc}",
            )

        return self._fail(
            integration,
            integration.location,
            "LLM output used without structured validation",
        )
