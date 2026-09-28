from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph
from skylos.discover.semantics.vocabulary import FlowStatus


class OutputValidationPlugin(DefensePlugin):
    id = "output-validation"
    name = "Output Validation Present"
    severity = "high"
    owasp_llm = "LLM02"
    description = (
        "LLM output must pass structural parsing or schema validation "
        "before its resolved use"
    )
    remediation = (
        "Use the result of json.loads(), ast.literal_eval(), or a supported "
        "Pydantic validator for the same LLM response before consuming it. "
        "Review custom validation helpers when Skylos reports uncertainty."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return integration.integration_type != "mcp_server"

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        status = integration.output_flow_status
        if status is not None:
            if status == FlowStatus.VALIDATED:
                proof = next(
                    (
                        item
                        for item in integration.output_flow_evidence
                        if item.status == FlowStatus.VALIDATED
                    ),
                    None,
                )
                location = (
                    proof.validation_location
                    if proof and proof.validation_location
                    else integration.location
                )
                return self._pass(
                    integration,
                    location,
                    "Model output is structurally validated before its resolved use",
                )

            proof = next(
                (
                    item
                    for item in integration.output_flow_evidence
                    if item.status == status
                ),
                None,
            )
            location = (
                proof.use_location
                if proof and proof.use_location
                else integration.location
            )
            reason = proof.reason if proof else "The output path could not be proven"
            if status == FlowStatus.UNKNOWN:
                return self._fail(
                    integration,
                    location,
                    f"Output validation uncertain: {reason}",
                )
            return self._fail(
                integration,
                location,
                f"Output used without proven validation: {reason}",
            )

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
