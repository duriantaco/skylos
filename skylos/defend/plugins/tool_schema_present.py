from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class ToolSchemaPresentPlugin(DefensePlugin):
    id = "tool-schema-present"
    name = "Tool Schema Present"
    severity = "critical"
    owasp_llm = "LLM04"
    description = "Tool definitions must have explicit typed argument schemas"
    remediation = (
        "Add type annotations to all tool function parameters. "
        "Use Pydantic models or typed schemas for tool argument validation."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return integration.integration_type == "agent" and len(integration.tools) > 0

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        untyped = [t for t in integration.tools if not t.has_typed_schema]

        if not untyped:
            return self._pass(
                integration,
                integration.location,
                f"All {len(integration.tools)} tool(s) have typed schemas",
            )

        names = ", ".join(t.name for t in untyped)
        return self._fail(
            integration,
            integration.location,
            f"{len(untyped)} tool(s) without typed schemas: {names}",
        )
