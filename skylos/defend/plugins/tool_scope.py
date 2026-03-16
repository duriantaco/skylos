from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class ToolScopePlugin(DefensePlugin):
    id = "tool-scope"
    name = "Tool Scope Restricted"
    severity = "critical"
    owasp_llm = "LLM04"
    description = (
        "Tool functions must not have unrestricted access to shell, filesystem, or network"
    )
    remediation = (
        "Wrap dangerous operations in tool functions with permission checks, "
        "allowlists, or sandboxing. Restrict tool capabilities to minimum required scope."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return integration.integration_type == "agent" and len(integration.tools) > 0

    def check(self, integration: LLMIntegration, graph: AIIntegrationGraph) -> DefenseResult:
        dangerous_tools = []
        for tool in integration.tools:
            if tool.dangerous_calls:
                calls = ", ".join(tool.dangerous_calls)
                dangerous_tools.append(f"{tool.name}: {calls}")

        if not dangerous_tools:
            return self._pass(
                integration,
                integration.location,
                "No dangerous operations in tool functions",
            )

        details = "; ".join(dangerous_tools)
        return self._fail(
            integration,
            integration.location,
            f"Tools with unrestricted dangerous operations: {details}",
        )
