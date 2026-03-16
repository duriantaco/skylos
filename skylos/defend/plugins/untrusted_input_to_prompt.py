from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class UntrustedInputToPromptPlugin(DefensePlugin):
    id = "untrusted-input-to-prompt"
    name = "Untrusted Input to Prompt"
    severity = "critical"
    owasp_llm = "LLM01"
    description = (
        "User-controlled input and prompt construction detected in same scope — "
        "must have intermediate processing (validation, escaping, delimiters)"
    )
    remediation = (
        "Add input validation, sanitization, or prompt delimiters between "
        "user input and prompt construction. Use structured prompt templates."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return bool(integration.input_sources) and bool(integration.prompt_sites)

    def check(self, integration: LLMIntegration, graph: AIIntegrationGraph) -> DefenseResult:
        has_defense = (
            integration.has_prompt_delimiter
            or integration.has_input_length_limit
        )

        if has_defense:
            return self._pass(
                integration,
                integration.location,
                "Input and prompt in same scope with intermediate processing",
            )

        sources = ", ".join(integration.input_sources[:3])
        return self._fail(
            integration,
            integration.location,
            f"Raw input ({sources}) and prompt construction in same scope without processing",
        )
