from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class PromptDelimiterPlugin(DefensePlugin):
    id = "prompt-delimiter"
    name = "Prompt Delimiter Present"
    severity = "high"
    owasp_llm = "LLM01"
    description = (
        "User input in prompts must be wrapped in delimiters "
        "(XML tags, backticks, quotes) to prevent prompt injection"
    )
    remediation = (
        "Wrap user input in XML tags like <user_input>...</user_input> or "
        "triple backticks in your prompt template."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return bool(integration.input_sources) and bool(integration.prompt_sites)

    def check(self, integration: LLMIntegration, graph: AIIntegrationGraph) -> DefenseResult:
        if integration.has_prompt_delimiter:
            return self._pass(
                integration,
                integration.location,
                "User input is delimited in prompt template",
            )

        return self._fail(
            integration,
            integration.location,
            "User input concatenated into prompt without delimiters",
        )
