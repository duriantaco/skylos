from skylos.defend.plugin import DefensePlugin
from skylos.defend.result import DefenseResult
from skylos.discover.integration import LLMIntegration
from skylos.discover.graph import AIIntegrationGraph


class RagContextIsolationPlugin(DefensePlugin):
    id = "rag-context-isolation"
    name = "RAG Context Isolation"
    severity = "high"
    owasp_llm = "LLM01"
    description = (
        "Retrieved context in RAG pipelines must be wrapped in delimiters "
        "before injection into prompts to prevent indirect prompt injection"
    )
    remediation = (
        "Wrap retrieved documents in clear delimiters (e.g., XML tags, "
        "triple backticks) before inserting into the prompt template."
    )

    def applies_to(self, integration: LLMIntegration) -> bool:
        return integration.has_rag_context

    def check(
        self, integration: LLMIntegration, graph: AIIntegrationGraph
    ) -> DefenseResult:
        if integration.has_prompt_delimiter:
            return self._pass(
                integration,
                integration.location,
                "RAG context has prompt delimiters for isolation",
            )

        return self._fail(
            integration,
            integration.location,
            "RAG pipeline lacks context isolation delimiters",
        )
