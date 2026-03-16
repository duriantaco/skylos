from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolDef:
    name: str
    location: str
    has_typed_schema: bool = False
    dangerous_calls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "location": self.location,
            "has_typed_schema": self.has_typed_schema,
            "dangerous_calls": self.dangerous_calls,
        }


@dataclass
class LLMIntegration:
    provider: str
    location: str
    integration_type: str
    prompt_sites: list[str] = field(default_factory=list)
    tools: list[ToolDef] = field(default_factory=list)
    input_sources: list[str] = field(default_factory=list)
    output_sinks: list[str] = field(default_factory=list)
    has_system_prompt: bool = False
    model_pinned: bool = False
    model_value: str = ""
    has_output_validation: bool = False
    output_validation_location: str = ""
    has_prompt_delimiter: bool = False
    has_input_length_limit: bool = False
    input_length_limit_location: str = ""
    has_rag_context: bool = False
    has_pii_filter: bool = False
    has_logging: bool = False
    has_max_tokens: bool = False
    has_rate_limiting: bool = False

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "location": self.location,
            "integration_type": self.integration_type,
            "prompt_sites": self.prompt_sites,
            "tools": [t.to_dict() for t in self.tools],
            "input_sources": self.input_sources,
            "output_sinks": self.output_sinks,
            "has_system_prompt": self.has_system_prompt,
            "model_pinned": self.model_pinned,
            "model_value": self.model_value,
            "has_output_validation": self.has_output_validation,
            "output_validation_location": self.output_validation_location,
            "has_prompt_delimiter": self.has_prompt_delimiter,
            "has_input_length_limit": self.has_input_length_limit,
            "input_length_limit_location": self.input_length_limit_location,
            "has_rag_context": self.has_rag_context,
            "has_pii_filter": self.has_pii_filter,
            "has_logging": self.has_logging,
            "has_max_tokens": self.has_max_tokens,
            "has_rate_limiting": self.has_rate_limiting,
        }
