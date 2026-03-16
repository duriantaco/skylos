"""Defense plugins — each checks for a specific missing guardrail."""

from skylos.defend.plugins.no_dangerous_sink import NoDangerousSinkPlugin
from skylos.defend.plugins.tool_scope import ToolScopePlugin
from skylos.defend.plugins.tool_schema_present import ToolSchemaPresentPlugin
from skylos.defend.plugins.prompt_delimiter import PromptDelimiterPlugin
from skylos.defend.plugins.output_validation import OutputValidationPlugin
from skylos.defend.plugins.model_pinned import ModelPinnedPlugin
from skylos.defend.plugins.input_length_limit import InputLengthLimitPlugin

# Phase 3: extended defense plugins
from skylos.defend.plugins.untrusted_input_to_prompt import UntrustedInputToPromptPlugin
from skylos.defend.plugins.rag_context_isolation import RagContextIsolationPlugin
from skylos.defend.plugins.output_pii_filter import OutputPiiFilterPlugin

# Phase 3: ops plugins
from skylos.defend.plugins.logging_present import LoggingPresentPlugin
from skylos.defend.plugins.cost_controls import CostControlsPlugin
from skylos.defend.plugins.rate_limiting import RateLimitingPlugin

ALL_PLUGINS = [
    # Defense plugins
    NoDangerousSinkPlugin(),
    ToolScopePlugin(),
    ToolSchemaPresentPlugin(),
    PromptDelimiterPlugin(),
    OutputValidationPlugin(),
    ModelPinnedPlugin(),
    InputLengthLimitPlugin(),
    UntrustedInputToPromptPlugin(),
    RagContextIsolationPlugin(),
    OutputPiiFilterPlugin(),
    # Ops plugins
    LoggingPresentPlugin(),
    CostControlsPlugin(),
    RateLimitingPlugin(),
]

__all__ = ["ALL_PLUGINS"]
