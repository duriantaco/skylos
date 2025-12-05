from .base import BaseAdapter
from .openai_adapter import OpenAIAdapter
from .anthropic_adapter import AnthropicAdapter


def get_adapter(model, api_key=None):
    model_lower = model.lower()

    if "claude" in model_lower:
        return AnthropicAdapter(model, api_key)

    return OpenAIAdapter(model, api_key)
