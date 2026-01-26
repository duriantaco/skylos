from .base import BaseAdapter
from .litellm_adapter import LiteLLMAdapter

__all__ = ["BaseAdapter", "get_adapter", "LiteLLMAdapter"]


def get_adapter(model, api_key=None, api_base=None):
    return LiteLLMAdapter(model, api_key, api_base)
