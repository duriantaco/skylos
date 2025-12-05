import os
from .base import BaseAdapter


class AnthropicAdapter(BaseAdapter):
    def __init__(self, model: str, api_key):
        super().__init__(model, api_key)
        try:
            import anthropic
        except ImportError:
            raise ImportError("Anthropic SDK not found. Run `pip install anthropic`.")

        key = self.api_key or os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError("No Anthropic API Key found. Set ANTHROPIC_API_KEY.")

        self.client = anthropic.Anthropic(api_key=key)

    def complete(self, system_prompt, user_prompt):
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                temperature=0.2,
            )
            return response.content[0].text
        except Exception as e:
            return f"Anthropic Error: {str(e)}"
