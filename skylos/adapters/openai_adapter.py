import os
from .base import BaseAdapter


class OpenAIAdapter(BaseAdapter):
    def __init__(self, model, api_key):
        super().__init__(model, api_key)
        try:
            import openai
        except ImportError:
            raise ImportError("OpenAI not found. Run `pip install openai`.")

        key = self.api_key or os.getenv("OPENAI_API_KEY")
        if not key:
            raise ValueError("No OpenAI API Key found. Set OPENAI_API_KEY or login.")

        self.client = openai.OpenAI(api_key=key)

    def complete(self, system_prompt, user_prompt):
        try:
            response = self.client.responses.create(
                model=self.model, instructions=system_prompt, input=user_prompt
            )

            return response.output_text.strip()

        except Exception as e:
            return f"OpenAI Error: {str(e)}"
