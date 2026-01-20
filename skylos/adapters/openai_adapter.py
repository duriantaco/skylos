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
        base_url = os.getenv("OPENAI_BASE_URL") or os.getenv("SKYLOS_LLM_BASE_URL")

        is_local = False
        if base_url:
            local_hosts = ["localhost", "127.0.0.1", "0.0.0.0"]
            for h in local_hosts:
                if h in base_url:
                    is_local = True
                    break

        if not key and is_local:
            key = "skylos-local"

        if not key:
            raise ValueError("No OpenAI API Key found. Set OPENAI_API_KEY or login.")

        if base_url:
            self.client = openai.OpenAI(api_key=key, base_url=base_url)
        else:
            self.client = openai.OpenAI(api_key=key)

    def complete(self, system_prompt, user_prompt):
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
            )
            return response.choices[0].message.content.strip()

        except Exception as e:
            return f"OpenAI Error: {str(e)}"
