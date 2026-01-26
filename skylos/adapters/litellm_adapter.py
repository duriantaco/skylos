import os
from .base import BaseAdapter
from skylos.credentials import get_key, PROVIDERS


class LiteLLMAdapter(BaseAdapter):
    def __init__(self, model, api_key=None, api_base=None):
        super().__init__(model, api_key)

        try:
            import litellm

            self.litellm = litellm
            self.litellm.drop_params = True
        except ImportError:
            raise ImportError("Run: pip install skylos[llm]")

        self.api_base = api_base or os.getenv("SKYLOS_LLM_BASE_URL")

        if not api_key and not self._is_local():
            provider = self._detect_provider()
            api_key = get_key(provider)
            if api_key:
                self._set_env_key(provider, api_key)
                self.api_key = api_key

    def _detect_provider(self):
        m = self.model.lower()
        if m.startswith("ollama/"):
            return "ollama"
        if "claude" in m:
            return "anthropic"
        if m.startswith("gemini/"):
            return "google"
        if m.startswith("mistral/"):
            return "mistral"
        if m.startswith("groq/"):
            return "groq"
        return "openai"

    def _is_local(self):
        model = (self.model or "").strip().lower()

        if model.startswith("ollama/"):
            return True

        api_base = (self.api_base or "").strip().lower()
        if api_base:
            if "localhost" in api_base:
                return True
            if "127.0.0.1" in api_base:
                return True

        return False

    def _set_env_key(self, provider, key):
        env_var = PROVIDERS.get(provider)
        if env_var:
            os.environ[env_var] = key

    def complete(self, system_prompt, user_prompt):
        try:
            kwargs = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.2,
                "api_key": self.api_key,
            }

            if self.api_base:
                kwargs["api_base"] = self.api_base

            if self._is_local():
                kwargs["api_key"] = "not-needed"

            response = self.litellm.completion(**kwargs)
            return response.choices[0].message.content.strip()

        except Exception as e:
            provider = self._detect_provider()
            return f"Error: {e}\n\nRun 'skylos login' and select '{provider}'."

    def stream(self, system_prompt, user_prompt):
        try:
            kwargs = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.2,
                "stream": True,
                "api_key": self.api_key,
            }

            if self.api_base:
                kwargs["api_base"] = self.api_base

            if self._is_local():
                kwargs["api_key"] = "not-needed"

            response = self.litellm.completion(**kwargs)
            for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except Exception as e:
            provider = self._detect_provider()
            yield f"Error: {e}\n\nRun 'skylos login' and select '{provider}'."
