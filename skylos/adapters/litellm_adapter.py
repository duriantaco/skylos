import os
from .base import BaseAdapter
from skylos.credentials import get_key, PROVIDERS


class LiteLLMAdapter(BaseAdapter):
    def __init__(self, model, api_key=None, api_base=None, enable_cache=True):
        super().__init__(model, api_key)
        self.enable_cache = enable_cache

        try:
            import litellm

            self.litellm = litellm
            self.litellm.drop_params = True
        except ImportError:
            raise ImportError(
                "LiteLLM is required but missing. Your Skylos installation is incomplete. "
                "Reinstall Skylos."
            )

        self.api_base = api_base or os.getenv("SKYLOS_LLM_BASE_URL")
        self._resolve_api_key()

    def _detect_provider(self):
        model = (self.model or "").lower()

        if model.startswith("ollama/"):
            return "ollama"
        if "claude" in model:
            return "anthropic"
        if model.startswith("gemini/"):
            return "google"
        if model.startswith("mistral/"):
            return "mistral"
        if model.startswith("groq/"):
            return "groq"

        return "openai"

    def _is_local(self):
        model = (self.model or "").strip().lower()
        if model.startswith("ollama/"):
            return True

        base_url = (self.api_base or "").strip().lower()
        if base_url:
            if "localhost" in base_url:
                return True
            if "127.0.0.1" in base_url:
                return True

        return False
    
    def _is_anthropic(self):
        return self._detect_provider() == "anthropic"

    def _get_provider_env_var(self, provider):
        if not provider:
            return None
        return PROVIDERS.get(provider)

    def _resolve_api_key(self):
        if self._is_local():
            return

        if self.api_key:
            self._set_provider_env_var_if_missing(self.api_key)
            return

        provider = self._detect_provider()
        env_var = self._get_provider_env_var(provider)

        if env_var:
            env_value = os.getenv(env_var)
            if env_value:
                self.api_key = env_value
                return

        keyring_key = get_key(provider)
        if keyring_key:
            if env_var:
                os.environ[env_var] = keyring_key
            self.api_key = keyring_key
            return

    def _set_provider_env_var_if_missing(self, key):
        if not key:
            return

        provider = self._detect_provider()
        env_var = self._get_provider_env_var(provider)

        if not env_var:
            return

        existing = os.getenv(env_var)
        if existing:
            return

        os.environ[env_var] = key

    def _missing_key_message(self):
        provider = self._detect_provider()
        env_var = self._get_provider_env_var(provider)

        if env_var:
            return (
                "No API key found for provider '{}'.\n"
                "Set {} or run 'skylos key' and select '{}'."
            ).format(provider, env_var, provider)

        return (
            "No API key found for provider '{}'.\nRun 'skylos key' and select '{}'."
        ).format(provider, provider)

    def _looks_like_auth_error(self, message):
        if not message:
            return False

        msg = message.lower()

        if "unauthorized" in msg:
            return True
        if "invalid api key" in msg:
            return True
        if "incorrect api key" in msg:
            return True
        if "authentication" in msg:
            return True
        if "401" in msg:
            return True
        if "403" in msg:
            return True

        return False

    def _looks_like_connection_error(self, message):
        if not message:
            return False

        msg = message.lower()

        if "connection refused" in msg:
            return True
        if "failed to establish a new connection" in msg:
            return True
        if "name or service not known" in msg:
            return True
        if "nodename nor servname provided" in msg:
            return True
        if "timed out" in msg:
            return True

        return False

    def _format_exception_message(self, exc):
        text = str(exc)

        if (not self._is_local()) and (not self.api_key):
            return self._missing_key_message()

        if self._looks_like_auth_error(text):
            provider = self._detect_provider()
            return "Error: {}\n\nRun 'skylos key' and select '{}'.".format(
                text, provider
            )

        if self._looks_like_connection_error(text):
            if self.api_base:
                return "Error: {}\n\nCheck SKYLOS_LLM_BASE_URL / --base-url: {}".format(
                    text, self.api_base
                )
            return (
                "Error: {}\n\n"
                "If you're using a local LLM, set SKYLOS_LLM_BASE_URL "
                "(e.g. http://localhost:11434/v1)."
            ).format(text)

        return "Error: {}".format(text)

    def complete(self, system_prompt, user_prompt):
        try:
            self._resolve_api_key()

            if (not self._is_local()) and (not self.api_key):
                return self._missing_key_message()

            if self.enable_cache and self._is_anthropic():
                messages = [
                    {
                        "role": "system",
                        "content": [
                            {
                                "type": "text",
                                "text": system_prompt,
                                "cache_control": {"type": "ephemeral"},
                            }
                        ],
                    },
                    {"role": "user", "content": user_prompt},
                ]
            else:
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ]

            kwargs = {
                "model": self.model,
                "messages": messages,
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
            return self._format_exception_message(e)

    def stream(self, system_prompt, user_prompt):
        try:
            self._resolve_api_key()

            if (not self._is_local()) and (not self.api_key):
                yield self._missing_key_message()
                return

            if self.enable_cache and self._is_anthropic():
                messages = [
                    {
                        "role": "system",
                        "content": [
                            {
                                "type": "text",
                                "text": system_prompt,
                                "cache_control": {"type": "ephemeral"},
                            }
                        ],
                    },
                    {"role": "user", "content": user_prompt},
                ]
            else:
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ]

            kwargs = {
                "model": self.model,
                "messages": messages,
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
            yield self._format_exception_message(e)
