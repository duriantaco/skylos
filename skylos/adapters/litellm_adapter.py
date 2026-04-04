import os
import time
from .base import BaseAdapter
from skylos.credentials import get_key, PROVIDERS


class LiteLLMAdapter(BaseAdapter):
    RETRYABLE_ERROR_SNIPPETS = (
        "connection error",
        "connection refused",
        "failed to establish a new connection",
        "name or service not known",
        "nodename nor servname provided",
        "timed out",
        "timeout",
        "service unavailable",
        "internalservererror",
        "server error",
        "overloaded",
        "rate limit",
        "ratelimit",
        "429",
    )

    def __init__(
        self,
        model,
        api_key=None,
        api_base=None,
        provider=None,
        enable_cache=True,
        max_tokens=None,
        timeout=None,
        retry_attempts=3,
        temperature=0.0,
    ):
        super().__init__(model, api_key)
        self.enable_cache = enable_cache
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.retry_attempts = max(1, int(retry_attempts or 1))
        self.temperature = temperature
        self.last_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
        self.total_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
        self.explicit_provider = (provider or "").strip().lower() or None

        os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "true")
        try:
            import litellm

            self.litellm = litellm
            self.litellm.drop_params = True
        except ImportError:
            raise ImportError(
                "LiteLLM is required for this feature. "
                "Install it with: pip install skylos[llm]"
            )

        self.api_base = api_base or os.getenv("SKYLOS_LLM_BASE_URL")
        self._resolve_api_key()

    def _detect_provider(self):
        if self.explicit_provider:
            return self.explicit_provider

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

    def _should_retry_exception(self, exc):
        msg = str(exc or "").lower()
        if not msg:
            return False
        return any(snippet in msg for snippet in self.RETRYABLE_ERROR_SNIPPETS)

    def _retry_delay(self, attempt):
        return min(0.5 * (2**attempt), 2.0)

    def reset_usage(self):
        self.last_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
        self.total_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }

    def _normalize_usage(self, usage):
        if usage is None:
            return {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            }

        if isinstance(usage, dict):
            prompt = int(usage.get("prompt_tokens") or 0)
            completion = int(usage.get("completion_tokens") or 0)
            total = int(usage.get("total_tokens") or (prompt + completion))
            return {
                "prompt_tokens": max(prompt, 0),
                "completion_tokens": max(completion, 0),
                "total_tokens": max(total, 0),
            }

        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion = int(getattr(usage, "completion_tokens", 0) or 0)
        total = int(getattr(usage, "total_tokens", 0) or (prompt + completion))
        return {
            "prompt_tokens": max(prompt, 0),
            "completion_tokens": max(completion, 0),
            "total_tokens": max(total, 0),
        }

    def _record_usage(self, response):
        usage = self._normalize_usage(getattr(response, "usage", None))
        self.last_usage = usage
        for key, value in usage.items():
            self.total_usage[key] += value

    def _complete_once(self, system_prompt, user_prompt, response_format=None):
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
            "temperature": self.temperature,
            "api_key": self.api_key,
        }

        if self.max_tokens is not None:
            kwargs["max_tokens"] = self.max_tokens
        if self.timeout is not None:
            kwargs["timeout"] = self.timeout

        if self.api_base:
            kwargs["api_base"] = self.api_base

        if self._is_local():
            kwargs["api_key"] = "not-needed"

        if response_format is not None:
            kwargs["response_format"] = response_format

        response = self.litellm.completion(**kwargs)
        self._record_usage(response)
        return response.choices[0].message.content.strip()

    def _stream_once(self, system_prompt, user_prompt):
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
            "temperature": self.temperature,
            "stream": True,
            "api_key": self.api_key,
        }

        if self.max_tokens is not None:
            kwargs["max_tokens"] = self.max_tokens
        if self.timeout is not None:
            kwargs["timeout"] = self.timeout

        if self.api_base:
            kwargs["api_base"] = self.api_base

        if self._is_local():
            kwargs["api_key"] = "not-needed"

        response = self.litellm.completion(**kwargs)
        for chunk in response:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

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

    def complete(self, system_prompt, user_prompt, response_format=None):
        last_error = None
        for attempt in range(self.retry_attempts):
            try:
                return self._complete_once(
                    system_prompt,
                    user_prompt,
                    response_format=response_format,
                )
            except Exception as e:
                last_error = e
                if (
                    not self._should_retry_exception(e)
                    or attempt == self.retry_attempts - 1
                ):
                    return self._format_exception_message(e)
                time.sleep(self._retry_delay(attempt))

        return self._format_exception_message(last_error)

    def stream(self, system_prompt, user_prompt):
        last_error = None
        for attempt in range(self.retry_attempts):
            try:
                yield from self._stream_once(system_prompt, user_prompt)
                return
            except Exception as e:
                last_error = e
                if (
                    not self._should_retry_exception(e)
                    or attempt == self.retry_attempts - 1
                ):
                    yield self._format_exception_message(e)
                    return
                time.sleep(self._retry_delay(attempt))

        yield self._format_exception_message(last_error)
