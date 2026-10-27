from skylos.llm.runtime import resolve_llm_runtime


class DummyConsole:
    def __init__(self):
        self.messages = []

    def print(self, message):
        self.messages.append(message)

    def input(self, prompt, password=False):
        raise EOFError


def test_resolve_llm_runtime_handles_eoferror(monkeypatch):
    monkeypatch.setattr("skylos.llm.runtime.get_key", lambda provider: None)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    provider, api_key, base_url, is_local = resolve_llm_runtime(
        model="gpt-4.1",
        provider_override=None,
        base_url_override=None,
        console=DummyConsole(),
        allow_prompt=True,
    )

    assert provider == "openai"
    assert api_key is None
    assert base_url is None
    assert is_local is False


def test_gemini_models_read_the_google_key(monkeypatch):
    monkeypatch.setattr("skylos.cloud.credentials._keyring", lambda: None)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")
    monkeypatch.delenv("SKYLOS_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    provider, api_key, _base_url, is_local = resolve_llm_runtime(
        model="gemini/gemini-2.0-flash",
        provider_override=None,
        base_url_override=None,
        console=None,
        allow_prompt=False,
    )

    assert (provider, api_key, is_local) == ("google", "gemini-test-key", False)


def test_provider_key_env_var_matches_the_runtime_lookup():
    from skylos.llm.runtime import provider_key_env_var

    assert provider_key_env_var("gpt-4.1") == "OPENAI_API_KEY"
    assert provider_key_env_var("claude-sonnet-4-20250514") == "ANTHROPIC_API_KEY"
    assert provider_key_env_var("gemini/gemini-2.0-flash") == "GEMINI_API_KEY"
    assert provider_key_env_var("ollama/llama3") is None
    assert provider_key_env_var("gpt-4.1", provider="groq") == "GROQ_API_KEY"


def test_llm_extra_checks_report_a_missing_litellm(monkeypatch):
    import importlib.util

    from skylos.llm import runtime

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)

    assert runtime.llm_extra_installed() is False
    assert runtime.llm_extra_importable() is False
    assert runtime.LLM_EXTRA_INSTALL_COMMAND == 'pip install "skylos[llm]"'
    assert 'pip install "skylos[llm]"' in runtime.LLM_EXTRA_MISSING_MESSAGE


def test_llm_extra_importable_is_false_when_litellm_fails_to_import(monkeypatch):
    import builtins
    import importlib.util
    import sys

    from skylos.llm import runtime

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "true")
    monkeypatch.delitem(sys.modules, "litellm", raising=False)
    real_import = builtins.__import__

    def broken_import(name, *args, **kwargs):
        if name == "litellm":
            raise RuntimeError("broken install")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken_import)

    assert runtime.llm_extra_installed() is True
    assert runtime.llm_extra_importable() is False
