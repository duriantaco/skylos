import builtins
import sys
import types
import pytest

from skylos.adapters.openai_adapter import OpenAIAdapter


class _FakeMessage:
    def __init__(self, content):
        self.content = content


class _FakeChoice:
    def __init__(self, content):
        self.message = _FakeMessage(content)


class _FakeCompletionResponse:
    def __init__(self, content):
        self.choices = [_FakeChoice(content)]


class _FakeChatCompletionsAPI:
    def __init__(self, *, should_raise=None):
        self.should_raise = should_raise
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        if self.should_raise:
            raise self.should_raise
        return _FakeCompletionResponse("  hello world  ")


class _FakeChat:
    def __init__(self, completions_api: _FakeChatCompletionsAPI):
        self.completions = completions_api


class _FakeClient:
    def __init__(self, api_key, base_url, completions_api: _FakeChatCompletionsAPI):
        self.api_key = api_key
        self.base_url = base_url
        self.chat = _FakeChat(completions_api)


def _install_fake_openai(monkeypatch, *, completions_api=None, capture=None):
    if completions_api is None:
        completions_api = _FakeChatCompletionsAPI()

    def _OpenAI(api_key, base_url=None):
        if capture is not None:
            capture["api_key"] = api_key
            capture["base_url"] = base_url
        return _FakeClient(
            api_key=api_key, base_url=base_url, completions_api=completions_api
        )

    fake_openai = types.SimpleNamespace(OpenAI=_OpenAI)
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    return completions_api


def test_init_raises_if_openai_missing(monkeypatch):
    if "openai" in sys.modules:
        monkeypatch.delitem(sys.modules, "openai", raising=False)

    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "openai":
            raise ImportError("nope")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    with pytest.raises(ImportError) as e:
        OpenAIAdapter(model="gpt-x", api_key="abc")
    assert "OpenAI not found" in str(e.value)


def test_init_raises_if_no_key(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    with pytest.raises(ValueError) as e:
        OpenAIAdapter(model="gpt-x", api_key=None)
    assert "No OpenAI API Key found" in str(e.value)


def test_init_uses_explicit_api_key(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    ad = OpenAIAdapter(model="gpt-x", api_key="MY_KEY")
    assert ad.client is not None
    assert cap["api_key"] == "MY_KEY"
    assert cap["base_url"] is None


def test_init_uses_env_key(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    monkeypatch.setenv("OPENAI_API_KEY", "ENV_KEY")
    ad = OpenAIAdapter(model="gpt-x", api_key=None)

    assert cap["api_key"] == "ENV_KEY"
    assert ad.client.api_key == "ENV_KEY"


def test_init_uses_base_url_from_env(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)

    monkeypatch.setenv("OPENAI_API_KEY", "KEY")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")

    ad = OpenAIAdapter(model="qwen", api_key=None)

    assert cap["base_url"] == "http://localhost:11434/v1"
    assert ad.client.base_url == "http://localhost:11434/v1"


def test_init_uses_skylos_base_url_env(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)

    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setenv("SKYLOS_LLM_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "KEY")

    ad = OpenAIAdapter(model="mistral", api_key=None)

    assert cap["base_url"] == "http://localhost:1234/v1"


def test_init_openai_base_url_takes_precedence(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)

    monkeypatch.setenv("OPENAI_BASE_URL", "http://primary:8000/v1")
    monkeypatch.setenv("SKYLOS_LLM_BASE_URL", "http://fallback:8000/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "KEY")

    ad = OpenAIAdapter(model="model", api_key=None)

    assert cap["base_url"] == "http://primary:8000/v1"


def test_init_uses_placeholder_key_for_local_endpoint(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")

    ad = OpenAIAdapter(model="qwen", api_key=None)

    assert cap["api_key"] == "skylos-local"
    assert cap["base_url"] == "http://localhost:11434/v1"


def test_complete_success_calls_chat_completions(monkeypatch):
    completions_api = _FakeChatCompletionsAPI()
    _install_fake_openai(monkeypatch, completions_api=completions_api)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    ad = OpenAIAdapter(model="gpt-x", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out == "hello world"
    assert completions_api.last_kwargs["model"] == "gpt-x"
    assert completions_api.last_kwargs["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USER"},
    ]
    assert completions_api.last_kwargs["temperature"] == 0.2


def test_complete_returns_error_string_on_exception(monkeypatch):
    completions_api = _FakeChatCompletionsAPI(should_raise=RuntimeError("boom"))
    _install_fake_openai(monkeypatch, completions_api=completions_api)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    ad = OpenAIAdapter(model="gpt-x", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out.startswith("OpenAI Error:")
    assert "boom" in out


def test_explicit_api_key_takes_precedence_over_env(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    monkeypatch.setenv("OPENAI_API_KEY", "ENV_KEY")
    ad = OpenAIAdapter(model="gpt-x", api_key="EXPLICIT_KEY")

    assert cap["api_key"] == "EXPLICIT_KEY"


def test_placeholder_key_for_127_0_0_1_endpoint(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:8000/v1")

    ad = OpenAIAdapter(model="llama", api_key=None)

    assert cap["api_key"] == "skylos-local"
    assert cap["base_url"] == "http://127.0.0.1:8000/v1"


def test_remote_base_url_still_requires_key(monkeypatch):
    _install_fake_openai(monkeypatch)

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.together.xyz/v1")

    with pytest.raises(ValueError) as e:
        OpenAIAdapter(model="llama", api_key=None)
    assert "No OpenAI API Key found" in str(e.value)


def test_model_passed_to_complete(monkeypatch):
    completions_api = _FakeChatCompletionsAPI()
    _install_fake_openai(monkeypatch, completions_api=completions_api)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    ad = OpenAIAdapter(model="qwen2.5-coder:7b", api_key="K")
    ad.complete("system", "user")

    assert completions_api.last_kwargs["model"] == "qwen2.5-coder:7b"


def test_empty_string_api_key_treated_as_missing(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    with pytest.raises(ValueError) as e:
        OpenAIAdapter(model="gpt-x", api_key="")
    assert "No OpenAI API Key found" in str(e.value)
