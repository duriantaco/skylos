import builtins
import os
import sys
import types
import pytest

from skylos.adapters.litellm_adapter import LiteLLMAdapter


class _FakeLitellmResponse:
    def __init__(self, text: str):
        self.choices = [
            types.SimpleNamespace(message=types.SimpleNamespace(content=text))
        ]


class _FakeLitellmChunk:
    def __init__(self, delta_text: str | None):
        self.choices = [
            types.SimpleNamespace(delta=types.SimpleNamespace(content=delta_text))
        ]


class _FakeLiteLLMModule:
    def __init__(
        self, *, should_raise: Exception | None = None, text="ok", stream_chunks=None
    ):
        self.should_raise = should_raise
        self.text = text
        self.stream_chunks = stream_chunks or ["a", "b", None]
        self.last_kwargs = None
        self.drop_params = False

    def completion(self, **kwargs):
        self.last_kwargs = kwargs
        if self.should_raise:
            raise self.should_raise

        if kwargs.get("stream"):

            def _gen():
                for c in self.stream_chunks:
                    yield _FakeLitellmChunk(c)

            return _gen()

        return _FakeLitellmResponse(self.text)


def _install_fake_litellm(monkeypatch, *, fake_module=None):
    if fake_module is None:
        fake_module = _FakeLiteLLMModule()
    monkeypatch.setitem(sys.modules, "litellm", fake_module)
    return fake_module


def test_init_raises_if_litellm_missing(monkeypatch):
    if "litellm" in sys.modules:
        monkeypatch.delitem(sys.modules, "litellm", raising=False)

    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "litellm":
            raise ImportError("nope")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    with pytest.raises(ImportError) as e:
        LiteLLMAdapter(model="gpt-4o-mini", api_key="abc")

    assert "pip install skylos[llm]" in str(e.value)


def test_init_sets_litellm_drop_params_true(monkeypatch):
    fake = _install_fake_litellm(monkeypatch)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K")
    assert ad.litellm is fake
    assert ad.litellm.drop_params is True


def test_init_uses_keyring_when_no_key_and_not_local(monkeypatch):
    _install_fake_litellm(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    import skylos.adapters.litellm_adapter as adapter_mod

    monkeypatch.setattr(adapter_mod, "PROVIDERS", {"openai": "OPENAI_API_KEY"})
    monkeypatch.setattr(adapter_mod, "get_key", lambda provider: "KEY_FROM_KEYRING")

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key=None)

    assert ad.api_key == "KEY_FROM_KEYRING"
    assert os.environ["OPENAI_API_KEY"] == "KEY_FROM_KEYRING"


def test_init_does_not_call_keyring_when_local_model(monkeypatch):
    _install_fake_litellm(monkeypatch)

    import skylos.adapters.litellm_adapter as adapter_mod

    def boom(_provider):
        raise AssertionError("get_key() should NOT be called for local mode")

    monkeypatch.setattr(adapter_mod, "get_key", boom)
    monkeypatch.setattr(adapter_mod, "PROVIDERS", {"ollama": "OLLAMA_API_KEY"})

    ad = LiteLLMAdapter(model="ollama/llama3.1", api_key=None)
    assert ad._is_local() is True


def test_complete_success_calls_litellm_completion(monkeypatch):
    fake = _FakeLiteLLMModule(text="hello from litellm")
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="claude-3-5-sonnet", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out == "hello from litellm"
    assert fake.last_kwargs == {
        "model": "claude-3-5-sonnet",
        "messages": [
            {"role": "system", "content": "SYS"},
            {"role": "user", "content": "USER"},
        ],
        "temperature": 0.2,
        "api_key": "K",
    }


def test_complete_adds_api_base_when_present(monkeypatch):
    fake = _FakeLiteLLMModule(text="ok")
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(
        model="gpt-4o-mini",
        api_key="K",
        api_base="http://localhost:11434/v1",
    )
    _ = ad.complete("SYS", "USER")

    assert fake.last_kwargs["api_base"] == "http://localhost:11434/v1"


def test_complete_local_forces_api_key_not_needed(monkeypatch):
    fake = _FakeLiteLLMModule(text="local ok")
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(
        model="ollama/llama3.1",
        api_key=None,
        api_base="http://localhost:11434/v1",
    )

    out = ad.complete("SYS", "USER")
    assert out == "local ok"
    assert fake.last_kwargs["api_key"] == "not-needed"


def test_complete_returns_error_string_on_exception(monkeypatch):
    fake = _FakeLiteLLMModule(should_raise=RuntimeError("boom"))
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="claude-3-5-sonnet", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out.startswith("Error:")
    assert "boom" in out
    assert "skylos login" in out
    assert "anthropic" in out


def test_stream_success_yields_delta_chunks(monkeypatch):
    fake = _FakeLiteLLMModule(stream_chunks=["he", "llo", None])
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K")
    parts = list(ad.stream("SYS", "USER"))

    assert "".join(parts) == "hello"
    assert fake.last_kwargs["stream"] is True


def test_stream_error_yields_single_error_message(monkeypatch):
    fake = _FakeLiteLLMModule(should_raise=RuntimeError("explode"))
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gemini/gemini-1.5-flash", api_key="K")
    parts = list(ad.stream("SYS", "USER"))

    assert len(parts) == 1
    assert parts[0].startswith("Error:")
    assert "explode" in parts[0]
    assert "skylos login" in parts[0]
    assert "google" in parts[0]
