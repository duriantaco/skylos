import builtins
import sys
import types
import pytest

from skylos.adapters.anthropic_adapter import AnthropicAdapter


class _FakeMsg:
    def __init__(self, text: str):
        self.text = text


class _FakeResponse:
    def __init__(self, text: str):
        self.content = [_FakeMsg(text)]


class _FakeMessagesAPI:
    def __init__(self, *, should_raise: Exception | None = None, text="ok"):
        self.should_raise = should_raise
        self.text = text
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        if self.should_raise:
            raise self.should_raise
        return _FakeResponse(self.text)


class _FakeClient:
    def __init__(self, api_key: str, messages_api: _FakeMessagesAPI):
        self.api_key = api_key
        self.messages = messages_api


def _install_fake_anthropic(monkeypatch, *, messages_api=None, capture=None):
    if messages_api is None:
        messages_api = _FakeMessagesAPI()

    def _Anthropic(api_key: str):
        if capture is not None:
            capture["api_key"] = api_key
        return _FakeClient(api_key=api_key, messages_api=messages_api)

    fake_anthropic = types.SimpleNamespace(Anthropic=_Anthropic)
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic)
    return messages_api


def test_init_raises_if_anthropic_missing(monkeypatch):
    if "anthropic" in sys.modules:
        monkeypatch.delitem(sys.modules, "anthropic", raising=False)

    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("nope")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    with pytest.raises(ImportError) as e:
        AnthropicAdapter(model="claude-x", api_key="abc")
    assert "Anthropic SDK not found" in str(e.value)


def test_init_raises_if_no_key(monkeypatch):
    _install_fake_anthropic(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(ValueError) as e:
        AnthropicAdapter(model="claude-x", api_key=None)
    assert "No Anthropic API Key found" in str(e.value)


def test_init_uses_explicit_api_key(monkeypatch):
    cap = {}
    _install_fake_anthropic(monkeypatch, capture=cap)

    ad = AnthropicAdapter(model="claude-x", api_key="MY_KEY")
    assert ad.client is not None
    assert cap["api_key"] == "MY_KEY"


def test_init_uses_env_key(monkeypatch):
    cap = {}
    _install_fake_anthropic(monkeypatch, capture=cap)

    monkeypatch.setenv("ANTHROPIC_API_KEY", "ENV_KEY")
    ad = AnthropicAdapter(model="claude-x", api_key=None)

    assert cap["api_key"] == "ENV_KEY"
    assert ad.client.api_key == "ENV_KEY"


def test_complete_success_calls_messages_create(monkeypatch):
    messages_api = _FakeMessagesAPI(text="hello from claude")
    _install_fake_anthropic(monkeypatch, messages_api=messages_api)

    ad = AnthropicAdapter(model="claude-x", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out == "hello from claude"
    assert messages_api.last_kwargs == {
        "model": "claude-x",
        "max_tokens": 4096,
        "system": "SYS",
        "messages": [{"role": "user", "content": "USER"}],
        "temperature": 0.2,
    }


def test_complete_returns_error_string_on_exception(monkeypatch):
    messages_api = _FakeMessagesAPI(should_raise=RuntimeError("boom"))
    _install_fake_anthropic(monkeypatch, messages_api=messages_api)

    ad = AnthropicAdapter(model="claude-x", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out.startswith("Anthropic Error:")
    assert "boom" in out
