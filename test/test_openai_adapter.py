import builtins
import os
import sys
import types
import pytest

from skylos.adapters.openai_adapter import OpenAIAdapter


class _FakeResponse:
    def __init__(self, output_text: str):
        self.output_text = output_text


class _FakeResponsesAPI:
    def __init__(self, *, should_raise: Exception | None = None):
        self.should_raise = should_raise
        self.last_kwargs = None

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        if self.should_raise:
            raise self.should_raise
        return _FakeResponse("  hello world  ")


class _FakeClient:
    def __init__(self, api_key, responses_api: _FakeResponsesAPI):
        self.api_key = api_key
        self.responses = responses_api


def _install_fake_openai(monkeypatch, *, responses_api=None, capture=None):
    if responses_api is None:
        responses_api = _FakeResponsesAPI()

    def _OpenAI(api_key: str):
        if capture is not None:
            capture["api_key"] = api_key
        return _FakeClient(api_key=api_key, responses_api=responses_api)

    fake_openai = types.SimpleNamespace(OpenAI=_OpenAI)
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    return responses_api


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

    with pytest.raises(ValueError) as e:
        OpenAIAdapter(model="gpt-x", api_key=None)
    assert "No OpenAI API Key found" in str(e.value)


def test_init_uses_explicit_api_key(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)

    ad = OpenAIAdapter(model="gpt-x", api_key="MY_KEY")
    assert ad.client is not None
    assert cap["api_key"] == "MY_KEY"


def test_init_uses_env_key(monkeypatch):
    cap = {}
    _install_fake_openai(monkeypatch, capture=cap)

    monkeypatch.setenv("OPENAI_API_KEY", "ENV_KEY")
    ad = OpenAIAdapter(model="gpt-x", api_key=None)

    assert cap["api_key"] == "ENV_KEY"
    assert ad.client.api_key == "ENV_KEY"


def test_complete_success_calls_responses_create(monkeypatch):
    responses_api = _FakeResponsesAPI()
    _install_fake_openai(monkeypatch, responses_api=responses_api)

    ad = OpenAIAdapter(model="gpt-x", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out == "hello world"  # stripped
    assert responses_api.last_kwargs == {
        "model": "gpt-x",
        "instructions": "SYS",
        "input": "USER",
    }


def test_complete_returns_error_string_on_exception(monkeypatch):
    responses_api = _FakeResponsesAPI(should_raise=RuntimeError("boom"))
    _install_fake_openai(monkeypatch, responses_api=responses_api)

    ad = OpenAIAdapter(model="gpt-x", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out.startswith("OpenAI Error:")
    assert "boom" in out
