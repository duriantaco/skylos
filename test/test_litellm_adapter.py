import builtins
import os
import sys
import types
import pytest

from skylos.adapters.litellm_adapter import LiteLLMAdapter


class _FakeLitellmResponse:
    def __init__(self, text: str | None, usage=None, finish_reason=None):
        self.choices = [
            types.SimpleNamespace(
                message=types.SimpleNamespace(content=text),
                finish_reason=finish_reason,
            )
        ]
        self.usage = usage


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

    assert "LiteLLM is required" in str(e.value)


def test_init_sets_litellm_drop_params_true(monkeypatch):
    fake = _install_fake_litellm(monkeypatch)
    monkeypatch.delenv("LITELLM_LOCAL_MODEL_COST_MAP", raising=False)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K")
    assert ad.litellm is fake
    assert ad.litellm.drop_params is True
    assert os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] == "true"


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
    monkeypatch.delenv("SKYLOS_LLM_BASE_URL", raising=False)

    ad = LiteLLMAdapter(model="claude-3-5-sonnet", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out == "hello from litellm"
    assert fake.last_kwargs == {
        "model": "claude-3-5-sonnet",
        "messages": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": "SYS",
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
            },
            {"role": "user", "content": "USER"},
        ],
        "temperature": 0.0,
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


def test_complete_adds_max_tokens_when_present(monkeypatch):
    fake = _FakeLiteLLMModule(text="ok")
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K", max_tokens=321)
    _ = ad.complete("SYS", "USER")

    assert fake.last_kwargs["max_tokens"] == 321


def test_complete_adds_timeout_when_present(monkeypatch):
    fake = _FakeLiteLLMModule(text="ok")
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K", timeout=12)
    _ = ad.complete("SYS", "USER")

    assert fake.last_kwargs["timeout"] == 12


def test_complete_adds_reasoning_effort_when_present(monkeypatch):
    fake = _FakeLiteLLMModule(text="ok")
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(
        model="gpt-5.4",
        api_key="K",
        provider="openai",
        reasoning_effort="high",
    )
    _ = ad.complete("SYS", "USER")

    assert fake.last_kwargs["reasoning_effort"] == "high"
    assert fake.last_kwargs["custom_llm_provider"] == "openai"


def test_complete_records_usage_tokens(monkeypatch):
    usage = types.SimpleNamespace(
        prompt_tokens=111,
        completion_tokens=22,
        total_tokens=133,
    )
    fake = _FakeLiteLLMModule()
    fake.text = "ok"

    def completion(**kwargs):
        fake.last_kwargs = kwargs
        return _FakeLitellmResponse("ok", usage=usage)

    fake.completion = completion
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out == "ok"
    assert ad.last_usage == {
        "prompt_tokens": 111,
        "completion_tokens": 22,
        "total_tokens": 133,
    }
    assert ad.total_usage == {
        "prompt_tokens": 111,
        "completion_tokens": 22,
        "total_tokens": 133,
    }


def test_complete_records_bounded_metadata_only_diagnostics(monkeypatch):
    usage = types.SimpleNamespace(
        prompt_tokens=111,
        completion_tokens=22,
        total_tokens=133,
        completion_tokens_details=types.SimpleNamespace(reasoning_tokens=17),
    )
    fake = _FakeLiteLLMModule()

    def completion(**kwargs):
        fake.last_kwargs = kwargs
        return _FakeLitellmResponse(
            "  private provider response  ",
            usage=usage,
            finish_reason="stop",
        )

    fake.completion = completion
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K")

    assert ad.complete("SYS", "USER") == "private provider response"
    assert ad.last_completion_diagnostic == {
        "finish_reason": "stop",
        "content_chars": 25,
        "completion_tokens": 22,
        "reasoning_tokens": 17,
        "signal": None,
    }
    assert "private provider response" not in repr(ad.last_completion_diagnostic)


@pytest.mark.parametrize(
    ("provider_finish_reason", "content", "expected_content_chars"),
    [
        ("length", None, 0),
        ("max_tokens", '{"action":', 10),
        ("MAX_TOKENS", "", 0),
        ("max-output-tokens", "{", 1),
        ("token limit", "{}", 2),
    ],
)
def test_complete_normalizes_provider_output_budget_finish_reasons(
    monkeypatch,
    provider_finish_reason,
    content,
    expected_content_chars,
):
    usage = {
        "prompt_tokens": 111,
        "completion_tokens": 4096,
        "total_tokens": 4207,
        "completion_tokens_details": {"reasoning_tokens": 4096},
    }
    fake = _FakeLiteLLMModule()

    def completion(**kwargs):
        fake.last_kwargs = kwargs
        return _FakeLitellmResponse(
            content,
            usage=usage,
            finish_reason=provider_finish_reason,
        )

    fake.completion = completion
    _install_fake_litellm(monkeypatch, fake_module=fake)
    ad = LiteLLMAdapter(model="gpt-5.4", api_key="K", provider="openai")

    assert ad.complete("SYS", "USER") == (content or "")
    assert ad.last_completion_diagnostic == {
        "finish_reason": "length",
        "content_chars": expected_content_chars,
        "completion_tokens": 4096,
        "reasoning_tokens": 4096,
        "signal": "output_budget_exhausted",
    }


def test_complete_does_not_persist_unknown_finish_reason(monkeypatch):
    fake = _FakeLiteLLMModule()

    def completion(**kwargs):
        fake.last_kwargs = kwargs
        return _FakeLitellmResponse(
            "ok",
            finish_reason="repository-controlled-finish-reason",
        )

    fake.completion = completion
    _install_fake_litellm(monkeypatch, fake_module=fake)
    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K")

    assert ad.complete("SYS", "USER") == "ok"
    assert ad.last_completion_diagnostic["finish_reason"] is None
    assert ad.last_completion_diagnostic["signal"] is None


def test_complete_error_clears_usage_from_previous_success(monkeypatch):
    usage = types.SimpleNamespace(
        prompt_tokens=111,
        completion_tokens=22,
        total_tokens=133,
    )

    class _SuccessThenErrorLiteLLM:
        def __init__(self):
            self.calls = 0
            self.drop_params = False

        def completion(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                return _FakeLitellmResponse("ok", usage=usage)
            raise RuntimeError("provider unavailable")

    fake = _SuccessThenErrorLiteLLM()
    _install_fake_litellm(monkeypatch, fake_module=fake)
    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K", retry_attempts=1)

    assert ad.complete("SYS", "FIRST") == "ok"
    assert ad.complete("SYS", "SECOND").startswith("Error:")
    assert ad.last_usage == {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }
    assert ad.total_usage == {
        "prompt_tokens": 111,
        "completion_tokens": 22,
        "total_tokens": 133,
    }
    assert ad.last_completion_diagnostic == {
        "finish_reason": None,
        "content_chars": None,
        "completion_tokens": None,
        "reasoning_tokens": None,
        "signal": None,
    }


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


def test_complete_retries_transient_errors_then_succeeds(monkeypatch):
    class _RetryThenSuccessLiteLLM:
        def __init__(self):
            self.calls = 0
            self.drop_params = False

        def completion(self, **kwargs):
            self.calls += 1
            if self.calls < 3:
                raise RuntimeError("Connection error")
            return _FakeLitellmResponse("ok after retry")

    fake = _RetryThenSuccessLiteLLM()
    _install_fake_litellm(monkeypatch, fake_module=fake)
    monkeypatch.setattr("skylos.adapters.litellm_adapter.time.sleep", lambda _: None)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out == "ok after retry"
    assert fake.calls == 3


def test_complete_honors_retry_attempt_limit(monkeypatch):
    class _AlwaysFailLiteLLM:
        def __init__(self):
            self.calls = 0
            self.drop_params = False

        def completion(self, **kwargs):
            self.calls += 1
            raise RuntimeError("Connection error")

    fake = _AlwaysFailLiteLLM()
    _install_fake_litellm(monkeypatch, fake_module=fake)
    monkeypatch.setattr("skylos.adapters.litellm_adapter.time.sleep", lambda _: None)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K", retry_attempts=1)
    out = ad.complete("SYS", "USER")

    assert out.startswith("Error:")
    assert fake.calls == 1


def test_stream_success_yields_delta_chunks(monkeypatch):
    fake = _FakeLiteLLMModule(stream_chunks=["he", "llo", None])
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K")
    parts = list(ad.stream("SYS", "USER"))

    assert "".join(parts) == "hello"
    assert fake.last_kwargs["stream"] is True


def test_stream_adds_max_tokens_when_present(monkeypatch):
    fake = _FakeLiteLLMModule(stream_chunks=["ok"])
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gpt-4o-mini", api_key="K", max_tokens=456)
    parts = list(ad.stream("SYS", "USER"))

    assert "".join(parts) == "ok"
    assert fake.last_kwargs["max_tokens"] == 456


def test_stream_adds_reasoning_effort_when_present(monkeypatch):
    fake = _FakeLiteLLMModule(stream_chunks=["ok"])
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(
        model="gpt-5.4",
        api_key="K",
        provider="openai",
        reasoning_effort="high",
    )
    parts = list(ad.stream("SYS", "USER"))

    assert "".join(parts) == "ok"
    assert fake.last_kwargs["reasoning_effort"] == "high"
    assert fake.last_kwargs["custom_llm_provider"] == "openai"


def test_stream_error_yields_single_error_message(monkeypatch):
    fake = _FakeLiteLLMModule(should_raise=RuntimeError("explode"))
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="gemini/gemini-1.5-flash", api_key="K")
    parts = list(ad.stream("SYS", "USER"))

    assert len(parts) == 1
    assert parts[0].startswith("Error:")
    assert "explode" in parts[0]


def test_complete_auth_error_suggests_login(monkeypatch):
    fake = _FakeLiteLLMModule(should_raise=RuntimeError("401 Unauthorized"))
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(model="claude-3-5-sonnet", api_key="K")
    out = ad.complete("SYS", "USER")

    assert out.startswith("Error:")
    assert "skylos key" in out
    assert "anthropic" in out


def test_complete_connection_error_mentions_base_url(monkeypatch):
    fake = _FakeLiteLLMModule(should_raise=RuntimeError("connection refused"))
    _install_fake_litellm(monkeypatch, fake_module=fake)

    ad = LiteLLMAdapter(
        model="gpt-4o-mini", api_key="K", api_base="http://localhost:11434/v1"
    )
    out = ad.complete("SYS", "USER")

    assert out.startswith("Error:")
    assert "SKYLOS_LLM_BASE_URL" in out or "--base-url" in out


def test_explicit_provider_overrides_model_based_key_resolution(monkeypatch):
    _install_fake_litellm(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    import skylos.adapters.litellm_adapter as adapter_mod

    monkeypatch.setattr(
        adapter_mod,
        "PROVIDERS",
        {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"},
    )
    monkeypatch.setattr(
        adapter_mod,
        "get_key",
        lambda provider: "ANTHRO_KEY" if provider == "anthropic" else None,
    )

    ad = LiteLLMAdapter(model="gpt-4.1", api_key=None, provider="anthropic")

    assert ad.api_key == "ANTHRO_KEY"
    assert os.environ["ANTHROPIC_API_KEY"] == "ANTHRO_KEY"
