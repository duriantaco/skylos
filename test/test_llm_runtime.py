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
