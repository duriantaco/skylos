import json
import pytest

import skylos.llm.agents as agents
from skylos.adapters.litellm_adapter import LiteLLMAdapter


class FakeAdapter:
    def __init__(self, complete_text=None, stream_chunks=None):
        self.complete_text = complete_text or ""
        self.stream_chunks = stream_chunks or []
        self.complete_calls = []
        self.stream_calls = []

    def complete(self, system, user, response_format=None):
        self.complete_calls.append(
            {"system": system, "user": user, "response_format": response_format}
        )
        return self.complete_text

    def stream(self, system, user):
        self.stream_calls.append({"system": system, "user": user})
        for c in self.stream_chunks:
            yield c


class DummyContextBuilder:
    def __init__(self, context_text="CTX"):
        self.context_text = context_text
        self.analysis_calls = []
        self.fix_calls = []

    def build_analysis_context(self, source, file_path=None, defs_map=None):
        self.analysis_calls.append(
            {"source": source, "file_path": file_path, "defs_map": defs_map}
        )
        return self.context_text

    def build_fix_context(
        self, source, file_path, issue_line, issue_message, defs_map=None
    ):
        self.fix_calls.append(
            {
                "source": source,
                "file_path": file_path,
                "issue_line": issue_line,
                "issue_message": issue_message,
                "defs_map": defs_map,
            }
        )
        return self.context_text


def test_create_agent_valid_types():
    for t in agents.AGENT_REGISTRY.keys():
        a = agents.create_agent(t, config=agents.AgentConfig(api_key="x", stream=False))
        assert a is not None


def test_create_agent_invalid_type_raises():
    with pytest.raises(ValueError):
        agents.create_agent("not_real")


def test_create_llm_adapter_returns_litellm_adapter(monkeypatch):
    cfg = agents.AgentConfig(model="gpt-4o-mini", api_key="X")
    adapter = agents.create_llm_adapter(cfg)

    assert isinstance(adapter, LiteLLMAdapter)


def test_create_llm_adapter_litellm_sets_api_base_from_env(monkeypatch):
    monkeypatch.setenv("SKYLOS_LLM_BASE_URL", "http://localhost:11434/v1")

    cfg = agents.AgentConfig(model="gpt-4o-mini", api_key="X")
    adapter = agents.create_llm_adapter(cfg)

    assert adapter.api_base == "http://localhost:11434/v1"


def test_security_agent_include_examples_true_for_small_context(monkeypatch):
    ctx = "x" * 100
    fake_builder = DummyContextBuilder(context_text=ctx)
    fake_adapter = FakeAdapter(complete_text='{"findings": []}')

    monkeypatch.setattr(agents, "ContextBuilder", lambda: fake_builder)
    monkeypatch.setattr(agents, "create_llm_adapter", lambda config: fake_adapter)

    called = {}

    def fake_build_security_prompt(context, include_examples=True):
        called["include_examples"] = include_examples
        return ("SYS", "USER")

    monkeypatch.setattr(agents, "build_security_prompt", fake_build_security_prompt)

    monkeypatch.setattr(agents, "parse_llm_response", lambda text, fp: [])

    cfg = agents.AgentConfig(api_key="x", stream=False)
    a = agents.SecurityAgent(cfg)
    out = a.analyze("source", "file.py")

    assert out == []
    assert called["include_examples"] is True

    assert len(fake_adapter.complete_calls) == 1
    assert (
        fake_adapter.complete_calls[0]["response_format"]
        == agents.FINDINGS_RESPONSE_FORMAT
    )


def test_security_agent_include_examples_false_for_large_context(monkeypatch):
    ctx = "x" * 20001
    fake_builder = DummyContextBuilder(context_text=ctx)
    fake_adapter = FakeAdapter(stream_chunks=["{", '"findings"', ":", "[]", "}"])

    monkeypatch.setattr(agents, "ContextBuilder", lambda: fake_builder)
    monkeypatch.setattr(agents, "create_llm_adapter", lambda config: fake_adapter)

    called = {}

    def fake_build_security_prompt(context, include_examples=True):
        called["include_examples"] = include_examples
        return ("SYS", "USER")

    monkeypatch.setattr(agents, "build_security_prompt", fake_build_security_prompt)

    parsed = {}

    def fake_parse_llm_response(text, fp):
        parsed["text"] = text
        parsed["fp"] = fp
        return []

    monkeypatch.setattr(agents, "parse_llm_response", fake_parse_llm_response)

    cfg = agents.AgentConfig(api_key="x", stream=True)
    a = agents.SecurityAgent(cfg)
    out = a.analyze("source", "file.py")

    assert out == []
    assert called["include_examples"] is False

    assert len(fake_adapter.complete_calls) == 0
    assert len(fake_adapter.stream_calls) == 1

    assert parsed["fp"] == "file.py"
    assert json.loads(parsed["text"]) == {"findings": []}


def test_security_audit_agent_always_uses_complete_with_response_format(monkeypatch):
    ctx = "x" * 100
    fake_builder = DummyContextBuilder(context_text=ctx)
    fake_adapter = FakeAdapter(complete_text='{"findings": []}')

    monkeypatch.setattr(agents, "ContextBuilder", lambda: fake_builder)
    monkeypatch.setattr(agents, "create_llm_adapter", lambda config: fake_adapter)

    called = {}

    def fake_build_security_audit_prompt(context, include_examples=True):
        called["include_examples"] = include_examples
        return ("SYS", "USER")

    monkeypatch.setattr(
        agents, "build_security_audit_prompt", fake_build_security_audit_prompt
    )
    monkeypatch.setattr(agents, "parse_llm_response", lambda text, fp: [])

    cfg = agents.AgentConfig(api_key="x", stream=True)
    a = agents.SecurityAuditAgent(cfg)

    out = a.analyze("src", "audit.py")
    assert out == []

    assert len(fake_adapter.complete_calls) == 1
    assert (
        fake_adapter.complete_calls[0]["response_format"]
        == agents.FINDINGS_RESPONSE_FORMAT
    )
    assert called["include_examples"] is True

    assert len(fake_adapter.stream_calls) == 0


def test_fixer_agent_fix_happy_path_builds_codefix(monkeypatch):
    fake_builder = DummyContextBuilder(context_text="CTX")
    fake_response = json.dumps(
        {
            "problem": "Bad thing",
            "solution": "Fix it",
            "confidence": "high",
            "code_lines": ["print('fixed')"],
        }
    )
    fake_adapter = FakeAdapter(complete_text=fake_response)

    monkeypatch.setattr(agents, "ContextBuilder", lambda: fake_builder)
    monkeypatch.setattr(agents, "create_llm_adapter", lambda config: fake_adapter)

    monkeypatch.setattr(
        agents, "build_fix_prompt", lambda ctx, ln, msg: ("SYS", "USER")
    )

    cfg = agents.AgentConfig(api_key="x", stream=False)
    fx = agents.FixerAgent(cfg)

    src = "line1\nline2\nline3\nline4\nline5\nline6\n"
    fix = fx.fix(src, "file.py", issue_line=3, issue_message="oops")

    assert fix is not None
    assert fix.finding.rule_id == "SKY-FIX"
    assert fix.finding.location.file == "file.py"
    assert fix.finding.location.line == 3
    assert fix.fixed_code.strip() == "print('fixed')"
    assert fix.confidence.value == "high"
    assert "Solution:" in fix.description


def test_fixer_agent_fix_solution_null_is_ok(monkeypatch):
    fake_builder = DummyContextBuilder(context_text="CTX")
    fake_response = json.dumps(
        {
            "problem": "Bad thing",
            "solution": None,
            "confidence": "medium",
            "code_lines": ["print('fixed')"],
        }
    )
    fake_adapter = FakeAdapter(complete_text=fake_response)

    monkeypatch.setattr(agents, "ContextBuilder", lambda: fake_builder)
    monkeypatch.setattr(agents, "create_llm_adapter", lambda config: fake_adapter)
    monkeypatch.setattr(
        agents, "build_fix_prompt", lambda ctx, ln, msg: ("SYS", "USER")
    )

    cfg = agents.AgentConfig(api_key="x", stream=False)
    fx = agents.FixerAgent(cfg)

    src = "a\nb\nc\n"
    fix = fx.fix(src, "file.py", 2, "oops")

    assert fix is not None
    assert "Solution:" not in fix.description


def test_fixer_agent_fix_empty_fixed_code_returns_none(monkeypatch):
    fake_builder = DummyContextBuilder(context_text="CTX")
    fake_response = json.dumps(
        {
            "problem": "Bad thing",
            "solution": "Fix it",
            "confidence": "high",
            "code_lines": [""],
        }
    )
    fake_adapter = FakeAdapter(complete_text=fake_response)

    monkeypatch.setattr(agents, "ContextBuilder", lambda: fake_builder)
    monkeypatch.setattr(agents, "create_llm_adapter", lambda config: fake_adapter)
    monkeypatch.setattr(
        agents, "build_fix_prompt", lambda ctx, ln, msg: ("SYS", "USER")
    )

    cfg = agents.AgentConfig(api_key="x", stream=False)
    fx = agents.FixerAgent(cfg)

    src = "a\nb\nc\n"
    fix = fx.fix(src, "file.py", 2, "oops")

    assert fix is None


def test_fixer_agent_fix_invalid_json_returns_none(monkeypatch):
    fake_builder = DummyContextBuilder(context_text="CTX")
    fake_adapter = FakeAdapter(complete_text="not json")

    monkeypatch.setattr(agents, "ContextBuilder", lambda: fake_builder)
    monkeypatch.setattr(agents, "create_llm_adapter", lambda config: fake_adapter)
    monkeypatch.setattr(
        agents, "build_fix_prompt", lambda ctx, ln, msg: ("SYS", "USER")
    )

    cfg = agents.AgentConfig(api_key="x", stream=False)
    fx = agents.FixerAgent(cfg)

    src = "a\nb\nc\n"
    fix = fx.fix(src, "file.py", 2, "oops")

    assert fix is None
