import ast

from skylos.llm.schemas import Finding, CodeLocation, IssueType, Severity, Confidence
from skylos.llm.analyzer import SkylosLLM, AnalyzerConfig

import skylos.llm.analyzer as analyzer_mod


def mk_finding(
    file="file.py",
    line=1,
    issue_type=IssueType.SECURITY,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    message="Issue detected",
):
    return Finding(
        rule_id="SKY-L001",
        issue_type=issue_type,
        severity=severity,
        confidence=confidence,
        message=message,
        location=CodeLocation(file=file, line=line),
        explanation=None,
        suggestion=None,
    )


class DummyValidator:
    def __init__(self, passthrough=True):
        self.calls = []
        self.passthrough = passthrough

    def validate(self, findings, source, file_path):
        self.calls.append((findings, source, file_path))
        return list(findings), {"accepted": len(findings)}


class DummyContextBuilder:
    def __init__(self):
        self.calls = []

    def build_analysis_context(
        self, source, file_path, defs_map=None, include_review_hints=False
    ):
        self.calls.append(("analysis", file_path, include_review_hints))
        return "CTX"

    def build_fix_context(self, source, file_path, line, message, defs_map=None):
        self.calls.append(("fix", file_path, line))
        return "FIX_CTX"


class DummyAuditAgent:
    def __init__(self, findings=None):
        self.calls = []
        self.findings = findings or []

    def analyze(self, source, file_path, defs_map=None, context=None):
        self.calls.append((file_path, context))
        return list(self.findings)


def test_analyze_file_returns_empty_if_missing(tmp_path):
    cfg = AnalyzerConfig(quiet=True)
    s = SkylosLLM(cfg)

    missing = tmp_path / "nope.py"
    out = s.analyze_file(missing)

    assert out == []


def test_analyze_file_small_uses_whole_file_path(tmp_path, monkeypatch):
    fp = tmp_path / "a.py"
    fp.write_text("print('hi')\n", encoding="utf-8")

    cfg = AnalyzerConfig(quiet=True, max_chunk_tokens=10_000)
    s = SkylosLLM(cfg)

    s.validator = DummyValidator()

    calls = {"count": 0}

    def fake_analyze_whole(
        source, file_path, defs_map=None, chunk_start_line=1, **kwargs
    ):
        calls["count"] += 1
        return [mk_finding(file=file_path, line=1, severity=Severity.HIGH)]

    monkeypatch.setattr(s, "_analyze_whole_file", fake_analyze_whole)

    out = s.analyze_file(fp)

    assert calls["count"] == 1
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH

    assert len(s.validator.calls) == 1
    _, src_used, fp_used = s.validator.calls[0]
    assert "print('hi')" in src_used
    assert str(fp) == fp_used


def test_analyze_file_large_chunks_and_offsets_lines(tmp_path, monkeypatch):
    fp = tmp_path / "big.py"

    src = "a = 1\nb = 2\n\nc = 3\nd = 4\n\ne = 5\nf = 6\n"
    fp.write_text(src, encoding="utf-8")

    cfg = AnalyzerConfig(quiet=True, max_chunk_tokens=5)
    s = SkylosLLM(cfg)

    s.context_builder = DummyContextBuilder()
    s.validator = DummyValidator()

    monkeypatch.setattr(
        analyzer_mod, "deduplicate_findings", lambda findings: list(findings)
    )

    class FreshAuditAgent:
        def __init__(self):
            self.calls = []

        def analyze(self, source, file_path, defs_map=None, context=None):
            self.calls.append((file_path, context))
            return [mk_finding(file=file_path, line=2, severity=Severity.MEDIUM)]

    agent = FreshAuditAgent()

    def fake_analyze_whole_file(
        source,
        file_path,
        defs_map=None,
        chunk_start_line=1,
        issue_types=None,
        **kwargs,
    ):
        abs_line = 2 + (chunk_start_line - 1)
        return [mk_finding(file=file_path, line=abs_line, severity=Severity.MEDIUM)]

    monkeypatch.setattr(s, "_analyze_whole_file", fake_analyze_whole_file)


def test_analyze_files_builds_analysis_result_and_summary(tmp_path, monkeypatch):
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text("print('a')\n", encoding="utf-8")
    f2.write_text("print('b')\n", encoding="utf-8")

    cfg = AnalyzerConfig(quiet=True, parallel=False)
    s = SkylosLLM(cfg)

    def fake_analyze_file(
        file_path, defs_map=None, static_findings=None, issue_types=None, **kwargs
    ):
        fp = str(file_path)
        return [
            mk_finding(file=fp, line=1, severity=Severity.HIGH),
            mk_finding(file=fp, line=1, severity=Severity.LOW),
        ]

    monkeypatch.setattr(s, "analyze_file", fake_analyze_file)

    class DummyProgress:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def add_task(self, *args, **kwargs):
            return 1

        def update(self, *args, **kwargs):
            return None

    s.ui.create_progress = lambda: DummyProgress()

    result = s.analyze_files([f1, f2])

    assert result.files_analyzed == 2
    assert len(result.findings) == 4
    assert "Found 4 issues" in result.summary
    assert "high" in result.summary
    assert "low" in result.summary


def test_dead_code_issue_type_raises_valueerror(tmp_path):
    """SkylosLLM must fail fast when asked to do dead_code per-file analysis."""
    import pytest

    f = tmp_path / "a.py"
    f.write_text("x = 1\n", encoding="utf-8")

    cfg = AnalyzerConfig()
    llm = SkylosLLM(cfg)

    with pytest.raises(ValueError, match="not a per-file operation"):
        llm.analyze_file(str(f), issue_types=["dead_code"])


def test_analyzer_config_propagates_provider_and_base_url_to_agent_config():
    cfg = AnalyzerConfig(
        model="gpt-4.1",
        api_key="KEY",
        provider="anthropic",
        base_url="https://example.test/v1",
        quiet=True,
    )

    llm = SkylosLLM(cfg)

    assert llm.agent_config.provider == "anthropic"
    assert llm.agent_config.base_url == "https://example.test/v1"


def test_force_full_file_paths_uses_whole_file_review(tmp_path, monkeypatch):
    fp = tmp_path / "review.py"
    fp.write_text(
        "def a():\n    return 1\n\ndef b():\n    return 2\n",
        encoding="utf-8",
    )

    cfg = AnalyzerConfig(
        quiet=True,
        full_file_review=False,
        force_full_file_paths={str(fp)},
    )
    llm = SkylosLLM(cfg)
    llm.validator = DummyValidator()

    calls = {"count": 0}

    def fake_analyze_whole(
        source, file_path, defs_map=None, chunk_start_line=1, issue_types=None, **kwargs
    ):
        calls["count"] += 1
        return [mk_finding(file=file_path, line=1, severity=Severity.HIGH)]

    monkeypatch.setattr(llm, "_analyze_whole_file", fake_analyze_whole)

    out = llm.analyze_file(fp)

    assert calls["count"] == 1
    assert len(out) == 1


def test_quality_selector_flags_simple_but_long_review_function():
    cfg = AnalyzerConfig(quiet=True, enable_security=False, enable_quality=True)
    llm = SkylosLLM(cfg)

    node = ast.parse(
        """
def render_report(value):
    line_1 = value
    line_2 = value
    line_3 = value
    line_4 = value
    line_5 = value
    line_6 = value
    line_7 = value
    line_8 = value
    line_9 = value
    line_10 = value
    return line_10
"""
    ).body[0]

    assert llm._should_analyze_quality_function("render_report", {"node": node}) is True


def test_small_quality_file_analyzes_all_functions(tmp_path, monkeypatch):
    fp = tmp_path / "quality.py"
    fp.write_text(
        "def helper_one():\n    return 1\n\ndef helper_two():\n    return 2\n",
        encoding="utf-8",
    )

    cfg = AnalyzerConfig(
        quiet=True,
        enable_security=False,
        enable_quality=True,
        batch_functions=False,
    )
    llm = SkylosLLM(cfg)
    llm.validator = DummyValidator()

    monkeypatch.setattr(
        analyzer_mod.CodeGraph,
        "get_review_context",
        lambda self, func_name, defs_map=None, **kwargs: f"CTX:{func_name}",
    )
    monkeypatch.setattr(
        analyzer_mod.CodeGraph, "find_taint_paths", lambda self, func_name: []
    )

    seen_contexts = []

    def fake_analyze_whole_file(
        source,
        file_path,
        defs_map=None,
        chunk_start_line=1,
        issue_types=None,
        **kwargs,
    ):
        seen_contexts.append(source)
        return []

    monkeypatch.setattr(llm, "_analyze_whole_file", fake_analyze_whole_file)

    out = llm.analyze_file(fp, issue_types=["quality"])

    assert out == []
    assert len(seen_contexts) == 2
    assert any("helper_one" in ctx for ctx in seen_contexts)
    assert any("helper_two" in ctx for ctx in seen_contexts)


def test_full_file_review_bypasses_function_filter(tmp_path, monkeypatch):
    fp = tmp_path / "review.py"
    source = (
        "def helper_one():\n"
        "    return 1\n\n"
        "def helper_two(value):\n"
        "    try:\n"
        "        return int(value)\n"
        "    except ValueError:\n"
        "        return None\n"
    )
    fp.write_text(source, encoding="utf-8")

    cfg = AnalyzerConfig(
        quiet=True,
        enable_security=True,
        enable_quality=True,
        full_file_review=True,
    )
    llm = SkylosLLM(cfg)
    llm.validator = DummyValidator()

    seen_sources = []

    def fake_analyze_whole_file(
        source,
        file_path,
        defs_map=None,
        chunk_start_line=1,
        issue_types=None,
        **kwargs,
    ):
        seen_sources.append((source, file_path, issue_types))
        return [mk_finding(file=file_path, line=4, issue_type=IssueType.QUALITY)]

    monkeypatch.setattr(llm, "_analyze_whole_file", fake_analyze_whole_file)

    out = llm.analyze_file(fp, issue_types=["quality"])

    assert len(out) == 1
    assert len(seen_sources) == 1
    assert seen_sources[0][0] == source
    assert seen_sources[0][1] == str(fp)
    assert seen_sources[0][2] == ["quality"]


def test_full_file_review_uses_combined_review_agent_when_security_and_quality_enabled(
    tmp_path, monkeypatch
):
    fp = tmp_path / "review.py"
    fp.write_text(
        "def parse_payload(payload):\n    return int(payload)\n", encoding="utf-8"
    )

    cfg = AnalyzerConfig(
        quiet=True,
        enable_security=True,
        enable_quality=True,
        full_file_review=True,
    )
    llm = SkylosLLM(cfg)
    llm.validator = DummyValidator()

    seen_issue_types = []

    def fake_get_agent(agent_type):
        class _Agent:
            def analyze(self, source, file_path, defs_map=None, context=None):
                return []

        seen_issue_types.append(agent_type)
        return _Agent()

    monkeypatch.setattr(llm, "_get_agent", fake_get_agent)

    out = llm.analyze_file(fp)

    assert out == []
    assert seen_issue_types == ["review"]


def test_full_file_review_requests_review_hints_for_quality_capable_agents(
    tmp_path, monkeypatch
):
    fp = tmp_path / "review.py"
    fp.write_text(
        "def parse_payload(payload):\n    return int(payload)\n", encoding="utf-8"
    )

    cfg = AnalyzerConfig(
        quiet=True,
        enable_security=True,
        enable_quality=True,
        full_file_review=True,
    )
    llm = SkylosLLM(cfg)
    llm.validator = DummyValidator()
    llm.context_builder = DummyContextBuilder()

    def fake_get_agent(agent_type):
        class _Agent:
            def analyze(self, source, file_path, defs_map=None, context=None):
                return []

        return _Agent()

    monkeypatch.setattr(llm, "_get_agent", fake_get_agent)

    out = llm.analyze_file(fp)

    assert out == []
    assert llm.context_builder.calls == [("analysis", str(fp), True)]


def test_analyze_files_reports_tokens_used_from_agent_adapters(tmp_path, monkeypatch):
    fp = tmp_path / "review.py"
    fp.write_text(
        "def parse_payload(payload):\n    return int(payload)\n", encoding="utf-8"
    )

    cfg = AnalyzerConfig(
        quiet=True,
        enable_security=True,
        enable_quality=True,
        full_file_review=True,
    )
    llm = SkylosLLM(cfg)
    llm.validator = DummyValidator()
    llm.context_builder = DummyContextBuilder()

    class _Adapter:
        def __init__(self):
            self.total_usage = {"total_tokens": 321}
            self.reset_calls = 0

        def reset_usage(self):
            self.reset_calls += 1
            self.total_usage = {"total_tokens": 0}

    adapter = _Adapter()

    class _Agent:
        def __init__(self):
            self._adapter = adapter

        def analyze(self, source, file_path, defs_map=None, context=None):
            self._adapter.total_usage = {"total_tokens": 321}
            return []

    agent = _Agent()
    llm._agents["review"] = agent
    monkeypatch.setattr(llm, "_get_agent", lambda agent_type: agent)

    result = llm.analyze_files([fp])

    assert result.tokens_used == 321
    assert adapter.reset_calls == 1
