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

    def build_analysis_context(self, source, file_path, defs_map=None):
        self.calls.append(("analysis", file_path))
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
