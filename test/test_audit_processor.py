from __future__ import annotations

from pathlib import Path

from skylos.audit.processor import process_deep_audit_records
from skylos.audit.redaction import REDACTION
from skylos.audit.store import AuditStore
from skylos.audit.types import AuditCandidate, sha256_file


def _fake_github_token() -> str:
    return "ghp_" + "1234567890abcdef" + "1234567890abcdef" + "123456"


class FakeAnalyzer:
    def __init__(self):
        self.calls: list[Path] = []

    def analyze_file(self, file_path, issue_types=None):
        self.calls.append(Path(file_path))
        return [
            {
                "rule_id": "SKY-L001",
                "issue_type": "security",
                "severity": "high",
                "message": f"Finding in {Path(file_path).name}",
                "location": {"file": str(file_path), "line": 1},
                "confidence": "high",
            }
        ]


class LineThreeAnalyzer:
    def analyze_file(self, file_path, issue_types=None):
        return [
            {
                "rule_id": "SKY-D216",
                "issue_type": "security",
                "severity": "high",
                "message": "Possible SSRF",
                "location": {"file": str(file_path), "line": 3},
                "confidence": "high",
            }
        ]


class CapturingAgent:
    def __init__(self):
        self.sources: list[str] = []
        self.contexts: list[str | None] = []

    def analyze(self, source, file_path, defs_map=None, context=None):
        self.sources.append(source)
        self.contexts.append(context)
        return []


class AgentBackedAnalyzer:
    def __init__(self):
        self.agent = CapturingAgent()

    def _get_agent(self, agent_type):
        return self.agent


class ExplodingAgent:
    def analyze(self, source, file_path, defs_map=None, context=None):
        raise RuntimeError(f"adapter down with token={_fake_github_token()}")


class ExplodingAnalyzer:
    def __init__(self):
        self.agent = ExplodingAgent()

    def _get_agent(self, agent_type):
        return self.agent


def _candidate(
    candidate_id: str,
    *,
    priority: int = 800,
    rule_id: str = "SKY-D999",
    redacted: bool = False,
) -> AuditCandidate:
    return AuditCandidate(
        candidate_id=candidate_id,
        kind="static_finding",
        rule_id=rule_id,
        line=1,
        severity_hint="high",
        reason="candidate",
        redacted=redacted,
        priority=priority,
        code_hash=candidate_id,
    )


def _threat_trace_candidate() -> AuditCandidate:
    return AuditCandidate(
        candidate_id="trace-cand",
        kind="threat_trace",
        rule_id="SKY-AUDIT-TRACE",
        line=3,
        severity_hint="high",
        reason="Static threat trace: request.args.get reaches requests.get in proxy",
        evidence="static_unvalidated",
        priority=875,
        source_kind="request.args.get",
        sink_kind="requests.get",
        code_hash="trace-123",
        data={
            "threat_trace": {
                "trace_id": "trace-123",
                "entrypoint": "proxy [app.get]",
                "source": {
                    "file": "app.py",
                    "line": 2,
                    "name": "request.args.get",
                    "kind": "source",
                },
                "sink": {
                    "file": "app.py",
                    "line": 3,
                    "name": "requests.get",
                    "kind": "sink",
                },
                "validation": "static_unvalidated",
            }
        },
    )


def _write_record(
    store: AuditStore,
    file_path: Path,
    *,
    language: str = "python",
    candidates: list[AuditCandidate] | None = None,
    status: str | None = None,
):
    record = store.upsert_scan_record(
        file_path=file_path,
        file_hash=sha256_file(file_path),
        language=language,
        candidates=candidates or [_candidate("cand")],
        config_hash="cfg",
    )
    if status:
        record.status = status
        store.write_file_record(record)
    store.set_current_scan_files([*(store.current_scan_files or ()), file_path])
    return record


def _mark_analyzed_for_context(
    store: AuditStore,
    record,
    *,
    model: str = "test-model",
    provider: str | None = None,
):
    record.status = "analyzed"
    record.analysis_history.append(
        {
            "stage": "agent_process",
            "run_id": "prior-run",
            "model": model,
            "provider": provider,
        }
    )
    store.write_file_record(record)
    return record


def test_process_deep_audit_records_prioritizes_and_respects_limit(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    high = repo / "high.py"
    low = repo / "low.py"
    high.write_text("eval(user_input)\n", encoding="utf-8")
    low.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, low, candidates=[_candidate("low", priority=100)])
    _write_record(store, high, candidates=[_candidate("high", priority=900)])

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        limit=1,
        run_id="run-one",
    )

    assert [path.name for path in analyzer.calls] == ["high.py"]
    assert summary.processed_files == 1
    assert summary.limited is True
    assert summary.complete is False
    assert store.read_file_record(high).status == "analyzed"
    assert store.read_file_record(low).status == "pending"


def test_process_deep_audit_records_respects_allowed_file_scope(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    changed = repo / "changed.py"
    old = repo / "old.py"
    changed.write_text("eval(user_input)\n", encoding="utf-8")
    old.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, changed, candidates=[_candidate("changed", priority=100)])
    _write_record(store, old, candidates=[_candidate("old", priority=900)])

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        allowed_files=[changed],
        run_id="run-changed",
    )

    assert [path.name for path in analyzer.calls] == ["changed.py"]
    assert summary.considered_files == 1
    assert summary.processed_files == 1
    assert summary.complete is True
    assert store.read_file_record(old).status == "pending"


def test_process_deep_audit_records_defaults_to_current_scan_scope(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    hidden = repo / ".git" / "config"
    hidden.parent.mkdir()
    hidden.write_text(
        "[remote]\n  url = https://token@example.invalid/repo\n",
        encoding="utf-8",
    )
    app = repo / "app.py"
    app.write_text("print('ok')\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, hidden, candidates=[_candidate("poison", priority=900)])
    store.set_current_scan_files([app])

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-current-scope",
    )

    assert analyzer.calls == []
    assert summary.considered_files == 0
    assert summary.processed_files == 0
    assert summary.complete is True
    assert store.read_file_record(hidden).status == "pending"


def test_process_deep_audit_records_without_scope_fails_closed(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, candidates=[_candidate("candidate", priority=900)])
    store.current_scan_files = None

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-no-scope",
    )

    assert analyzer.calls == []
    assert summary.considered_files == 0
    assert summary.processed_files == 0
    assert summary.complete is True
    assert store.read_file_record(app).status == "pending"


def test_process_deep_audit_records_skips_secret_candidates(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    raw_secret = _fake_github_token()
    app.write_text(f'TOKEN="{raw_secret}"\n', encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(
        store,
        app,
        candidates=[
            _candidate(
                "secret",
                rule_id="SKY-S101",
                redacted=True,
            )
        ],
    )

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-secret",
    )
    stored = store.record_path(app).read_text(encoding="utf-8")

    assert analyzer.calls == []
    assert summary.skipped_secret_files == 1
    assert summary.remaining_pending_files == 1
    assert summary.complete is False
    assert store.read_file_record(app).status == "skipped"
    assert raw_secret not in stored

    rerun_summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-secret-rerun",
    )

    assert analyzer.calls == []
    assert rerun_summary.skipped_secret_files == 1
    assert rerun_summary.remaining_pending_files == 1
    assert rerun_summary.complete is False


def test_process_deep_audit_records_redacts_incidental_secrets_before_agent_call(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    raw_secret = _fake_github_token()
    app.write_text(
        f'TOKEN="{raw_secret}"\n'
        "def handler(user_input):\n"
        "    return eval(user_input)\n",
        encoding="utf-8",
    )
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, candidates=[_candidate("danger")])

    analyzer = AgentBackedAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-redact",
    )

    assert summary.processed_files == 1
    assert len(analyzer.agent.sources) == 1
    assert raw_secret not in analyzer.agent.sources[0]
    assert REDACTION in analyzer.agent.sources[0]
    assert store.read_file_record(app).status == "analyzed"


def test_process_deep_audit_records_passes_threat_trace_candidate_context(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text(
        "from flask import request\n"
        "import requests\n"
        "def proxy():\n"
        "    url = request.args.get('url')\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, candidates=[_threat_trace_candidate()])

    analyzer = AgentBackedAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-threat-context",
    )

    assert summary.processed_files == 1
    assert len(analyzer.agent.contexts) == 1
    context = analyzer.agent.contexts[0]
    assert context is not None
    assert "[DEEP AUDIT CANDIDATES]" in context
    assert "request.args.get@L2 -> requests.get@L3" in context


def test_process_deep_audit_records_attaches_threat_trace_to_matching_finding(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("import requests\nurl = 'x'\nrequests.get(url)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, candidates=[_threat_trace_candidate()])

    summary = process_deep_audit_records(
        store=store,
        analyzer=LineThreeAnalyzer(),
        model="test-model",
        run_id="run-threat-finding",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 1
    assert record is not None
    assert record.findings[0]["metadata"]["threat_trace"]["trace_id"] == "trace-123"


def test_process_deep_audit_records_marks_agent_errors_without_raw_secret(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text(
        "def handler(user_input):\n    return eval(user_input)\n",
        encoding="utf-8",
    )
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)

    summary = process_deep_audit_records(
        store=store,
        analyzer=ExplodingAnalyzer(),
        model="test-model",
        run_id="run-error",
    )

    record = store.read_file_record(app)
    stored = store.record_path(app).read_text(encoding="utf-8")

    assert summary.error_files == 1
    assert summary.complete is False
    assert record is not None
    assert record.status == "error"
    assert _fake_github_token() not in stored
    assert REDACTION in stored


def test_process_deep_audit_records_marks_unsupported_languages(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.ts"
    app.write_text("eval(userInput)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, language="typescript")

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-ts",
    )

    assert analyzer.calls == []
    assert summary.unsupported_files == 1
    assert summary.remaining_pending_files == 1
    assert summary.complete is False
    record = store.read_file_record(app)
    assert record.status == "not_analyzed"
    assert [
        item.get("stage") for item in record.analysis_history if isinstance(item, dict)
    ] == ["unsupported_agent_language"]

    rerun_summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-ts-rerun",
    )

    assert analyzer.calls == []
    assert rerun_summary.unsupported_files == 1
    assert rerun_summary.remaining_pending_files == 1
    assert rerun_summary.complete is False

    forced_summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        force=True,
        run_id="run-ts-force",
    )
    forced_record = store.read_file_record(app)

    assert analyzer.calls == []
    assert forced_summary.unsupported_files == 1
    assert [
        item.get("stage")
        for item in forced_record.analysis_history
        if isinstance(item, dict)
    ] == ["unsupported_agent_language"]


def test_process_deep_audit_records_skips_analyzed_with_same_context_unless_forced(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app)
    _mark_analyzed_for_context(store, record)

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-skip",
    )

    assert analyzer.calls == []
    assert summary.processed_files == 0

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        force=True,
        run_id="run-force",
    )

    assert [path.name for path in analyzer.calls] == ["app.py"]
    assert summary.processed_files == 1


def test_process_deep_audit_records_reprocesses_stale_model_context(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app)
    _mark_analyzed_for_context(store, record, model="old-model", provider="old")

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="new-model",
        provider="new",
        run_id="run-new-context",
    )

    updated = store.read_file_record(app)

    assert [path.name for path in analyzer.calls] == ["app.py"]
    assert summary.processed_files == 1
    assert summary.complete is True
    assert updated is not None
    assert updated.analysis_history[-1]["model"] == "new-model"
    assert updated.analysis_history[-1]["provider"] == "new"


def test_process_deep_audit_records_respects_fresh_locks(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)
    assert store.acquire_lock(app, run_id="other-run")

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-main",
    )

    assert analyzer.calls == []
    assert summary.locked_files == 1
    assert store.read_file_record(app).status == "processing"


def test_process_deep_audit_records_recovers_stale_locks(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app)
    record.status = "processing"
    record.locked_by_run_id = "old-run"
    record.locked_at = "2000-01-01T00:00:00+00:00"
    store.write_file_record(record)

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-main",
    )

    assert [path.name for path in analyzer.calls] == ["app.py"]
    assert summary.processed_files == 1
    assert store.read_file_record(app).status == "analyzed"


def test_process_deep_audit_records_merges_duplicate_findings(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)

    analyzer = FakeAnalyzer()
    process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-one",
    )
    process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        force=True,
        run_id="run-two",
    )

    record = store.read_file_record(app)
    assert record is not None
    assert len(record.findings) == 1
