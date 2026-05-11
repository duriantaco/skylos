from __future__ import annotations

from pathlib import Path

from skylos.audit_processor import process_deep_audit_records
from skylos.audit_redaction import REDACTION
from skylos.audit_store import AuditStore
from skylos.audit_types import AuditCandidate, sha256_file


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


class CapturingAgent:
    def __init__(self):
        self.sources: list[str] = []

    def analyze(self, source, file_path, defs_map=None, context=None):
        self.sources.append(source)
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
    assert store.read_file_record(app).status == "not_analyzed"

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
