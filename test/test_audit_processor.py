from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import skylos.audit.processor as audit_processor
from skylos.audit.processor import (
    DEEP_AUDIT_ANALYSIS_VERSION,
    process_deep_audit_records,
)
from skylos.audit.redaction import REDACTION
from skylos.audit.store import AuditStore
from skylos.audit.types import AuditCandidate, sha256_file
from skylos.llm.investigator import (
    INVESTIGATOR_DEFINITION_HASH,
    INVESTIGATOR_PROTOCOL_VERSION,
    InvestigationIncompleteError,
)


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


class DuplicateProvenanceAnalyzer:
    def analyze_file(self, file_path, issue_types=None):
        finding = {
            "rule_id": "SKY-L001",
            "issue_type": "security",
            "severity": "high",
            "message": "Finding",
            "location": {"file": str(file_path), "line": 1},
            "confidence": "high",
            "audit_finding_id": "model-controlled-id",
            "audit_produced_by_run_id": "model-controlled-run",
            "audit_source_hash": "0" * 64,
        }
        return [dict(finding), dict(finding)]


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


class RepositoryInvestigatorAgent:
    def __init__(self, *, related_file: str | None = None):
        self.related_file = related_file
        self.calls: list[dict] = []
        self.findings: list[dict] = []

    def investigate(
        self,
        source,
        file_path,
        *,
        context,
        candidates,
        tools,
        run_id,
    ):
        if self.related_file:
            tools.execute("read_file", {"path": self.related_file})
        self.calls.append(
            {
                "source": source,
                "file_path": file_path,
                "context": context,
                "candidate_count": len(candidates),
                "candidate_ids": [item["candidate_id"] for item in candidates],
                "tools_id": id(tools),
                "run_id": run_id,
            }
        )
        return SimpleNamespace(
            findings=list(self.findings),
            status="complete",
            metadata={
                "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
                "definition_hash": INVESTIGATOR_DEFINITION_HASH,
                "covered_candidate_ids": [item["candidate_id"] for item in candidates],
                **tools.metadata(),
            },
        )


class RepositoryInvestigatorAnalyzer:
    def __init__(self, *, related_file: str | None = None):
        self.agent = RepositoryInvestigatorAgent(related_file=related_file)

    def _get_agent(self, agent_type):
        return self.agent


class BatchingRepositoryInvestigatorAgent:
    def __init__(
        self,
        *,
        max_candidates: int = 20,
        fail_candidate_id: str | None = None,
        fail_above_size: int | None = None,
        omit_candidate_coverage: bool = False,
        provenance_mismatch_candidate_id: str | None = None,
        fail_completion_safety: bool = False,
    ) -> None:
        self.limits = SimpleNamespace(max_candidates=max_candidates)
        self.fail_candidate_id = fail_candidate_id
        self.fail_above_size = fail_above_size
        self.omit_candidate_coverage = omit_candidate_coverage
        self.provenance_mismatch_candidate_id = provenance_mismatch_candidate_id
        self.fail_completion_safety = fail_completion_safety
        self.calls: list[dict] = []
        self.tools: list[object] = []
        self.failed_tool_metadata: list[dict] = []

    def investigate(
        self,
        source,
        file_path,
        *,
        context,
        candidates,
        tools,
        run_id,
    ):
        candidate_ids = [item["candidate_id"] for item in candidates]
        self.tools.append(tools)
        self.calls.append(
            {
                "candidate_ids": candidate_ids,
                "tools_id": id(tools),
                "run_id": run_id,
            }
        )
        if self.fail_candidate_id in candidate_ids:
            exc = InvestigationIncompleteError(
                "investigator prompt-size budget exhausted"
            )
            exc.investigation_metadata = {
                "turns": 2,
                "llm_calls": 2,
                "usage": {
                    "input_tokens": len(candidate_ids) * 10,
                    "prompt_tokens": 1,
                },
                "visited_files": ["failed-attempt.py"],
                "clean_evidence": [{"invariant": "must not be trusted"}],
            }
            raise exc
        if (
            self.fail_above_size is not None
            and len(candidate_ids) > self.fail_above_size
        ):
            tools.execute("read_file", {"path": "parent_only.py"})
            self.failed_tool_metadata.append(tools.metadata())
            exc = InvestigationIncompleteError(
                "investigator prompt-size budget exhausted"
            )
            exc.investigation_metadata = {
                "turns": 4,
                "llm_calls": 3,
                "usage": {
                    "input_tokens": 60,
                    "prompt_tokens": 7,
                    "untrusted-dynamic-key": 999,
                },
                "tool_calls": 99,
                "source_observation_calls": 4,
                "evidence_bytes": 90,
                "unsafe_discovery_truncations": 2,
                "sensitive_denials": 1,
                "visited_files": ["failed-parent-only.py"],
                "source_observed_files": ["failed-parent-only.py"],
                "related_files": [
                    {"path": "failed-parent-only.py", "sha256": "not-evidence"}
                ],
                "inspected_ranges": {"failed-parent-only.py": [[1, 1]]},
                "clean_evidence": [{"invariant": "failed parent must not count"}],
                "catalog_digest": "failed-parent-catalog",
            }
            raise exc
        first = candidate_ids[0]
        last = candidate_ids[-1]
        metadata = {
            "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
            "definition_hash": INVESTIGATOR_DEFINITION_HASH,
            "covered_candidate_ids": candidate_ids,
            "turns": 1,
            "llm_calls": 1,
            "usage": {"input_tokens": len(candidate_ids)},
            "reviewer_guidance": {
                "registry_version": "reviewer-packs-v1",
                "definition_hash": "test-reviewer-pack-definition",
                "selected_packs": [{"id": "candidate.dataflow", "version": "1"}],
                "selection_truncated": False,
            },
            **tools.metadata(),
        }
        if self.omit_candidate_coverage:
            metadata.pop("covered_candidate_ids")
        if self.provenance_mismatch_candidate_id in candidate_ids:
            metadata["definition_hash"] = "stale-investigator-definition"
        if self.fail_completion_safety:
            tools.catalog_truncated = True
        return SimpleNamespace(
            findings=[
                {
                    "rule_id": "SKY-AUDIT-LOGIC",
                    "issue_type": "bug",
                    "severity": "high",
                    "message": f"Reviewed candidate batch {first} through {last}",
                    "location": {"file": file_path, "line": 1},
                    "confidence": "high",
                    "metadata": {
                        "investigation_evidence": {
                            "category": "business_invariant",
                            "invariant": f"candidate batch {first} through {last}",
                        }
                    },
                }
            ],
            status="complete",
            metadata=metadata,
        )


class BatchingRepositoryInvestigatorAnalyzer:
    def __init__(
        self,
        *,
        max_candidates: int = 20,
        fail_candidate_id: str | None = None,
        fail_above_size: int | None = None,
        omit_candidate_coverage: bool = False,
        provenance_mismatch_candidate_id: str | None = None,
        fail_completion_safety: bool = False,
    ) -> None:
        self.agent = BatchingRepositoryInvestigatorAgent(
            max_candidates=max_candidates,
            fail_candidate_id=fail_candidate_id,
            fail_above_size=fail_above_size,
            omit_candidate_coverage=omit_candidate_coverage,
            provenance_mismatch_candidate_id=provenance_mismatch_candidate_id,
            fail_completion_safety=fail_completion_safety,
        )

    def _get_agent(self, agent_type):
        return self.agent


class TerminalRepositoryInvestigatorAgent:
    def investigate(
        self,
        source,
        file_path,
        *,
        context,
        candidates,
        tools,
        run_id,
    ):
        exc = InvestigationIncompleteError(
            f"terminal adapter failure with token={_fake_github_token()}"
        )
        exc.investigation_metadata = {
            "turns": 3,
            "llm_calls": 2,
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 4,
                "total_tokens": 15,
                _fake_github_token(): 999,
            },
            "visited_files": ["failed-evidence.py"],
            "related_files": [
                {"path": "failed-evidence.py", "sha256": _fake_github_token()}
            ],
            "clean_evidence": [{"invariant": _fake_github_token()}],
        }
        raise exc


class TerminalRepositoryInvestigatorAnalyzer:
    def __init__(self) -> None:
        self.agent = TerminalRepositoryInvestigatorAgent()

    def _get_agent(self, agent_type):
        return self.agent


class StaticContextBuilder:
    def __init__(self, context: str):
        self.context = context

    def build_analysis_context(self, source, **kwargs):
        return self.context


def _candidate(
    candidate_id: str,
    *,
    priority: int = 800,
    rule_id: str = "SKY-D999",
    redacted: bool = False,
    signal_quality: str = "exploratory",
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
        signal_quality=signal_quality,
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
        candidates=(candidates if candidates is not None else [_candidate("cand")]),
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
            "analysis_version": DEEP_AUDIT_ANALYSIS_VERSION,
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


def test_process_deep_audit_records_prioritizes_signal_quality_before_score(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    proven = repo / "proven.py"
    exploratory = repo / "exploratory.py"
    proven.write_text("eval(user_input)\n", encoding="utf-8")
    exploratory.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(
        store,
        exploratory,
        candidates=[
            _candidate("exploratory", priority=999, signal_quality="exploratory")
        ],
    )
    _write_record(
        store,
        proven,
        candidates=[_candidate("proven", priority=1, signal_quality="proven")],
    )

    analyzer = FakeAnalyzer()
    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        limit=1,
        run_id="run-quality-priority",
    )

    assert [path.name for path in analyzer.calls] == ["proven.py"]
    assert summary.processed_files == 1
    assert summary.limited is True


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


def test_process_deep_audit_records_drops_result_after_claim_is_lost(
    tmp_path: Path,
    monkeypatch,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)

    monkeypatch.setattr(
        store,
        "commit_claimed_record",
        lambda record, *, run_id, lease_id: False,
    )

    summary = process_deep_audit_records(
        store=store,
        analyzer=FakeAnalyzer(),
        model="test-model",
        run_id="run-late-worker",
    )
    record = store.read_file_record(app)

    assert summary.processed_files == 0
    assert summary.findings_added == 0
    assert summary.locked_files == 1
    assert summary.complete is False
    assert record is not None
    assert record.status == "processing"
    assert record.findings == []


def test_process_deep_audit_records_does_not_mark_error_after_claim_is_lost(
    tmp_path: Path,
    monkeypatch,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)

    monkeypatch.setattr(
        store,
        "mark_error",
        lambda file_path, message, *, run_id=None, lease_id=None: False,
    )

    summary = process_deep_audit_records(
        store=store,
        analyzer=ExplodingAnalyzer(),
        model="test-model",
        run_id="run-late-error",
    )
    record = store.read_file_record(app)

    assert summary.error_files == 0
    assert summary.locked_files == 1
    assert summary.complete is False
    assert record is not None
    assert record.status == "processing"
    assert not any(item.get("stage") == "error" for item in record.analysis_history)


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
    first = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-one",
    )
    second = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        force=True,
        run_id="run-two",
    )

    record = store.read_file_record(app)
    assert record is not None
    assert len(record.findings) == 1
    assert first.findings_added == 1
    assert second.findings_added == 0
    assert record.findings[0]["audit_produced_by_run_id"] == "run-one"
    assert record.findings[0]["audit_source_hash"] == record.file_hash
    assert record.analysis_history[-2]["new_finding_ids"] == [
        record.findings[0]["audit_finding_id"]
    ]
    assert record.analysis_history[-1]["new_finding_ids"] == []
    assert len(record.analysis_history[-2]["finding_snapshot"]) == 1
    assert len(record.analysis_history[-1]["finding_snapshot"]) == 1


def test_process_deep_audit_records_owns_provenance_and_deduplicates_result(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)

    summary = process_deep_audit_records(
        store=store,
        analyzer=DuplicateProvenanceAnalyzer(),
        model="test-model",
        run_id="trusted-run",
    )
    record = store.read_file_record(app)

    assert summary.findings_added == 1
    assert record is not None
    assert len(record.findings) == 1
    assert record.findings[0]["audit_finding_id"] != "model-controlled-id"
    assert record.findings[0]["audit_produced_by_run_id"] == "trusted-run"
    assert record.findings[0]["audit_source_hash"] == record.file_hash


def test_repository_investigator_processes_polyglot_records(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.ts"
    app.write_text(
        "export function updateOrder(order: Order) { order.status = 'done'; }\n",
        encoding="utf-8",
    )
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, language="typescript")
    analyzer = RepositoryInvestigatorAnalyzer()

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-polyglot",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 1
    assert summary.unsupported_files == 0
    assert analyzer.agent.calls[0]["file_path"] == "app.ts"
    assert record is not None
    assert record.status == "analyzed"
    assert (
        record.analysis_history[-1]["protocol_version"] == INVESTIGATOR_PROTOCOL_VERSION
    )
    assert record.analysis_history[-1]["tool_schema_version"] == "audit-read-tools-v2"


def test_repository_investigator_reviews_files_without_static_candidates(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text(
        "def complete(order):\n    order.status = 'complete'\n",
        encoding="utf-8",
    )
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, candidates=[])
    analyzer = RepositoryInvestigatorAnalyzer()

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-holistic",
    )

    assert summary.considered_files == 1
    assert summary.processed_files == 1
    assert analyzer.agent.calls[0]["candidate_count"] == 0
    assert store.read_file_record(app).status == "analyzed"


def test_terminal_holistic_investigator_failure_persists_only_operational_metadata(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, candidates=[])

    summary = process_deep_audit_records(
        store=store,
        analyzer=TerminalRepositoryInvestigatorAnalyzer(),
        model="terminal-model",
        provider="terminal-provider",
        run_id="run-terminal-holistic",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 0
    assert summary.error_files == 1
    assert summary.complete is False
    assert record is not None
    assert record.status == "error"
    failure = record.analysis_history[-1]
    assert failure["stage"] == "error"
    assert failure["model"] == "terminal-model"
    assert failure["provider"] == "terminal-provider"
    assert "[REDACTED_SECRET]" in failure["message"]
    assert _fake_github_token() not in str(failure)
    assert failure["investigation"] == {
        "metadata_scope": "operational_only",
        "attempt_count": 1,
        "attempt_limit": 32,
        "completed_attempt_count": 0,
        "failed_attempt_count": 1,
        "recoverable_failed_attempt_count": 0,
        "turns": 3,
        "llm_calls": 2,
        "tool_calls": 0,
        "source_observation_calls": 0,
        "evidence_bytes": 0,
        "unsafe_discovery_truncations": 0,
        "sensitive_denials": 0,
        "attempt_budget_exhausted": False,
        "usage": {
            "completion_tokens": 4,
            "prompt_tokens": 11,
            "total_tokens": 15,
        },
    }


def test_holistic_investigator_does_not_mass_error_after_thirty_two_files(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    for index in range(33):
        source = repo / f"workflow_{index:02d}.py"
        source.write_text(
            f"def workflow_{index:02d}():\n    return {index}\n",
            encoding="utf-8",
        )
        _write_record(store, source, candidates=[])
    analyzer = RepositoryInvestigatorAnalyzer()

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-many-holistic-files",
    )

    assert summary.considered_files == 33
    assert summary.processed_files == 33
    assert summary.error_files == 0
    assert summary.complete is True
    assert len(analyzer.agent.calls) == 33
    assert all(record.status == "analyzed" for record in store.iter_file_records())


def test_repository_investigator_chunks_large_candidate_sets_deterministically(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    candidates = [_candidate(f"candidate-{index:02d}") for index in range(45)]
    _write_record(store, app, candidates=candidates)
    analyzer = BatchingRepositoryInvestigatorAnalyzer(max_candidates=20)
    del analyzer.agent.limits

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-candidate-batches",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 1
    assert summary.complete is True
    assert record is not None
    assert record.status == "analyzed"
    assert [len(call["candidate_ids"]) for call in analyzer.agent.calls] == [20, 20, 5]
    assert [call["candidate_ids"] for call in analyzer.agent.calls] == [
        [f"candidate-{index:02d}" for index in range(0, 20)],
        [f"candidate-{index:02d}" for index in range(20, 40)],
        [f"candidate-{index:02d}" for index in range(40, 45)],
    ]
    assert len({id(tools) for tools in analyzer.agent.tools}) == 3
    assert [finding["message"] for finding in record.findings] == [
        "Reviewed candidate batch candidate-00 through candidate-19",
        "Reviewed candidate batch candidate-20 through candidate-39",
        "Reviewed candidate batch candidate-40 through candidate-44",
    ]
    investigation = record.analysis_history[-1]["investigation"]
    assert investigation["covered_candidate_ids"] == [
        f"candidate-{index:02d}" for index in range(45)
    ]
    assert investigation["candidate_batching"] == {
        "strategy": "deterministic_adaptive_v1",
        "candidate_limit": 20,
        "attempt_limit": 32,
        "initial_batch_count": 3,
        "completed_batch_count": 3,
        "attempt_count": 3,
        "batches": [
            {
                "candidate_ids": [f"candidate-{index:02d}" for index in range(0, 20)],
                "findings_count": 1,
                "finish_reasoning_sha256": None,
            },
            {
                "candidate_ids": [f"candidate-{index:02d}" for index in range(20, 40)],
                "findings_count": 1,
                "finish_reasoning_sha256": None,
            },
            {
                "candidate_ids": [f"candidate-{index:02d}" for index in range(40, 45)],
                "findings_count": 1,
                "finish_reasoning_sha256": None,
            },
        ],
    }
    assert investigation["reviewer_guidance"] == {
        "registry_version": "reviewer-packs-v1",
        "definition_hash": "test-reviewer-pack-definition",
        "selected_packs": [{"id": "candidate.dataflow", "version": "1"}],
        "selection_truncated": False,
    }


def test_repository_investigator_caps_configured_candidate_batch_size(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    candidates = [_candidate(f"candidate-{index:02d}") for index in range(45)]
    _write_record(store, app, candidates=candidates)
    analyzer = BatchingRepositoryInvestigatorAnalyzer(max_candidates=100)

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-capped-candidate-batches",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 1
    assert record is not None
    assert [len(call["candidate_ids"]) for call in analyzer.agent.calls] == [20, 20, 5]
    assert (
        record.analysis_history[-1]["investigation"]["candidate_batching"][
            "candidate_limit"
        ]
        == 20
    )


def test_repository_investigator_adaptive_split_counts_failed_parent_cost(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    parent_only = repo / "parent_only.py"
    parent_only.write_text("PARENT_ONLY = True\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    candidates = [_candidate(f"candidate-{index:02d}") for index in range(6)]
    _write_record(store, app, candidates=candidates)
    analyzer = BatchingRepositoryInvestigatorAnalyzer(
        max_candidates=6,
        fail_above_size=3,
    )

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-adaptive-cost",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 1
    assert summary.findings_added == 2
    assert summary.complete is True
    assert record is not None
    assert record.status == "analyzed"
    expected_ids = [f"candidate-{index:02d}" for index in range(6)]
    assert [call["candidate_ids"] for call in analyzer.agent.calls] == [
        expected_ids,
        expected_ids[:3],
        expected_ids[3:],
    ]
    parent_run_id = analyzer.agent.calls[0]["run_id"]
    assert [call["run_id"] for call in analyzer.agent.calls] == [
        parent_run_id,
        f"{parent_run_id}-a",
        f"{parent_run_id}-b",
    ]
    assert len({call["tools_id"] for call in analyzer.agent.calls}) == 3
    assert [finding["message"] for finding in record.findings] == [
        "Reviewed candidate batch candidate-00 through candidate-02",
        "Reviewed candidate batch candidate-03 through candidate-05",
    ]

    investigation = record.analysis_history[-1]["investigation"]
    assert investigation["covered_candidate_ids"] == expected_ids
    assert investigation["turns"] == 6
    assert investigation["llm_calls"] == 5
    assert investigation["usage"] == {
        "input_tokens": 66,
        "prompt_tokens": 7,
    }
    failed_tools = analyzer.agent.failed_tool_metadata[0]
    assert investigation["tool_calls"] == failed_tools["tool_calls"] == 1
    assert (
        investigation["source_observation_calls"]
        == failed_tools["source_observation_calls"]
        == 1
    )
    assert investigation["evidence_bytes"] == failed_tools["evidence_bytes"]
    assert investigation["candidate_batching"]["attempt_count"] == 3
    assert investigation["candidate_batching"]["completed_batch_count"] == 2
    assert investigation["candidate_batching"]["batches"] == [
        {
            "candidate_ids": expected_ids[:3],
            "findings_count": 1,
            "finish_reasoning_sha256": None,
        },
        {
            "candidate_ids": expected_ids[3:],
            "findings_count": 1,
            "finish_reasoning_sha256": None,
        },
    ]
    # Failed-parent operational costs count, but only completed children may
    # establish evidence and freshness provenance for the committed result.
    assert investigation["visited_files"] == ["workflow.py"]
    assert investigation["source_observed_files"] == []
    assert [item["path"] for item in investigation["related_files"]] == ["workflow.py"]
    assert "parent_only.py" not in investigation["inspected_ranges"]
    assert investigation["clean_evidence"] == []
    assert "untrusted-dynamic-key" not in investigation["usage"]


def test_repository_investigator_large_batch_failure_discards_partial_results(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    candidates = [_candidate(f"candidate-{index:02d}") for index in range(25)]
    _write_record(store, app, candidates=candidates)
    analyzer = BatchingRepositoryInvestigatorAnalyzer(
        max_candidates=20,
        fail_candidate_id="candidate-22",
    )

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-incomplete-candidate-batch",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 0
    assert summary.findings_added == 0
    assert summary.error_files == 1
    assert summary.complete is False
    assert record is not None
    assert record.status == "error"
    assert record.findings == []
    assert not any(
        item.get("stage") == "agent_process" for item in record.analysis_history
    )
    # The failing five-candidate chunk is split deterministically, but the
    # singleton failure still rejects the whole file and cannot loop forever.
    assert [len(call["candidate_ids"]) for call in analyzer.agent.calls] == [
        20,
        5,
        2,
        3,
        1,
    ]
    failure = record.analysis_history[-1]
    assert failure["stage"] == "error"
    assert failure["model"] == "test-model"
    assert failure["provider"] is None
    investigation = failure["investigation"]
    assert investigation == {
        "metadata_scope": "operational_only",
        "attempt_count": 5,
        "attempt_limit": 32,
        "completed_attempt_count": 2,
        "failed_attempt_count": 3,
        "recoverable_failed_attempt_count": 2,
        "turns": 8,
        "llm_calls": 8,
        "tool_calls": 0,
        "source_observation_calls": 0,
        "evidence_bytes": 0,
        "unsafe_discovery_truncations": 0,
        "sensitive_denials": 0,
        "attempt_budget_exhausted": False,
        "usage": {"input_tokens": 112, "prompt_tokens": 3},
    }


def test_repository_investigator_requires_exact_coverage_for_each_batch(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(
        store,
        app,
        candidates=[_candidate(f"candidate-{index}") for index in range(3)],
    )
    analyzer = BatchingRepositoryInvestigatorAnalyzer(omit_candidate_coverage=True)

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-missing-batch-coverage",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 0
    assert summary.error_files == 1
    assert record is not None
    assert record.status == "error"
    assert record.findings == []
    # Coverage failures are integrity failures, not a reason to split into
    # easier batches that could conceal a missing candidate decision.
    assert len(analyzer.agent.calls) == 1


def test_repository_investigator_completion_safety_failure_keeps_usage(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, candidates=[_candidate("candidate-00")])
    analyzer = BatchingRepositoryInvestigatorAnalyzer(
        fail_completion_safety=True,
    )

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-completion-safety-failure",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 0
    assert summary.error_files == 1
    assert len(analyzer.agent.calls) == 1
    assert record is not None
    assert record.status == "error"
    assert record.findings == []
    failure = record.analysis_history[-1]
    assert failure["stage"] == "error"
    assert failure["message"] == (
        "Agent processing failed: investigator catalog completion safety check failed"
    )
    assert failure["investigation"] == {
        "metadata_scope": "operational_only",
        "attempt_count": 1,
        "attempt_limit": 32,
        "completed_attempt_count": 0,
        "failed_attempt_count": 1,
        "recoverable_failed_attempt_count": 0,
        "turns": 1,
        "llm_calls": 1,
        "tool_calls": 0,
        "source_observation_calls": 0,
        "evidence_bytes": 0,
        "unsafe_discovery_truncations": 0,
        "sensitive_denials": 0,
        "attempt_budget_exhausted": False,
        "usage": {"input_tokens": 1},
    }
    assert "catalog_digest" not in failure["investigation"]
    assert "covered_candidate_ids" not in failure["investigation"]
    assert "reviewer_guidance" not in failure["investigation"]


def test_repository_investigator_rejects_mismatched_batch_provenance(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(
        store,
        app,
        candidates=[_candidate(f"candidate-{index:02d}") for index in range(25)],
    )
    analyzer = BatchingRepositoryInvestigatorAnalyzer(
        max_candidates=20,
        provenance_mismatch_candidate_id="candidate-22",
    )

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-mismatched-batch-provenance",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 0
    assert summary.findings_added == 0
    assert summary.error_files == 1
    assert record is not None
    assert record.status == "error"
    assert record.findings == []
    assert not any(
        item.get("stage") == "agent_process" for item in record.analysis_history
    )
    assert [len(call["candidate_ids"]) for call in analyzer.agent.calls] == [20, 5]


def test_repository_investigator_attempt_budget_resets_for_each_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    first = repo / "a.py"
    second = repo / "b.py"
    first.write_text("def first():\n    return 1\n", encoding="utf-8")
    second.write_text("def second():\n    return 2\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(
        store,
        first,
        candidates=[_candidate(f"a-{index:02d}") for index in range(21)],
    )
    _write_record(
        store,
        second,
        candidates=[_candidate(f"b-{index:02d}") for index in range(21)],
    )
    analyzer = BatchingRepositoryInvestigatorAnalyzer(max_candidates=20)
    monkeypatch.setattr(audit_processor, "MAX_INVESTIGATOR_BATCH_ATTEMPTS", 3)

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-global-batch-budget",
    )

    first_record = store.read_file_record(first)
    second_record = store.read_file_record(second)
    assert summary.processed_files == 2
    assert summary.error_files == 0
    assert summary.complete is True
    assert len(analyzer.agent.calls) == 4
    assert first_record is not None and first_record.status == "analyzed"
    assert second_record is not None and second_record.status == "analyzed"


def test_repository_investigator_oversized_candidate_set_fails_before_calls(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(
        store,
        app,
        candidates=[_candidate(f"candidate-{index:03d}") for index in range(641)],
    )
    analyzer = BatchingRepositoryInvestigatorAnalyzer(max_candidates=10_000)

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-oversized-candidate-set",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 0
    assert summary.error_files == 1
    assert analyzer.agent.calls == []
    assert record is not None and record.status == "error"
    failure = record.analysis_history[-1]["investigation"]
    assert failure["attempt_count"] == 0
    assert failure["attempt_limit"] == 32
    assert failure["attempt_budget_exhausted"] is True


def test_repository_investigator_preflights_batch_attempt_budget(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(
        store,
        app,
        candidates=[_candidate(f"candidate-{index}") for index in range(4)],
    )
    analyzer = BatchingRepositoryInvestigatorAnalyzer(max_candidates=1)
    monkeypatch.setattr(audit_processor, "MAX_INVESTIGATOR_BATCH_ATTEMPTS", 3)

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-batch-attempt-budget",
    )

    record = store.read_file_record(app)
    assert summary.processed_files == 0
    assert summary.error_files == 1
    assert summary.complete is False
    assert analyzer.agent.calls == []
    assert record is not None
    assert record.status == "error"
    assert record.findings == []
    failure = record.analysis_history[-1]
    assert failure["stage"] == "error"
    assert failure["investigation"] == {
        "metadata_scope": "operational_only",
        "attempt_count": 0,
        "attempt_limit": 3,
        "completed_attempt_count": 0,
        "failed_attempt_count": 0,
        "recoverable_failed_attempt_count": 0,
        "turns": 0,
        "llm_calls": 0,
        "tool_calls": 0,
        "source_observation_calls": 0,
        "evidence_bytes": 0,
        "unsafe_discovery_truncations": 0,
        "sensitive_denials": 0,
        "attempt_budget_exhausted": True,
        "usage": {},
    }


def test_repository_investigator_replaces_stale_findings_after_clean_rerun(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def complete(order):\n    return order\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app)
    record.findings = [
        {
            "audit_finding_id": "finding-old",
            "rule_id": "SKY-AUDIT-LOGIC",
            "message": "stale finding",
        }
    ]
    record.analysis_history.append(
        {
            "stage": "agent_process",
            "run_id": "run-old-generation",
            "finding_snapshot": list(record.findings),
        }
    )
    store.write_file_record(record)

    summary = process_deep_audit_records(
        store=store,
        analyzer=RepositoryInvestigatorAnalyzer(),
        model="test-model",
        run_id="run-clean-generation",
    )

    updated = store.read_file_record(app)
    assert summary.processed_files == 1
    assert updated is not None
    assert updated.findings == []
    assert updated.analysis_history[-1]["replaced_findings_count"] == 1
    assert updated.analysis_history[-1]["finding_snapshot"] == []
    assert updated.analysis_history[-2]["finding_snapshot"][0]["message"] == (
        "stale finding"
    )


def test_related_file_hash_change_invalidates_analyzed_context(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "routes.py"
    policy = repo / "policy.py"
    app.write_text(
        "from policy import authorize\ndef update(user):\n    return authorize(user)\n",
        encoding="utf-8",
    )
    policy.write_text(
        "def authorize(user):\n    return user.is_authenticated\n",
        encoding="utf-8",
    )
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)
    analyzer = RepositoryInvestigatorAnalyzer(related_file="policy.py")

    first = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-related-first",
    )
    unchanged = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-related-unchanged",
    )
    policy.write_text(
        "def authorize(user):\n    return user.is_authenticated and user.active\n",
        encoding="utf-8",
    )
    changed = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-related-changed",
    )

    assert first.processed_files == 1
    assert unchanged.processed_files == 0
    assert changed.processed_files == 1
    assert len(analyzer.agent.calls) == 2


def test_entry_file_change_after_scan_is_not_analyzed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("def handler():\n    return True\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)
    app.write_text("def handler():\n    return False\n", encoding="utf-8")
    analyzer = RepositoryInvestigatorAnalyzer()

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-stale-entry",
    )

    record = store.read_file_record(app)
    assert summary.error_files == 1
    assert analyzer.agent.calls == []
    assert record is not None
    assert record.status == "error"
    assert "source changed after candidate discovery" in str(record.analysis_history)


def test_entry_freshness_hash_preserves_crlf_bytes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_bytes(b"def handler():\r\n    return True\r\n")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)
    analyzer = RepositoryInvestigatorAnalyzer()

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-crlf-entry",
    )

    assert summary.processed_files == 1
    assert "\r\n" in analyzer.agent.calls[0]["source"]


def test_repository_investigator_redacts_precomputed_context(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("def handler():\n    return True\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)
    raw_secret = _fake_github_token()
    analyzer = RepositoryInvestigatorAnalyzer()
    analyzer.context_builder = StaticContextBuilder(f"deployment token: {raw_secret}")

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-redacted-context",
    )

    assert summary.processed_files == 1
    context = analyzer.agent.calls[0]["context"]
    assert raw_secret not in context
    assert REDACTION in context


def test_repository_investigator_honors_persisted_scan_excludes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    excluded = repo / "private.py"
    app.write_text("def handler():\n    return True\n", encoding="utf-8")
    excluded.write_text("def internal_policy():\n    return True\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg", exclude_paths=[excluded])
    _write_record(store, app)
    analyzer = RepositoryInvestigatorAnalyzer(related_file="private.py")

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-excluded-context",
    )

    assert summary.error_files == 1
    assert analyzer.agent.calls == []
    assert store.read_file_record(app).status == "error"


def test_related_hash_metadata_survives_sensitive_looking_path_names(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    auth_dir = repo / "auth"
    auth_dir.mkdir(parents=True)
    app = repo / "app.py"
    policy = auth_dir / "policy.py"
    app.write_text("def handler():\n    return True\n", encoding="utf-8")
    policy.write_text("def authorize():\n    return True\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)
    analyzer = RepositoryInvestigatorAnalyzer(related_file="auth/policy.py")

    first = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-auth-path-first",
    )
    second = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-auth-path-second",
    )

    record = store.read_file_record(app)
    related = record.analysis_history[-1]["related_files"]
    policy_item = next(item for item in related if item["path"] == "auth/policy.py")
    assert first.processed_files == 1
    assert second.processed_files == 0
    assert len(policy_item["sha256"]) == 64
    assert policy_item["sha256"] != REDACTION


def test_new_repository_file_invalidates_cached_clean_investigation(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("def handler():\n    return True\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)
    analyzer = RepositoryInvestigatorAnalyzer()

    first = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-catalog-first",
    )
    (repo / "middleware.py").write_text(
        "def authorize(request):\n    return request.user is not None\n",
        encoding="utf-8",
    )
    second = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-catalog-changed",
    )

    assert first.processed_files == 1
    assert second.processed_files == 1
    assert len(analyzer.agent.calls) == 2


def test_no_candidate_investigation_error_remains_unresolved(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("def handler():\n    return True\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, candidates=[])
    analyzer = RepositoryInvestigatorAnalyzer(related_file="missing.py")

    summary = process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-no-candidate-error",
    )

    assert summary.error_files == 1
    assert summary.remaining_pending_files == 1
    assert summary.complete is False


def test_distinct_logic_flaws_at_same_location_get_distinct_ids(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "workflow.py"
    app.write_text("def update(order):\n    order.status = 'done'\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app)
    analyzer = RepositoryInvestigatorAnalyzer()
    base = {
        "rule_id": "SKY-AUDIT-LOGIC",
        "issue_type": "bug",
        "severity": "high",
        "message": "logic flaw",
        "location": {"file": "workflow.py", "line": 2},
        "confidence": "high",
        "metadata": {
            "investigation_evidence": {
                "category": "state_transition",
                "actor": "caller",
                "action": "update",
                "resource": "order",
                "trigger": "request",
                "actual_behavior": "state changes",
                "impact": "invalid state",
            }
        },
    }
    first = {
        **base,
        "metadata": {
            "investigation_evidence": {
                **base["metadata"]["investigation_evidence"],
                "invariant": "paid orders only",
            }
        },
    }
    second = {
        **base,
        "metadata": {
            "investigation_evidence": {
                **base["metadata"]["investigation_evidence"],
                "invariant": "unshipped orders only",
            }
        },
    }
    analyzer.agent.findings = [first, second]

    process_deep_audit_records(
        store=store,
        analyzer=analyzer,
        model="test-model",
        run_id="run-distinct-logic-ids",
    )

    findings = store.read_file_record(app).findings
    assert len(findings) == 2
    assert len({finding["audit_finding_id"] for finding in findings}) == 2
