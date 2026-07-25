from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from skylos.audit.freshness import is_revalidation_entry_current
from skylos.audit.redaction import REDACTION
from skylos.audit.revalidator import revalidate_deep_audit_findings
from skylos.audit.store import AuditStore
from skylos.audit.types import AuditCandidate, sha256_file
from skylos.llm.investigator import (
    INVESTIGATOR_DEFINITION_HASH,
    INVESTIGATOR_PROTOCOL_VERSION,
)


def _fake_github_token() -> str:
    return "ghp_" + "1234567890abcdef" + "1234567890abcdef" + "123456"


class FakeVerifier:
    def __init__(
        self,
        verdict: str = "true_positive",
        *,
        include_evidence: bool = True,
        include_invariant: bool = True,
    ):
        self.verdict = verdict
        self.include_evidence = include_evidence
        self.include_invariant = include_invariant
        self.calls: list[dict] = []

    def verify_finding(self, *, finding, context, file_path, mode):
        self.calls.append(
            {
                "finding": finding,
                "context": context,
                "file_path": file_path,
                "mode": mode,
            }
        )
        payload = {"verdict": self.verdict, "reason": f"{mode} verdict"}
        if self.verdict not in {"false_positive", "fixed"}:
            return payload
        if self.include_invariant:
            payload["invariant"] = "the cited source refutes the stored finding"
        if self.include_evidence:
            payload["evidence"] = [_legacy_evidence(file_path)]
        return payload


def _legacy_evidence(file_path: str) -> dict:
    return {
        "file": file_path,
        "line": 1,
        "end_line": 1,
        "role": "exact current-source proof",
    }


class RepositoryVerifier:
    def __init__(self, agent):
        self.agent = agent

    def _get_agent(self, agent_type):
        assert agent_type == "security_audit"
        return self.agent


class RepositoryResultAgent:
    def __init__(self, *, finding: bool = False, refusal: bool = False):
        self.finding = finding
        self.refusal = refusal
        self.calls: list[dict] = []

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
        tools.register_initial_file(
            file_path,
            visible_end_line=max(1, len(source.splitlines())),
        )
        tools.execute("read_file", {"path": file_path})
        candidate_id = candidates[0]["candidate_id"]
        evidence = self._evidence(
            tools,
            file_path,
            purpose="cause" if self.finding else "mitigation",
        )
        metadata = self._metadata(candidate_id, evidence)
        findings = self._findings(file_path, evidence)
        self.calls.append(
            {
                "source": source,
                "file_path": file_path,
                "context": context,
                "candidates": candidates,
                "run_id": run_id,
            }
        )
        return SimpleNamespace(findings=findings, status="complete", metadata=metadata)

    def _evidence(self, tools, file_path: str, *, purpose: str) -> dict:
        return {
            "file": file_path,
            "line": 1,
            "end_line": 1,
            "role": "revalidation proof",
            "purpose": purpose,
            "causal_pair": None,
            "file_hash": tools.related_file_hashes[file_path],
        }

    def _metadata(self, candidate_id: str, evidence: dict) -> dict:
        metadata = {
            "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
            "definition_hash": INVESTIGATOR_DEFINITION_HASH,
            "covered_candidate_ids": [candidate_id],
            "clean_evidence": [
                {
                    "invariant": "stored finding is absent",
                    "candidate_ids": [candidate_id],
                    "evidence": [evidence],
                }
            ],
        }
        if self.refusal:
            metadata["refused"] = True
        if self.finding:
            metadata["clean_evidence"] = []
        return metadata

    def _findings(self, file_path: str, evidence: dict) -> list[dict]:
        if not self.finding:
            return []
        return [
            {
                "rule_id": "SKY-AUDIT-SECURITY",
                "issue_type": "security",
                "severity": "high",
                "message": "finding reproduced",
                "location": {"file": file_path, "line": 1},
                "metadata": {"investigation_evidence": {"evidence": [evidence]}},
            }
        ]


def _candidate(
    candidate_id: str = "cand",
    *,
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
        priority=800,
    )


def _write_analyzed_record(
    store: AuditStore,
    path: Path,
    *,
    candidates: list[AuditCandidate] | None = None,
):
    record = store.upsert_scan_record(
        file_path=path,
        file_hash=sha256_file(path),
        language="python",
        candidates=candidates or [_candidate()],
        config_hash="cfg",
    )
    record.status = "analyzed"
    record.findings = [
        {
            "audit_finding_id": "finding-one",
            "audit_source_hash": record.file_hash,
            "issue_type": "security",
            "severity": "high",
            "message": "finding",
            "location": {"file": str(path), "line": 1},
        }
    ]
    store.write_file_record(record)
    store.set_current_scan_files([*(store.current_scan_files or ()), path])
    return record


def test_revalidate_deep_audit_findings_appends_verdict_without_deleting(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)

    verifier = FakeVerifier("true_positive")
    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        provider="test",
        run_id="run-revalidate",
    )
    record = store.read_file_record(app)

    assert summary.revalidated_findings == 1
    assert summary.true_positive == 1
    assert record is not None
    assert len(record.findings) == 1
    assert record.revalidation[-1]["finding_id"] == "finding-one"
    assert record.revalidation[-1]["verdict"] == "true_positive"
    assert verifier.calls[0]["file_path"] == "app.py"


def test_revalidation_limit_reports_incomplete_when_eligible_work_remains(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_analyzed_record(store, app)
    record.findings.append(
        {
            "audit_finding_id": "finding-two",
            "audit_source_hash": record.file_hash,
            "issue_type": "security",
            "severity": "high",
            "message": "second finding",
            "location": {"file": str(app), "line": 1},
        }
    )
    store.write_file_record(record)
    verifier = FakeVerifier("true_positive")

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        limit=1,
        run_id="run-limited",
    )

    assert summary.considered_findings == 2
    assert summary.revalidated_findings == 1
    assert summary.limited is True
    assert summary.complete is False
    assert len(verifier.calls) == 1


def test_revalidate_deep_audit_findings_drops_verdict_after_record_changes(
    tmp_path: Path,
    monkeypatch,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)
    monkeypatch.setattr(
        store,
        "append_revalidation_entry",
        lambda *args, **kwargs: False,
    )

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=FakeVerifier("true_positive"),
        model="test-model",
        run_id="run-record-changed",
    )
    record = store.read_file_record(app)

    assert summary.true_positive == 0
    assert summary.uncertain == 1
    assert summary.error_findings == 1
    assert summary.complete is False
    assert record is not None
    assert record.revalidation == []


def test_revalidate_deep_audit_findings_skips_same_context_unless_forced(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)

    verifier = FakeVerifier("true_positive")
    revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        provider="test",
        run_id="run-one",
    )
    revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        provider="test",
        run_id="run-two",
    )
    forced = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        provider="test",
        force=True,
        run_id="run-force",
    )

    record = store.read_file_record(app)

    assert len(verifier.calls) == 2
    assert forced.revalidated_findings == 1
    assert record is not None
    assert len(record.revalidation) == 2


def test_revalidate_deep_audit_findings_can_mark_changed_file_fixed(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)

    app.write_text("print('fixed')\n", encoding="utf-8")
    rescanned = store.upsert_scan_record(
        file_path=app,
        file_hash=sha256_file(app),
        language="python",
        candidates=[],
        config_hash="cfg",
    )

    assert rescanned.status == "not_analyzed"
    assert len(rescanned.findings) == 1

    verifier = FakeVerifier("fixed")
    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        provider="test",
        force=True,
        run_id="run-fixed",
    )
    record = store.read_file_record(app)

    assert summary.revalidated_findings == 1
    assert summary.fixed == 1
    assert record is not None
    assert record.revalidation[-1]["verdict"] == "fixed"


def test_revalidate_deep_audit_findings_redacts_context_before_verifier(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    raw_secret = _fake_github_token()
    app.write_text(f'TOKEN="{raw_secret}"\neval(user_input)\n', encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)

    verifier = FakeVerifier("uncertain")
    revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        run_id="run-redact",
    )

    context = verifier.calls[0]["context"]
    assert raw_secret not in str(context)
    assert REDACTION in str(context)


def test_revalidate_deep_audit_findings_skips_secret_candidate_records(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("TOKEN='secret'\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(
        store,
        app,
        candidates=[_candidate("secret", rule_id="SKY-S101", redacted=True)],
    )

    verifier = FakeVerifier("true_positive")
    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        run_id="run-secret",
    )

    assert verifier.calls == []
    assert summary.skipped_findings == 1
    assert summary.complete is False


def test_revalidate_deep_audit_findings_defaults_to_current_scan_scope(
    tmp_path: Path,
):
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
    _write_analyzed_record(store, hidden)
    store.set_current_scan_files([app])

    verifier = FakeVerifier("true_positive")
    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        run_id="run-current-scope",
    )

    assert verifier.calls == []
    assert summary.considered_findings == 0
    assert summary.revalidated_findings == 0
    assert summary.complete is True


def test_revalidate_deep_audit_findings_without_scope_fails_closed(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)
    store.current_scan_files = None

    verifier = FakeVerifier("true_positive")
    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        run_id="run-no-scope",
    )

    assert verifier.calls == []
    assert summary.considered_findings == 0
    assert summary.revalidated_findings == 0
    assert summary.complete is True


def test_revalidate_deep_audit_findings_challenges_uncertain_verdicts(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_analyzed_record(store, app)
    record.revalidation = [
        {
            "finding_id": "finding-one",
            "verdict": "uncertain",
            "model": "old-model",
            "mode": "revalidate",
        }
    ]
    store.write_file_record(record)

    verifier = FakeVerifier("false_positive")
    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        challenge=True,
        run_id="run-challenge",
    )
    updated = store.read_file_record(app)

    assert summary.challenged_findings == 1
    assert summary.false_positive == 1
    assert verifier.calls[0]["mode"] == "challenge"
    assert updated is not None
    assert updated.revalidation[-1]["mode"] == "challenge"


def test_legacy_false_positive_without_exact_evidence_fails_closed(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=FakeVerifier("false_positive", include_evidence=False),
        model="test-model",
        run_id="run-unproven",
    )
    record = store.read_file_record(app)

    assert summary.false_positive == 0
    assert summary.uncertain == 1
    assert summary.error_findings == 1
    assert summary.complete is False
    assert record is not None
    assert record.revalidation[-1]["evidence_validated"] is False
    assert record.revalidation[-1]["complete"] is False


def test_legacy_false_positive_without_origin_hash_fails_closed(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_analyzed_record(store, app)
    record.findings[0].pop("audit_source_hash")
    store.write_file_record(record)

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=FakeVerifier("false_positive"),
        model="test-model",
        run_id="run-no-legacy-origin",
    )
    updated = store.read_file_record(app)

    assert summary.false_positive == 0
    assert summary.uncertain == 1
    assert summary.error_findings == 1
    assert summary.complete is False
    assert updated is not None
    assert updated.revalidation[-1]["complete"] is False


def test_legacy_false_positive_without_refuting_invariant_fails_closed(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=FakeVerifier("false_positive", include_invariant=False),
        model="test-model",
        run_id="run-no-invariant",
    )
    updated = store.read_file_record(app)

    assert summary.false_positive == 0
    assert summary.uncertain == 1
    assert summary.error_findings == 1
    assert updated is not None
    assert updated.revalidation[-1]["complete"] is False


def test_legacy_suppression_evidence_must_cover_stored_location(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("safe_setup()\neval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_analyzed_record(store, app)
    record.findings[0]["location"] = {
        "file": str(app),
        "line": 2,
        "end_line": 2,
    }
    store.write_file_record(record)

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=FakeVerifier("false_positive"),
        model="test-model",
        run_id="run-off-location-evidence",
    )
    updated = store.read_file_record(app)

    assert summary.false_positive == 0
    assert summary.uncertain == 1
    assert summary.error_findings == 1
    assert updated is not None
    assert updated.revalidation[-1]["complete"] is False


def test_revalidation_refuses_source_hash_mismatch_before_verifier(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)
    app.write_text("print('changed without scan')\n", encoding="utf-8")

    verifier = FakeVerifier()
    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        run_id="run-stale-source",
    )

    assert verifier.calls == []
    assert summary.uncertain == 1
    assert summary.error_findings == 1
    assert summary.complete is False


def test_revalidation_refuses_symlinked_entry_file(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    outside = tmp_path / "outside.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    outside.write_text("print('outside')\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_analyzed_record(store, app)
    app.unlink()
    app.symlink_to(outside)
    # Keep the already-loaded record stable so this exercise reaches the
    # revalidator's own no-follow source boundary. AuditStore independently
    # rejects this path while decoding its record index.
    monkeypatch.setattr(store, "iter_file_records", lambda: [record])
    monkeypatch.setattr(store, "read_file_record", lambda _path: record)
    monkeypatch.setattr(
        store,
        "append_revalidation_entry",
        lambda *args, **kwargs: False,
    )

    verifier = FakeVerifier()
    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        run_id="run-symlink",
    )

    assert verifier.calls == []
    assert summary.uncertain == 1
    assert summary.error_findings == 1
    assert summary.complete is False


def test_repository_protocol_v3_clean_evidence_supports_false_positive(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)
    agent = RepositoryResultAgent()

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=RepositoryVerifier(agent),
        model="test-model",
        run_id="run-repository-clean",
    )
    record = store.read_file_record(app)

    assert summary.false_positive == 1
    assert summary.complete is True
    assert record is not None
    assert record.revalidation[-1]["evidence_validated"] is True
    assert record.revalidation[-1]["evidence_source"] == "repository_investigator"
    assert record.revalidation[-1]["related_files"][0]["path"] == "app.py"
    evidence = record.revalidation[-1]["evidence"][0]
    assert evidence["purpose"] == "mitigation"
    assert evidence["causal_pair"] is None
    assert record.revalidation[-1]["refuting_invariant"] == (
        "stored finding is absent"
    )


def test_repository_protocol_v3_finding_evidence_supports_true_positive(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)
    agent = RepositoryResultAgent(finding=True)

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=RepositoryVerifier(agent),
        model="test-model",
        run_id="run-repository-finding",
    )
    record = store.read_file_record(app)

    assert summary.true_positive == 1
    assert summary.complete is True
    assert record is not None
    evidence = record.revalidation[-1]["evidence"][0]
    assert evidence["purpose"] == "cause"
    assert evidence["causal_pair"] is None


def test_repository_clean_changed_source_is_fixed_with_origin_hash(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)
    app.write_text("print('fixed')\n", encoding="utf-8")
    store.upsert_scan_record(
        file_path=app,
        file_hash=sha256_file(app),
        language="python",
        candidates=[],
        config_hash="cfg",
    )

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=RepositoryVerifier(RepositoryResultAgent()),
        model="test-model",
        force=True,
        run_id="run-repository-fixed",
    )

    assert summary.fixed == 1
    assert summary.complete is True


def test_repository_clean_without_origin_hash_fails_closed(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_analyzed_record(store, app)
    record.findings[0].pop("audit_source_hash")
    store.write_file_record(record)

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=RepositoryVerifier(RepositoryResultAgent()),
        model="test-model",
        run_id="run-no-origin",
    )

    assert summary.false_positive == 0
    assert summary.fixed == 0
    assert summary.uncertain == 1
    assert summary.complete is False


def test_repository_refusal_is_uncertain_and_incomplete(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)

    summary = revalidate_deep_audit_findings(
        store=store,
        verifier=RepositoryVerifier(RepositoryResultAgent(refusal=True)),
        model="test-model",
        run_id="run-refusal",
    )

    assert summary.uncertain == 1
    assert summary.error_findings == 1
    assert summary.complete is False


def test_changed_source_invalidates_cached_verdict(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)
    verifier = FakeVerifier()
    revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        run_id="run-before-change",
    )

    app.write_text("eval(other_input)\n", encoding="utf-8")
    store.upsert_scan_record(
        file_path=app,
        file_hash=sha256_file(app),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )
    revalidate_deep_audit_findings(
        store=store,
        verifier=verifier,
        model="test-model",
        run_id="run-after-change",
    )

    assert len(verifier.calls) == 2


def test_positive_catalog_freshness_is_rechecked_before_reuse(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_analyzed_record(store, app)
    revalidate_deep_audit_findings(
        store=store,
        verifier=FakeVerifier(),
        model="test-model",
        run_id="run-catalog-freshness",
    )
    record = store.read_file_record(app)

    assert record is not None
    finding = record.findings[0]
    entry = record.revalidation[-1]
    catalog_cache: dict[tuple, bool] = {}
    assert is_revalidation_entry_current(
        record,
        finding,
        entry,
        catalog_cache=catalog_cache,
    )
    assert catalog_cache == {}

    (repo / "new_module.py").write_text("print('new')\n", encoding="utf-8")

    assert not is_revalidation_entry_current(
        record,
        finding,
        entry,
        catalog_cache=catalog_cache,
    )
