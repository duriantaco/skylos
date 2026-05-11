from __future__ import annotations

from pathlib import Path

from skylos.audit_redaction import REDACTION
from skylos.audit_revalidator import revalidate_deep_audit_findings
from skylos.audit_store import AuditStore
from skylos.audit_types import AuditCandidate, sha256_file


def _fake_github_token() -> str:
    return "ghp_" + "1234567890abcdef" + "1234567890abcdef" + "123456"


class FakeVerifier:
    def __init__(self, verdict: str = "true_positive"):
        self.verdict = verdict
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
        return {"verdict": self.verdict, "reason": f"{mode} verdict"}


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
            "severity": "high",
            "message": "finding",
            "location": {"file": str(path), "line": 1},
        }
    ]
    store.write_file_record(record)
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
