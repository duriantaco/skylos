from __future__ import annotations

from pathlib import Path

from skylos.audit.ci import evaluate_deep_audit_ci_gate
from skylos.audit.store import AuditStore
from skylos.audit.types import AuditCandidate, AuditProcessSummary, sha256_file


def _candidate(candidate_id: str, *, severity: str = "high") -> AuditCandidate:
    return AuditCandidate(
        candidate_id=candidate_id,
        kind="static_finding",
        rule_id="SKY-D999",
        line=1,
        severity_hint=severity,
        reason="candidate",
        priority=800,
    )


def _write_record(
    store: AuditStore,
    path: Path,
    *,
    severity: str = "high",
    status: str = "pending",
):
    record = store.upsert_scan_record(
        file_path=path,
        file_hash=sha256_file(path),
        language="python",
        candidates=[_candidate(path.name, severity=severity)],
        config_hash="cfg",
    )
    record.status = status
    store.write_file_record(record)
    return record


def test_ci_gate_fails_for_pending_candidate_at_threshold(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, severity="high")

    summary = evaluate_deep_audit_ci_gate(store=store, fail_on="high")

    assert summary.exit_code == 1
    assert summary.blocking_counts["pending"] == 1
    assert summary.complete is False


def test_ci_gate_passes_for_candidates_below_threshold(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, severity="medium")

    summary = evaluate_deep_audit_ci_gate(store=store, fail_on="high")

    assert summary.exit_code == 0
    assert summary.blocking_counts["pending"] == 0


def test_ci_gate_ignores_false_positive_revalidated_findings(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app, status="analyzed")
    record.findings = [
        {
            "audit_finding_id": "finding-one",
            "severity": "critical",
            "message": "critical finding",
        }
    ]
    record.revalidation = [
        {
            "finding_id": "finding-one",
            "verdict": "false_positive",
            "model": "test-model",
        }
    ]
    store.write_file_record(record)

    summary = evaluate_deep_audit_ci_gate(store=store, fail_on="high")

    assert summary.exit_code == 0
    assert summary.blocking_counts["findings"] == 0


def test_ci_gate_limited_run_blocks_when_unresolved_threshold_work_remains(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, severity="critical")
    process_summary = AuditProcessSummary(
        run_id="run",
        project_id="default",
        project_root=str(repo),
        considered_files=1,
        processed_files=0,
        findings_added=0,
        skipped_secret_files=0,
        unsupported_files=0,
        locked_files=0,
        error_files=0,
        remaining_pending_files=1,
        limited=True,
        complete=False,
    )

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="high",
        process_summary=process_summary,
    )

    assert summary.exit_code == 1
    assert summary.blocking_counts["limited"] == 1


def test_ci_gate_blocks_unsupported_not_analyzed_polyglot_work(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "route.ts"
    app.write_text(
        "import cp from 'child_process';\ncp.exec(userInput);\n",
        encoding="utf-8",
    )
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, severity="high", status="not_analyzed")

    summary = evaluate_deep_audit_ci_gate(store=store, fail_on="high")

    assert summary.exit_code == 1
    assert summary.blocking_counts["not_analyzed"] == 1
    assert summary.complete is False
