from __future__ import annotations

from pathlib import Path

import pytest

from skylos.audit.ci import evaluate_deep_audit_ci_gate
from skylos.audit.freshness import (
    REVALIDATION_DEFINITION_HASH,
    REVALIDATION_PROTOCOL_VERSION,
    finding_fingerprint,
)
from skylos.audit.investigator_tools import (
    DEFAULT_EXCLUDED_FOLDERS,
    INVESTIGATOR_TOOL_SCHEMA_VERSION,
    AuditReadOnlyTools,
)
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    AuditCandidate,
    AuditProcessSummary,
    AuditScanSummary,
    sha256_file,
)
from skylos.llm.investigator import (
    INVESTIGATOR_DEFINITION_HASH,
    INVESTIGATOR_PROTOCOL_VERSION,
)


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


def _current_revalidation(record, finding, *, verdict: str):
    tools = AuditReadOnlyTools(
        record.project_root,
        exclude_folders=DEFAULT_EXCLUDED_FOLDERS,
    )
    tools.register_initial_file(record.file)
    metadata = tools.metadata()
    return {
        "finding_id": finding["audit_finding_id"],
        "verdict": verdict,
        "reason": "validated verdict",
        "complete": True,
        "evidence_validated": True,
        "evidence_source": "repository_investigator",
        "evidence": [
            {
                "file": record.file,
                "line": 1,
                "end_line": 1,
                "role": "validated source proof",
                "purpose": "mitigation",
                "causal_pair": None,
                "file_hash": record.file_hash,
            }
        ],
        "refuting_invariant": (
            "The stored expression cannot receive attacker-controlled input."
        ),
        "source_hash": record.file_hash,
        "finding_hash": finding_fingerprint(finding),
        "config_hash": record.config_hash,
        "candidate_engine_version": record.candidate_engine_version,
        "protocol_version": REVALIDATION_PROTOCOL_VERSION,
        "definition_hash": REVALIDATION_DEFINITION_HASH,
        "investigator_definition_hash": INVESTIGATOR_DEFINITION_HASH,
        "tool_schema_version": INVESTIGATOR_TOOL_SCHEMA_VERSION,
        "catalog_digest": metadata["catalog_digest"],
        "catalog_exclude_folders": list(DEFAULT_EXCLUDED_FOLDERS),
        "catalog_excluded_paths": [],
        "catalog_denied_paths": [],
        "related_files": metadata["related_files"],
    }


def _mark_current_analysis(record, tools, *, model: str = "test-model"):
    metadata = tools.metadata()
    record.status = "analyzed"
    record.analysis_history.append(
        {
            "stage": "agent_process",
            "run_id": "analysis-run",
            "model": model,
            "provider": "test-provider",
            "analysis_version": INVESTIGATOR_PROTOCOL_VERSION,
            "protocol_version": INVESTIGATOR_PROTOCOL_VERSION,
            "definition_hash": INVESTIGATOR_DEFINITION_HASH,
            "tool_schema_version": INVESTIGATOR_TOOL_SCHEMA_VERSION,
            "catalog_digest": metadata["catalog_digest"],
            "related_files": metadata["related_files"],
        }
    )


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


@pytest.mark.parametrize(
    ("status", "blocking_bucket"),
    [
        ("pending", "pending"),
        ("error", "error"),
        ("analyzed", "stale_analyzed"),
    ],
)
def test_model_gate_blocks_unresolved_candidate_below_failure_threshold(
    tmp_path: Path,
    status: str,
    blocking_bucket: str,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, severity="medium", status=status)

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="high",
        model="test-model",
        provider="test-provider",
    )

    assert summary.exit_code == 1
    assert summary.blocking_counts[blocking_bucket] == 1


def test_ci_gate_blocks_rejected_sources_regardless_of_threshold(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    scan_summary = AuditScanSummary(
        project_id="default",
        project_root=str(repo),
        files_scanned=0,
        records_written=0,
        candidate_count=0,
        redacted_candidates=0,
        pending_files=0,
        not_analyzed_files=0,
        complete=False,
        rejected_source_files=1,
    )

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="critical",
        scan_summary=scan_summary,
    )

    assert summary.exit_code == 1
    assert summary.blocking_counts["rejected_source_files"] == 1
    assert summary.complete is False
    assert summary.reason == "deep audit source files were rejected before analysis"


def test_model_gate_blocks_candidate_free_incomplete_holistic_record(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "plain.py"
    app.write_text("print('plain')\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = store.upsert_scan_record(
        file_path=app,
        file_hash=sha256_file(app),
        language="python",
        candidates=[],
        config_hash="cfg",
    )
    record.status = "error"
    store.write_file_record(record)
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
        error_files=1,
        remaining_pending_files=0,
        limited=False,
        complete=False,
    )

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="critical",
        model="test-model",
        provider="test-provider",
        process_summary=process_summary,
    )

    assert summary.exit_code == 1
    assert summary.blocking_counts["error"] == 1


def test_model_gate_allows_current_candidate_free_analyzed_clean_record(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "plain.py"
    app.write_text("print('plain')\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = store.upsert_scan_record(
        file_path=app,
        file_hash=sha256_file(app),
        language="python",
        candidates=[],
        config_hash="cfg",
    )
    tools = AuditReadOnlyTools(repo, exclude_folders=DEFAULT_EXCLUDED_FOLDERS)
    tools.register_initial_file(record.file)
    _mark_current_analysis(record, tools)
    store.write_file_record(record)

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="critical",
        model="test-model",
        provider="test-provider",
    )

    assert summary.exit_code == 0
    assert not any(summary.blocking_counts.values())


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
            "audit_source_hash": record.file_hash,
            "severity": "critical",
            "message": "critical finding",
            "location": {"line": 1, "end_line": 1},
        }
    ]
    record.revalidation = [
        _current_revalidation(
            record,
            record.findings[0],
            verdict="false_positive",
        )
    ]
    store.write_file_record(record)

    summary = evaluate_deep_audit_ci_gate(store=store, fail_on="high")

    assert summary.exit_code == 0
    assert summary.blocking_counts["findings"] == 0


def test_ci_gate_does_not_trust_proofless_false_positive(tmp_path: Path):
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
            "audit_source_hash": record.file_hash,
            "severity": "critical",
            "message": "critical finding",
            "location": {"line": 1, "end_line": 1},
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

    assert summary.exit_code == 1
    assert summary.blocking_counts["findings"] == 1


def test_ci_gate_does_not_trust_stale_false_positive(tmp_path: Path):
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
        _current_revalidation(
            record,
            record.findings[0],
            verdict="false_positive",
        )
    ]
    store.write_file_record(record)
    app.write_text("eval(other_input)\n", encoding="utf-8")

    summary = evaluate_deep_audit_ci_gate(store=store, fail_on="high")

    assert summary.exit_code == 1
    assert summary.blocking_counts["findings"] == 1


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


def test_ci_gate_blocks_analysis_from_old_investigator_protocol(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app, status="analyzed")
    tools = AuditReadOnlyTools(repo, exclude_folders=DEFAULT_EXCLUDED_FOLDERS)
    tools.register_initial_file(record.file)
    _mark_current_analysis(record, tools)
    record.analysis_history[-1]["protocol_version"] = "old-protocol"
    store.write_file_record(record)

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="high",
        model="test-model",
        provider="test-provider",
    )

    assert summary.exit_code == 1
    assert summary.blocking_counts["stale_analyzed"] == 1


def test_ci_gate_blocks_analysis_when_repository_catalog_changed(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app, status="analyzed")
    tools = AuditReadOnlyTools(repo, exclude_folders=DEFAULT_EXCLUDED_FOLDERS)
    tools.register_initial_file(record.file)
    _mark_current_analysis(record, tools)
    store.write_file_record(record)
    (repo / "new_context.py").write_text("ALLOW = True\n", encoding="utf-8")

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="high",
        model="test-model",
        provider="test-provider",
    )

    assert summary.exit_code == 1
    assert summary.blocking_counts["stale_analyzed"] == 1


def test_changed_ci_gate_counts_only_findings_produced_by_current_run(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app, status="analyzed")
    record.findings = [
        {
            "audit_finding_id": "finding-old",
            "audit_produced_by_run_id": "run-old",
            "severity": "critical",
            "message": "pre-existing finding",
        },
        {
            "audit_finding_id": "finding-new",
            "audit_produced_by_run_id": "run-current",
            "severity": "high",
            "message": "new finding",
        },
    ]
    store.write_file_record(record)

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="high",
        finding_run_id="run-current",
    )

    assert summary.exit_code == 1
    assert summary.blocking_counts["findings"] == 1


def test_changed_ci_gate_does_not_refail_preexisting_findings(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _write_record(store, app, status="analyzed")
    record.findings = [
        {
            "audit_finding_id": "finding-old",
            "audit_produced_by_run_id": "run-old",
            "severity": "critical",
            "message": "pre-existing finding",
        }
    ]
    store.write_file_record(record)

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="high",
        finding_run_id="run-current",
    )

    assert summary.exit_code == 0
    assert summary.blocking_counts["findings"] == 0


def test_changed_ci_gate_still_fails_closed_for_unresolved_current_work(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _write_record(store, app, severity="critical", status="pending")

    summary = evaluate_deep_audit_ci_gate(
        store=store,
        fail_on="high",
        finding_run_id="run-current",
    )

    assert summary.exit_code == 1
    assert summary.blocking_counts["pending"] == 1
