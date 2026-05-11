from __future__ import annotations

import json
from pathlib import Path

from skylos.audit_export import (
    build_deep_audit_export,
    render_deep_audit_export,
    write_deep_audit_export,
)
from skylos.audit_store import AuditStore
from skylos.audit_types import (
    STATUS_ANALYZED,
    STATUS_DELETED,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_SKIPPED,
    AuditCandidate,
    sha256_file,
)


def _candidate(
    candidate_id: str,
    *,
    severity: str = "high",
    redacted: bool = False,
    reason: str = "candidate",
) -> AuditCandidate:
    return AuditCandidate(
        candidate_id=candidate_id,
        kind="static_finding",
        rule_id="SKY-D999",
        line=2,
        severity_hint=severity,
        reason=reason,
        redacted=redacted,
        priority=800,
    )


def _record(
    store: AuditStore,
    path: Path,
    *,
    status: str = STATUS_PENDING,
    candidate: AuditCandidate | None = None,
):
    record = store.upsert_scan_record(
        file_path=path,
        file_hash=sha256_file(path),
        language="python",
        candidates=[candidate or _candidate(path.name)],
        config_hash="cfg",
    )
    record.status = status
    store.write_file_record(record)
    return record


def test_json_export_includes_completion_skipped_counts_and_redacts_secrets(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    secret = repo / "secret.py"
    raw_token = "ghp_123456789012345678901234"
    secret.write_text(f"TOKEN = '{raw_token}'\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")

    analyzed = _record(store, app, status=STATUS_ANALYZED)
    analyzed.findings = [
        {
            "audit_finding_id": "finding-one",
            "rule_id": "SKY-D001",
            "severity": "critical",
            "message": "command injection",
            "line": 1,
        }
    ]
    analyzed.revalidation = [
        {
            "finding_id": "finding-one",
            "verdict": "true_positive",
            "reason": "sink remains reachable",
        }
    ]
    store.write_file_record(analyzed)

    _record(
        store,
        secret,
        status=STATUS_SKIPPED,
        candidate=_candidate(
            "secret-candidate",
            redacted=True,
            reason=f"secret-bearing context {raw_token}",
        ),
    )

    export = build_deep_audit_export(store=store)
    rendered = json.dumps(export, sort_keys=True)

    assert export["completion"]["complete"] is False
    assert export["completion"]["analyzed_files"] == 1
    assert export["completion"]["skipped_files"] == 1
    assert export["completion"]["skipped_candidates"] == 1
    assert {entry["verdict"] for entry in export["entries"]} == {
        "true_positive",
        "skipped",
    }
    assert raw_token not in rendered
    assert "[REDACTED_SECRET]" in rendered


def test_export_filters_by_min_severity_and_verdict(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    low = repo / "low.py"
    low.write_text("print('ok')\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")

    high_record = _record(store, app, status=STATUS_ANALYZED)
    high_record.findings = [
        {
            "audit_finding_id": "finding-high",
            "rule_id": "SKY-D001",
            "severity": "high",
            "message": "high finding",
            "line": 1,
        }
    ]
    high_record.revalidation = [
        {"finding_id": "finding-high", "verdict": "fixed", "reason": "patched"}
    ]
    store.write_file_record(high_record)
    _record(
        store,
        low,
        status=STATUS_PENDING,
        candidate=_candidate("low-candidate", severity="low"),
    )

    export = build_deep_audit_export(
        store=store,
        min_severity="high",
        verdicts=["fixed"],
    )

    assert export["entry_count"] == 1
    assert export["entries"][0]["id"] == "finding-high"
    assert export["entries"][0]["verdict"] == "fixed"


def test_export_surfaces_not_analyzed_polyglot_work(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "route.ts"
    app.write_text(
        "import cp from 'child_process';\ncp.exec(userInput);\n",
        encoding="utf-8",
    )
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    _record(
        store,
        app,
        status=STATUS_NOT_ANALYZED,
        candidate=_candidate("ts-candidate", severity="high"),
    )

    export = build_deep_audit_export(store=store, verdicts=["not_analyzed"])

    assert export["completion"]["complete"] is False
    assert export["completion"]["not_analyzed_files"] == 1
    assert export["entry_count"] == 1
    assert export["entries"][0]["verdict"] == "not_analyzed"


def test_export_treats_no_candidate_files_as_complete(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "plain.py"
    app.write_text("print('ok')\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    store.upsert_scan_record(
        file_path=app,
        file_hash=sha256_file(app),
        language="python",
        candidates=[],
        config_hash="cfg",
    )

    export = build_deep_audit_export(store=store)

    assert export["completion"]["complete"] is True
    assert export["completion"]["no_candidate_files"] == 1
    assert export["completion"]["not_analyzed_files"] == 0
    assert export["entry_count"] == 0


def test_export_excludes_deleted_records_from_active_entries(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "deleted.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _record(store, app, status=STATUS_DELETED)
    record.findings = [
        {
            "audit_finding_id": "finding-deleted",
            "rule_id": "SKY-D001",
            "severity": "critical",
            "message": "old finding",
            "line": 1,
        }
    ]
    store.write_file_record(record)

    export = build_deep_audit_export(store=store)

    assert export["completion"]["deleted_files"] == 1
    assert export["entry_count"] == 0
    assert export["records"] == []

    with_deleted = build_deep_audit_export(store=store, include_deleted=True)

    assert with_deleted["completion"]["deleted_files"] == 1
    assert with_deleted["entry_count"] == 2
    assert {entry["verdict"] for entry in with_deleted["entries"]} == {"deleted"}
    assert with_deleted["records"][0]["status"] == STATUS_DELETED


def test_sarif_export_includes_results_rules_and_completion(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _record(store, app, status=STATUS_ANALYZED)
    record.findings = [
        {
            "audit_finding_id": "finding-one",
            "rule_id": "SKY-D001",
            "severity": "high",
            "message": "high finding",
            "line": 1,
        }
    ]
    store.write_file_record(record)

    export = build_deep_audit_export(store=store)
    sarif = json.loads(render_deep_audit_export(export, "sarif"))

    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "SKY-D001"
    assert run["results"][0]["ruleId"] == "SKY-D001"
    assert run["properties"]["deep_audit"]["completion"]["analyzed_files"] == 1


def test_markdown_export_and_directory_are_stable(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _record(store, app, status=STATUS_ANALYZED)
    record.findings = [
        {
            "audit_finding_id": "finding-one",
            "rule_id": "SKY-D001",
            "severity": "high",
            "message": "high finding",
            "line": 1,
        }
    ]
    record.revalidation = [
        {"finding_id": "finding-one", "verdict": "uncertain", "reason": "needs review"}
    ]
    store.write_file_record(record)

    export = build_deep_audit_export(store=store)
    markdown = render_deep_audit_export(export, "md")
    out_dir = tmp_path / "audit-report"
    written = write_deep_audit_export(export, out_dir, "md-dir")

    assert "# Skylos Deep Audit Report" in markdown
    assert (
        "| high | uncertain | analyzed | SKY-D001 | app.py:1 | high finding |"
        in markdown
    )
    assert [path.name for path in written] == [
        "index.md",
        "001-high-sky-d001-app.py.md",
    ]
    assert (out_dir / "index.md").exists()
    assert (out_dir / "001-high-sky-d001-app.py.md").exists()
