from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from skylos.audit.freshness import (
    REVALIDATION_DEFINITION_HASH,
    REVALIDATION_PROTOCOL_VERSION,
    finding_fingerprint,
)
from skylos.audit.export import (
    build_deep_audit_export,
    render_deep_audit_export,
    write_deep_audit_export,
)
from skylos.audit.investigator_tools import (
    DEFAULT_EXCLUDED_FOLDERS,
    INVESTIGATOR_TOOL_SCHEMA_VERSION,
    AuditReadOnlyTools,
)
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    STATUS_ANALYZED,
    STATUS_DELETED,
    STATUS_NOT_ANALYZED,
    STATUS_PENDING,
    STATUS_SKIPPED,
    AuditCandidate,
    language_for_path,
    sha256_file,
)
from skylos.llm.investigator import INVESTIGATOR_DEFINITION_HASH


def _candidate(
    candidate_id: str,
    *,
    kind: str = "static_finding",
    rule_id: str = "SKY-D999",
    line: int = 2,
    severity: str = "high",
    redacted: bool = False,
    reason: str = "candidate",
    evidence: str = "static",
    signal_quality: str = "exploratory",
    data: dict[str, Any] | None = None,
) -> AuditCandidate:
    return AuditCandidate(
        candidate_id=candidate_id,
        kind=kind,
        rule_id=rule_id,
        line=line,
        severity_hint=severity,
        reason=reason,
        evidence=evidence,
        signal_quality=signal_quality,
        redacted=redacted,
        priority=800,
        data=data or {},
    )


def _threat_trace(trace_id: str = "trace-123") -> dict[str, Any]:
    return {
        "trace_id": trace_id,
        "file": "app.py",
        "entrypoint": "proxy [app.get]",
        "source": {
            "file": "app.py",
            "line": 6,
            "name": "request.args.get",
            "kind": "source",
        },
        "sink": {
            "file": "app.py",
            "line": 7,
            "name": "requests.get",
            "kind": "sink",
        },
        "sink_category": "ssrf",
        "path": [],
        "guards": [],
        "confidence": "medium",
        "validation": "static_unvalidated",
        "limitations": ["python_intra_procedural_only"],
    }


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
        language=language_for_path(path),
        candidates=[candidate or _candidate(path.name)],
        config_hash="cfg",
    )
    record.status = status
    store.write_file_record(record)
    return record


def _current_revalidation(record, finding, *, verdict: str, reason: str):
    tools = AuditReadOnlyTools(
        record.project_root,
        exclude_folders=DEFAULT_EXCLUDED_FOLDERS,
    )
    tools.register_initial_file(record.file)
    metadata = tools.metadata()
    return {
        "finding_id": finding["audit_finding_id"],
        "verdict": verdict,
        "reason": reason,
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
        _current_revalidation(
            analyzed,
            analyzed.findings[0],
            verdict="true_positive",
            reason="sink remains reachable",
        )
    ]
    analyzed.analysis_history = [
        {
            "stage": "agent_process",
            "model": "audit-model",
            "provider": "test-provider",
            "investigation": {
                "llm_calls": 2,
                "usage": {"prompt_tokens": 11, "completion_tokens": 5},
                "reviewer_guidance": {
                    "selected_packs": [
                        {"id": "framework.python_web", "version": "1.0.0"}
                    ]
                },
            },
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
    assert export["coverage"]["metric"] == "candidate_observation_coverage"
    assert export["coverage"]["scope"] == "repository"
    assert export["coverage"]["candidate_count"] == 2
    assert export["coverage"]["finding_count"] == 1
    assert export["coverage"]["observed_finding_verdicts"] == {"true_positive": 1}
    assert export["coverage"]["analysis"] == {
        "completed_runs": 1,
        "failed_runs_with_telemetry": 0,
        "error_events": 0,
        "llm_calls": 2,
        "completed_llm_calls": 2,
        "failed_llm_calls": 0,
        "usage": {"completion_tokens": 5, "prompt_tokens": 11},
        "completed_usage": {"completion_tokens": 5, "prompt_tokens": 11},
        "failed_usage": {},
        "by_model_provider": [
            {
                "provider": "test-provider",
                "model": "audit-model",
                "completed_runs": 1,
                "failed_runs": 0,
                "llm_calls": 2,
                "completed_llm_calls": 2,
                "failed_llm_calls": 0,
                "usage": {"completion_tokens": 5, "prompt_tokens": 11},
                "completed_usage": {
                    "completion_tokens": 5,
                    "prompt_tokens": 11,
                },
                "failed_usage": {},
            }
        ],
        "model_provider_rows_truncated": False,
        "reviewer_pack_runs": [
            {"pack_id": "framework.python_web", "completed_runs": 1}
        ],
        "reviewer_pack_rows_truncated": False,
    }
    assert raw_token not in rendered
    assert "[REDACTED_SECRET]" in rendered


def test_export_counts_failed_operational_usage_without_trusting_failure_evidence(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("print('ok')\n", encoding="utf-8")
    raw_token = "ghp_123456789012345678901234"
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _record(store, app, status=STATUS_ANALYZED)
    record.analysis_history = [
        {
            "stage": "agent_process",
            "model": "audit-model",
            "provider": "test-provider",
            "investigation": {
                "llm_calls": 2,
                "usage": {"prompt_tokens": 11},
                "reviewer_guidance": {
                    "selected_packs": [
                        {"id": "framework.python_web", "version": "1.0.0"}
                    ]
                },
            },
        }
    ]
    store.write_file_record(record)
    assert store.mark_error(
        app,
        f"terminal failure with {raw_token}",
        model="audit-model",
        provider="test-provider",
        operational_metadata={
            "metadata_scope": "operational_only",
            "attempt_count": 1,
            "llm_calls": 3,
            "usage": {
                "prompt_tokens": 7,
                "total_tokens": 10,
                raw_token: 999,
            },
            "visited_files": [raw_token],
            "clean_evidence": [{"invariant": raw_token}],
        },
    )
    assert store.mark_error(app, "generic failure without model usage")

    export = build_deep_audit_export(store=store)
    analysis = export["coverage"]["analysis"]
    rendered = json.dumps(export, sort_keys=True)

    assert analysis["completed_runs"] == 1
    assert analysis["failed_runs_with_telemetry"] == 1
    assert analysis["error_events"] == 2
    assert analysis["llm_calls"] == 5
    assert analysis["completed_llm_calls"] == 2
    assert analysis["failed_llm_calls"] == 3
    assert analysis["usage"] == {"prompt_tokens": 18, "total_tokens": 10}
    assert analysis["completed_usage"] == {"prompt_tokens": 11}
    assert analysis["failed_usage"] == {
        "prompt_tokens": 7,
        "total_tokens": 10,
    }
    assert analysis["by_model_provider"] == [
        {
            "provider": "test-provider",
            "model": "audit-model",
            "completed_runs": 1,
            "failed_runs": 1,
            "llm_calls": 5,
            "completed_llm_calls": 2,
            "failed_llm_calls": 3,
            "usage": {"prompt_tokens": 18, "total_tokens": 10},
            "completed_usage": {"prompt_tokens": 11},
            "failed_usage": {"prompt_tokens": 7, "total_tokens": 10},
        }
    ]
    assert analysis["reviewer_pack_runs"] == [
        {"pack_id": "framework.python_web", "completed_runs": 1}
    ]
    assert raw_token not in rendered
    error_history = [
        item
        for item in store.read_file_record(app).analysis_history
        if item.get("stage") == "error"
    ][0]
    assert set(error_history["investigation"]) == {
        "metadata_scope",
        "attempt_count",
        "attempt_limit",
        "completed_attempt_count",
        "failed_attempt_count",
        "recoverable_failed_attempt_count",
        "turns",
        "llm_calls",
        "tool_calls",
        "source_observation_calls",
        "evidence_bytes",
        "unsafe_discovery_truncations",
        "sensitive_denials",
        "attempt_budget_exhausted",
        "usage",
    }


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
            "audit_source_hash": "0" * 64,
            "rule_id": "SKY-D001",
            "severity": "high",
            "message": "high finding",
            "line": 1,
            "location": {"line": 1, "end_line": 1},
        }
    ]
    high_record.revalidation = [
        _current_revalidation(
            high_record,
            high_record.findings[0],
            verdict="fixed",
            reason="patched",
        )
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
        candidate=_candidate(
            "ts-candidate",
            severity="high",
            signal_quality="strong",
        ),
    )

    export = build_deep_audit_export(store=store, verdicts=["not_analyzed"])

    assert export["completion"]["complete"] is False
    assert export["completion"]["not_analyzed_files"] == 1
    assert export["entry_count"] == 1
    assert export["entries"][0]["verdict"] == "not_analyzed"
    assert export["entries"][0]["signal_quality"] == "strong"
    assert export["entries"][0]["priority"] == 800
    assert export["coverage"]["by_signal_quality"]["strong"] == 1
    assert export["coverage"]["by_language"]["typescript"] == {
        "files": 1,
        "files_with_candidates": 1,
        "candidates": 1,
        "findings": 0,
    }


def test_export_coverage_bounds_and_redacts_hostile_dimension_labels(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("print('ok')\n", encoding="utf-8")
    raw_token = "ghp_123456789012345678901234"
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _record(
        store,
        app,
        status=STATUS_NOT_ANALYZED,
        candidate=_candidate(
            "hostile-dimension",
            rule_id=raw_token,
            evidence=raw_token,
        ),
    )
    record.language = raw_token
    record.analysis_history = [
        {
            "stage": "agent_process",
            "model": raw_token,
            "provider": raw_token,
            "investigation": {
                "llm_calls": 1,
                "usage": {raw_token: 99},
                "reviewer_guidance": {
                    "selected_packs": [{"id": raw_token, "version": "1"}]
                },
            },
        }
    ]
    store.write_file_record(record)

    export = build_deep_audit_export(store=store, allowed_files=[app])
    rendered = json.dumps(export, sort_keys=True)

    assert raw_token not in rendered
    assert export["filters"]["file_scope"] == "allowed_files"
    assert export["filters"]["allowed_file_count"] == 1
    assert export["coverage"]["scope"] == "allowed_files"
    assert export["coverage"]["by_language"]["other"]["files"] == 1
    assert export["coverage"]["by_candidate_source"] == {"other": 1}
    assert export["coverage"]["by_rule"] == {"other": {"candidates": 1, "findings": 0}}
    assert export["coverage"]["analysis"]["usage"] == {}
    assert export["coverage"]["analysis"]["reviewer_pack_runs"] == [
        {"pack_id": "[REDACTED_SECRET]", "completed_runs": 1}
    ]


def test_export_surfaces_threat_traces_in_all_formats(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text(
        "from flask import Flask, request\n"
        "import requests\n"
        "app = Flask(__name__)\n"
        "@app.get('/proxy')\n"
        "def proxy():\n"
        "    url = request.args.get('url')\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    pending = repo / "pending.py"
    pending.write_text("print('pending')\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")

    trace = _threat_trace()
    analyzed = _record(store, app, status=STATUS_ANALYZED)
    analyzed.findings = [
        {
            "audit_finding_id": "finding-trace",
            "rule_id": "SKY-D102",
            "severity": "high",
            "message": "untrusted URL reaches HTTP client",
            "line": 7,
            "metadata": {"threat_trace": trace},
        }
    ]
    store.write_file_record(analyzed)
    _record(
        store,
        pending,
        status=STATUS_NOT_ANALYZED,
        candidate=_candidate(
            "candidate-trace",
            kind="threat_trace",
            rule_id="SKY-AUDIT-TRACE",
            line=7,
            reason="request data reaches requests.get",
            evidence="static_unvalidated",
            data={"threat_trace": _threat_trace("trace-candidate")},
        ),
    )

    export = build_deep_audit_export(store=store)
    entries = {entry["id"]: entry for entry in export["entries"]}

    assert entries["finding-trace"]["threat_trace"]["trace_id"] == "trace-123"
    assert entries["candidate-trace"]["threat_trace"]["trace_id"] == "trace-candidate"

    sarif = json.loads(render_deep_audit_export(export, "sarif"))
    metadata_by_rule = {
        result["ruleId"]: result["properties"]["skylos_metadata"]
        for result in sarif["runs"][0]["results"]
    }
    assert metadata_by_rule["SKY-D102"]["threat_trace"]["trace_id"] == "trace-123"
    assert (
        metadata_by_rule["SKY-D102"]["threat_trace_summary"]
        == "request.args.get@L6 -> requests.get@L7 (static_unvalidated)"
    )

    markdown = render_deep_audit_export(export, "md")
    assert (
        "| Severity | Verdict | Status | Rule | Location | Threat Trace | Message |"
        in markdown
    )
    assert "request.args.get@L6 -> requests.get@L7 (static_unvalidated)" in markdown

    out_dir = tmp_path / "audit-report"
    write_deep_audit_export(export, out_dir, "md-dir")
    detail = (out_dir / "001-high-sky-d102-app.py.md").read_text(encoding="utf-8")
    assert "## Threat Trace" in detail
    assert "- Entrypoint: `proxy [app.get]`" in detail
    assert "- Source: `request.args.get` at `app.py` at line `6`" in detail


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
    assert (
        run["properties"]["deep_audit"]["coverage"]["metric"]
        == "candidate_observation_coverage"
    )


def test_export_uses_nested_investigator_location_line(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _record(store, app, status=STATUS_ANALYZED)
    record.findings = [
        {
            "audit_finding_id": "finding-nested-location",
            "rule_id": "SKY-D001",
            "severity": "high",
            "message": "nested location finding",
            "location": {"file": "app.py", "line": 17, "end_line": 18},
        }
    ]
    store.write_file_record(record)

    export = build_deep_audit_export(store=store)

    assert export["entries"][0]["line"] == 17
    sarif = json.loads(render_deep_audit_export(export, "sarif"))
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "region"
    ]
    assert region["startLine"] == 17
    assert "| app.py:17 |" in render_deep_audit_export(export, "md")


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
    rewritten = write_deep_audit_export(export, out_dir, "md-dir")

    assert "# Skylos Deep Audit Report" in markdown
    assert (
        "| high | uncertain | analyzed | SKY-D001 | app.py:1 | high finding |"
        in markdown
    )
    assert [path.name for path in written] == [
        "index.md",
        "001-high-sky-d001-app.py.md",
    ]
    assert [path.name for path in rewritten] == [path.name for path in written]
    assert (out_dir / "index.md").exists()
    assert (out_dir / "001-high-sky-d001-app.py.md").exists()


def test_markdown_directory_manifest_tracks_current_files_without_sweeping(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = _record(store, app, status=STATUS_ANALYZED)
    record.findings = [
        {
            "audit_finding_id": "finding-stale",
            "rule_id": "SKY-D001",
            "severity": "high",
            "message": "finding",
            "location": {"file": "app.py", "line": 1},
        }
    ]
    store.write_file_record(record)
    output_dir = tmp_path / "report"

    export = build_deep_audit_export(store=store)
    written = write_deep_audit_export(export, output_dir, "md-dir")
    stale_path = written[1]
    user_file = output_dir / "notes.md"
    user_file.write_text("keep me\n", encoding="utf-8")

    export["entries"] = []
    export["entry_count"] = 0
    write_deep_audit_export(export, output_dir, "md-dir")

    manifest = json.loads(
        (output_dir / ".skylos-deep-audit-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["files"] == ["index.md"]
    assert stale_path.exists()
    assert user_file.read_text(encoding="utf-8") == "keep me\n"


def test_markdown_directory_rejects_symlink_output(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "report"
    output.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        write_deep_audit_export(
            {"entries": [], "completion": {}},
            output,
            "md-dir",
        )

    assert not (target / "index.md").exists()


def test_markdown_directory_rejects_symlinked_parent(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    parent = tmp_path / "linked-parent"
    parent.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="must not contain symlinks"):
        write_deep_audit_export(
            {"entries": [], "completion": {}},
            parent / "report",
            "md-dir",
        )

    assert not (target / "report").exists()
