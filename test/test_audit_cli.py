from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import skylos.cli as cli
from skylos.audit_types import AuditProcessSummary, AuditScanSummary


def test_agent_audit_deep_scan_only_runs_without_llm_support(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "audit.json"

    called = {}

    def fake_scan(path, *, changed_files=None):
        called["path"] = Path(path)
        called["changed_files"] = changed_files
        return (
            AuditScanSummary(
                project_id="default",
                project_root=str(repo),
                files_scanned=1,
                records_written=1,
                candidate_count=1,
                redacted_candidates=0,
                pending_files=1,
                not_analyzed_files=0,
            ),
            SimpleNamespace(
                project_dir=repo / ".skylos" / "audit" / "projects" / "default"
            ),
        )

    monkeypatch.setattr(
        "skylos.audit_candidates.scan_deep_audit_candidates",
        fake_scan,
    )

    def fail_if_llm_checked():
        raise AssertionError("LLM support should not be checked")

    monkeypatch.setattr(cli, "_ensure_llm_support", fail_if_llm_checked)
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            "agent",
            "audit",
            str(repo),
            "--deep",
            "--scan-only",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    assert called["path"] == repo
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["mode"] == "deep_scan_only"
    assert payload["summary"]["candidate_count"] == 1


def test_agent_audit_requires_explicit_deep_flag(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "agent", "audit", str(repo)])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_agent_audit_scan_only_rejects_unimplemented_ci_flags(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            "agent",
            "audit",
            str(repo),
            "--deep",
            "--scan-only",
            "--fail-on",
            "high",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_agent_audit_scan_only_rejects_unimplemented_processing_flags(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            "agent",
            "audit",
            str(repo),
            "--deep",
            "--scan-only",
            "--resume",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_agent_audit_scan_only_rejects_force_until_processing_exists(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            "agent",
            "audit",
            str(repo),
            "--deep",
            "--scan-only",
            "--force",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_agent_audit_processing_rejects_changed_until_ci_phase(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            "agent",
            "audit",
            str(repo),
            "--deep",
            "--changed",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_agent_audit_deep_processing_runs_after_scan(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "audit.json"
    store = SimpleNamespace(
        project_dir=repo / ".skylos" / "audit" / "projects" / "default"
    )
    calls = {}

    def fake_scan(path, *, changed_files=None):
        calls["scan_path"] = Path(path)
        return (
            AuditScanSummary(
                project_id="default",
                project_root=str(repo),
                files_scanned=1,
                records_written=1,
                candidate_count=1,
                redacted_candidates=0,
                pending_files=1,
                not_analyzed_files=0,
                complete=False,
            ),
            store,
        )

    def fake_process(**kwargs):
        calls["process"] = kwargs
        return AuditProcessSummary(
            run_id="process-one",
            project_id="default",
            project_root=str(repo),
            considered_files=1,
            processed_files=1,
            findings_added=1,
            skipped_secret_files=0,
            unsupported_files=0,
            locked_files=0,
            error_files=0,
            remaining_pending_files=0,
            limited=False,
            complete=True,
        )

    class FakeLLM:
        def __init__(self, config):
            self.config = config

    monkeypatch.setattr(
        "skylos.audit_candidates.scan_deep_audit_candidates",
        fake_scan,
    )
    monkeypatch.setattr(
        "skylos.audit_processor.process_deep_audit_records",
        fake_process,
    )
    monkeypatch.setattr(cli, "_ensure_llm_support", lambda: True)
    monkeypatch.setattr(cli, "_build_analyzer_config", lambda **kwargs: kwargs)
    monkeypatch.setattr(cli, "SkylosLLM", FakeLLM)
    monkeypatch.setattr(
        cli,
        "resolve_llm_runtime",
        lambda **kwargs: ("ollama", None, None, True),
    )
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            "agent",
            "audit",
            str(repo),
            "--deep",
            "--limit",
            "3",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["mode"] == "deep_process"
    assert payload["processing"]["processed_files"] == 1
    assert calls["process"]["limit"] == 3
    assert calls["process"]["force"] is False
