from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.audit import candidates as audit_candidates
from skylos.audit.store import AuditStore
from skylos.audit.types import (
    CANDIDATE_ENGINE_VERSION,
    MAX_AUDIT_SOURCE_BYTES,
    AuditCandidate,
    AuditFileRecord,
    sha256_file,
    sha256_text,
)


def _fake_github_token() -> str:
    return "ghp_" + "1234567890abcdef" + "1234567890abcdef" + "123456"


def _fake_stripe_token() -> str:
    return "sk_" + "live_" + "1234567890abcdef" + "1234567890abcdef"


def test_scan_deep_audit_candidates_redacts_secret_payloads(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    env_file = repo / ".env"
    raw_secret = _fake_github_token()
    env_file.write_text(f'GITHUB_TOKEN="{raw_secret}"\n', encoding="utf-8")

    def fake_static(files, **kwargs):
        return {
            "danger": [],
            "secrets": [
                {
                    "rule_id": "SKY-S101",
                    "severity": "CRITICAL",
                    "provider": "github",
                    "message": "Potential github secret detected",
                    "file": str(env_file),
                    "line": 1,
                    "value": raw_secret,
                    "preview": "ghp_...3456",
                }
            ],
        }

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(env_file)
    stored = store.record_path(env_file).read_text(encoding="utf-8")

    assert summary.candidate_count == 1
    assert summary.redacted_candidates == 1
    assert record is not None
    assert record.language == "env"
    secret_candidates = [
        candidate for candidate in record.candidates if candidate.rule_id == "SKY-S101"
    ]
    assert len(secret_candidates) == 1
    assert secret_candidates[0].redacted is True
    assert secret_candidates[0].signal_quality == "strong"
    assert summary.coverage["metric"] == "candidate_observation_coverage"
    assert summary.coverage["scope"] == "repository"
    assert summary.coverage["by_language"]["env"]["candidate_count"] == 1
    assert summary.coverage["by_signal_quality"]["strong"] == 1
    assert summary.coverage["by_rule"]["SKY-S101"]["candidate_count"] == 1
    assert raw_secret not in stored


def test_scan_deep_audit_candidates_detects_real_env_secret(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    raw_secret = _fake_github_token()
    env_file = repo / ".env"
    env_file.write_text(f'GITHUB_TOKEN="{raw_secret}"\n', encoding="utf-8")

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(env_file)
    stored = store.record_path(env_file).read_text(encoding="utf-8")

    assert summary.files_scanned == 1
    assert summary.candidate_count >= 1
    assert summary.complete is False
    assert record is not None
    assert record.status == "pending"
    assert any(candidate.rule_id == "SKY-S101" for candidate in record.candidates)
    assert raw_secret not in stored


def test_scan_deep_audit_candidates_detects_env_variant_secret(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env_file = repo / ".env.production"
    env_file.write_text(
        f'API_KEY="{_fake_stripe_token()}"\n',
        encoding="utf-8",
    )

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(env_file)

    assert summary.files_scanned == 1
    assert record is not None
    assert record.language == "env"
    assert any(candidate.rule_id == "SKY-S101" for candidate in record.candidates)


def test_scan_deep_audit_candidates_skips_symlinked_audit_files(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    py_secret = outside / "py_secret"
    env_secret = outside / "env_secret"
    py_secret.write_text("PY_OUTSIDE\n", encoding="utf-8")
    env_secret.write_text("AWS_SECRET_ACCESS_KEY=ENV_OUTSIDE\n", encoding="utf-8")
    try:
        (repo / "leak.py").symlink_to(py_secret)
        (repo / ".env").symlink_to(env_secret)
    except OSError:
        pytest.skip("symlinks are not supported on this filesystem")

    seen = {}

    def fake_static(files, **kwargs):
        seen["files"] = list(files)
        return {"danger": [], "secrets": []}

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)

    assert summary.files_scanned == 0
    assert summary.rejected_source_files == 0
    assert summary.coverage["rejected_source_files"] == 0
    assert summary.complete is True
    assert summary.coverage["scope"] == "repository"
    assert seen["files"] == []
    assert store.iter_file_records() == []


def test_scan_deep_audit_candidates_changed_files_skip_symlinked_audit_files(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    env_secret = outside / "env_secret"
    env_secret.write_text(
        "AWS_SECRET_ACCESS_KEY=ENV_CHANGED_OUTSIDE\n", encoding="utf-8"
    )
    link = repo / ".env"
    try:
        link.symlink_to(env_secret)
    except OSError:
        pytest.skip("symlinks are not supported on this filesystem")

    seen = {}

    def fake_static(files, **kwargs):
        seen["files"] = list(files)
        return {"danger": [], "secrets": []}

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, store = audit_candidates.scan_deep_audit_candidates(
        repo,
        changed_files=[link],
    )

    assert summary.files_scanned == 0
    assert summary.rejected_source_files == 1
    assert summary.coverage["rejected_source_files"] == 1
    assert summary.complete is False
    assert summary.coverage["scope"] == "changed_files"
    assert seen["files"] == []
    assert store.iter_file_records() == []


def test_scan_deep_audit_candidates_rejects_symlinked_parent_component(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    real = repo / "real"
    real.mkdir()
    target = real / "app.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    linked_parent = repo / "linked"
    linked_file = repo / "linked-app.py"
    linked_parent.symlink_to(real, target_is_directory=True)
    linked_file.symlink_to(target)
    seen = {}

    def fake_static(files, **kwargs):
        seen["files"] = list(files)
        return {"danger": [], "secrets": []}

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, store = audit_candidates.scan_deep_audit_candidates(
        repo,
        changed_files=[linked_parent / "app.py"],
    )

    assert summary.files_scanned == 0
    assert summary.rejected_source_files == 1
    assert summary.complete is False
    assert seen["files"] == []
    assert store.iter_file_records() == []
    with pytest.raises(OSError, match="Unable to safely hash"):
        sha256_file(linked_parent / "app.py", project_root=repo)
    with pytest.raises(OSError, match="Unable to safely hash"):
        sha256_file(linked_file)


def test_scan_deep_audit_candidates_reports_oversized_and_nonregular_sources(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    oversized = repo / "oversized.py"
    oversized.write_bytes(b"#" * (MAX_AUDIT_SOURCE_BYTES + 1))
    nonregular = repo / "directory.py"
    nonregular.mkdir()
    seen = {}

    def fake_static(files, **kwargs):
        seen["files"] = list(files)
        return {"danger": [], "secrets": []}

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, store = audit_candidates.scan_deep_audit_candidates(
        repo,
        changed_files=[oversized, nonregular],
    )

    assert summary.files_scanned == 0
    assert summary.rejected_source_files == 2
    assert summary.coverage["rejected_source_files"] == 2
    assert summary.complete is False
    assert seen["files"] == []
    assert store.iter_file_records() == []
    with pytest.raises(OSError, match="Unable to safely hash"):
        sha256_file(oversized)
    with pytest.raises(OSError, match="Unable to safely hash"):
        sha256_file(nonregular)


def test_changed_deleted_source_is_not_reported_as_rejected(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    deleted = repo / "deleted.py"
    seen = {}

    def fake_static(files, **kwargs):
        seen["files"] = list(files)
        return {"danger": [], "secrets": []}

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, store = audit_candidates.scan_deep_audit_candidates(
        repo,
        changed_files=[deleted],
    )

    assert summary.files_scanned == 0
    assert summary.rejected_source_files == 0
    assert summary.complete is True
    assert seen["files"] == []
    assert store.iter_file_records() == []


def test_sha256_file_accepts_source_at_the_audit_size_limit(tmp_path: Path) -> None:
    source = "#" * MAX_AUDIT_SOURCE_BYTES
    path = tmp_path / "bounded.py"
    path.write_text(source, encoding="utf-8")

    assert sha256_file(path) == sha256_text(source)


def test_repository_scan_reports_oversized_regular_source(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    oversized = repo / "oversized.py"
    oversized.write_bytes(b"#" * (MAX_AUDIT_SOURCE_BYTES + 1))
    seen = {}

    def fake_static(files, **kwargs):
        seen["files"] = list(files)
        return {"danger": [], "secrets": []}

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)

    assert summary.files_scanned == 0
    assert summary.rejected_source_files == 1
    assert summary.coverage["rejected_source_files"] == 1
    assert summary.complete is False
    assert seen["files"] == []
    assert store.iter_file_records() == []


def test_polyglot_candidate_read_rejects_symlinked_parent_component(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    real = repo / "real"
    real.mkdir()
    target = real / "route.ts"
    target.write_text("eval(userInput);\n", encoding="utf-8")
    linked_parent = repo / "linked"
    linked_parent.symlink_to(real, target_is_directory=True)

    assert (
        audit_candidates.build_polyglot_signal_candidates(
            linked_parent / "route.ts",
            project_root=repo,
        )
        == []
    )


def test_scan_deep_audit_candidates_is_stable_across_reruns(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")

    def fake_static(files, **kwargs):
        return {
            "danger": [
                {
                    "rule_id": "SKY-D201",
                    "severity": "CRITICAL",
                    "message": "Use of eval() detected",
                    "file": str(app),
                    "line": 1,
                }
            ],
            "secrets": [],
        }

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    audit_candidates.scan_deep_audit_candidates(repo)
    summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(app)

    assert summary.records_written == 1
    assert record is not None
    ids = [candidate.candidate_id for candidate in record.candidates]
    assert len(ids) == len(set(ids))


def test_scan_requeues_records_from_the_v1_candidate_engine(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")

    def fake_static(files, **kwargs):
        return {
            "danger": [
                {
                    "rule_id": "SKY-D201",
                    "severity": "HIGH",
                    "message": "Use of eval() detected",
                    "file": str(app),
                    "line": 1,
                }
            ],
            "secrets": [],
        }

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)
    _summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    stale = store.read_file_record(app)
    assert stale is not None
    stale.status = "analyzed"
    stale.candidate_engine_version = "deep-audit-v1"
    store.write_file_record(stale)

    _summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    refreshed = store.read_file_record(app)

    assert CANDIDATE_ENGINE_VERSION == "deep-audit-v2"
    assert refreshed is not None
    assert refreshed.status == "pending"
    assert refreshed.candidate_engine_version == CANDIDATE_ENGINE_VERSION


def test_scan_deep_audit_candidates_records_static_threat_trace_candidate(
    tmp_path: Path, monkeypatch
):
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

    monkeypatch.setattr(
        audit_candidates,
        "run_static_on_files",
        lambda files, **kwargs: {"danger": [], "secrets": []},
    )

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(app)

    assert summary.candidate_count >= 1
    assert record is not None
    trace_candidates = [
        candidate
        for candidate in record.candidates
        if candidate.kind == "threat_trace" and candidate.rule_id == "SKY-AUDIT-TRACE"
    ]
    assert len(trace_candidates) == 1
    candidate = trace_candidates[0]
    assert candidate.line == 7
    assert candidate.source_kind == "request.args.get"
    assert candidate.sink_kind == "requests.get"
    assert candidate.evidence == "static_unvalidated"
    assert candidate.signal_quality == "strong"
    assert candidate.data["threat_trace"]["validation"] == "static_unvalidated"


def test_scan_deep_audit_candidates_records_non_candidate_files(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "plain.py"
    app.write_text("print('clean')\n", encoding="utf-8")

    monkeypatch.setattr(
        audit_candidates,
        "run_static_on_files",
        lambda files, **kwargs: {"danger": [], "secrets": []},
    )

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(app)
    payload = json.loads(store.record_path(app).read_text(encoding="utf-8"))

    assert summary.files_scanned == 1
    assert record is not None
    assert record.status == "not_analyzed"
    assert payload["candidates"] == []
    assert store.current_scan_files == {"plain.py"}


def test_scan_deep_audit_candidates_marks_deleted_records(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "deleted.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")

    monkeypatch.setattr(
        audit_candidates,
        "run_static_on_files",
        lambda files, **kwargs: {"danger": [], "secrets": []},
    )

    _summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    app.unlink()

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record("deleted.py")

    assert summary.deleted_files == 1
    assert summary.files_scanned == 0
    assert record is not None
    assert record.status == "deleted"


def test_scan_deep_audit_candidates_changed_files_respect_excludes(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    audit_file = (
        repo / ".skylos" / "audit" / "projects" / "default" / "files" / "x.json"
    )
    audit_file.parent.mkdir(parents=True)
    audit_file.write_text(
        f'{{"api_key":"{_fake_stripe_token()}"}}\n',
        encoding="utf-8",
    )
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")

    seen = {}

    def fake_static(files, **kwargs):
        seen["files"] = [Path(file_path).name for file_path in files]
        return {"danger": [], "secrets": []}

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, _store = audit_candidates.scan_deep_audit_candidates(
        repo,
        changed_files=[audit_file, app],
    )

    assert summary.files_scanned == 1
    assert seen["files"] == ["app.py"]


def test_scan_deep_audit_candidates_excludes_active_output_path(
    tmp_path: Path,
    monkeypatch,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("print('ok')\n", encoding="utf-8")
    out = repo / "audit.json"
    out.write_text('{"previous": true}\n', encoding="utf-8")
    seen = {}

    def fake_static(files, **kwargs):
        seen["files"] = sorted(Path(file_path).name for file_path in files)
        return {"danger": [], "secrets": []}

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    summary, store = audit_candidates.scan_deep_audit_candidates(
        repo,
        exclude_paths=[out],
    )

    assert summary.files_scanned == 1
    assert seen["files"] == ["app.py"]
    assert store.read_file_record(app) is not None
    assert store.read_file_record(out) is None


def test_audit_store_rejects_record_with_mismatched_internal_file(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    other = repo / "other.py"
    app.write_text("print('app')\n", encoding="utf-8")
    other.write_text("print('other')\n", encoding="utf-8")

    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = AuditFileRecord(
        project_id="default",
        project_root=str(repo.resolve()),
        file="other.py",
        file_hash=sha256_file(other),
        language="python",
        status="pending",
        config_hash="cfg",
    )
    store.record_path(app).write_text(
        json.dumps(record.to_dict()),
        encoding="utf-8",
    )

    assert store.read_file_record(app) is None


def test_scan_deep_audit_candidates_reports_processing_records_incomplete(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")

    def fake_static(files, **kwargs):
        return {
            "danger": [
                {
                    "rule_id": "SKY-D201",
                    "severity": "CRITICAL",
                    "message": "Use of eval() detected",
                    "file": str(app),
                    "line": 1,
                }
            ],
            "secrets": [],
        }

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    _summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(app)
    assert record is not None
    record.status = "processing"
    store.write_file_record(record)

    summary, _store = audit_candidates.scan_deep_audit_candidates(repo)

    assert summary.processing_files == 1
    assert summary.complete is False


def test_scan_deep_audit_candidates_reports_error_records_incomplete(
    tmp_path: Path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("eval(user_input)\n", encoding="utf-8")

    def fake_static(files, **kwargs):
        return {
            "danger": [
                {
                    "rule_id": "SKY-D201",
                    "severity": "CRITICAL",
                    "message": "Use of eval() detected",
                    "file": str(app),
                    "line": 1,
                }
            ],
            "secrets": [],
        }

    monkeypatch.setattr(audit_candidates, "run_static_on_files", fake_static)

    _summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(app)
    assert record is not None
    record.status = "error"
    store.write_file_record(record)

    summary, _store = audit_candidates.scan_deep_audit_candidates(repo)

    assert summary.error_files == 1
    assert summary.complete is False


@pytest.mark.parametrize(
    ("filename", "source", "language", "rule_id"),
    [
        (
            "route.ts",
            "import cp from 'child_process';\ncp.exec(userInput);\n",
            "typescript",
            "SKY-D212",
        ),
        (
            "handler.js",
            "export function get(req) { return fetch(req.query.url); }\n",
            "javascript",
            "SKY-D216",
        ),
        (
            "main.go",
            "package main\n"
            'import "os/exec"\n'
            "func run(name string) { exec.Command(name) }\n",
            "go",
            "SKY-D212",
        ),
        (
            "Controller.java",
            "class Controller {\n"
            "  void run(String cmd) throws Exception {\n"
            "    Runtime.getRuntime().exec(cmd);\n"
            "  }\n"
            "}\n",
            "java",
            "SKY-D212",
        ),
        (
            "index.php",
            "<?php system($_GET['cmd']); ?>\n",
            "php",
            "SKY-D212",
        ),
        (
            "main.rs",
            "use std::process::Command;\n"
            "fn run(cmd: &str) { Command::new(cmd).spawn(); }\n",
            "rust",
            "SKY-D212",
        ),
        (
            "main.dart",
            "import 'dart:io';\nvoid run(String cmd) { Process.run(cmd, []); }\n",
            "dart",
            "SKY-D212",
        ),
    ],
)
def test_scan_deep_audit_candidates_ingests_polyglot_static_signals(
    tmp_path: Path,
    monkeypatch,
    filename: str,
    source: str,
    language: str,
    rule_id: str,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / filename
    target.write_text(  # skylos: ignore[SKY-D215,SKY-D324] pytest tmp_path fixture
        source,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        audit_candidates,
        "run_static_on_files",
        lambda files, **kwargs: {"danger": [], "secrets": []},
    )

    summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    record = store.read_file_record(target)

    assert summary.candidate_count >= 1
    assert record is not None
    assert record.language == language
    assert record.status == "pending"
    assert any(
        candidate.kind == "polyglot_static_signal"
        and candidate.rule_id == rule_id
        and candidate.signal_quality == "exploratory"
        for candidate in record.candidates
    )

    first_ids = [candidate.candidate_id for candidate in record.candidates]
    _summary, store = audit_candidates.scan_deep_audit_candidates(repo)
    rerun = store.read_file_record(target)

    assert rerun is not None
    assert [candidate.candidate_id for candidate in rerun.candidates] == first_ids


def test_candidate_quality_is_conservative_and_sorts_independently_from_severity():
    exploratory_critical = AuditCandidate(
        candidate_id="exploratory-critical",
        kind="path_signal",
        rule_id="SKY-AUDIT-PATH",
        line=1,
        severity_hint="critical",
        reason="path-only hypothesis",
        signal_quality="unrecognized-model-claim",
        priority=1000,
    )
    proven_low = AuditCandidate(
        candidate_id="proven-low",
        kind="threat_trace",
        rule_id="SKY-AUDIT-TRACE",
        line=2,
        severity_hint="low",
        reason="exact static source-to-sink trace",
        signal_quality="proven",
        priority=200,
    )

    ordered = sorted(
        [exploratory_critical, proven_low],
        key=audit_candidates._candidate_sort_key,
    )
    restored = AuditCandidate.from_dict(exploratory_critical.to_dict())

    assert exploratory_critical.signal_quality == "exploratory"
    assert [candidate.candidate_id for candidate in ordered] == [
        "proven-low",
        "exploratory-critical",
    ]
    assert restored.signal_quality == "exploratory"


def test_candidate_signal_quality_preserves_v1_positional_construction() -> None:
    candidate = AuditCandidate(
        "candidate-positional",
        "static_finding",
        "SKY-D999",
        4,
        "high",
        "legacy positional candidate",
        "static",
        True,
        777,
        "handler",
        "request",
        "sink",
        "code-hash",
        {"legacy": True},
    )

    assert candidate.redacted is True
    assert candidate.priority == 777
    assert candidate.symbol == "handler"
    assert candidate.data == {"legacy": True}
    assert candidate.signal_quality == "exploratory"


def test_audit_file_record_preserves_v1_positional_construction() -> None:
    record = AuditFileRecord(
        "default",
        "/repo",
        "app.py",
        "f" * 64,
        "python",
        "processing",
        [],
        [],
        [{"stage": "legacy"}],
        [],
        "run-v1",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:01:00+00:00",
        "2026-01-01T00:02:00+00:00",
        "1.0.0",
        "config-v1",
        "deep-audit-v1",
        1,
    )

    assert record.locked_by_run_id == "run-v1"
    assert record.locked_at == "2026-01-01T00:00:00+00:00"
    assert record.last_scanned_at == "2026-01-01T00:01:00+00:00"
    assert record.last_analyzed_at == "2026-01-01T00:02:00+00:00"
    assert record.skylos_version == "1.0.0"
    assert record.config_hash == "config-v1"
    assert record.candidate_engine_version == "deep-audit-v1"
    assert record.schema_version == 1
    assert record.lock_lease_id is None
    assert record.to_dict()["lock_lease_id"] is None


def test_store_preserves_quality_first_candidate_order(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    app = repo / "app.py"
    app.write_text("print('ok')\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    exploratory = AuditCandidate(
        candidate_id="exploratory-critical",
        kind="path_signal",
        rule_id="SKY-AUDIT-PATH",
        line=1,
        severity_hint="critical",
        reason="path-only hypothesis",
        signal_quality="exploratory",
        priority=1000,
    )
    strong = AuditCandidate(
        candidate_id="strong-low",
        kind="static_finding",
        rule_id="SKY-D999",
        line=1,
        severity_hint="low",
        reason="validated analyzer signal",
        signal_quality="strong",
        priority=200,
    )

    record = store.upsert_scan_record(
        file_path=app,
        file_hash=sha256_file(app),
        language="python",
        candidates=[exploratory, strong],
        config_hash="cfg",
    )
    restored = store.read_file_record(app)

    assert [item.candidate_id for item in record.candidates] == [
        "strong-low",
        "exploratory-critical",
    ]
    assert restored is not None
    assert [item.candidate_id for item in restored.candidates] == [
        "strong-low",
        "exploratory-critical",
    ]
