from __future__ import annotations

import json
from pathlib import Path

from skylos import audit_candidates
from skylos.audit_store import AuditStore
from skylos.audit_types import AuditFileRecord, sha256_file


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
