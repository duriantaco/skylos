from __future__ import annotations

from pathlib import Path

import pytest

from skylos.audit_store import AuditStore
from skylos.audit_types import (
    STATUS_ANALYZED,
    STATUS_PENDING,
    AuditCandidate,
    sha256_file,
    utc_now,
)


def _fake_github_token() -> str:
    return "ghp_" + "1234567890abcdef" + "1234567890abcdef" + "123456"


def _candidate(candidate_id: str = "cand-one") -> AuditCandidate:
    return AuditCandidate(
        candidate_id=candidate_id,
        kind="static_finding",
        rule_id="SKY-D999",
        line=1,
        severity_hint="high",
        reason="test candidate",
        priority=800,
        code_hash="abc123",
    )


def test_audit_store_writes_and_reads_file_record(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('hello')\n", encoding="utf-8")

    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )

    loaded = store.read_file_record("app.py")

    assert record.status == STATUS_PENDING
    assert loaded is not None
    assert loaded.file == "app.py"
    assert loaded.candidates[0].candidate_id == "cand-one"
    assert store.record_path("app.py").exists()


def test_audit_store_rerun_deduplicates_candidates(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('hello')\n", encoding="utf-8")

    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    for _ in range(2):
        store.upsert_scan_record(
            file_path=source,
            file_hash=sha256_file(source),
            language="python",
            candidates=[_candidate(), _candidate()],
            config_hash="cfg",
        )

    loaded = store.read_file_record("app.py")

    assert loaded is not None
    assert [candidate.candidate_id for candidate in loaded.candidates] == ["cand-one"]


def test_audit_store_file_hash_change_invalidates_prior_findings(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('hello')\n", encoding="utf-8")

    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )
    record.status = STATUS_ANALYZED
    record.findings = [{"rule_id": "OLD"}]
    record.analysis_history = [{"stage": "old"}]
    store.write_file_record(record)

    source.write_text("print('changed')\n", encoding="utf-8")
    updated = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )

    assert updated.status == STATUS_PENDING
    assert updated.findings == []
    assert updated.analysis_history == []


def test_audit_store_rejects_corrupted_json(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('hello')\n", encoding="utf-8")

    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    path = store.record_path(source)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")

    assert store.read_file_record(source) is None


def test_audit_store_root_confines_paths(tmp_path: Path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside.py"
    repo.mkdir()
    outside.write_text("print('no')\n", encoding="utf-8")

    store = AuditStore(repo)

    with pytest.raises(ValueError):
        store.record_path(outside)


def test_audit_store_recovers_stale_lock(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('hello')\n", encoding="utf-8")

    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )

    assert store.acquire_lock(source, run_id="run-one", now=utc_now())
    assert not store.acquire_lock(source, run_id="run-two", stale_after_seconds=3600)

    record = store.read_file_record(source)
    assert record is not None
    record.locked_at = "2000-01-01T00:00:00+00:00"
    store.write_file_record(record)

    assert store.acquire_lock(source, run_id="run-two", stale_after_seconds=3600)


def test_audit_store_sanitizes_preserved_history_and_errors(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    raw_secret = _fake_github_token()
    source.write_text("print('hello')\n", encoding="utf-8")

    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )
    record.status = STATUS_ANALYZED
    record.analysis_history = [{"prompt": raw_secret}]
    record.findings = [{"message": raw_secret}]
    record.revalidation = [{"reason": raw_secret}]
    store.write_file_record(record)

    updated = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )
    stored = store.record_path(source).read_text(encoding="utf-8")

    assert updated.status == STATUS_ANALYZED
    assert raw_secret not in stored
    assert "[REDACTED_SECRET]" in stored

    store.mark_error(source, f"failed with {raw_secret}")
    stored = store.record_path(source).read_text(encoding="utf-8")

    assert raw_secret not in stored
