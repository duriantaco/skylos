from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from skylos.audit.store import AuditStore
from skylos.audit.types import (
    STATUS_ANALYZED,
    STATUS_DELETED,
    STATUS_ERROR,
    STATUS_PENDING,
    STATUS_PROCESSING,
    AuditCandidate,
    sha256_file,
    stable_json_hash,
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


def test_audit_store_rejects_project_id_path_escape(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    with pytest.raises(ValueError, match="safe path segment"):
        AuditStore(repo, project_id="../outside")

    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    with pytest.raises(ValueError, match="run_id must be a safe path segment"):
        store.write_run("../../outside", {"mode": "test"})


def test_audit_store_rejects_symlinked_state_directory(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / ".skylos").symlink_to(outside, target_is_directory=True)

    store = AuditStore(repo)
    with pytest.raises(RuntimeError, match="contains a symlink"):
        store.init_project(config_hash="cfg")

    assert list(outside.iterdir()) == []


def test_audit_store_persists_scan_exclusion_scope(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = AuditStore(repo)

    store.init_project(
        config_hash="cfg",
        exclude_folders=["private", "generated/**"],
        exclude_paths=[repo / "sensitive.py", "artifacts"],
    )

    exclude_folders, exclude_paths = store.read_scan_excludes()
    assert exclude_folders == ("generated/**", "private")
    assert exclude_paths == ("artifacts", "sensitive.py")


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


def test_audit_store_file_hash_change_resets_status_but_preserves_history(
    tmp_path: Path,
):
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
    assert updated.findings == [{"rule_id": "OLD"}]
    assert updated.analysis_history == [{"stage": "old"}]


@pytest.mark.parametrize(
    "status",
    [STATUS_ANALYZED, STATUS_PROCESSING, STATUS_ERROR],
)
def test_audit_store_unchanged_empty_rescan_preserves_terminal_status(
    tmp_path: Path,
    status: str,
) -> None:
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
        candidates=[],
        config_hash="cfg",
    )
    record.status = status
    store.write_file_record(record)

    updated = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[],
        config_hash="cfg",
    )

    assert updated.status == status


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


def test_audit_store_rejects_symlinked_record_file(tmp_path: Path):
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
    record_path = store.record_path(source)
    outside_record = tmp_path / "outside-record.json"
    record_path.replace(outside_record)
    record_path.symlink_to(outside_record)

    assert store.read_file_record(source) is None


def test_audit_store_rejects_oversized_record_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
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
    monkeypatch.setattr("skylos.audit.store.MAX_AUDIT_RECORD_BYTES", 8)

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

    assert store.acquire_lock(source, run_id="run-one", now=utc_now()) is True
    assert (
        store.acquire_lock(source, run_id="run-two", stale_after_seconds=3600) is False
    )

    record = store.read_file_record(source)
    assert record is not None
    record.locked_at = "2000-01-01T00:00:00+00:00"
    store.write_file_record(record)

    assert (
        store.acquire_lock(source, run_id="run-two", stale_after_seconds=3600) is True
    )


def test_audit_store_serializes_concurrent_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('hello')\n", encoding="utf-8")
    first_store = AuditStore(repo)
    second_store = AuditStore(repo)
    first_store.init_project(config_hash="cfg")
    first_store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )

    first_write_started = threading.Event()
    release_first_write = threading.Event()
    second_started = threading.Event()
    results: dict[str, str | None] = {}
    errors: list[BaseException] = []
    original_write = first_store._write_json_atomic

    def blocking_write(path: Path, payload: dict) -> None:
        if (
            path == first_store.record_path(source)
            and payload.get("status") == STATUS_PROCESSING
        ):
            first_write_started.set()
            if not release_first_write.wait(timeout=2):
                raise TimeoutError("test did not release the first claim")
        original_write(path, payload)

    monkeypatch.setattr(first_store, "_write_json_atomic", blocking_write)

    def claim(name: str, store: AuditStore) -> None:
        try:
            if name == "second":
                second_started.set()
            results[name] = store.acquire_lock(source, run_id=f"run-{name}")
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first_thread = threading.Thread(target=claim, args=("first", first_store))
    second_thread = threading.Thread(target=claim, args=("second", second_store))
    first_thread.start()
    assert first_write_started.wait(timeout=2)
    second_thread.start()
    assert second_started.wait(timeout=2)
    try:
        time.sleep(0.05)
        assert "second" not in results
    finally:
        release_first_write.set()
        first_thread.join(timeout=2)
        second_thread.join(timeout=2)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert errors == []
    assert results["first"] is True
    assert results["second"] is False
    loaded = first_store.read_file_record(source)
    assert loaded is not None
    assert loaded.locked_by_run_id == "run-first"


def test_audit_store_fences_stale_commit_and_error_after_reclaim(tmp_path: Path):
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

    old_lease_id = store.acquire_lease(source, run_id="run-old")
    assert old_lease_id
    stale_worker_record = store.read_file_record(source)
    assert stale_worker_record is not None

    reclaimable = store.read_file_record(source)
    assert reclaimable is not None
    reclaimable.locked_at = "2000-01-01T00:00:00+00:00"
    store.write_file_record(reclaimable)
    new_lease_id = store.acquire_lease(
        source,
        run_id="run-new",
        stale_after_seconds=0,
    )
    assert new_lease_id

    stale_worker_record.status = STATUS_ANALYZED
    stale_worker_record.locked_by_run_id = None
    stale_worker_record.locked_at = None
    stale_worker_record.findings = [{"audit_finding_id": "stale-result"}]
    assert not store.commit_claimed_record(
        stale_worker_record,
        run_id="run-old",
        lease_id=old_lease_id,
    )
    assert not store.mark_error(
        source,
        "late failure",
        run_id="run-old",
        lease_id=old_lease_id,
    )

    current = store.read_file_record(source)
    assert current is not None
    assert current.status == STATUS_PROCESSING
    assert current.locked_by_run_id == "run-new"
    assert current.findings == []
    assert not any(
        item.get("message") == "late failure" for item in current.analysis_history
    )

    current.status = STATUS_ANALYZED
    current.locked_by_run_id = None
    current.lock_lease_id = None
    current.locked_at = None
    current.findings = [{"audit_finding_id": "winner-result"}]
    assert store.commit_claimed_record(
        current,
        run_id="run-new",
        lease_id=new_lease_id,
    )
    committed = store.read_file_record(source)
    assert committed is not None
    assert committed.findings == [{"audit_finding_id": "winner-result"}]


def test_audit_store_fences_reused_run_id_with_unique_lease_id(tmp_path: Path):
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

    first_lease_id = store.acquire_lease(source, run_id="reused-run")
    assert first_lease_id
    stale_record = store.read_file_record(source)
    assert stale_record is not None

    second_lease_id = store.acquire_lease(source, run_id="reused-run")
    assert second_lease_id
    assert second_lease_id != first_lease_id

    stale_record.status = STATUS_ANALYZED
    stale_record.locked_by_run_id = None
    stale_record.lock_lease_id = None
    stale_record.locked_at = None
    assert not store.commit_claimed_record(
        stale_record,
        run_id="reused-run",
        lease_id=first_lease_id,
    )

    current = store.read_file_record(source)
    assert current is not None
    assert current.status == STATUS_PROCESSING
    assert current.lock_lease_id == second_lease_id


def test_audit_store_fences_revalidation_append_after_rescan(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )
    finding = {"audit_finding_id": "finding-one", "severity": "high"}
    record.findings = [finding]
    store.write_file_record(record)
    old_source_hash = record.file_hash

    source.write_text("print('changed')\n", encoding="utf-8")
    rescanned = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[],
        config_hash="cfg",
    )

    assert not store.append_revalidation_entry(
        source,
        expected_source_hash=old_source_hash,
        expected_config_hash="cfg",
        expected_finding_hash=stable_json_hash(finding),
        entry={"finding_id": "finding-one", "verdict": "false_positive"},
    )
    current = store.read_file_record(source)
    assert current is not None
    assert current.file_hash == rescanned.file_hash
    assert current.revalidation == []


def test_audit_store_rejects_revalidation_while_record_is_processing(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("eval(user_input)\n", encoding="utf-8")
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    record = store.upsert_scan_record(
        file_path=source,
        file_hash=sha256_file(source),
        language="python",
        candidates=[_candidate()],
        config_hash="cfg",
    )
    finding = {"audit_finding_id": "finding-one", "severity": "high"}
    record.findings = [finding]
    store.write_file_record(record)
    assert store.acquire_lock(source, run_id="processor-run")

    assert not store.append_revalidation_entry(
        source,
        expected_source_hash=record.file_hash,
        expected_config_hash="cfg",
        expected_finding_hash=stable_json_hash(finding),
        entry={"finding_id": "finding-one", "verdict": "false_positive"},
    )
    current = store.read_file_record(source)
    assert current is not None
    assert current.status == STATUS_PROCESSING
    assert current.revalidation == []


def test_audit_store_can_atomically_claim_inactive_record(tmp_path: Path):
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
    store.write_file_record(record)

    assert not store.acquire_lock(source, run_id="normal-run")
    assert store.acquire_lock(source, run_id="forced-run", allow_inactive=True)
    claimed = store.read_file_record(source)
    assert claimed is not None
    assert claimed.status == STATUS_PROCESSING
    assert claimed.locked_by_run_id == "forced-run"


def test_audit_store_mutation_guard_times_out_without_removing_owner(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    lock_path = store.project_dir / ".mutation.lock"
    lock_path.mkdir()

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="audit mutation lock"):
        with store._mutation_guard(timeout_seconds=0.02):
            pass
    assert time.monotonic() - started < 1
    assert lock_path.is_dir()
    lock_path.rmdir()


def test_audit_store_mutation_guard_recovers_verified_stale_empty_lock(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    lock_path = store.project_dir / ".mutation.lock"
    lock_path.mkdir()
    stale = time.time() - 7200
    lock_path.touch()
    os.utime(lock_path, (stale, stale))

    with store._mutation_guard(timeout_seconds=0.1):
        assert lock_path.is_dir()

    assert not lock_path.exists()


def test_audit_store_mutation_guard_rejects_symlink(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = AuditStore(repo)
    store.init_project(config_hash="cfg")
    outside = tmp_path / "outside"
    outside.mkdir()
    lock_path = store.project_dir / ".mutation.lock"
    lock_path.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked audit mutation lock"):
        with store._mutation_guard(timeout_seconds=0):
            pass
    assert lock_path.is_symlink()
    assert outside.is_dir()


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


def test_audit_store_marks_deleted_records_without_losing_history(tmp_path: Path):
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
    record.findings = [{"audit_finding_id": "finding-one", "rule_id": "OLD"}]
    store.write_file_record(record)

    source.unlink()
    marked = store.mark_deleted_records()
    loaded = store.read_file_record("app.py")

    assert [item.file for item in marked] == ["app.py"]
    assert loaded is not None
    assert loaded.status == STATUS_DELETED
    assert loaded.findings == [{"audit_finding_id": "finding-one", "rule_id": "OLD"}]
    assert loaded.locked_by_run_id is None
    assert loaded.analysis_history[-1]["stage"] == "file_deleted"
