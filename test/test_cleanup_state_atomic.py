"""History publication keeps the last complete state on interrupted writes."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from skylos.cleanup_state import STATE_PATH, load_cleanup_state, update_cleanup_state


def _plan(task_id="first"):
    return {
        "status": "ready",
        "tasks": [
            {
                "id": task_id,
                "rule_id": "SKY-U002",
                "file": "app.py",
                "name": "math",
                "source_sha256": "source",
            }
        ],
        "advisories": [],
    }


def test_task_and_scope_paths_cannot_redirect_the_history_root(tmp_path):
    selected = tmp_path / "selected"
    selected.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    plan = _plan()
    plan["tasks"][0]["file"] = "../outside/app.py"
    update_cleanup_state(
        selected, {"target": str(outside), "project_root": str(outside)}, plan
    )
    assert (selected / STATE_PATH).is_file()
    assert not (outside / ".skylos").exists()


def test_regular_file_cannot_be_a_history_root(tmp_path):
    selected = tmp_path / "selected.py"
    selected.write_text("value = 1\n")
    with pytest.raises(ValueError, match="directory"):
        update_cleanup_state(selected, {"target": str(selected)}, _plan())
    assert selected.read_text() == "value = 1\n"


def test_real_interrupted_write_preserves_last_complete_history(tmp_path):
    pytest.importorskip("resource")
    script = """
import resource
import signal
import sys
from pathlib import Path
from skylos.cleanup_state import STATE_PATH, update_cleanup_state
root = Path(sys.argv[1])
scope = {"target": str(root)}
plan = {"status": "ready", "tasks": [{"id": "first", "rule_id": "SKY-U002", "file": "app.py"}], "advisories": []}
update_cleanup_state(root, scope, plan)
original = (root / STATE_PATH).read_bytes()
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (128, 128))
try:
    update_cleanup_state(root, scope, plan, disposition={"id": "first", "status": "deferred", "reason": "x" * 10000})
except (ValueError, OSError):
    pass
else:
    raise AssertionError("the file-size limit must interrupt publication")
assert (root / STATE_PATH).read_bytes() == original, "last complete cleanup history was overwritten"
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert load_cleanup_state(tmp_path)["version"] == 1


def _initial(root):
    scope = {"target": str(root)}
    update_cleanup_state(root, scope, _plan())
    path = root / STATE_PATH
    return scope, path, path.read_bytes()


def _assert_tidy(path):
    assert not list(path.parent.glob(".cleanup.*.tmp"))
    assert not (path.parent / "cleanup.lock").exists()


def test_partial_enospc_write_does_not_truncate_existing_state(tmp_path, monkeypatch):
    import errno
    import skylos.cleanup_state as state

    scope, path, original = _initial(tmp_path)
    real_write = state.os.write

    def interrupted(descriptor, content):
        real_write(descriptor, content[:32])
        raise OSError(errno.ENOSPC, "simulated disk full")

    monkeypatch.setattr(state.os, "write", interrupted)
    with pytest.raises(ValueError, match="atomically published"):
        update_cleanup_state(tmp_path, scope, _plan("second"))
    assert path.read_bytes() == original
    assert load_cleanup_state(tmp_path)["version"] == 1
    _assert_tidy(path)


@pytest.mark.parametrize("operation", ["fsync", "replace"])
def test_prepublication_failure_preserves_previous_history(
    tmp_path, monkeypatch, operation
):
    import skylos.cleanup_state as state

    scope, path, original = _initial(tmp_path)

    def interrupted(*args, **kwargs):
        raise OSError("simulated publication interruption")

    monkeypatch.setattr(state.os, operation, interrupted)
    with pytest.raises(ValueError, match="atomically published"):
        update_cleanup_state(tmp_path, scope, _plan("second"))
    assert path.read_bytes() == original
    _assert_tidy(path)


def test_intervening_writer_is_not_overwritten(tmp_path, monkeypatch):
    import skylos.cleanup_state as state

    scope, path, _original = _initial(tmp_path)
    replacement = b'{"version":1,"scopes":{"other_writer":{"tasks":{}}}}\n'
    real_sync = state.os.fsync

    def another_writer(descriptor):
        real_sync(descriptor)
        path.write_bytes(replacement)

    monkeypatch.setattr(state.os, "fsync", another_writer)
    with pytest.raises(ValueError, match="changed during"):
        update_cleanup_state(tmp_path, scope, _plan("second"))
    assert path.read_bytes() == replacement
    assert "other_writer" in load_cleanup_state(tmp_path)["scopes"]
    _assert_tidy(path)


def test_directory_replacement_preserves_both_user_histories(tmp_path, monkeypatch):
    import skylos.cleanup_state as state

    scope, path, original = _initial(tmp_path)
    old_directory = tmp_path / ".skylos" / "previous-cache"
    replacement = b'{"version":1,"scopes":{"other_writer":{"tasks":{}}}}\n'
    real_sync = state.os.fsync

    def another_directory(descriptor):
        real_sync(descriptor)
        path.parent.rename(old_directory)
        path.parent.mkdir()
        path.write_bytes(replacement)

    monkeypatch.setattr(state.os, "fsync", another_directory)
    with pytest.raises(ValueError, match="directory changed"):
        update_cleanup_state(tmp_path, scope, _plan("second"))
    assert path.read_bytes() == replacement
    assert (old_directory / "cleanup.json").read_bytes() == original
    _assert_tidy(path)
    assert not list(old_directory.glob(".cleanup.*.tmp"))
    assert not (old_directory / "cleanup.lock").exists()


@pytest.mark.parametrize("component", [".skylos", ".skylos/cache"])
def test_symlinked_history_ancestor_is_never_followed(tmp_path, component):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / component
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        update_cleanup_state(root, {"target": str(root)}, _plan())
    with pytest.raises((ValueError, OSError)):
        load_cleanup_state(root)
    assert list(outside.iterdir()) == []


def test_symlink_final_history_and_lock_are_never_followed(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    scope, path, original = _initial(root)
    outside = tmp_path / "outside.json"
    outside.write_bytes(original)
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises((ValueError, OSError)):
        update_cleanup_state(root, scope, _plan("second"))
    assert outside.read_bytes() == original
    path.unlink()
    path.write_bytes(original)
    lock = path.parent / "cleanup.lock"
    lock.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe"):
        update_cleanup_state(root, scope, _plan("second"))
    assert path.read_bytes() == original
    assert lock.is_symlink()


def test_hardlinked_history_is_refused_without_read_or_replacement(tmp_path):
    scope, path, original = _initial(tmp_path)
    outside = tmp_path / "linked-history.json"
    outside.hardlink_to(path)
    with pytest.raises(ValueError, match="unsafe"):
        load_cleanup_state(tmp_path)
    with pytest.raises(ValueError, match="unsafe"):
        update_cleanup_state(tmp_path, scope, _plan("second"))
    assert path.read_bytes() == outside.read_bytes() == original
    _assert_tidy(path)


def test_cooperating_concurrent_updates_preserve_both_task_records(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    scope = {"target": str(tmp_path)}
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [
            workers.submit(update_cleanup_state, tmp_path, scope, _plan(name))
            for name in ("first", "second")
        ]
        for future in futures:
            future.result(timeout=10)
    history = load_cleanup_state(tmp_path)
    bucket = next(iter(history["scopes"].values()))
    assert set(bucket["tasks"]) == {"first", "second"}
    _assert_tidy(tmp_path / STATE_PATH)


def test_malformed_state_and_storage_limit_remain_unchanged(tmp_path):
    scope, path, original = _initial(tmp_path)
    path.write_text("{")
    with pytest.raises(ValueError, match="malformed"):
        update_cleanup_state(tmp_path, scope, _plan())
    assert path.read_text() == "{"
    path.write_bytes(original)
    with pytest.raises(ValueError, match="storage limit"):
        update_cleanup_state(
            tmp_path,
            scope,
            _plan(),
            disposition={
                "id": "first",
                "status": "deferred",
                "reason": "x" * 8_000_001,
            },
        )
    assert path.read_bytes() == original
    assert json.loads(original)["version"] == 1
    _assert_tidy(path)


def test_expired_empty_directory_lock_can_be_recovered(tmp_path):
    import os
    import time
    import skylos.cleanup_state as state

    scope, path, _original = _initial(tmp_path)
    lock = path.parent / "cleanup.lock"
    lock.mkdir()
    timestamp = time.time() - state.PROJECT_CACHE_LOCK_STALE_SECONDS - 1
    os.utime(lock, (timestamp, timestamp))
    update_cleanup_state(tmp_path, scope, _plan("second"))
    assert load_cleanup_state(tmp_path)["version"] == 1
    _assert_tidy(path)


def test_root_symlink_is_refused_before_history_directories_are_created(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe"):
        update_cleanup_state(alias, {"target": str(alias)}, _plan())
    assert list(root.iterdir()) == []


def test_lock_released_during_contention_is_retried(tmp_path, monkeypatch):
    import skylos.cleanup_state as state

    scope, path, _original = _initial(tmp_path)
    lock = path.parent / "cleanup.lock"
    lock.mkdir()
    real_stat = state.os.stat
    real_rmdir = state.os.rmdir
    released = []

    def release_before_stat(name, *args, **kwargs):
        if name == "cleanup.lock" and not released:
            released.append(True)
            real_rmdir(name, dir_fd=kwargs["dir_fd"])
            raise FileNotFoundError("the other writer just released the lock")
        return real_stat(name, *args, **kwargs)

    monkeypatch.setattr(state.os, "stat", release_before_stat)
    update_cleanup_state(tmp_path, scope, _plan("second"))
    assert released == [True]
    assert load_cleanup_state(tmp_path)["version"] == 1
    _assert_tidy(path)


def test_interrupted_writer_keeps_history_and_releases_owned_temporary_files(
    tmp_path, monkeypatch
):
    import skylos.cleanup_state as state

    scope, path, original = _initial(tmp_path)
    real_write = state.os.write

    def interrupted(descriptor, content):
        real_write(descriptor, content[:32])
        raise KeyboardInterrupt()

    monkeypatch.setattr(state.os, "write", interrupted)
    with pytest.raises(KeyboardInterrupt):
        update_cleanup_state(tmp_path, scope, _plan("second"))
    assert path.read_bytes() == original
    _assert_tidy(path)


def test_unsupported_guarded_storage_has_clean_cli_error_and_no_state_fallback(
    tmp_path, monkeypatch
):
    import io
    import skylos.cleanup_state as state
    from skylos.commands.cleanup_cmd import run_cleanup_command

    monkeypatch.setattr(state.os, "supports_dir_fd", set())
    report = {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "ai_verification": {"state": "complete"},
        },
        "quality": [],
        "ai_defects": [],
    }
    output = io.StringIO()
    code = run_cleanup_command(
        [str(tmp_path), "--format", "json"],
        stdout=output,
        analyze_func=lambda *_a, **_kw: report,
    )
    result = json.loads(output.getvalue())
    assert code == 2
    assert result["status"] == "incomplete"
    assert "unavailable on this platform" in result["limitations"][0]
    output = io.StringIO()
    code = run_cleanup_command(
        [str(tmp_path), "--format", "json", "--no-state"],
        stdout=output,
        analyze_func=lambda *_a, **_kw: report,
    )
    assert code == 0
    assert json.loads(output.getvalue())["status"] == "clear"
    assert not (tmp_path / ".skylos").exists()
