from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from skylos.core.api_symbol_truth import (
    API_SURFACE_CACHE_LOCK_PATH,
    SURFACE_KIND_CLI,
    SURFACE_KIND_CONFIG,
    SURFACE_KIND_PYTHON_MODULE,
    SURFACE_KIND_ROUTE,
    SURFACE_KIND_SCHEMA,
    api_symbol_surface_key,
    cache_api_symbol_surface,
    cached_api_symbol_surface,
    load_api_symbol_truth_cache,
    normalize_api_symbol_surface,
)
from skylos.core.safe_cache_io import (
    PROJECT_CACHE_LOCK_STALE_SECONDS,
    project_cache_lock,
)


def test_api_symbol_truth_cache_holds_multiple_surface_kinds(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_PYTHON_MODULE,
            "name": "sampleapi",
            "source": "test",
            "environment_key": "env-a",
            "members": {
                "make_user": {
                    "kind": "function",
                    "parameters": [{"name": "active", "kind": "KEYWORD_ONLY"}],
                }
            },
        },
    )
    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_CLI,
            "name": "skylos",
            "flags": ["--format", "--diff"],
        },
    )
    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_CONFIG,
            "name": "skylos.toml",
            "config_keys": ["rules", "exclude"],
        },
    )
    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_ROUTE,
            "name": "api",
            "routes": ["/v1/items"],
        },
    )
    assert cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_SCHEMA,
            "name": "User",
            "schema_fields": ["id", "email"],
        },
    )

    payload = load_api_symbol_truth_cache(project_root)

    assert set(payload["surfaces"]) == {
        "python_module:sampleapi",
        "cli:skylos",
        "config:skylos.toml",
        "route:api",
        "schema:User",
    }
    assert cached_api_symbol_surface(
        project_root,
        SURFACE_KIND_PYTHON_MODULE,
        "sampleapi",
    ) is None
    shared = cached_api_symbol_surface(
        project_root,
        SURFACE_KIND_PYTHON_MODULE,
        "sampleapi",
        environment_key="env-a",
    )
    assert shared["members"]["make_user"]["kind"] == "function"
    assert shared["members"]["make_user"]["parameters"] == [
        {"name": "active", "kind": "KEYWORD_ONLY"}
    ]
    assert (
        cached_api_symbol_surface(
            project_root,
            SURFACE_KIND_PYTHON_MODULE,
            "sampleapi",
            environment_key="stale",
        )
        is None
    )


def test_api_symbol_truth_cache_rejects_malformed_surfaces(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    assert normalize_api_symbol_surface({"kind": "unknown", "name": "x"}) is None
    assert normalize_api_symbol_surface(
        {"kind": SURFACE_KIND_CLI, "name": "skylos"}
    ) is None
    assert api_symbol_surface_key("unknown", "x") is None
    assert api_symbol_surface_key(SURFACE_KIND_CLI, 123) is None
    assert normalize_api_symbol_surface(
        {
            "kind": SURFACE_KIND_CLI,
            "name": "skylos",
            "flags": ["--format", 123, None],
        }
    )["flags"] == ["--format"]
    assert (
        normalize_api_symbol_surface(
            {
                "kind": SURFACE_KIND_PYTHON_MODULE,
                "name": "sampleapi",
                "environment_key": "env-a",
                "members": ["make_user"],
            }
        )
        is None
    )
    assert (
        normalize_api_symbol_surface(
            {
                "kind": SURFACE_KIND_PYTHON_MODULE,
                "name": "sampleapi",
                "environment_key": "env-a",
                "members": {"make_user": ["bad"]},
            }
        )
        is None
    )
    assert not cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_CLI,
            "name": "skylos\nbad",
            "flags": ["--format"],
        },
    )
    assert load_api_symbol_truth_cache(project_root)["surfaces"] == {}


def test_api_symbol_truth_cache_rejects_hard_linked_transaction_lock(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    lock_path = project_root / API_SURFACE_CACHE_LOCK_PATH
    lock_path.parent.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("sentinel", encoding="utf-8")
    lock_path.hardlink_to(outside)

    saved = cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_CLI,
            "name": "skylos",
            "flags": ["--format"],
        },
    )

    assert saved is False
    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert not (project_root / ".skylos/cache/api_symbol_truth.json").exists()


def test_api_symbol_truth_cache_rejects_symlinked_transaction_lock(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    lock_path = project_root / API_SURFACE_CACHE_LOCK_PATH
    lock_path.parent.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("sentinel", encoding="utf-8")
    lock_path.symlink_to(outside)

    saved = cache_api_symbol_surface(
        project_root,
        {
            "kind": SURFACE_KIND_CLI,
            "name": "skylos",
            "flags": ["--format"],
        },
    )

    assert saved is False
    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert not (project_root / ".skylos/cache/api_symbol_truth.json").exists()


def test_api_surface_transaction_lock_serializes_processes(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    child_code = """
import sys
from skylos.core.api_symbol_truth import API_SURFACE_CACHE_LOCK_PATH
from skylos.core.safe_cache_io import project_cache_lock

with project_cache_lock(sys.argv[1], API_SURFACE_CACHE_LOCK_PATH) as acquired:
    print("locked" if acquired else "failed", flush=True)
    if acquired:
        sys.stdin.readline()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", child_code, str(project_root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    ready = threading.Event()
    child_status = []

    def read_child_status():
        if process.stdout is not None:
            child_status.append(process.stdout.readline().strip())
        ready.set()

    reader = threading.Thread(target=read_child_status, daemon=True)
    reader.start()
    try:
        assert ready.wait(timeout=2.0)
        assert child_status == ["locked"]
        started = time.monotonic()
        with project_cache_lock(
            project_root,
            API_SURFACE_CACHE_LOCK_PATH,
            timeout_seconds=0.05,
        ) as acquired:
            assert acquired is False
        assert time.monotonic() - started < 0.5
        assert process.stdin is not None
        process.stdin.write("\n")
        process.stdin.flush()
        assert process.wait(timeout=2.0) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2.0)
        reader.join(timeout=1.0)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    with project_cache_lock(
        project_root,
        API_SURFACE_CACHE_LOCK_PATH,
    ) as acquired:
        assert acquired is True


def test_api_surface_lock_handles_concurrent_cache_directory_creation(
    tmp_path,
    monkeypatch,
):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    create_barrier = threading.Barrier(2)
    original_mkdir = Path.mkdir

    def synchronized_mkdir(path, *args, **kwargs):
        if path == project_root / ".skylos":
            create_barrier.wait(timeout=1.0)
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", synchronized_mkdir)
    outcomes = []
    errors = []

    def acquire_lock():
        try:
            with project_cache_lock(
                project_root,
                API_SURFACE_CACHE_LOCK_PATH,
            ) as acquired:
                outcomes.append(acquired)
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=acquire_lock) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2.0)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert outcomes == [True, True]


def test_api_surface_lock_retries_if_lock_disappears_during_preflight(
    tmp_path,
    monkeypatch,
):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    lock_path = project_root / API_SURFACE_CACHE_LOCK_PATH
    lock_path.parent.mkdir(parents=True)
    owner_acquired = threading.Event()
    contender_checked = threading.Event()
    owner_released = threading.Event()
    original_is_dir = Path.is_dir
    original_mkdir = os.mkdir
    outcomes = []
    errors = []

    def synchronized_is_dir(path):
        if (
            path == lock_path
            and owner_acquired.is_set()
            and not owner_released.is_set()
        ):
            contender_checked.set()
            if not owner_released.wait(timeout=2.0):
                raise TimeoutError("lock owner did not release")
        return original_is_dir(path)

    def synchronized_mkdir(path, *args, **kwargs):
        if (
            Path(path) == lock_path
            and owner_acquired.is_set()
            and not owner_released.is_set()
        ):
            contender_checked.set()
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_dir", synchronized_is_dir)
    monkeypatch.setattr(os, "mkdir", synchronized_mkdir)

    def own_lock():
        try:
            with project_cache_lock(
                project_root,
                API_SURFACE_CACHE_LOCK_PATH,
                timeout_seconds=2.0,
            ) as acquired:
                outcomes.append(acquired)
                owner_acquired.set()
                if not contender_checked.wait(timeout=2.0):
                    raise TimeoutError("lock contender did not start")
        except (OSError, ValueError) as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            owner_released.set()

    def contend_for_lock():
        try:
            if not owner_acquired.wait(timeout=2.0):
                raise TimeoutError("lock owner did not acquire")
            with project_cache_lock(
                project_root,
                API_SURFACE_CACHE_LOCK_PATH,
                timeout_seconds=2.0,
            ) as acquired:
                outcomes.append(acquired)
        except (OSError, ValueError) as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    owner = threading.Thread(target=own_lock)
    contender = threading.Thread(target=contend_for_lock)
    owner.start()
    contender.start()
    owner.join(timeout=3.0)
    contender.join(timeout=3.0)

    assert not owner.is_alive()
    assert not contender.is_alive()
    assert errors == []
    assert outcomes == [True, True]


def test_api_surface_lock_recovers_empty_stale_directory(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    lock_path = project_root / API_SURFACE_CACHE_LOCK_PATH
    lock_path.mkdir(parents=True)
    stale_time = time.time() - PROJECT_CACHE_LOCK_STALE_SECONDS - 1.0
    os.utime(lock_path, (stale_time, stale_time))

    with project_cache_lock(
        project_root,
        API_SURFACE_CACHE_LOCK_PATH,
    ) as acquired:
        assert acquired is True

    assert not lock_path.exists()
