"""Trusted workspace callbacks share the guarded cleanup history transaction."""

from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from skylos.cleanup_state import (
    STATE_PATH,
    load_cleanup_state,
    mutate_cleanup_workspace,
    scope_identity,
    update_cleanup_state,
)


def _initial(root):
    scope = {"target": str(root), "config_digest": "first"}
    plan = {
        "status": "ready",
        "tasks": [{"id": "task", "rule_id": "SKY-U002", "file": "app.py"}],
        "advisories": [],
    }
    update_cleanup_state(root, scope, plan)
    return scope, load_cleanup_state(root)


def test_workspace_initializes_bucket_and_detaches_result(tmp_path):
    scope = {"target": str(tmp_path), "settings": {"enabled": True}}
    captured = []

    def add_plan(bucket):
        assert bucket == {"scope": scope, "tasks": {}}
        captured.append(bucket)
        bucket["plans"] = {"first": {"tasks": ["one"]}}
        return bucket["plans"]["first"]

    result = mutate_cleanup_workspace(tmp_path, scope, add_plan)
    result["tasks"].append("returned mutation")
    captured[0]["plans"]["first"]["tasks"].append("callback mutation")
    scope["settings"]["enabled"] = False
    saved = load_cleanup_state(tmp_path)
    bucket = next(iter(saved["scopes"].values()))
    assert bucket["plans"] == {"first": {"tasks": ["one"]}}
    assert bucket["scope"]["settings"] == {"enabled": True}


def test_workspace_preserves_tasks_other_namespaces_and_scopes(tmp_path):
    scope, original = _initial(tmp_path)
    other = {**scope, "config_digest": "other"}
    mutate_cleanup_workspace(
        tmp_path, other, lambda bucket: bucket.update(owner="other")
    )

    def add_review(bucket):
        bucket["review"] = {"task": "acknowledged"}
        return bucket["review"]

    result = mutate_cleanup_workspace(tmp_path, scope, add_review)
    saved = load_cleanup_state(tmp_path)
    bucket = saved["scopes"][scope_identity(scope)]
    assert bucket["tasks"] == original["scopes"][scope_identity(scope)]["tasks"]
    assert bucket["last_scan"] == original["scopes"][scope_identity(scope)]["last_scan"]
    assert bucket["review"] == result == {"task": "acknowledged"}
    assert saved["scopes"][scope_identity(other)]["owner"] == "other"


@pytest.mark.parametrize("problem", ["raise", "scope", "tasks", "serialization"])
def test_workspace_callback_failure_preserves_complete_state(tmp_path, problem):
    scope, _ = _initial(tmp_path)
    path = tmp_path / STATE_PATH
    original = path.read_bytes()

    def fail(bucket):
        bucket["plans"] = {"first": "must not be written"}
        if problem == "raise":
            raise RuntimeError("callback interrupted")
        if problem == "scope":
            bucket["scope"]["config_digest"] = "changed"
        elif problem == "tasks":
            bucket["tasks"] = []
        else:
            bucket["plans"] = object()

    with pytest.raises((RuntimeError, ValueError, TypeError)):
        mutate_cleanup_workspace(tmp_path, scope, fail)
    assert path.read_bytes() == original
    assert not (path.parent / "cleanup.lock").exists()


@pytest.mark.parametrize("bucket", [[], {"scope": {}, "tasks": {}}, {"tasks": []}])
def test_workspace_rejects_malformed_or_mismatched_bucket(tmp_path, bucket):
    scope, state = _initial(tmp_path)
    path = tmp_path / STATE_PATH
    state["scopes"][scope_identity(scope)] = bucket
    path.write_text(json.dumps(state), encoding="utf-8")
    original = path.read_bytes()
    called = []

    with pytest.raises(ValueError, match="workspace scope or task history"):
        mutate_cleanup_workspace(tmp_path, scope, lambda value: called.append(value))
    assert called == []
    assert path.read_bytes() == original


def test_workspace_failed_publication_preserves_previous_state(tmp_path, monkeypatch):
    import skylos.cleanup_state as state

    scope, _ = _initial(tmp_path)
    path = tmp_path / STATE_PATH
    original = path.read_bytes()

    def fail(*_a, **_kw):
        raise OSError("simulated publish failure")

    monkeypatch.setattr(state, "_atomic_write_state", fail)
    with pytest.raises(OSError, match="publish failure"):
        mutate_cleanup_workspace(
            tmp_path, scope, lambda bucket: bucket.update(plans={})
        )
    assert path.read_bytes() == original


def test_workspace_callbacks_do_not_lose_concurrent_updates(tmp_path):
    scope = {"target": str(tmp_path)}

    def add(_index):
        def increment(bucket):
            bucket["counter"] = bucket.get("counter", 0) + 1
            return bucket["counter"]

        return mutate_cleanup_workspace(tmp_path, scope, increment)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(add, range(8)))
    assert sorted(results) == list(range(1, 9))
    assert load_cleanup_state(tmp_path)["scopes"][scope_identity(scope)]["counter"] == 8


def test_workspace_symlink_state_is_not_followed(tmp_path):
    scope, _ = _initial(tmp_path)
    path = tmp_path / STATE_PATH
    outside = tmp_path / "outside.json"
    path.rename(outside)
    path.symlink_to(outside)
    original = outside.read_bytes()
    called = []
    with pytest.raises((ValueError, OSError)):
        mutate_cleanup_workspace(tmp_path, scope, lambda bucket: called.append(bucket))
    assert called == []
    assert outside.read_bytes() == original
