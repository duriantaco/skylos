"""Sync must never follow swapped parents or accept arbitrary filenames."""

import os

import pytest

from skylos.cloud import sync_state


@pytest.fixture
def sync_tree(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    state = repo / ".skylos"
    state.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "config.yaml"
    sentinel.write_text("sentinel")
    return repo, state, outside, sentinel


def _requires_descriptors():
    if not (
        {os.open, os.stat, os.rename, os.unlink, os.mkdir} <= os.supports_dir_fd
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
    ):
        pytest.skip("requires POSIX no-follow directory descriptors")


def test_root_swap_before_open_never_activates_outside(sync_tree, monkeypatch):
    _requires_descriptors()
    repo, _, outside, sentinel = sync_tree
    # Mirror the destination layout so following the replacement would overwrite
    # the sentinel, rather than merely fail because an outside directory is absent.
    (outside / ".skylos").mkdir()
    destination = outside / ".skylos" / "config.yaml"
    destination.write_text("outside configuration")
    original_open = os.open
    retained = repo.with_name("retained")
    swapped = False

    def raced_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and kwargs.get("dir_fd") is None:
            repo.rename(retained)
            repo.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(sync_state.os, "open", raced_open)
    monkeypatch.setattr(
        sync_state.os, "supports_dir_fd", os.supports_dir_fd | {raced_open}
    )
    with (
        pytest.raises(OSError),
        sync_state.activate_sync_files(repo, {"config.yaml": "replacement"}),
    ):
        pytest.fail("a substituted root was activated")
    assert swapped
    assert sentinel.read_text() == "sentinel"
    assert destination.read_text() == "outside configuration"
    assert not list((retained / ".skylos").iterdir())


@pytest.mark.parametrize(
    "name",
    [
        "../config.yaml",
        "../../outside/config.yaml",
        "/config.yaml",
        r"..\config.yaml",
        "config.yaml:stream",
        "config.yaml/child",
        "",
        ".",
        "..",
    ],
)
def test_activation_rejects_invalid_names_before_creating_state(tmp_path, name):
    repo = tmp_path / "repo"
    repo.mkdir()
    with (
        pytest.raises(sync_state.UnsafeSyncPath, match="filename"),
        sync_state.activate_sync_files(repo, {name: "replacement"}),
    ):
        pytest.fail("unsafe name was activated")
    assert not (repo / ".skylos").exists()


@pytest.mark.parametrize("operation", ["read", "stage", "remove", "replace"])
def test_directory_operations_reject_traversal(sync_tree, operation):
    repo, _, _, sentinel = sync_tree
    directory = sync_state._SyncDirectory(repo, create=False)
    try:
        with pytest.raises(sync_state.UnsafeSyncPath, match="filename"):
            if operation == "stage":
                directory.stage("../../outside/config.yaml", b"replacement")
            elif operation == "replace":
                directory.replace("../../outside/config.yaml", "config.yaml")
            else:
                getattr(directory, operation)("../../outside/config.yaml")
    finally:
        directory.close()
    assert sentinel.read_text() == "sentinel"


def test_unsupported_platform_refuses_path_fallback(sync_tree, monkeypatch):
    if os.name == "nt":
        pytest.skip("Windows uses its native handle adapter")
    repo, state, _, sentinel = sync_tree
    monkeypatch.setattr(sync_state.os, "supports_dir_fd", set())
    with (
        pytest.raises(sync_state.UnsafeSyncPath, match="no-follow directory"),
        sync_state.activate_sync_files(repo, {"config.yaml": "replacement"}),
    ):
        pytest.fail("unsafe path fallback was used")
    assert not list(state.iterdir())
    assert sentinel.read_text() == "sentinel"


def test_parent_swap_before_read_cannot_redirect_descriptor(sync_tree, monkeypatch):
    _requires_descriptors()
    repo, state, outside, sentinel = sync_tree
    destination = state / "config.yaml"
    destination.write_text("repo configuration")
    directory = sync_state._SyncDirectory(repo, create=False)
    original_open = os.open
    retained = repo / "retained-state"

    def raced_open(path, flags, *args, **kwargs):
        if path == "config.yaml":
            state.rename(retained)
            state.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(sync_state.os, "open", raced_open)
    try:
        assert directory.read("config.yaml") == b"repo configuration"
    finally:
        directory.close()
    assert sentinel.read_text() == "sentinel"


def test_parent_swap_before_stage_cannot_redirect_write(sync_tree, monkeypatch):
    _requires_descriptors()
    repo, state, outside, sentinel = sync_tree
    directory = sync_state._SyncDirectory(repo, create=False)
    original_open = os.open
    retained = repo / "retained-state"

    def raced_open(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            state.rename(retained)
            state.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(sync_state.os, "open", raced_open)
    try:
        temporary = directory.stage("config.yaml", b"new configuration")
        assert (retained / temporary).read_bytes() == b"new configuration"
        assert list(outside.iterdir()) == [sentinel]
        directory.remove(temporary)
    finally:
        directory.close()
    assert not list(retained.iterdir())
    assert sentinel.read_text() == "sentinel"


def test_changed_leaf_identity_is_rejected(sync_tree, monkeypatch):
    _requires_descriptors()
    repo, state, _, _ = sync_tree
    destination = state / "config.yaml"
    destination.write_text("repo configuration")
    directory = sync_state._SyncDirectory(repo, create=False)
    original_open = os.open

    def raced_open(path, flags, *args, **kwargs):
        if path == "config.yaml":
            destination.rename(state / "retained-config")
            destination.write_text("changed file")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(sync_state.os, "open", raced_open)
    try:
        with pytest.raises(sync_state.UnsafeSyncPath, match="changed while reading"):
            directory.read("config.yaml")
    finally:
        directory.close()


def test_valid_sync_and_rollback_leave_no_temporaries(sync_tree):
    repo, state, _, sentinel = sync_tree
    files = {"config.yaml": "new configuration", "suppressions.json": "{}"}
    with sync_state.activate_sync_files(repo, files):
        assert (state / "config.yaml").read_text() == files["config.yaml"]
        assert (state / "suppressions.json").read_text() == files["suppressions.json"]
    assert {path.name for path in state.iterdir()} == set(files)
    with (
        pytest.raises(RuntimeError, match="caller failed"),
        sync_state.activate_sync_files(repo, {"config.yaml": "must roll back"}),
    ):
        raise RuntimeError("caller failed")
    assert (state / "config.yaml").read_text() == files["config.yaml"]
    assert {path.name for path in state.iterdir()} == set(files)
    assert sentinel.read_text() == "sentinel"


def test_staged_symlink_swap_before_rename_rolls_back(sync_tree, monkeypatch):
    _requires_descriptors()
    repo, state, _, sentinel = sync_tree
    destination = state / "config.yaml"
    destination.write_text("previous configuration")
    original_replace = os.replace
    swapped = False

    def raced_replace(source, target, *args, **kwargs):
        nonlocal swapped
        if not swapped:
            (state / source).unlink()
            (state / source).symlink_to(sentinel)
            swapped = True
        return original_replace(source, target, *args, **kwargs)

    monkeypatch.setattr(sync_state.os, "replace", raced_replace)
    with (
        pytest.raises(OSError),
        sync_state.activate_sync_files(repo, {"config.yaml": "new configuration"}),
    ):
        pytest.fail("symlink was accepted as activated configuration")
    assert swapped
    assert sentinel.read_text() == "sentinel"
    assert not destination.is_symlink()
    assert destination.read_text() == "previous configuration"
    assert {path.name for path in state.iterdir()} == {"config.yaml"}


def test_changed_activated_bytes_cannot_report_success(sync_tree):
    repo, state, _, sentinel = sync_tree
    destination = state / "config.yaml"
    destination.write_text("previous configuration")
    with (
        pytest.raises(sync_state.UnsafeSyncPath, match="during trust storage"),
        sync_state.activate_sync_files(repo, {"config.yaml": "new configuration"}),
    ):
        destination.write_text("changed during caller")
    assert destination.read_text() == "previous configuration"
    assert {path.name for path in state.iterdir()} == {"config.yaml"}
    assert sentinel.read_text() == "sentinel"
