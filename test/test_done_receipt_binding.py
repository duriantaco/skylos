"""Done receipts must describe the checkout being uploaded."""

from __future__ import annotations

import copy
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from skylos import api
from skylos.done.engine import run
from skylos.done.receipt import (
    MAX_RECEIPT_BYTES,
    _prepare_receipts_directory,
    build_receipt,
    load_receipt_for_upload,
    receipt_upload_error,
    validate_receipt,
    write_receipt,
)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=receipt-test",
            "-c",
            "user.email=test@example.com",
            *args,
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def clean_receipt(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "app.py").write_text("def total(a, b):\n    return a + b\n")
    _git(root, "add", "app.py")
    _git(root, "commit", "-qm", "initial")
    receipt = build_receipt(run(root, run_tests=False))
    path = write_receipt(root, receipt)
    assert path is not None
    return root, receipt, path


def test_clean_receipt_matches_checkout_and_upload(clean_receipt):
    root, receipt, path = clean_receipt
    loaded, error = load_receipt_for_upload(path, root)
    assert loaded == receipt
    assert error is None
    assert (
        api._done_receipt_for_upload(
            {"done_receipt": receipt},
            commit_hash=receipt["head"]["sha"],
            repo_root=root,
        )
        == receipt
    )


@pytest.mark.parametrize("component", [".skylos", "receipts"])
def test_receipt_directory_rejects_symlink_components(tmp_path, component):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    if component == ".skylos":
        (root / component).symlink_to(outside, target_is_directory=True)
    else:
        (root / ".skylos").mkdir()
        (root / ".skylos" / component).symlink_to(
            outside, target_is_directory=True
        )
    assert _prepare_receipts_directory(root) is None
    assert not list(outside.iterdir())


def test_receipt_directory_rejects_parent_replaced_during_creation(
    tmp_path, monkeypatch
):
    if os.mkdir not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("descriptor-relative directory creation unavailable")
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    original_mkdir = os.mkdir

    def replace_created_parent(path, *args, **kwargs):
        original_mkdir(path, *args, **kwargs)
        if path == ".skylos" and kwargs.get("dir_fd") is not None:
            (root / ".skylos").rmdir()
            (root / ".skylos").symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(os, "mkdir", replace_created_parent)
    monkeypatch.setattr(
        os, "supports_dir_fd", {*os.supports_dir_fd, replace_created_parent}
    )
    assert _prepare_receipts_directory(root) is None
    assert not list(outside.iterdir())


def test_receipt_directory_checked_fallback(tmp_path, monkeypatch):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    monkeypatch.setattr(os, "supports_dir_fd", set())
    assert _prepare_receipts_directory(root) == root / ".skylos" / "receipts"
    (root / ".skylos" / "receipts").rmdir()
    (root / ".skylos" / "receipts").symlink_to(
        outside, target_is_directory=True
    )
    assert _prepare_receipts_directory(root) is None
    assert not list(outside.iterdir())


def test_receipt_writer_rejects_invalid_filename_before_writing(clean_receipt):
    root, receipt, _path = clean_receipt
    malformed = copy.deepcopy(receipt)
    malformed["head"]["sha"] = "../../app.py"
    assert write_receipt(root, malformed) is None


@pytest.mark.parametrize(
    "extra",
    [object(), float("nan"), "x" * MAX_RECEIPT_BYTES],
    ids=["non-serializable", "non-finite", "oversized"],
)
def test_receipt_writer_rejects_unreadable_serialized_payload(clean_receipt, extra):
    root, receipt, _path = clean_receipt
    malformed = copy.deepcopy(receipt)
    malformed["extra"] = extra
    assert write_receipt(root, malformed) is None


def test_receipt_directory_rejects_invalid_root():
    assert _prepare_receipts_directory(Path("\x00")) is None


@pytest.mark.parametrize("change", ["unstaged", "staged", "untracked", "deleted"])
def test_stale_clean_receipt_refuses_current_changes(clean_receipt, change):
    root, receipt, path = clean_receipt
    if change == "untracked":
        (root / "new.py").write_text("def new_feature():\n    return False\n")
    elif change == "deleted":
        (root / "app.py").unlink()
    else:
        (root / "app.py").write_text("def total(a, b):\n    return a - b\n")
        if change == "staged":
            _git(root, "add", "app.py")

    assert receipt["head"]["dirty"] is False
    loaded, error = load_receipt_for_upload(path, root)
    assert loaded is None
    assert "uncommitted changes" in error
    with pytest.raises(ValueError, match="uncommitted changes"):
        api._done_receipt_for_upload(
            {"done_receipt": receipt},
            commit_hash=receipt["head"]["sha"],
            repo_root=root,
        )


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
@pytest.mark.parametrize("change", ["modified", "deleted", "symlink", "mode"])
def test_stale_receipt_refuses_index_hidden_changes(clean_receipt, flag, change):
    root, receipt, path = clean_receipt
    target = root / "app.py"
    original_stat = target.stat()
    _git(root, "config", "core.filemode", "true")
    _git(root, "update-index", flag, "app.py")
    if change == "modified":
        target.write_text("def total(a, b):\n    return a - b\n")
        os.utime(target, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    elif change == "deleted":
        target.unlink()
    elif change == "symlink":
        target.unlink()
        target.symlink_to(root.parent / "outside.py")
    else:
        target.chmod(original_stat.st_mode | 0o100)
    assert _git(root, "status", "--porcelain") == ""
    index = (root / ".git/index").read_bytes()

    loaded, error = load_receipt_for_upload(path, root)
    assert loaded is None
    assert "uncommitted changes" in error
    with pytest.raises(ValueError, match="uncommitted changes"):
        api._done_receipt_for_upload(
            {"done_receipt": receipt},
            commit_hash=receipt["head"]["sha"],
            repo_root=root,
        )
    assert (root / ".git/index").read_bytes() == index


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_clean_index_hidden_file_remains_uploadable(clean_receipt, flag):
    root, receipt, path = clean_receipt
    _git(root, "update-index", flag, "app.py")
    index = (root / ".git/index").read_bytes()

    assert load_receipt_for_upload(path, root) == (receipt, None)
    assert receipt_upload_error(receipt, root) is None
    assert (root / ".git/index").read_bytes() == index


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
@pytest.mark.parametrize("changed", [False, True])
def test_index_hidden_crlf_uses_builtin_normalization(clean_receipt, flag, changed):
    root, _receipt, _path = clean_receipt
    (root / ".gitattributes").write_text("*.py text eol=crlf\n")
    _git(root, "add", ".gitattributes")
    _git(root, "commit", "-qm", "configure text normalization")
    (root / "app.py").write_bytes(b"def total(a, b):\r\n    return a + b\r\n")
    _git(root, "add", "app.py")
    receipt = build_receipt(run(root, run_tests=False))
    assert receipt["head"]["dirty"] is False
    _git(root, "update-index", flag, "app.py")
    if changed:
        (root / "app.py").write_bytes(b"def total(a, b):\r\n    return a - b\r\n")
    index = (root / ".git/index").read_bytes()

    error = receipt_upload_error(receipt, root)
    assert (error is not None) is changed
    if changed:
        assert "uncommitted changes" in error
    assert (root / ".git/index").read_bytes() == index


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_index_hidden_symlink_compares_link_target(clean_receipt, flag):
    root, _receipt, _path = clean_receipt
    target = root / "link.py"
    target.symlink_to("app.py")
    _git(root, "add", "link.py")
    _git(root, "commit", "-qm", "add tracked symlink")
    receipt = build_receipt(run(root, run_tests=False))
    _git(root, "update-index", flag, "link.py")
    index = (root / ".git/index").read_bytes()
    assert receipt_upload_error(receipt, root) is None

    target.unlink()
    target.symlink_to("missing.py")
    assert "uncommitted changes" in receipt_upload_error(receipt, root)
    assert (root / ".git/index").read_bytes() == index


def test_combined_index_flags_still_check_actual_content(clean_receipt):
    root, receipt, _path = clean_receipt
    _git(root, "update-index", "--assume-unchanged", "app.py")
    _git(root, "update-index", "--skip-worktree", "app.py")
    index = (root / ".git/index").read_bytes()
    assert receipt_upload_error(receipt, root) is None
    (root / "app.py").write_text("def total(a, b):\n    return a - b\n")
    assert "uncommitted changes" in receipt_upload_error(receipt, root)
    assert (root / ".git/index").read_bytes() == index


def test_hidden_mode_change_respects_core_filemode_false(clean_receipt):
    root, receipt, _path = clean_receipt
    _git(root, "config", "core.filemode", "false")
    _git(root, "update-index", "--assume-unchanged", "app.py")
    target = root / "app.py"
    target.chmod(target.stat().st_mode | 0o100)
    index = (root / ".git/index").read_bytes()
    assert receipt_upload_error(receipt, root) is None
    assert (root / ".git/index").read_bytes() == index


def test_sparse_checkout_missing_files_cannot_vouch_for_current_content(clean_receipt):
    root, receipt, _path = clean_receipt
    _git(root, "sparse-checkout", "set", "--no-cone", "missing-directory/")
    assert not (root / "app.py").exists()
    index = (root / ".git/index").read_bytes()
    assert "uncommitted changes" in receipt_upload_error(receipt, root)
    assert (root / ".git/index").read_bytes() == index


@pytest.mark.parametrize(
    "attribute", ["filter=fixture", "ident", "working-tree-encoding=UTF-16", "-text"]
)
def test_hidden_checkout_transform_is_not_executed_or_approximated(
    clean_receipt, attribute
):
    root, _receipt, _path = clean_receipt
    (root / ".gitattributes").write_text(f"*.py text eol=crlf {attribute}\n")
    # Avoid invoking the configured transform while constructing the fixture.
    _git(root, "add", ".gitattributes")
    _git(root, "commit", "-qm", "set checkout transform")
    receipt = build_receipt(run(root, run_tests=False))
    marker = root.parent / "filter-executed"
    code = f"from pathlib import Path; Path({str(marker)!r}).touch()"
    command = f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"
    _git(root, "update-index", "--assume-unchanged", "app.py")
    _git(root, "config", "filter.fixture.clean", command)
    _git(root, "config", "filter.fixture.smudge", command)
    _git(root, "config", "filter.fixture.required", "true")
    (root / "app.py").write_bytes(b"def total(a, b):\r\n    return a + b\r\n")
    index = (root / ".git/index").read_bytes()
    assert not marker.exists()
    assert "uncommitted changes" in receipt_upload_error(receipt, root)
    assert not marker.exists()
    assert (root / ".git/index").read_bytes() == index


@pytest.mark.parametrize("flag", [None, "--assume-unchanged", "--skip-worktree"])
def test_receipt_rechecked_after_initial_loading(clean_receipt, monkeypatch, flag):
    root, receipt, path = clean_receipt
    loaded, error = load_receipt_for_upload(path, root)
    assert loaded is not None and error is None
    if flag:
        _git(root, "update-index", flag, "app.py")
    # Analysis can take time: an edit after parsing --done-receipt must not
    # retain the earlier authorization when the actual payload is prepared.
    (root / "app.py").write_text("def total(a, b):\n    return 0\n")
    monkeypatch.setattr(api, "get_git_root", lambda: str(root))
    monkeypatch.setattr(
        api, "get_git_info", lambda: (receipt["head"]["sha"], "main", None, False)
    )
    with pytest.raises(ValueError, match="uncommitted changes"):
        api._prepare_report_upload({"definitions": {}, "done_receipt": loaded})


def test_receipt_refuses_other_upload_commit(clean_receipt):
    root, receipt, _path = clean_receipt
    with pytest.raises(ValueError, match="upload commit"):
        api._done_receipt_for_upload(
            {"done_receipt": receipt}, commit_hash="f" * 40, repo_root=root
        )


def test_receipt_binding_requires_checkout(clean_receipt):
    _root, receipt, _path = clean_receipt
    with pytest.raises(ValueError, match="without a Git checkout"):
        api._done_receipt_for_upload(
            {"done_receipt": receipt}, commit_hash=receipt["head"]["sha"]
        )


def test_pr_head_receipt_upload_uses_checkout_not_event_sha(clean_receipt, monkeypatch):
    root, receipt, _path = clean_receipt
    monkeypatch.chdir(root)
    monkeypatch.delenv("SKYLOS_COMMIT", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)
    monkeypatch.setenv("GITHUB_REF", "refs/pull/19/merge")

    commit, _branch, _actor, ci = api.get_git_info()
    assert commit == receipt["head"]["sha"]
    assert ci["sha"] == "f" * 40
    prepared = api._prepare_report_upload({"definitions": {}, "done_receipt": receipt})
    assert prepared.metadata["commit_hash"] == commit
    assert prepared.metadata["done_receipt"] == receipt


def test_explicit_commit_override_is_preserved_and_checked(clean_receipt, monkeypatch):
    root, receipt, _path = clean_receipt
    monkeypatch.chdir(root)
    monkeypatch.setenv("SKYLOS_COMMIT", "e" * 40)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)

    assert api.get_git_info()[0] == "e" * 40
    with pytest.raises(ValueError, match="upload commit"):
        api._prepare_report_upload({"definitions": {}, "done_receipt": receipt})


def test_ci_event_commit_is_fallback_without_checkout(monkeypatch):
    monkeypatch.delenv("SKYLOS_COMMIT", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)
    monkeypatch.setattr(api, "_read_git_head", lambda: (None, None))
    assert api.get_git_info()[0] == "f" * 40


@pytest.mark.parametrize(
    "location",
    [
        ("verdict",),
        ("base", "source"),
        ("checks", 0, "id"),
        ("checks", 0, "mode"),
        ("checks", 0, "status"),
    ],
)
def test_malformed_json_values_are_reported_without_crashing(clean_receipt, location):
    _root, receipt, _path = clean_receipt
    malformed = copy.deepcopy(receipt)
    parent = malformed
    for key in location[:-1]:
        parent = parent[key]
    parent[location[-1]] = []
    assert validate_receipt(malformed)


@pytest.mark.parametrize("field", ["finding", "unverified"])
def test_boolean_line_numbers_are_not_valid_receipt_lines(clean_receipt, field):
    _root, receipt, _path = clean_receipt
    malformed = copy.deepcopy(receipt)
    if field == "finding":
        malformed["checks"][0]["findings"] = [
            {"rule": None, "file": "app.py", "line": True, "message": "invalid line"}
        ]
    else:
        malformed["unverified"] = [{"file": "app.py", "line": True}]
    assert validate_receipt(malformed)
