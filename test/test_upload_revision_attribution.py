import os
import subprocess

import pytest

from skylos import api
from skylos.api._source_revision import _blob_oid, source_revision_state


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_full_tree_upload_pins_clean_head_and_marks_worktree_changes(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    source = repo / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "base")
    sha = _git(repo, "rev-parse", "HEAD")
    monkeypatch.chdir(repo)

    result = {
        "analysis_summary": {
            "comparison_scope": {
                "complete_repository": True,
                "repository_root": str(repo),
            }
        },
        "grade": {"overall": {"score": 90, "letter": "A"}},
    }

    assert source_revision_state(result, str(repo), sha) == "clean"
    prepared = api._prepare_report_upload(result)
    assert prepared.metadata["source_revision_state"] == "clean"
    assert prepared.core_payload["source_revision_state"] == "clean"
    assert prepared.compatibility_payload["source_revision_state"] == "clean"
    assert prepared.metadata["commit_hash"] == sha

    extra = repo / "extra.py"
    extra.write_text("extra = True\n", encoding="utf-8")
    assert source_revision_state(result, str(repo), sha) == "dirty"
    extra.unlink()

    source.write_text("value = 2\n", encoding="utf-8")
    assert source_revision_state(result, str(repo), sha) == "dirty"
    assert api._prepare_report_upload(result).metadata["source_revision_state"] == "dirty"
    _git(repo, "add", "app.py")
    assert source_revision_state(result, str(repo), sha) == "dirty"


def test_upload_does_not_claim_exact_commit_for_partial_or_mismatched_scan(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "base")
    sha = _git(repo, "rev-parse", "HEAD")

    full = {"analysis_summary": {"comparison_scope": {
        "complete_repository": True, "repository_root": str(repo),
    }}}
    partial = {"analysis_summary": {"comparison_scope": {
        "complete_repository": False, "repository_root": str(repo),
    }}}
    assert source_revision_state(full, str(repo), "a" * 40) == "unknown"
    assert source_revision_state(partial, str(repo), sha) == "unknown"
    assert source_revision_state(full, None, sha) == "unknown"


def test_git_blob_reader_rejects_traversal_and_symlink_parent(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("secret = True\n", encoding="utf-8")
    (root / "redirect").symlink_to(outside, target_is_directory=True)

    root_fd = os.open(root, os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            _blob_oid(root_fd, b"../outside/secret.py", b"100644", 40, [1024])
        with pytest.raises((OSError, ValueError)):
            _blob_oid(root_fd, b"redirect/secret.py", b"100644", 40, [1024])
    finally:
        os.close(root_fd)
