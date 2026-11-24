from hashlib import sha256
import json
from pathlib import Path
import subprocess

import pytest

from skylos.core import secret_history
from skylos.core.git_safety import read_only_git_environment


def _git(root, *args):
    return subprocess.check_output(
        ["git", *args],
        cwd=root,
        env=read_only_git_environment(),
        stderr=subprocess.PIPE,
        timeout=15,
        text=True,
    ).strip()


def _commit(root, message):
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD")


def _synthetic_token():
    return "gh" + "p_" + sha256(b"local-history-test-fixture").hexdigest()[:36]


def _findings(result):
    return {(row["file"], row["git_commit"]) for row in result["secrets"]}


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-q", "--initial-branch=main")
    _git(root, "config", "user.email", "history-fixture@example.invalid")
    _git(root, "config", "user.name", "Local fixture")
    (root / "README.md").write_text("History fixture\n", encoding="utf-8")
    _commit(root, "Initial commit")
    return root


def test_history_finds_deleted_blob_without_reading_worktree(repo):
    token = _synthetic_token()
    path = repo / "settings.env"
    path.write_text(f"API_TOKEN={token}\n", encoding="utf-8")
    historical_commit = _commit(repo, "Add settings")
    path.unlink()
    _commit(repo, "Delete settings")
    (repo / "untracked.env").write_text(f"API_TOKEN={token}\n", encoding="utf-8")

    result = secret_history.scan_git_history(repo)
    assert not result["analysis_errors"]
    assert _findings(result) == {("settings.env", historical_commit)}
    assert result["analysis_summary"]["git_history"]["commits_scanned"] == 3
    assert token not in json.dumps(result)
    assert _findings(secret_history.scan_git_history(path)) == _findings(result)


def test_repeated_blob_reports_once_in_each_path_context(repo):
    token = _synthetic_token()
    for folder in ("a", "b"):
        (repo / folder).mkdir()
        (repo / folder / "same.py").write_text(f'TOKEN = "{token}"\n', encoding="utf-8")
    _commit(repo, "Add two copies")
    (repo / "other.py").write_text("SAFE_NUMBER = 1\n", encoding="utf-8")
    head = _commit(repo, "Another snapshot with the same copies")

    full = secret_history.scan_git_history(repo)
    assert _findings(full) == {("a/same.py", head), ("b/same.py", head)}
    assert len({item["git_blob"] for item in full["secrets"]}) == 1
    assert not full["analysis_errors"]
    scoped = secret_history.scan_git_history(repo / "b")
    assert _findings(scoped) == {("b/same.py", head)}
    assert scoped["analysis_summary"]["git_history"]["scope"] == "b"


def test_scoped_history_keeps_lexical_path_across_worktree_symlink(repo, tmp_path):
    directory = repo / "historical"
    directory.mkdir()
    former = directory / "settings.env"
    former.write_text(f"TOKEN={_synthetic_token()}\n", encoding="utf-8")
    historical = _commit(repo, "Add historical settings")
    former.unlink()
    directory.rmdir()
    outside = tmp_path / "unrelated"
    outside.mkdir()
    directory.symlink_to(outside, target_is_directory=True)
    _commit(repo, "Replace historical directory with a link")

    scoped = secret_history.scan_git_history(former)
    assert _findings(scoped) == {("historical/settings.env", historical)}
    assert scoped["analysis_summary"]["git_history"]["scope"] == "historical/settings.env"


def test_merge_visits_side_branch_snapshot_and_ref_can_select_it(repo):
    _git(repo, "checkout", "-qb", "side")
    text = repo / "removed.txt"
    text.write_text(f"{_synthetic_token()}\n", encoding="utf-8")
    side = _commit(repo, "Fixture exists on the side branch")
    text.unlink()
    _commit(repo, "Remove side branch fixture")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "-q", "--no-ff", "side")

    result = secret_history.scan_git_history(repo)
    assert _findings(result) == {("removed.txt", side)}
    assert result["analysis_summary"]["git_history"]["commits_scanned"] == 4
    limited = secret_history.scan_git_history(repo, ref=side, max_commits=1)
    assert _findings(limited) == {("removed.txt", side)}
    assert limited["analysis_summary"]["git_history"]["status"] == "incomplete"
    assert {row["kind"] for row in limited["analysis_errors"]} == {"history_commit_limit"}


def test_shallow_and_missing_ref_report_incomplete(repo, tmp_path):
    (repo / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    _commit(repo, "Second commit")
    shallow = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth=1", repo.as_uri(), str(shallow))

    result = secret_history.scan_git_history(shallow)
    assert result["analysis_summary"]["git_history"]["shallow"] is True
    assert result["analysis_summary"]["git_history"]["status"] == "incomplete"
    assert {row["kind"] for row in result["analysis_errors"]} == {"history_shallow"}
    unavailable = secret_history.scan_git_history(repo, ref="missing-test-ref")
    assert unavailable["analysis_summary"]["git_history"]["commits_scanned"] == 0
    assert unavailable["analysis_errors"]
    assert secret_history.scan_git_history(tmp_path)["analysis_errors"]


def test_historical_blobs_skip_nul_binary_and_links_and_keep_utf16(repo):
    token = _synthetic_token()
    (repo / "binary.py").write_bytes(b"\x00" + token.encode())
    (repo / "link.py").symlink_to(token)
    (repo / "wide.env").write_bytes(f"API_TOKEN={token}\n".encode("utf-16"))
    head = _commit(repo, "Add binary, link and wide text")
    result = secret_history.scan_git_history(repo)
    assert _findings(result) == {("wide.env", head)}
    assert result["secrets"][0]["source_encoding"] in {"utf16le", "utf16be"}
    coverage = result["analysis_summary"]["git_history"]
    assert coverage["binary_blobs_skipped"] == 1
    assert coverage["nonregular_entries_skipped"] == 1
    assert coverage["status"] == "complete"


def test_supported_suffixless_sources_are_not_subject_to_shebang_guard(repo):
    token = _synthetic_token()
    for filename in ("Dockerfile", "Containerfile"):
        (repo / filename).write_text(f"ENV TOKEN={token}\n", encoding="utf-8")
    (repo / "script").write_text(f"#!/bin/sh\nTOKEN={token}\n", encoding="utf-8")
    (repo / "plain").write_text(f"Only a text file: {token}\n", encoding="utf-8")
    head = _commit(repo, "Add supported suffixless paths")
    result = secret_history.scan_git_history(repo)
    assert _findings(result) == {
        ("Containerfile", head), ("Dockerfile", head), ("script", head)
    }


def test_missing_object_and_size_limits_report_incomplete(repo, monkeypatch):
    path = repo / "oversized.txt"
    path.write_text("large for this test\n", encoding="utf-8")
    _commit(repo, "Add source to be limited")
    monkeypatch.setattr(secret_history, "_MAX_BLOB_BYTES", 5)
    limited = secret_history.scan_git_history(repo)
    assert any(row["kind"] == "history_blob_limit" for row in limited["analysis_errors"])
    assert limited["analysis_summary"]["git_history"]["status"] == "incomplete"

    object_id = _git(repo, "rev-parse", "HEAD:oversized.txt")
    git_dir = Path(_git(repo, "rev-parse", "--absolute-git-dir"))
    (git_dir / "objects" / object_id[:2] / object_id[2:]).unlink()
    broken = secret_history.scan_git_history(repo)
    assert broken["analysis_errors"]
    assert broken["analysis_summary"]["git_history"]["status"] == "incomplete"


def test_finding_cap_stops_further_blob_scans(repo, monkeypatch):
    for filename in ("a.py", "b.py", "c.py"):
        (repo / filename).write_text(f'TOKEN = "{_synthetic_token()}"\n', encoding="utf-8")
    _commit(repo, "Add three historical occurrences")
    monkeypatch.setattr(secret_history, "_MAX_FINDINGS", 1)
    visited = []
    original_scan = secret_history.scan_ctx

    def scan(ctx):
        visited.append(ctx["relpath"])
        return original_scan(ctx)

    monkeypatch.setattr(secret_history, "scan_ctx", scan)
    result = secret_history.scan_git_history(repo)
    assert len(result["secrets"]) == 1
    assert visited == ["README.md", "a.py", "b.py"]
    assert result["analysis_summary"]["git_history"]["status"] == "incomplete"
    assert "finding limit" in result["analysis_errors"][0]["message"]


@pytest.mark.parametrize("ref", ["", " ", "HEAD\n", "x" * 1025])
def test_bad_ref_argument_is_rejected_before_running_git(repo, ref):
    with pytest.raises(ValueError, match="printable Git revision"):
        secret_history.scan_git_history(repo, ref=ref)


def test_revision_range_is_rejected_as_not_a_single_commit(repo):
    assert "resolve" in secret_history.scan_git_history(
        repo, ref="HEAD..HEAD"
    )["analysis_errors"][0]["message"]


def test_git_history_never_uses_worktree_attribute_filters(repo):
    (repo / ".gitattributes").write_text("*.py filter=fixture diff=fixture\n", encoding="utf-8")
    (repo / "app.py").write_text(f'TOKEN = "{_synthetic_token()}"\n', encoding="utf-8")
    head = _commit(repo, "Add historical source and attributes")
    for key in ("filter.fixture.clean", "filter.fixture.smudge", "diff.fixture.textconv"):
        _git(repo, "config", key, "touch should-not-run")
    result = secret_history.scan_git_history(repo)
    assert _findings(result) == {("app.py", head)}
    assert not (repo / "should-not-run").exists()


def test_legacy_graph_overrides_do_not_prune_committed_ancestry(repo):
    path = repo / "historical.env"
    path.write_text(f"TOKEN={_synthetic_token()}\n", encoding="utf-8")
    historical = _commit(repo, "Commit a historical fixture")
    path.unlink()
    head = _commit(repo, "Delete the fixture")
    git_dir = Path(_git(repo, "rev-parse", "--absolute-git-dir"))
    (git_dir / "info" / "grafts").write_text(head + "\n", encoding="utf-8")
    result = secret_history.scan_git_history(repo)
    assert _findings(result) == {("historical.env", historical)}
