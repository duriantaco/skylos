"""Acceptance tests compare local Git snapshots without running fixture code."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.verification.changes import ComparisonTarget, compare_target_changes


_RETURN = "def run(callback, value):\n    return callback(value)\n"
_LOST_RETURN = "def run(callback, value):\n    callback(value)\n    return None\n"


def _git(repo: Path, *args: str) -> str:
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    return subprocess.run(
        [
            "git",
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def _write(repo: Path, name: str, source: str, *, encoding: str = "utf-8") -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source, encoding=encoding)


def _commit(repo: Path, *names: str) -> str:
    _git(repo, "add", "--", *names)
    _git(
        repo,
        "-c",
        "user.name=Skylos Test",
        "-c",
        "user.email=skylos-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "fixture snapshot",
    )
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def baseline_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is required")
    created = 0

    def create(files: dict[str, str] | None = None) -> tuple[Path, str]:
        nonlocal created
        created += 1
        repo = tmp_path / f"baseline repository {created}"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "feature")
        files = files or {"app.py": _RETURN}
        for name, source in files.items():
            _write(repo, name, source)
        commit = _commit(repo, *files)
        _git(repo, "branch", "comparison-base")
        return repo, commit

    return create


def _one(paths, **kwargs):
    reports = compare_target_changes(paths, **kwargs)
    assert len(reports) == 1
    return reports[0]


def _symbols(result):
    return [(item["file"], item["symbol"]) for item in result["comparisons"]]


def _assert_branch_identity(result, repo, baseline, head, *, ref_commit=None):
    assert result["base"]["ref"] == "comparison-base"
    assert result["base"]["commit"] == baseline
    assert result["current"]["kind"] == "commit"
    assert result["current"]["commit"] == head
    context = result["context"]
    assert Path(context["repository_root"]) == repo
    assert context["mode"] == "branch"
    assert context["base_ref"] == "comparison-base"
    assert context["base_ref_commit"] == (ref_commit or baseline)
    assert context["base_commit"] == baseline
    assert context["head_commit"] == head
    assert context["current_kind"] == "commit"
    assert context["current_commit"] == head


def test_local_return_loss_compares_head_with_working_sources(baseline_repo):
    repo, head = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)

    result = _one([repo / "app.py"])

    assert result["status"] == "different"
    assert _symbols(result) == [("app.py", "run")]
    assert result["base"]["ref"] == "HEAD"
    assert result["base"]["commit"] == head
    assert result["current"]["kind"] == "working_tree"
    assert result["current"]["commit"] is None
    context = result["context"]
    assert context["mode"] == "local"
    assert context["base_commit"] == context["head_commit"] == head
    assert context["current_kind"] == "working_tree"
    assert context["current_commit"] is None
    explanation = result["comparisons"][0]["differences"][0]["explanation"]
    assert explanation["title"] == "Callback result discarded"


def test_clean_committed_branch_retains_return_loss(baseline_repo):
    repo, baseline = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)
    head = _commit(repo, "app.py")

    result = _one([repo], base_ref="comparison-base")

    assert result["status"] == "different"
    assert _symbols(result) == [("app.py", "run")]
    _assert_branch_identity(result, repo, baseline, head)
    assert _one([repo])["status"] == "unchanged"


@pytest.mark.parametrize("staged", [False, True], ids=["working-tree", "index"])
def test_local_restoration_cannot_hide_committed_return_loss(baseline_repo, staged):
    repo, baseline = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)
    head = _commit(repo, "app.py")
    _write(repo, "app.py", _RETURN)
    if staged:
        _git(repo, "add", "--", "app.py")

    result = _one([repo / "app.py"], base_ref="comparison-base")

    assert result["status"] == "different"
    _assert_branch_identity(result, repo, baseline, head)
    assert (
        result["current"]["source_hashes"]["app.py"]
        == hashlib.sha256(_LOST_RETURN.encode()).hexdigest()
    )


def test_diverged_reference_uses_merge_base_not_reference_tip(baseline_repo):
    repo, common = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)
    feature = _commit(repo, "app.py")
    _git(repo, "switch", "-q", "comparison-base")
    _write(repo, "app.py", "def run(callback, value):\n    return 'base branch'\n")
    reference_tip = _commit(repo, "app.py")
    _git(repo, "switch", "-q", "feature")

    result = _one([repo], base_ref="comparison-base")

    assert result["status"] == "different"
    _assert_branch_identity(result, repo, common, feature, ref_commit=reference_tip)
    assert (
        result["base"]["source_hashes"]["app.py"]
        == hashlib.sha256(_RETURN.encode()).hexdigest()
    )


def test_reference_is_resolved_in_target_repo_from_another_cwd(
    baseline_repo, monkeypatch
):
    repo, baseline = baseline_repo()
    other, _ = baseline_repo({"elsewhere.py": "def elsewhere():\n    return None\n"})
    _write(repo, "app.py", _LOST_RETURN)
    head = _commit(repo, "app.py")
    monkeypatch.chdir(other)

    result = _one([str(repo / "app.py")], base_ref="comparison-base")

    assert result["status"] == "different"
    _assert_branch_identity(result, repo, baseline, head)


def test_committed_comparison_never_loads_working_sources(baseline_repo, monkeypatch):
    from skylos.verification import context

    repo, _ = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)
    _commit(repo, "app.py")

    def forbidden_working_read(*args, **kwargs):
        pytest.fail("Committed comparison must not read working source files")

    monkeypatch.setattr(context, "_current_sources", forbidden_working_read)

    assert _one([repo], base_ref="comparison-base")["status"] == "different"


def test_refs_moving_during_snapshot_loading_cannot_change_pinned_comparison(
    baseline_repo, monkeypatch
):
    from skylos.verification import context

    repo, baseline = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)
    head = _commit(repo, "app.py")
    _write(repo, "app.py", _RETURN)
    later_commit = _commit(repo, "app.py")
    _git(repo, "update-ref", "refs/heads/feature", head, later_commit)
    original_loader = context._base_sources
    moved = False

    def move_refs_after_pinning(root, commit, **kwargs):
        nonlocal moved
        if not moved:
            moved = True
            _git(repo, "update-ref", "refs/heads/feature", later_commit, head)
            _git(
                repo, "update-ref", "refs/heads/comparison-base", later_commit, baseline
            )
        return original_loader(root, commit, **kwargs)

    monkeypatch.setattr(context, "_base_sources", move_refs_after_pinning)

    result = _one([repo / "app.py"], base_ref="comparison-base")

    assert _git(repo, "rev-parse", "HEAD") == later_commit
    assert _git(repo, "rev-parse", "comparison-base") == later_commit
    assert result["status"] == "different"
    _assert_branch_identity(result, repo, baseline, head)
    assert (
        result["current"]["source_hashes"]["app.py"]
        == hashlib.sha256(_LOST_RETURN.encode()).hexdigest()
    )


def test_dirty_directory_cannot_reclassify_a_committed_file(baseline_repo):
    repo, _ = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)
    _commit(repo, "app.py")
    (repo / "app.py").unlink()
    (repo / "app.py").mkdir()

    result = _one([repo / "app.py"], base_ref="comparison-base")

    assert result["status"] == "different"
    assert _symbols(result) == [("app.py", "run")]
    assert result["context"]["scopes"][0]["directory"] is False


@pytest.mark.parametrize("selected", ["pkg", "pkg/app.py"])
def test_committed_deletion_remains_visible_when_local_scope_is_absent(
    baseline_repo, selected
):
    repo, _ = baseline_repo({"pkg/app.py": _RETURN, "other.py": _RETURN})
    (repo / "pkg/app.py").unlink()
    (repo / "pkg").rmdir()
    _commit(repo, "pkg/app.py")

    result = _one([repo / selected], base_ref="comparison-base")

    assert result["status"] in {"different", "unknown"}
    assert ("pkg/app.py", "run") in _symbols(result)
    assert result["context"]["scopes"][0]["directory"] is (selected == "pkg")


@pytest.mark.parametrize("mode", ["local", "branch"])
def test_overlapping_targets_compare_each_function_once(baseline_repo, mode):
    repo, _ = baseline_repo({"pkg/app.py": _RETURN, "pkg/other.py": _RETURN})
    _write(repo, "pkg/app.py", _LOST_RETURN)
    _write(repo, "pkg/other.py", _LOST_RETURN)
    if mode == "branch":
        _commit(repo, "pkg/app.py", "pkg/other.py")

    result = _one(
        [repo / "pkg", repo / "pkg/app.py", repo / "pkg"],
        base_ref="comparison-base" if mode == "branch" else None,
    )

    assert result["status"] == "different"
    assert sorted(_symbols(result)) == [("pkg/app.py", "run"), ("pkg/other.py", "run")]


def test_multiple_file_targets_keep_their_scope_and_omit_unselected_files(
    baseline_repo,
):
    repo, _ = baseline_repo({name: _RETURN for name in ("a.py", "b.py", "c.py")})
    for name in ("a.py", "b.py", "c.py"):
        _write(repo, name, _LOST_RETURN)
    _commit(repo, "a.py", "b.py", "c.py")

    result = _one([repo / "a.py", repo / "b.py"], base_ref="comparison-base")

    assert sorted(_symbols(result)) == [("a.py", "run"), ("b.py", "run")]
    assert {scope["selected"] for scope in result["context"]["scopes"]} == {
        "a.py",
        "b.py",
    }


def test_target_file_range_and_exclusions_survive_scope_resolution(baseline_repo):
    before = _RETURN + "\ndef second(value):\n    return value\n"
    after = _LOST_RETURN + "\ndef second(value):\n    return None\n"
    repo, _ = baseline_repo({"pkg/app.py": before, "pkg/ignored/skip.py": _RETURN})
    _write(repo, "pkg/app.py", after)
    _write(repo, "pkg/ignored/skip.py", _LOST_RETURN)
    _commit(repo, "pkg/app.py", "pkg/ignored/skip.py")

    result = _one(
        [ComparisonTarget(repo / "pkg", file="app.py", line_range="1:3")],
        base_ref="comparison-base",
        exclude_folders=["ignored"],
    )

    assert _symbols(result) == [("pkg/app.py", "run")]
    scope = result["context"]["scopes"][0]
    assert scope["selected"] == "pkg/app.py"
    assert scope["directory"] is False
    assert tuple(scope["line_range"]) == (1, 3)
    assert set(scope["exclude_folders"]) == {"ignored"}


def test_directory_exclusions_apply_to_committed_branch_changes(baseline_repo):
    repo, _ = baseline_repo({"pkg/app.py": _RETURN, "pkg/ignored/skip.py": _RETURN})
    _write(repo, "pkg/app.py", _LOST_RETURN)
    _write(repo, "pkg/ignored/skip.py", _LOST_RETURN)
    _commit(repo, "pkg/app.py", "pkg/ignored/skip.py")

    result = _one(
        [repo / "pkg"], base_ref="comparison-base", exclude_folders=["ignored"]
    )

    assert _symbols(result) == [("pkg/app.py", "run")]


def test_multiple_repositories_have_independent_commit_identities(baseline_repo):
    first, first_base = baseline_repo()
    second, second_base = baseline_repo({"other.py": _RETURN})
    _write(first, "app.py", _LOST_RETURN)
    first_head = _commit(first, "app.py")
    _write(second, "other.py", _LOST_RETURN)
    second_head = _commit(second, "other.py")

    reports = compare_target_changes(
        [first, second / "other.py"], base_ref="comparison-base"
    )

    assert len(reports) == 2
    by_root = {Path(report["context"]["repository_root"]): report for report in reports}
    for repo, baseline, head in (
        (first, first_base, first_head),
        (second, second_base, second_head),
    ):
        result = by_root[repo]
        assert result["status"] == "different"
        _assert_branch_identity(result, repo, baseline, head)


def test_unknown_reference_is_explicitly_unavailable(baseline_repo):
    repo, _ = baseline_repo()

    result = _one([repo], base_ref="refs/heads/not-present")

    assert result["status"] == "unavailable"
    assert result["reasons"]
    assert result["comparisons"] == []
    assert result["base"]["commit"] is None


def test_unavailable_repository_does_not_discard_another_repository_result(
    baseline_repo,
):
    available, _ = baseline_repo()
    unavailable, _ = baseline_repo({"other.py": _RETURN})
    _write(available, "app.py", _LOST_RETURN)
    _commit(available, "app.py")
    _git(unavailable, "branch", "-D", "comparison-base")

    reports = compare_target_changes(
        [unavailable, available], base_ref="comparison-base"
    )

    assert len(reports) == 2
    by_root = {Path(report["context"]["repository_root"]): report for report in reports}
    assert by_root[available]["status"] == "different"
    assert by_root[unavailable]["status"] == "unavailable"
    assert by_root[unavailable]["reasons"]


def test_non_git_target_does_not_discard_a_git_repository_result(
    baseline_repo, tmp_path
):
    repo, _ = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)
    _write(tmp_path, "plain/app.py", _RETURN)

    reports = compare_target_changes([tmp_path / "plain", repo])

    assert len(reports) == 2
    assert sorted(report["status"] for report in reports) == [
        "different",
        "unavailable",
    ]
    successful = next(report for report in reports if report["status"] == "different")
    assert Path(successful["context"]["repository_root"]) == repo


@pytest.mark.parametrize("base_ref", [None, "comparison-base"])
def test_non_git_target_is_explicitly_unavailable(tmp_path, base_ref):
    _write(tmp_path, "app.py", _RETURN)

    result = _one([tmp_path / "app.py"], base_ref=base_ref)

    assert result["status"] == "unavailable"
    assert result["reasons"]
    assert result["comparisons"] == []


@pytest.mark.parametrize("base_ref", [None, "HEAD"])
def test_unborn_repository_is_explicitly_unavailable(tmp_path, base_ref):
    _git(tmp_path, "init", "-q", "-b", "feature")
    _write(tmp_path, "app.py", _RETURN)

    result = _one([tmp_path], base_ref=base_ref)

    assert result["status"] == "unavailable"
    assert result["reasons"]
    assert result["comparisons"] == []


def test_shallow_missing_merge_history_is_explicitly_unavailable(baseline_repo):
    repo, _ = baseline_repo()
    _write(repo, "app.py", _LOST_RETURN)
    head = _commit(repo, "app.py")
    _write(repo, ".git/shallow", head + "\n")
    assert _git(repo, "rev-parse", "--is-shallow-repository") == "true"

    result = _one([repo], base_ref="comparison-base")

    assert result["status"] == "unavailable"
    assert result["reasons"]
    assert result["comparisons"] == []
    assert any(
        "shallow" in reason.lower() or "history" in reason.lower()
        for reason in result["reasons"]
    )


@pytest.mark.parametrize("mode", ["local", "branch"])
def test_snapshot_identity_hashes_exact_encoded_bytes(baseline_repo, mode):
    repo, _ = baseline_repo()
    before = "# coding: latin-1\r\ndef run(value):\r\n    return 'caf\u00e9'\r\n"
    after = "# coding: latin-1\r\ndef run(value):\r\n    return 'th\u00e9'\r\n"
    manifest = "[project]\r\nname = 'fixture'\r\nversion = '1.0'\r\n"
    _write(repo, "app.py", before, encoding="latin-1")
    _write(repo, "pyproject.toml", manifest)
    baseline = _commit(repo, "app.py", "pyproject.toml")
    _git(repo, "branch", "-f", "comparison-base", baseline)
    _write(repo, "app.py", after, encoding="latin-1")
    if mode == "branch":
        _commit(repo, "app.py")
        _write(repo, "app.py", _RETURN)

    result = _one(
        [repo / "app.py"], base_ref="comparison-base" if mode == "branch" else None
    )

    assert result["status"] == "different"
    assert (
        result["base"]["source_hashes"]["app.py"]
        == hashlib.sha256(before.encode("latin-1")).hexdigest()
    )
    assert (
        result["current"]["source_hashes"]["app.py"]
        == hashlib.sha256(after.encode("latin-1")).hexdigest()
    )
    expected_manifest_hash = hashlib.sha256(manifest.encode()).hexdigest()
    assert result["base"]["source_hashes"]["pyproject.toml"] == expected_manifest_hash
    assert (
        result["current"]["source_hashes"]["pyproject.toml"] == expected_manifest_hash
    )
