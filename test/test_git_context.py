import os
import subprocess
from pathlib import Path

import pytest

from skylos.core.git_context import GitContext
from skylos.core.safe_cache_io import write_text_no_symlink


_CONTEXT_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
    "GIT_INDEX_FILE",
)


def _git(root, *args, index_file=None):
    env = dict(os.environ)
    for key in _CONTEXT_ENV:
        env.pop(key, None)
    if index_file is not None:
        env["GIT_INDEX_FILE"] = str(index_file)
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for key in _CONTEXT_ENV:
        monkeypatch.delenv(key, raising=False)
    root = tmp_path / "working repo"
    root.mkdir()
    _git(root, "init", "-q")
    package = root / "package"
    package.mkdir()
    assert write_text_no_symlink(package / "tracked.py", "value = 1\n")
    _git(root, "add", "package/tracked.py")
    _git(
        root,
        "-c",
        "user.name=Skylos Test",
        "-c",
        "user.email=skylos-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "fixture",
    )
    monkeypatch.chdir(root)
    return root


@pytest.mark.parametrize("relative_selector", [False, True])
@pytest.mark.parametrize("single_file", [False, True])
def test_hook_context_keeps_worktree_root(
    repo, monkeypatch, relative_selector, single_file
):
    selector = ".git" if relative_selector else str(repo / ".git")
    monkeypatch.setenv("GIT_DIR", selector)
    target = repo / "package"
    if single_file:
        target /= "tracked.py"

    context = GitContext.from_path(target)

    assert context.root == repo
    assert context.run("rev-parse", "--show-toplevel").stdout.strip() == str(repo)
    assert context.run("diff", "--name-only", "HEAD").stdout == ""
    assert os.environ["GIT_DIR"] == selector


def test_real_modification_survives_hook_context(repo, monkeypatch):
    monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
    source = repo / "package" / "tracked.py"
    assert write_text_no_symlink(source, "value = 2\n")

    result = GitContext.from_path(source).run("diff", "--name-only", "-z", "HEAD")

    assert result.returncode == 0
    assert result.stdout == "package/tracked.py\0"


def test_relative_alternate_index_follows_original_git_context(repo, monkeypatch):
    alternate = repo / ".git" / "alternate index"
    _git(repo, "read-tree", "HEAD", index_file=alternate)
    monkeypatch.chdir(repo / "package")
    monkeypatch.setenv("GIT_INDEX_FILE", ".git/alternate index")

    context = GitContext.from_path(repo / "package")

    assert context.env["GIT_INDEX_FILE"] == str(alternate)
    assert context.run("ls-files", "-z").stdout == "package/tracked.py\0"


def test_relative_alternate_index_with_explicit_git_dir(repo, monkeypatch):
    alternate = repo / ".git" / "alternate index"
    _git(repo, "read-tree", "HEAD", index_file=alternate)
    monkeypatch.chdir(repo / "package")
    monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", "../.git/alternate index")

    context = GitContext.from_path(repo / "package")

    assert context.env["GIT_INDEX_FILE"] == str(alternate)
    assert context.run("ls-files", "-z").stdout == "package/tracked.py\0"


def test_linked_worktree_does_not_inherit_other_worktrees_index(repo, monkeypatch):
    linked = repo.parent / "linked worktree"
    _git(repo, "worktree", "add", "--detach", str(linked), "HEAD")
    monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(repo))
    monkeypatch.setenv("GIT_INDEX_FILE", str(repo / ".git" / "index"))

    context = GitContext.from_path(linked / "package")

    assert (linked / ".git").is_file()
    assert context.root == linked
    assert "GIT_INDEX_FILE" not in context.env
    assert context.run("rev-parse", "--show-toplevel").stdout.strip() == str(linked)
    assert context.run("diff", "--name-only", "HEAD").stdout == ""


def test_markerless_explicit_worktree_with_external_git_dir(repo, monkeypatch):
    worktree = repo.parent / "external working tree"
    git_dir = repo.parent / "external metadata"
    worktree.mkdir()
    git_dir.mkdir()
    _git(
        worktree, "--git-dir", str(git_dir), "--work-tree", str(worktree), "init", "-q"
    )
    monkeypatch.setenv("GIT_DIR", str(git_dir))
    monkeypatch.setenv("GIT_WORK_TREE", str(worktree))

    context = GitContext.from_path(worktree)

    assert not (worktree / ".git").exists()
    assert context.root == worktree
    assert context.run("rev-parse", "--show-toplevel").stdout.strip() == str(worktree)


def test_nonrepo_fallback_does_not_use_unrelated_git_dir(repo, monkeypatch):
    target = repo.parent / "not a repo"
    target.mkdir()
    monkeypatch.setenv("GIT_DIR", str(repo / ".git"))

    context = GitContext.from_path(target)

    assert context.root == target
    assert context.run("rev-parse", "--show-toplevel").returncode != 0


def test_relative_paths_preserve_names_and_reject_outside_files(repo):
    context = GitContext.from_path(repo / "package")

    assert context.relative_path(repo / "package" / 'a "quoted" name.py') == (
        'package/a "quoted" name.py'
    )
    assert context.relative_path(repo.parent / "outside.py") is None
    assert context.relative_path(Path("package") / "tracked.py") == "package/tracked.py"
