"""A scanned repository's own Git config must never execute commands.

Skylos is run against repositories that may be hostile (auditors scan a target
company's code, often delivered as an archive that includes ``.git/``). Git
runs commands configured in the repository's own config during ordinary read
operations: ``core.fsmonitor``, clean/smudge/process filters selected by
``.gitattributes``, ``diff.external`` and per-driver ``diff.<d>.command`` /
``textconv``, ``core.pager``, ``core.sshCommand`` / ``credential.helper``, and
hooks. This fixture wires every one of those to a canary (an empty file created
by ``touch``) and asserts that running the real CLI entry points against the
repository creates no canary. See build-GIT-SAFETY.md for the mechanism.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from skylos.core import git_context as git_context_module
from skylos.core.git_context import GitContext
from skylos.core.git_safety import (
    _READ_ONLY_CONFIG_OVERRIDES,
    content_filter_config_overrides,
    needs_content_guard,
    read_only_git_command,
    read_only_git_environment,
    with_diff_guards,
    worktree_safe_git_command,
)
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.verification.refactor import _git as verification_git

REPO_ROOT = Path(__file__).resolve().parent.parent

# Each entry point runs with its own timeout; nothing may hang.
_CLI_TIMEOUT = 120


def _clean_environ() -> dict[str, str]:
    """The ambient environment minus Git, GitHub and Skylos variables.

    Ambient ``GIT_DIR``/``GIT_INDEX_FILE`` (pytest run from a Git hook) would
    point the fixture at the outer repository, a GitHub token would let
    ``cicd review`` post a real comment, and ``SKYLOS_TOKEN`` or
    ``SKYLOS_DIFF_BASE`` would change what the CLI does.
    """
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GIT_", "GH_", "GITHUB_", "SKYLOS_"))
    }


def _git(cwd: Path, *args: str, stdin: str | None = None) -> str:
    # Build the fixture with a clean environment so building it never fires a
    # canary (the malicious config is written afterwards).
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        input=stdin,
        capture_output=True,
        text=True,
        env={
            **_clean_environ(),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.com",
        },
    ).stdout


def _module(value: int) -> str:
    return (
        "import os\n\n\ndef used():\n"
        f"    return {value}\n\n\ndef unused_func():\n    return 2\n"
    )


def _commit_signed(repo: Path) -> None:
    """Commit the index as a commit carrying a (fake) signature: with
    ``log.showSignature`` set, ``git log``/``git show <commit>`` hand it to
    ``gpg.program``."""
    tree = _git(repo, "write-tree").strip()
    parent = _git(repo, "rev-parse", "HEAD").strip()
    signed = _git(
        repo,
        "hash-object",
        "-t",
        "commit",
        "-w",
        "--stdin",
        stdin=(
            f"tree {tree}\nparent {parent}\n"
            "author t <t@example.com> 1700000000 +0000\n"
            "committer t <t@example.com> 1700000000 +0000\n"
            "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n"
            " -----END PGP SIGNATURE-----\n\nsigned\n"
        ),
    ).strip()
    _git(repo, "update-ref", "HEAD", signed)


def _hostile_config(c, gpg_program: Path) -> str:
    """Every repository-config command vector, each wired to a canary."""
    return "\n".join(
        [
            "[core]",
            f"\tfsmonitor = touch {c('fsmonitor')}",
            f"\tpager = touch {c('pager')}; cat",
            f"\tsshCommand = touch {c('sshcommand')}",
            '[filter "evil"]',
            f"\tclean = touch {c('filter_clean')}; cat",
            f"\tsmudge = touch {c('filter_smudge')}; cat",
            f"\tprocess = touch {c('filter_process')}",
            "[diff]",
            f"\texternal = touch {c('diff_external')}",
            '[diff "evilconv"]',
            f"\ttextconv = touch {c('textconv')}",
            f"\tcommand = touch {c('diff_driver_cmd')}",
            "[alias]",
            f"\tstatus = !touch {c('alias')}; true",
            "[credential]",
            f"\thelper = !touch {c('credhelper')}; true",
            "[log]",
            "\tshowSignature = true",
            "[gpg]",
            f"\tprogram = {gpg_program}",
            "",
        ]
    )


def _write_hooks(repo: Path, c) -> None:
    hooks = repo / ".git" / "hooks"
    for hook in (
        "pre-commit",
        "post-checkout",
        "post-index-change",
        "fsmonitor-watchman",
        "post-merge",
        "reference-transaction",
    ):
        script = hooks / hook
        assert write_text_no_symlink(
            script, f"#!/bin/sh\ntouch {c('hook_' + hook.replace('-', '_'))}\n"
        )
        script.chmod(0o755)


def _write_history(repo: Path) -> None:
    """Written before the malicious config exists: three commits (the last one
    signed, and changing mod.py so ``HEAD~1...HEAD`` diffs have content), then
    a staged change so ``agent pre-commit`` reaches its cached diff, status and
    checkout-index snapshot paths."""
    assert write_text_no_symlink(repo / "mod.py", _module(1))
    assert write_text_no_symlink(repo / "tracked.txt", "hello\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "mod.py", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "init")
    assert write_text_no_symlink(repo / "mod.py", _module(5))
    _git(repo, "add", "mod.py")
    _git(repo, "commit", "-q", "-m", "second")
    assert write_text_no_symlink(repo / "mod.py", _module(6))
    _git(repo, "add", "mod.py")
    _commit_signed(repo)
    assert write_text_no_symlink(repo / "mod.py", _module(7))
    _git(repo, "add", "mod.py")


@pytest.fixture
def hostile_repo(tmp_path):
    """A repo whose config/attributes/hooks fire canaries if Git runs them.

    Returns ``(repo_path, canary_dir)``. ``canary_dir`` must stay empty.
    """
    repo = tmp_path / "repo"
    canary = tmp_path / "canary"
    repo.mkdir()
    canary.mkdir()

    def c(name: str) -> str:
        return str(canary / name)

    _write_history(repo)

    # gpg.program is executed directly (no shell), so it is a canary script.
    gpg_program = tmp_path / "gpg-program"
    gpg_program.write_text(f"#!/bin/sh\ntouch {c('gpg_program')}\nexit 1\n")
    gpg_program.chmod(0o755)
    with (repo / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write(_hostile_config(c, gpg_program))

    # Attributes select the filter + diff driver for every path, so any worktree
    # hashing or diff must run them unless they are neutralized. info/attributes
    # lives in the common Git dir, so it also applies to every temporary
    # worktree Skylos checks out (merge queue, done).
    for attributes in (repo / ".gitattributes", repo / ".git" / "info" / "attributes"):
        attributes.parent.mkdir(exist_ok=True)
        attributes.write_text("* filter=evil diff=evilconv\n", encoding="utf-8")
    # A worktree change so diffs and status have content to hash.
    (repo / "mod.py").write_text(_module(99), encoding="utf-8")
    (repo / "newfile.py").write_text("x = 1\n", encoding="utf-8")  # untracked

    _write_hooks(repo, c)
    return repo, canary


def _fired(canary: Path) -> list[str]:
    return sorted(p.name for p in canary.iterdir()) if canary.exists() else []


def _run_cli(repo: Path, *args: str) -> subprocess.CompletedProcess:
    """Run the real CLI against ``repo`` with an isolated HOME; never upload.

    A stub ``gh`` comes first on PATH: it answers ``--version`` (so ``cicd
    review`` reaches its Git diff) and fails everything else, so nothing can be
    posted even where a GitHub CLI is logged in.
    """
    home = repo.parent / "home"
    home.mkdir(exist_ok=True)
    stub_bin = repo.parent / "bin"
    stub_bin.mkdir(exist_ok=True)
    gh = stub_bin / "gh"
    assert write_text_no_symlink(
        gh,
        '#!/bin/sh\n[ "$1" = "--version" ] && echo "gh version 0.0.0" && exit 0\nexit 1\n',
    )
    gh.chmod(0o755)
    return subprocess.run(
        [sys.executable, "-m", "skylos.entry", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=_CLI_TIMEOUT,
        env={
            **_clean_environ(),
            "HOME": str(home),
            "PATH": f"{stub_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "PYTHONPATH": str(REPO_ROOT),
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )


# A valid, empty SARIF report so ``compare`` reaches its Git status read.
_EMPTY_SARIF = (
    '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[]}},'
    '"results":[]}]}'
)

# Each tuple is the CLI argv (run with cwd inside the hostile repo). These are
# the entry points that touch Git on an untrusted repository. ``{sarif}`` is
# replaced with a report written outside the repository.
_GIT_TOUCHING_ENTRY_POINTS = [
    pytest.param(["."], id="scan"),
    pytest.param([".", "--diff", "HEAD"], id="diff-head"),
    pytest.param([".", "--diff-base", "HEAD~1"], id="diff-base"),
    pytest.param([".", "-a", "--diff", "HEAD"], id="all-checks-diff"),
    pytest.param(["verify", "."], id="verify-behavior"),
    pytest.param(["verify", ".", "--diff", "HEAD"], id="verify-diff"),
    pytest.param(["provenance", "."], id="provenance"),
    pytest.param(["provenance", ".", "--diff-base", "HEAD~1"], id="provenance-base"),
    pytest.param(
        ["cicd", "review", ".", "--pr", "1", "--repo", "x/y", "--summary-only"],
        id="cicd-review",
    ),
    pytest.param(
        [
            "cicd",
            "review",
            ".",
            "--pr",
            "1",
            "--repo",
            "x/y",
            "--summary-only",
            "--diff-base",
            "HEAD~1",
        ],
        id="cicd-review-diff-base",
    ),
    pytest.param(["cicd", "gate", "."], id="cicd-gate"),
    pytest.param(["compare", ".", "--against", "{sarif}"], id="compare"),
    pytest.param(["done", ".", "--base", "HEAD~1"], id="done"),
    pytest.param(["agent", "pre-commit", "."], id="agent-pre-commit"),
    pytest.param(["debt", ".", "--changed"], id="debt-changed"),
]


@pytest.mark.parametrize("argv", _GIT_TOUCHING_ENTRY_POINTS)
def test_no_canary_fires_for_entry_point(hostile_repo, argv):
    repo, canary = hostile_repo
    sarif = repo.parent / "empty.sarif"
    sarif.write_text(_EMPTY_SARIF, encoding="utf-8")
    argv = [str(sarif) if arg == "{sarif}" else arg for arg in argv]
    try:
        _run_cli(repo, *argv)
    except subprocess.TimeoutExpired:  # pragma: no cover - would be a regression
        pytest.fail(f"CLI {argv!r} hung on the hostile repository")
    assert _fired(canary) == [], (
        f"CLI {argv!r} executed repository-configured Git commands: {_fired(canary)}"
    )


def test_scan_still_produces_results_on_hostile_repo(hostile_repo):
    """The guard degrades coverage at most; it must not blind the scan."""
    repo, canary = hostile_repo
    proc = _run_cli(repo, ".", "--format", "json")
    assert _fired(canary) == []
    import json

    payload = json.loads(proc.stdout)
    # The scan parsed the repository's Python and produced a structured result.
    assert isinstance(payload, dict)
    assert "analysis_summary" in payload or "unused_functions" in payload


# --------------------------------------------------------------------------
# Unit coverage for the hardened helper.
# --------------------------------------------------------------------------


def test_read_only_overrides_cover_every_vector():
    overrides = set(_READ_ONLY_CONFIG_OVERRIDES)
    assert "core.fsmonitor=false" in overrides
    assert f"core.hooksPath={os.devnull}" in overrides
    assert "core.pager=cat" in overrides
    assert "core.sshCommand=false" in overrides
    assert "credential.helper=" in overrides
    assert "protocol.allow=never" in overrides
    assert "diff.external=" in overrides
    assert "log.showSignature=false" in overrides
    assert "gpg.program=" in overrides
    command = read_only_git_command(["status"])
    assert command[0] == "git"
    assert "--no-optional-locks" in command
    assert "--no-pager" in command


def test_read_only_environment_strips_git_vars_and_sets_guards():
    env = read_only_git_environment({"GIT_DIR": "/evil", "PATH": "/usr/bin"})
    assert "GIT_DIR" not in env
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_PAGER"] == "cat"
    assert env["PATH"] == "/usr/bin"


def test_filter_overrides_enumerate_hostile_drivers(hostile_repo):
    repo, _ = hostile_repo
    overrides = content_filter_config_overrides(repo)
    assert overrides is not None
    assert "filter.evil.clean=" in overrides
    assert "filter.evil.smudge=" in overrides
    assert "filter.evil.process=" in overrides
    assert "filter.evil.required=false" in overrides
    assert "diff.evilconv.command=" in overrides
    assert "diff.evilconv.textconv=" in overrides


def test_filter_overrides_empty_for_clean_repo(tmp_path):
    repo = tmp_path / "clean"
    repo.mkdir()
    _git(repo, "init", "-q")
    assert content_filter_config_overrides(repo) == ()


def test_worktree_safe_command_adds_diff_guards(hostile_repo):
    repo, _ = hostile_repo
    command = worktree_safe_git_command(["diff", "HEAD"], repo)
    assert command is not None
    assert "--no-ext-diff" in command
    assert "--no-textconv" in command
    assert "-c" in command and "filter.evil.process=" in command


def test_gitcontext_status_does_not_execute_filters(hostile_repo):
    """Worktree-hashing and diff-rendering commands through GitContext fire
    no canary, and still succeed."""
    repo, canary = hostile_repo
    context = GitContext.from_path(repo)
    for args in (
        ("status", "--porcelain", "--untracked-files=all"),
        ("diff", "HEAD"),
        ("diff", "--name-only", "HEAD"),
        ("diff", "--cached", "HEAD"),
        ("log", "-p", "-2"),
        ("show", "HEAD"),
        ("blame", "mod.py"),
    ):
        result = context.run(*args)
        assert result.returncode == 0, (args, result.stderr)
    assert _fired(canary) == []


def test_gitcontext_refuses_content_commands_when_filters_unknown(
    hostile_repo, monkeypatch
):
    """When the filter config cannot be enumerated, only content-free plumbing
    runs; everything else is refused instead of running unneutralized."""
    repo, canary = hostile_repo
    monkeypatch.setattr(
        git_context_module, "content_filter_config_overrides", lambda *a, **k: None
    )
    context = GitContext.from_path(repo)
    assert context.filter_config_overrides is None
    for args in (
        ("status", "--porcelain"),
        ("diff", "HEAD"),
        ("log", "-p", "-1"),
        ("show", "HEAD"),
        ("blame", "mod.py"),
        ("ls-files", "-m"),
        ("cat-file", "--filters", "HEAD:mod.py"),
    ):
        result = context.run(*args)
        assert result.returncode == 2, args
        assert "filters" in result.stderr
    assert context.run("rev-parse", "HEAD").returncode == 0
    assert context.run("ls-tree", "HEAD").returncode == 0
    assert _fired(canary) == []


def test_worktree_safe_command_refuses_when_filters_unknown(hostile_repo, monkeypatch):
    repo, _ = hostile_repo
    monkeypatch.setattr(
        "skylos.core.git_safety.content_filter_config_overrides",
        lambda *a, **k: None,
    )
    assert worktree_safe_git_command(["status"], repo) is None
    assert worktree_safe_git_command(["diff", "HEAD"], repo) is None
    # Content-free plumbing never needs the filter inspection.
    assert worktree_safe_git_command(["rev-parse", "HEAD"], repo) is not None


def test_content_guard_classification():
    for args in (
        ["status"],
        ["diff", "--name-only"],
        ["log", "-p"],
        ["show", "HEAD:x"],
        ["blame", "x"],
        ["add", "x"],
        ["stash"],
        ["checkout-index", "--all"],
        ["describe", "--dirty"],
        ["-C", "repo", "rev-parse"],
        ["ls-files", "-m"],
        ["cat-file", "--textconv", "HEAD:x"],
        [],
    ):
        assert needs_content_guard(args), args
    for args in (
        ["rev-parse", "HEAD"],
        ["merge-base", "a", "b"],
        ["ls-tree", "-r", "HEAD"],
        ["cat-file", "blob", "abc"],
        ["ls-files", "--others", "--exclude-standard"],
        ["remote", "get-url", "origin"],
    ):
        assert not needs_content_guard(args), args


def test_diff_guards_injected_once():
    assert with_diff_guards(["diff", "HEAD"]) == [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "HEAD",
    ]
    assert with_diff_guards(["log", "--no-textconv", "-p"]) == [
        "log",
        "--no-ext-diff",
        "--no-textconv",
        "-p",
    ]
    assert with_diff_guards(["blame", "x"]) == ["blame", "--no-textconv", "x"]
    assert with_diff_guards(["status"]) == ["status"]


def test_verification_snapshot_diff_does_not_execute_filters(hostile_repo):
    """``skylos verify`` behavior comparison reads a worktree ``diff --raw``."""
    repo, canary = hostile_repo
    verification_git(
        repo, "diff", "--raw", "--no-ext-diff", "--no-textconv", "HEAD", "--"
    )
    verification_git(repo, "ls-files", "--stage", "-z")
    assert _fired(canary) == []


def test_merge_group_worktree_checkout_does_not_execute_filters(
    hostile_repo, monkeypatch
):
    """The merge-queue check checks a segment out with ``git worktree add``,
    which runs smudge/process filters unless they are neutralized."""
    from types import SimpleNamespace

    from skylos.cicd import merge_group

    repo, canary = hostile_repo
    head, base = subprocess.run(
        read_only_git_command(["rev-parse", "HEAD", "HEAD~1"]),
        cwd=str(repo),
        env=read_only_git_environment(),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    checked_out = []

    def fake_analyze_change(path, base_ref, config_ref=None):
        checked_out.extend(sorted(p.name for p in Path(path).iterdir()))
        return SimpleNamespace(complete=True, classes_incomplete=(), vetoes=())

    monkeypatch.setattr("skylos.cicd.approval.analyze_change", fake_analyze_change)

    segment = merge_group.Segment(1, base, head)
    assert merge_group._segment_vetoes(repo, segment, head) == []
    assert "mod.py" in checked_out
    assert _fired(canary) == []
