from __future__ import annotations

import io
import json
import os
import subprocess
from pathlib import Path

import pytest

from skylos.commands.hook_cmd import HookDeps, run_hook_command
from skylos.commands.hook_git_bypass import git_hooks_dir, hook_bypasses
from skylos.commands.hook_shell_commands import simple_commands
from skylos.core.safe_cache_io import write_text_no_symlink


def _hooks(directory: Path, *names: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = directory / name
        path.write_text("#!/bin/sh\nexit 0\n")  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
        path.chmod(0o755)
    return directory


@pytest.fixture
def repo(tmp_path) -> Path:
    (tmp_path / ".git").mkdir()
    _hooks(tmp_path / ".git" / "hooks", "pre-commit", "commit-msg", "pre-push")
    return tmp_path


def _bypasses(command: str, repo: Path, hooks: Path | None = None):
    directory = hooks if hooks is not None else repo / ".git" / "hooks"
    return hook_bypasses(
        simple_commands(command, repo), hooks_dir=lambda _cwd: directory
    )


BLOCKED = [
    "git commit --no-verify -m 'wip'",
    "git commit -m wip --no-verify",
    "git commit -n -m wip",
    "git commit -nm wip",
    "git commit -anm wip",
    "git commit -qan -m wip",
    "git commit --no-veri -m wip",
    "git commit --amend --no-edit --no-verify",
    "git push --no-verify",
    "git push origin main --no-verify",
    "git -C . commit --no-verify -m x",
    "git -c core.hooksPath=/dev/null commit -m x",
    "git -c core.HooksPath=/dev/null commit -m x",
    "git -c core.hooksPath= commit -m x",
    "git -c core.hooksPath=/tmp/empty commit -m x",
    "git -c core.hooksPath=/dev/null push",
    "git --config-env=core.hooksPath=EMPTY commit -m x",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x",
    "GIT_CONFIG_PARAMETERS=\"'core.hooksPath'='/dev/null'\" git commit -m x",
    "bash -c 'git commit --no-verify -m x'",
    "cd sub && git commit --no-verify -m x",
    "git add -A && git commit -m 'fix' --no-verify && git push",
    "git commit -m 'fix' \\\n  --no-verify",
    "git config core.hooksPath /dev/null",
    "git config --local core.hooksPath /tmp/nothing",
    "git config --global core.hooksPath /dev/null",
    "git config set core.hooksPath /dev/null",
    "git config alias.ci 'commit --no-verify'",
    "rm .git/hooks/pre-commit",
    "rm -f .git/hooks/pre-push",
    "rm -rf .git/hooks",
    "mv .git/hooks/pre-commit /tmp/",
    "chmod -x .git/hooks/pre-commit",
    "chmod a-x .git/hooks/commit-msg",
    "chmod 644 .git/hooks/pre-commit",
]


@pytest.mark.parametrize("command", BLOCKED)
def test_hook_bypasses_are_found(repo, command):
    (repo / "sub").mkdir(exist_ok=True)
    found = _bypasses(command, repo)
    assert found, command
    assert all(b.hooks for b in found)


ALLOWED = [
    "git commit -m 'wip'",
    "git commit -am 'fix -n flag handling'",
    "git commit -amn",  # -m takes "n" as the message
    "git commit -m 'skip --no-verify in docs'",
    "git commit -m --no-verify",
    "git commit -m '-n'",
    "git commit -am '-n'",
    "git merge -m '--no-verify' feature",
    "git rebase --exec 'git commit --amend --no-edit' main",
    "git commit --no-verify --verify -m x",  # the last one wins
    "git push -n",  # dry run, not --no-verify
    "git push --dry-run",
    "git log -n 5",
    "git status",
    "git diff --no-ext-diff",
    "git merge --no-ff feature",
    "git rebase -i HEAD~3",
    "git stash",
    "git -c user.name=x commit -m y",
    "git -c core.editor=vim commit",
    "HUSKY=0 npm ci",
    "HUSKY=0 npm install",
    "SKIP=1 make test",
    "LEFTHOOK=1 npm install",
    "LEFTHOOK=0 npm run build",
    "SKIP= git commit -m x",
    "HUSKY=1 git commit -m x",
    "git config core.hooksPath",
    "git config --get core.hooksPath",
    "git config user.email me@example.com",
    "git config alias.st status",
    "rm -rf node_modules",
    "rm .git/hooks/pre-commit.sample",
    "chmod +x .git/hooks/pre-commit",
    "chmod 755 .git/hooks/pre-commit",
    "echo git commit --no-verify",
    "grep -rn 'no-verify' .",
    "pre-commit run --all-files",
    "npx husky init",
]


@pytest.mark.parametrize("command", ALLOWED)
def test_normal_git_commands_are_not_bypasses(repo, command):
    assert _bypasses(command, repo) == [], command


# Hook-manager skip switches, with the files that show each manager in use.
MANAGER_SWITCHES = [
    ("husky", "HUSKY=0 git commit -m x"),
    ("husky", "HUSKY=0 git push"),
    ("husky", "export HUSKY=0 && git commit -m x"),
    ("husky", "export HUSKY=0; git add . && git commit -m x"),
    ("husky", "env HUSKY=0 git commit -m x"),
    ("husky", 'sh -c "HUSKY=0 git commit -m x"'),
    ("husky", "HUSKY_SKIP_HOOKS=1 git commit -m x"),
    ("pre-commit", "SKIP=pytest git commit -m x"),
    ("pre-commit", "SKIP=ruff,mypy git commit -m x"),
    ("pre-commit", "PRE_COMMIT_ALLOW_NO_CONFIG=1 git commit -m x"),
    ("overcommit", "SKIP=rubocop git commit -m x"),
    ("overcommit", "OVERCOMMIT_DISABLE=1 git commit -m x"),
    ("lefthook", "LEFTHOOK=0 git commit -m x"),
    ("lefthook", "LEFTHOOK=false git push"),
    ("lefthook", "LEFTHOOK_EXCLUDE=tests git commit -m x"),
    ("simple-git-hooks", "SKIP_SIMPLE_GIT_HOOKS=1 git commit -m x"),
]
MANAGER_FILES = {
    "husky": ".husky/pre-commit",
    "pre-commit": ".pre-commit-config.yaml",
    "overcommit": ".overcommit.yml",
    "lefthook": "lefthook.yml",
    "simple-git-hooks": ".simple-git-hooks.json",
}


@pytest.mark.parametrize("manager,command", MANAGER_SWITCHES)
def test_manager_switch_is_a_bypass_when_the_manager_is_in_use(
    repo, manager, command
):
    path = repo / MANAGER_FILES[manager]
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, "x\n")
    found = _bypasses(command, repo)
    assert found, command
    assert all(b.hooks for b in found)


@pytest.mark.parametrize("manager,command", MANAGER_SWITCHES)
def test_manager_switch_is_allowed_with_plain_git_hooks(repo, manager, command):
    # A plain .git/hooks script never reads HUSKY, SKIP, LEFTHOOK...
    assert _bypasses(command, repo) == [], command


def test_switch_of_another_manager_is_allowed(repo):
    assert write_text_no_symlink(repo / "lefthook.yml", "pre-commit: {}\n")
    assert _bypasses("HUSKY=0 git commit -m x", repo) == []
    assert _bypasses("LEFTHOOK=0 git commit -m x", repo)


@pytest.mark.parametrize(
    "manager,script,command",
    [
        ("husky v4", '#!/bin/sh\n# husky\n. "$(dirname "$0")/husky.sh"\n',
         "HUSKY_SKIP_HOOKS=1 git commit -m x"),
        ("lefthook", '#!/bin/sh\nlefthook run "pre-commit" "$@"\n',
         "LEFTHOOK=0 git commit -m x"),
        ("pre-commit", ("#!/usr/bin/env bash\n# File generated by pre-commit: "
         "https://pre-commit.com\nexec python3 -mpre_commit hook-impl\n"),
         "PRE_COMMIT_ALLOW_NO_CONFIG=1 git commit -m x"),
        ("simple-git-hooks", ('#!/bin/sh\nif [ "$SKIP_SIMPLE_GIT_HOOKS" = "1" ]; '
         "then exit 0; fi\nnpm test\n"), "SKIP_SIMPLE_GIT_HOOKS=1 git commit -m x"),
    ],
)  # fmt: skip
def test_hook_script_that_runs_the_manager_counts_without_its_config(
    tmp_path, manager, script, command
):
    hooks = _hooks(tmp_path / ".git" / "hooks", "pre-commit")
    assert write_text_no_symlink(hooks / "pre-commit", script)
    assert _bypasses(command, tmp_path), manager


def test_husky_hooks_path_counts_without_any_other_file(tmp_path):
    (tmp_path / ".git").mkdir()
    hooks = _hooks(tmp_path / "config" / ".husky", "pre-commit")
    assert _bypasses("HUSKY=0 git commit -m x", tmp_path, hooks=hooks)


def test_simple_git_hooks_in_package_json_counts(repo):
    package = '{"simple-git-hooks": {"pre-commit": "x"}}'
    assert write_text_no_symlink(repo / "package.json", package)
    assert _bypasses("SKIP_SIMPLE_GIT_HOOKS=1 git commit -m x", repo)


def test_unreadable_hook_script_assumes_every_manager(tmp_path):
    # A hook git runs through a symlink is not read, so its manager is
    # unknown: every switch counts (fail closed).
    script = _hooks(tmp_path / "scripts", "pre-commit") / "pre-commit"
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(parents=True)
    if os.name != "nt":
        (hooks / "pre-commit").symlink_to(script)
        assert _bypasses("HUSKY=0 git commit -m x", tmp_path)


def test_unknown_hooks_dir_assumes_every_manager(tmp_path):
    found = hook_bypasses(
        simple_commands("HUSKY=0 git commit -m x", tmp_path),
        hooks_dir=lambda _cwd: None,
    )
    assert found and found[0].how == "HUSKY=0"


def test_bypass_needs_an_installed_hook(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    (tmp_path / ".git" / "hooks" / "pre-commit.sample").write_text("#!/bin/sh\n")
    for command in ("git commit --no-verify -m x", "HUSKY=0 git commit -m x",
                    "git push --no-verify"):  # fmt: skip
        assert _bypasses(command, tmp_path) == [], command


def test_no_verify_only_counts_hooks_it_skips(tmp_path):
    _hooks(tmp_path / ".git" / "hooks", "pre-push")
    assert _bypasses("git commit --no-verify -m x", tmp_path) == []
    (found,) = _bypasses("git push --no-verify", tmp_path)
    assert found.hooks == ("pre-push",)


def test_non_executable_hook_does_not_run_and_is_not_bypassed(tmp_path):
    hooks = _hooks(tmp_path / ".git" / "hooks", "pre-commit")
    (hooks / "pre-commit").chmod(0o644)
    if os.name != "nt":
        assert _bypasses("git commit --no-verify -m x", tmp_path) == []


def test_husky_stub_counts_only_with_user_script(tmp_path):
    stubs = _hooks(tmp_path / ".husky" / "_", "pre-commit", "pre-push", "commit-msg")
    (tmp_path / ".husky" / "pre-commit").write_text("npm test\n")
    found = _bypasses("HUSKY=0 git push", tmp_path, hooks=stubs)
    assert found == []
    (found,) = _bypasses("HUSKY=0 git commit -m x", tmp_path, hooks=stubs)
    assert found.hooks == ("pre-commit",)


def test_hooks_path_pointing_at_the_same_hooks_is_allowed(tmp_path):
    hooks = _hooks(tmp_path / ".githooks", "pre-commit")
    (tmp_path / ".git").mkdir()
    assert _bypasses("git config core.hooksPath .githooks", tmp_path, hooks=hooks) == []
    assert (
        _bypasses("git -c core.hooksPath=.githooks commit -m x", tmp_path, hooks=hooks)
        == []
    )


def test_unknown_hooks_dir_assumes_hooks_exist(tmp_path):
    found = hook_bypasses(
        simple_commands("git commit --no-verify -m x", tmp_path),
        hooks_dir=lambda _cwd: None,
    )
    assert found and "pre-commit" in found[0].hooks


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_git_hooks_dir_follows_core_hooks_path(tmp_path):
    try:
        _git(tmp_path, "init", "-q")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    assert git_hooks_dir(tmp_path).resolve() == (tmp_path / ".git" / "hooks").resolve()
    _git(tmp_path, "config", "core.hooksPath", ".husky/_")
    (tmp_path / "sub").mkdir()
    assert (
        git_hooks_dir(tmp_path / "sub").resolve()
        == (tmp_path / ".husky" / "_").resolve()
    )
    assert git_hooks_dir(tmp_path.parent / "definitely-missing-dir") is None


def test_real_repository_end_to_end(tmp_path):
    try:
        _git(tmp_path, "init", "-q")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    found = hook_bypasses(simple_commands("git commit --no-verify -m x", tmp_path))
    assert found == []  # fresh repo: only .sample hooks
    _hooks(tmp_path / ".git" / "hooks", "pre-commit")
    found = hook_bypasses(simple_commands("git commit --no-verify -m x", tmp_path))
    assert found and found[0].hooks == ("pre-commit",)


# --------------------------------------------------------------------------
# Through the hook entry point
# --------------------------------------------------------------------------


def _run(tmp_path, command, *, client="claude", pyproject=None, hooks=None):
    if pyproject is not None:
        (tmp_path / "pyproject.toml").write_text(pyproject)  # skylos: ignore[SKY-D324] test fixture under pytest tmp_path
    stdout = io.StringIO()
    directory = hooks if hooks is not None else tmp_path / ".git" / "hooks"
    deps = HookDeps(
        env={"CLAUDE_PROJECT_DIR": str(tmp_path), "HOME": str(tmp_path / "home")},
        hooks_dir=lambda _cwd: directory,
    )
    if client == "cursor":
        payload = {"hook_event_name": "beforeShellExecution", "command": command,
                   "cwd": str(tmp_path)}  # fmt: skip
    else:
        payload = {"session_id": "s1", "tool_name": "Bash",
                   "tool_input": {"command": command}, "cwd": str(tmp_path)}  # fmt: skip
        if client == "codex":
            payload["turn_id"] = "t1"
    code = run_hook_command(
        ["pre-bash", "--client", client],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    text = stdout.getvalue().strip()
    return code, (json.loads(text) if text else None)


@pytest.mark.parametrize("client", ["claude", "codex"])
def test_hook_denies_no_verify(repo, client):
    code, out = _run(repo, "git commit --no-verify -m wip", client=client)
    assert code == 0
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny"
    reason = spec["permissionDecisionReason"]
    assert "--no-verify" in reason and "pre-commit" in reason
    assert "without the bypass" in reason


def test_hook_denies_bypass_in_cursor(repo):
    (repo / ".husky").mkdir()
    _, out = _run(repo, "HUSKY=0 git commit -m wip", client="cursor")
    assert out["permission"] == "deny"
    assert "HUSKY=0" in out["agent_message"]


def test_hook_allows_husky_switch_without_husky(repo):
    _, out = _run(repo, "HUSKY=0 git commit -m wip")
    assert out is None


def test_hook_allows_plain_commit(repo):
    _, out = _run(repo, "git commit -m wip")
    assert out is None


def test_bypass_block_can_be_turned_off(repo):
    _, out = _run(
        repo,
        "git commit --no-verify -m wip",
        pyproject="[tool.skylos.hooks]\nblock_hook_bypass = false\n",
    )
    assert out is None


def test_invalid_bypass_setting_keeps_blocking(repo):
    _, out = _run(
        repo,
        "git commit --no-verify -m wip",
        pyproject="[tool.skylos.hooks]\nblock_hook_bypass = 'no'\n",
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bypass_log_has_no_command_text(repo):
    _run(repo, "git commit --no-verify -m 'secret message'")
    log = (repo / ".skylos" / "hook.log").read_text()
    entry = json.loads(log.splitlines()[-1])
    assert entry["outcome"] == "block-bypass"
    assert "secret message" not in log


def test_hooks_path_to_another_hooks_directory_is_allowed(tmp_path):
    # "git config core.hooksPath .githooks" switches to the repo's own hooks.
    (tmp_path / ".git").mkdir()
    current = _hooks(tmp_path / ".git" / "hooks", "pre-commit", "pre-push")
    _hooks(tmp_path / ".githooks", "pre-push")
    assert (
        _bypasses("git config core.hooksPath .githooks", tmp_path, hooks=current) == []
    )
    (tmp_path / "empty").mkdir()
    assert _bypasses("git config core.hooksPath empty", tmp_path, hooks=current)
    assert _bypasses("git config core.hooksPath missing-dir", tmp_path, hooks=current)


def test_unset_hooks_path_counts_only_when_one_is_set(tmp_path):
    (tmp_path / ".git").mkdir()
    default = _hooks(tmp_path / ".git" / "hooks", "pre-commit")
    assert _bypasses("git config --unset core.hooksPath", tmp_path, hooks=default) == []
    husky = _hooks(tmp_path / ".husky" / "_", "pre-commit")
    (tmp_path / ".husky" / "pre-commit").write_text("npm test\n")
    found = _bypasses("git config --unset core.hooksPath", tmp_path, hooks=husky)
    assert found and found[0].hooks == ("pre-commit",)
    found = _bypasses("git config unset core.hooksPath", tmp_path, hooks=husky)
    assert found


def test_ordinary_file_removal_skips_the_git_lookup(tmp_path):
    calls = []

    def lookup(cwd):
        calls.append(cwd)
        return tmp_path

    hook_bypasses(simple_commands("rm -rf dist build/*.o", tmp_path), hooks_dir=lookup)
    assert calls == []
