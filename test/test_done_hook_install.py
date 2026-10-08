"""Prompt baselines and usable done budgets in the installed agent hooks."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess

import pytest

from skylos.commands import install_hooks_cmd as installer
from skylos.done.config import MAX_TEST_BUDGET_SECONDS, parse_done_config


def _handlers(config, agent, event):
    entries = config["hooks"][event]
    if agent == "cursor":
        return entries
    return [handler for group in entries for handler in group["hooks"]]


@pytest.mark.parametrize(
    "agent,prompt_event,stop_event,count",
    [
        ("claude", "UserPromptSubmit", "Stop", 9),
        # UserPromptSubmit is a documented Codex event, with no matcher.
        ("codex", "UserPromptSubmit", "Stop", 6),
        ("cursor", "beforeSubmitPrompt", "stop", 5),
    ],
)
def test_prompt_baseline_install_preserves_foreign_hooks_and_uninstalls(
    agent, prompt_event, stop_event, count
):
    foreign = {"command": "echo user-hook", "timeout": 8}
    if agent != "cursor":
        foreign = {"matcher": "*", "hooks": [{"type": "command", **foreign}]}
    original = {"version": 1, "hooks": {prompt_event: [foreign]}}
    installed, removed, added = installer.install_hooks(original, agent, "skylos")
    assert (removed, added) == (0, count)
    assert installed["hooks"][prompt_event][0] == foreign
    prompt_handlers = _handlers(installed, agent, prompt_event)
    assert len(prompt_handlers) == 2
    assert (
        "skylos hook session-start --client " + agent in prompt_handlers[1]["command"]
    )
    if agent != "cursor":
        assert "matcher" not in installed["hooks"][prompt_event][1]
    if agent == "codex":
        assert prompt_handlers[1]["statusMessage"]
    stop = _handlers(installed, agent, stop_event)[0]
    # Reserve the documented 1,800-second mutation budget without importing
    # optional mutation configuration from a separate working-tree change.
    assert stop["timeout"] >= MAX_TEST_BUDGET_SECONDS + 1800 + 60
    again, removed, added = installer.install_hooks(installed, agent, "skylos")
    assert again == installed
    assert (removed, added) == (count, count)
    cleaned, removed = installer.uninstall_hooks(installed, agent)
    assert cleaned == original
    assert removed == count


@pytest.mark.parametrize("maximum", [1, 3, 10])
def test_cursor_native_limit_allows_supported_done_retry_budget(maximum):
    trusted = parse_done_config(f"[tool.skylos.done]\nmax_stop_blocks = {maximum}\n")
    installed, _, _ = installer.install_hooks({}, "cursor", "skylos")
    stop = _handlers(installed, "cursor", "stop")[0]
    # On the last retry a native host must still submit the follow-up. The
    # following Stop call can then save a pass or the exhausted warning.
    for native_loop_count in range(trusted.max_stop_blocks):
        assert native_loop_count < stop["loop_limit"]
    assert stop["loop_limit"] == 10


@pytest.mark.parametrize("agent", installer.AGENTS)
def test_prompt_hook_interpreter_entry_is_recognized_on_reinstall(agent):
    installed, _, count = installer.install_hooks(
        {}, agent, ["/python with spaces/python", "-m", "skylos.entry"]
    )
    again, removed, added = installer.install_hooks(
        installed, agent, ["/python with spaces/python", "-m", "skylos.entry"]
    )
    assert again == installed and (removed, added) == (count, count)
    assert installer.uninstall_hooks(installed, agent)[1] == count


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell wrapper")
@pytest.mark.parametrize("agent", installer.AGENTS)
@pytest.mark.parametrize("old_binary", [False, True], ids=["missing", "old"])
def test_prompt_hook_binary_failure_does_not_reject_user_prompt(
    tmp_path, agent, old_binary
):
    # Use an installed standard executable rather than writing an executable
    # test file: a missing command or an argparse failure must allow the prompt.
    binary = "/bin/false" if old_binary else str(tmp_path / "missing-skylos")
    proc = subprocess.run(
        ["/bin/sh", "-c", installer.hook_command(binary, "session-start", agent)],
        input="{}",
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == ('{"continue":true}' if agent == "cursor" else "")


def test_prompt_hook_binary_check_requires_new_event(monkeypatch):
    calls = []

    def old_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(
            argv, 0, "skylos hook post-edit pre-read pre-bash stop recheck", ""
        )

    monkeypatch.setattr(installer.subprocess, "run", old_run)
    assert installer.probe_hook_support(["skylos"]) is None
    assert calls == [["skylos", "hook", "help"]]


def test_prompt_hook_binary_check_accepts_current_help(monkeypatch):
    def current_run(argv, **kwargs):
        stdout = "skylos hook session-start post-edit pre-read pre-bash stop recheck"
        if argv[-1] == "--version":
            stdout = "skylos 9.9.9"
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(installer.subprocess, "run", current_run)
    assert installer.probe_hook_support(["skylos"]) == "9.9.9"


def _install(project, home):
    args = argparse.Namespace(
        agent="claude",
        scope="project",
        uninstall=False,
        path=str(project),
        skylos_bin="skylos",
        dry_run=False,
        check_bin=True,
    )
    output = []
    code = installer.run_install_hooks_command(
        args,
        home=home,
        probe=lambda _: "9.9.9",
        print_func=output.append,
    )
    assert code == 0
    return output


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required")
@pytest.mark.parametrize(
    "root_ignore", [False, True], ids=["local-ignore", "root-ignore"]
)
def test_reinstall_repairs_receipt_ignore_without_modifying_config(
    tmp_path, root_ignore
):
    project = tmp_path / "project"
    project.mkdir()
    subprocess.run(
        ["git", "init", "-q", str(project)], check=True, capture_output=True, timeout=10
    )
    ignore = (
        project / ".gitignore" if root_ignore else project / ".skylos" / ".gitignore"
    )
    ignore.parent.mkdir(exist_ok=True)
    prefixes = installer.GITIGNORE_ENTRIES[:-1]
    old = (
        "# preserve user entries\ncustom.log\n"
        + "\n".join(
            prefixes
            if root_ignore
            else [entry.removeprefix(".skylos/") for entry in prefixes]
        )
        + "\n"
    )
    ignore.write_text(old, encoding="utf-8")
    config_path = project / ".claude" / "settings.json"
    config_path.parent.mkdir()
    config, _, _ = installer.install_hooks({}, "claude", "skylos")
    before_config = json.dumps(config, indent=2) + "\n"
    config_path.write_text(before_config, encoding="utf-8")

    _install(project, tmp_path / "fake-home")
    assert config_path.read_text(encoding="utf-8") == before_config
    after_ignore = ignore.read_text(encoding="utf-8")
    assert after_ignore.startswith(old)
    assert (
        ".skylos/receipts/" if root_ignore else "receipts/"
    ) in after_ignore.splitlines()
    for path in (
        ".skylos/agent-session.json",
        ".skylos/agent-session.lock",
        ".skylos/receipts/latest.json",
    ):
        proc = subprocess.run(
            ["git", "check-ignore", "--no-index", "-q", "--", path],
            cwd=project,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert proc.returncode == 0, path
    assert not (tmp_path / "fake-home").exists()
    _install(project, tmp_path / "fake-home")
    assert ignore.read_text(encoding="utf-8") == after_ignore


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symlinks unavailable")
def test_receipt_ignore_repair_preserves_symlink_target(tmp_path):
    (tmp_path / ".git").mkdir()
    local = tmp_path / ".skylos"
    local.mkdir()
    target = tmp_path / "user-ignore"
    target.write_text("keep unchanged\n", encoding="utf-8")
    try:
        (local / ".gitignore").symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    assert "Could not update" in installer.ensure_gitignored(tmp_path)
    assert target.read_text(encoding="utf-8") == "keep unchanged\n"
