"""Protected-path regressions at the hook's Git and symlink boundaries."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from skylos.cloud.guardrails import GuardrailContext, GuardrailSettings
from skylos.commands import hook_cmd
from skylos.commands.hook_cmd import HookDeps, run_hook_command


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def _repo(root: Path) -> None:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")


def _run(root: Path, home: Path, event: str, payload: dict, *, client="claude", patterns=("infra/**",)):
    context = GuardrailContext(
        source="org",
        settings=GuardrailSettings(protected_paths=patterns),
        allow_local_loosening=False,
        home=home,
    )
    deps = HookDeps(
        env={"CLAUDE_PROJECT_DIR": str(root)},
        guardrails=context,
        guardrails_home=home,
        verify=lambda *_args, **_kwargs: {"status": "pass", "findings": []},
    )
    output = io.StringIO()
    assert run_hook_command(
        [event, "--client", client],
        stdin=io.StringIO(json.dumps({"session_id": "protected-test", **payload})),
        stdout=output,
        deps=deps,
    ) == 0
    return json.loads(output.getvalue()) if output.getvalue().strip() else None


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize("committed", [False, True])
def test_shell_write_to_protected_path_survives_staging_or_commit(tmp_path, committed):
    root, home = tmp_path / "repo", tmp_path / "home"
    _repo(root)
    target = root / "infra" / "main.tf"
    target.parent.mkdir()
    target.write_text("original\n")
    _git(root, "add", "infra/main.tf")
    _git(root, "commit", "-qm", "base")

    _run(root, home, "pre-bash", {"tool_name": "Bash", "tool_input": {"command": "echo update >> infra/main.tf"}})
    target.write_text("changed\n")
    _git(root, "add", "infra/main.tf")
    if committed:
        _git(root, "commit", "-qm", "agent edit")

    stopped = _run(root, home, "stop", {})
    assert stopped["decision"] == "block"
    assert "infra/main.tf" in stopped["reason"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_ignored_protected_file_change_is_caught_at_stop(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _repo(root)
    (root / ".gitignore").write_text("infra/ignored.txt\n")
    target = root / "infra" / "ignored.txt"
    target.parent.mkdir()
    target.write_text("original\n")
    _git(root, "add", ".gitignore")
    _git(root, "commit", "-qm", "base")

    _run(root, home, "pre-bash", {"tool_name": "Bash", "tool_input": {"command": "echo update >> infra/ignored.txt"}})
    target.write_text("changed\n")
    stopped = _run(root, home, "stop", {})
    assert stopped["decision"] == "block"
    assert "infra/ignored.txt" in stopped["reason"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_protected_path_after_many_untracked_files_is_still_checked(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _repo(root)
    (root / "README").write_text("base\n")
    _git(root, "add", "README")
    _git(root, "commit", "-qm", "base")
    _run(root, home, "pre-bash", {"tool_name": "Bash", "tool_input": {"command": "touch zzz/important"}}, patterns=("zzz/**",))

    noise = root / "aaa"
    noise.mkdir()
    for index in range(5001):
        (noise / f"{index:04d}").touch()
    protected = root / "zzz" / "important"
    protected.parent.mkdir()
    protected.write_text("agent edit\n")

    stopped = _run(root, home, "stop", {}, patterns=("zzz/**",))
    assert stopped["decision"] == "block"
    assert "zzz/important" in stopped["reason"]


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlinks unavailable")
def test_protected_symlink_alias_is_denied_before_and_after_edit(tmp_path):
    root, home = tmp_path / "repo", tmp_path / "home"
    _repo(root)
    target = root / "app.py"
    target.write_text("before\n")
    alias = root / "infra" / "link.py"
    alias.parent.mkdir()
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")

    before = _run(root, home, "pre-edit", {"tool_name": "Edit", "tool_input": {"file_path": str(alias)}})
    assert before["hookSpecificOutput"]["permissionDecision"] == "deny"

    target.write_text("after\n")
    after = _run(root, home, "post-edit", {"tool_name": "Edit", "tool_input": {"file_path": str(alias)}}, client="codex")
    assert after["decision"] == "block"
    assert "infra/link.py" in after["reason"]

    stopped = _run(root, home, "stop", {}, client="cursor")
    assert "infra/link.py" in stopped["followup_message"]


def test_recheck_command_ignores_pythonpath(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["python"])
    command = hook_cmd.self_command()
    if sys.version_info >= (3, 11):
        assert " -E -P -m skylos.entry" in command
    else:
        assert " -I -m skylos.entry" in command
