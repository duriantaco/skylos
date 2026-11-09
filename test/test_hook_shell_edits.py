"""Files an agent changes through the shell get the same check as an Edit.

Claude Code's hooks reference: a PostToolUse hook matching Edit|Write does not run
when a Bash command rewrites the file. In a live run an agent wrote debug=True with
`cat > run.py`, and nothing looked at it, including Stop.
"""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

from skylos.commands.hook_cmd import HookDeps, run_hook_command

IDENTITY = ["-c", "user.name=t", "-c", "user.email=t@example.com"]


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / ".gitignore").write_text(".skylos/\nignored.py\n")
    (tmp_path / "app.py").write_text("one = 1\ntwo = 2\n")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, *IDENTITY, "commit", "-qm", "base")
    return tmp_path


class Verify:
    """Blocks wherever a line contains BAD."""

    def __init__(self):
        self.calls: list[str] = []

    def __call__(self, target, **kwargs):
        path = Path(target)
        self.calls.append(path.name)
        findings = []
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if "BAD" in line:
                findings.append(
                    {
                        "rule_id": "SKY-D346",
                        "severity": "HIGH",
                        "category": "security",
                        "message": "Flask debug mode enabled",
                        "range": {"file": path.name, "start_line": number},
                    }
                )
        return {"status": "fail" if findings else "pass", "findings": findings}


def _hook(root, event, verify, *, session="s1", **extra):
    deps = HookDeps(verify=verify)
    deps.env = {"CLAUDE_PROJECT_DIR": str(root)}
    stdout = io.StringIO()
    payload = {"session_id": session, "cwd": str(root), **extra}
    code = run_hook_command(
        [event, "--client", "claude"],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=deps,
    )
    text = stdout.getvalue().strip()
    assert code == 0
    if not text:
        return {}
    return json.loads(text)


def _bash(root, verify, command="cat > app.py", event="post-bash", **extra):
    return _hook(
        root,
        event,
        verify,
        tool_name="Bash",
        tool_input={"command": command},
        **extra,
    )


def test_a_file_written_through_the_shell_is_checked_and_blocks(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\n")

    out = _bash(repo, verify)

    assert out["decision"] == "block"
    assert "app.py:2 SKY-D346" in out["reason"]
    assert verify.calls == ["app.py"]


def test_a_new_file_created_through_the_shell_is_checked(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "new.py").write_text("BAD = True\n")

    out = _bash(repo, verify)

    assert out["decision"] == "block"
    assert "new.py:1" in out["reason"]


def test_a_read_only_command_checks_nothing(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)

    assert _bash(repo, verify, command="pytest -q") == {}
    assert verify.calls == []


def test_only_lines_the_change_added_can_block(repo):
    (repo / "app.py").write_text("one = 1\nBAD = True\n")
    _git(repo, "add", "-A")
    _git(repo, *IDENTITY, "commit", "-qm", "old debt")
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\nthree = 3\n")

    out = _bash(repo, verify)

    assert out.get("decision") != "block"
    assert verify.calls == ["app.py"]


def test_work_already_uncommitted_is_not_blamed_on_the_agent(repo):
    (repo / "app.py").write_text("one = 1\nBAD = True\n")
    verify = Verify()
    _hook(repo, "session-start", verify)

    assert _bash(repo, verify, command="ls") == {}
    assert verify.calls == []


def test_edits_a_person_made_between_prompts_are_not_blamed_on_the_agent(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\n")
    _hook(repo, "session-start", verify)

    assert _bash(repo, verify, command="ls") == {}
    assert verify.calls == []


def test_a_change_after_uncommitted_work_is_still_checked(repo):
    (repo / "app.py").write_text("one = 1\n")
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\n")

    out = _bash(repo, verify)

    assert out["decision"] == "block"


def test_gitignored_files_and_skylos_state_are_not_checked(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "ignored.py").write_text("BAD = True\n")
    (repo / ".skylos").mkdir(exist_ok=True)
    (repo / ".skylos" / "state.py").write_text("BAD = True\n")

    assert _bash(repo, verify) == {}
    assert verify.calls == []


def test_an_edit_tool_write_is_not_checked_again_by_the_next_command(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\n")
    _hook(
        repo,
        "post-edit",
        verify,
        tool_name="Write",
        tool_input={"file_path": str(repo / "app.py")},
    )
    assert verify.calls == ["app.py"]

    assert _bash(repo, verify, command="ls") == {}
    assert verify.calls == ["app.py"]


def test_the_same_shell_change_is_reported_once(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\n")

    assert _bash(repo, verify)["decision"] == "block"
    assert _bash(repo, verify, command="ls") == {}


def test_a_failed_command_that_changed_a_file_is_checked(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\n")

    out = _bash(repo, verify, command="sed -i x app.py; false", event="post-failure")

    assert out["decision"] == "block"


def test_a_deleted_file_is_not_an_error(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").unlink()

    assert _bash(repo, verify, command="rm app.py") == {}
    assert verify.calls == []


def test_the_first_event_without_a_baseline_blames_nothing_then_tracks(repo):
    verify = Verify()
    (repo / "app.py").write_text("one = 1\nBAD = True\n")

    assert _bash(repo, verify, command="ls") == {}
    assert verify.calls == []

    (repo / "app.py").write_text("one = 1\nBAD = True\nBAD2 = True\n")
    assert _bash(repo, verify)["decision"] == "block"


def test_stop_catches_a_shell_edit_no_post_hook_saw(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\n")

    out = _hook(repo, "stop", verify, hook_event_name="Stop")

    assert out["decision"] == "block"
    assert "SKY-D346" in out["reason"]


def test_stop_passes_once_the_shell_edit_is_fixed(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "app.py").write_text("one = 1\nBAD = True\n")
    assert _bash(repo, verify)["decision"] == "block"
    (repo / "app.py").write_text("one = 1\ntwo = 2\n")

    out = _hook(repo, "stop", verify, hook_event_name="Stop")

    assert out.get("decision") != "block"


def test_stop_with_nothing_changed_is_quiet(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)

    assert _hook(repo, "stop", verify, hook_event_name="Stop") == {}
    assert verify.calls == []


def test_a_mass_change_checks_a_bounded_number_and_stop_covers_the_rest(repo):
    verify = Verify()
    _hook(repo, "session-start", verify)
    for index in range(30):
        (repo / f"gen{index}.py").write_text("value = 1\n")
    (repo / "zzz.py").write_text("BAD = True\n")

    out = _bash(repo, verify, command="codegen")

    assert len(verify.calls) == 25
    assert out.get("decision") != "block"
    assert "when you stop" in out["hookSpecificOutput"]["additionalContext"]

    stopped = _hook(repo, "stop", verify, hook_event_name="Stop")

    assert len(set(verify.calls)) == 31
    assert stopped["decision"] == "block"
    assert "zzz.py" in stopped["reason"]


def test_a_symlink_made_through_the_shell_never_gets_external_code_analyzed(
    repo, tmp_path_factory
):
    outside = tmp_path_factory.mktemp("outside")
    (outside / "secret.py").write_text("BAD = True\n")
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "linked.py").symlink_to(outside / "secret.py")
    (repo / "folder").symlink_to(outside, target_is_directory=True)

    assert _bash(repo, verify, command="ln -s") == {}
    assert _hook(repo, "stop", verify, hook_event_name="Stop") == {}
    assert verify.calls == []


def test_a_real_file_beside_a_symlink_is_still_checked(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    (outside / "secret.py").write_text("value = 1\n")
    verify = Verify()
    _hook(repo, "session-start", verify)
    (repo / "linked.py").symlink_to(outside / "secret.py")
    (repo / "real.py").write_text("BAD = True\n")

    out = _bash(repo, verify)

    assert out["decision"] == "block"
    assert verify.calls == ["real.py"]
