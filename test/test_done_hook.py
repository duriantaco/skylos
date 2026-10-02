"""Done runs at Stop without depending on recorded post-edit findings."""

from __future__ import annotations

import io
import json
import shlex
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from skylos.commands import hook_cmd
from skylos.commands.hook_cmd import HookDeps, run_hook_command
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import DoneError, open_comparison
from skylos.done.checks import CheckResult, Finding
from skylos.done.config import DoneConfig
from skylos.done.engine import CheckOutcome, DoneResult
from skylos.done.receipt import read_receipt, validate_receipt


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            *arguments,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _write(root: Path, name: str, text: str) -> None:
    root = root.resolve(strict=True)
    path = root / name
    path.resolve(strict=False).relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)


@pytest.fixture
def configured_repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _write(tmp_path, ".gitignore", ".skylos/\n__pycache__/\n")
    _write(tmp_path, "pyproject.toml", "[tool.skylos.done]\nmax_stop_blocks = 2\n")
    _write(tmp_path, "app.py", "value = 1\n")
    _git(tmp_path, "add", ".gitignore", "pyproject.toml", "app.py")
    _git(tmp_path, "commit", "-qm", "initial")
    return tmp_path


def _hook(root, event, *, client="claude", session="session-1", extra=None, deps=None):
    payload = {"cwd": str(root), "session_id": session, **(extra or {})}
    stdout = io.StringIO()
    dependencies = deps or HookDeps()
    dependencies.env = {"CLAUDE_PROJECT_DIR": str(root)}
    code = run_hook_command(
        [event, "--client", client],
        stdin=io.StringIO(json.dumps(payload)),
        stdout=stdout,
        deps=dependencies,
    )
    text = stdout.getvalue().strip()
    return code, json.loads(text) if text else None


def _result(
    root, *, status="fail", message="test actually failed", maximum=2, findings=None
):
    check = CheckResult(
        id="tests_pass",
        rule="SKY-A113",
        status=status,
        summary=message,
        evidence={"summary": message},
        findings=findings or [],
    )
    return DoneResult(
        comparison=open_comparison(root),
        config=replace(DoneConfig(), max_stop_blocks=maximum),
        checks=[CheckOutcome("block", check)],
        verdict=status,
        seconds=0.0,
    )


def _mock_run(monkeypatch, result):
    calls = []

    def run(root, *, session_id):
        calls.append((root, session_id))
        return replace(result, checks=list(result.checks))

    monkeypatch.setattr("skylos.done.engine.run", run)
    return calls


def _latest(root):
    receipt = read_receipt(root / ".skylos" / "receipts" / "latest.json")
    assert receipt is not None
    assert validate_receipt(receipt) == []
    return receipt


@pytest.mark.parametrize("client", ["claude", "codex", "cursor"])
def test_configured_stop_runs_done_without_post_edit_records(
    configured_repo, monkeypatch, client
):
    calls = _mock_run(monkeypatch, _result(configured_repo))
    code, output = _hook(configured_repo, "stop", client=client)
    assert code == 0
    assert calls == [(configured_repo, "session-1")]
    reason = output["followup_message"] if client == "cursor" else output["reason"]
    assert "test actually failed" in reason
    assert "skylos done --session session-1" in reason
    if client != "cursor":
        assert output["decision"] == "block"
    receipt = _latest(configured_repo)
    assert receipt["verdict"] == "fail"
    assert receipt["agent"]["session_id"] == "session-1"
    assert receipt["stop_blocks"] == 1


@pytest.mark.parametrize(
    "event", ["session-start", "pre-read", "pre-bash", "post-edit", "stop"]
)
def test_first_hook_capture_uses_appropriate_before_edit_flag(
    configured_repo, monkeypatch, event
):
    from skylos.done import session

    calls = []
    original = session.capture_session

    def capture(root, session_id, *, before_edit):
        calls.append((session_id, before_edit))
        return original(root, session_id, before_edit=before_edit)

    monkeypatch.setattr(session, "capture_session", capture)
    _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _hook(configured_repo, event)
    assert calls == [("session-1", event in {"session-start", "pre-read", "pre-bash"})]
    state = hook_cmd._load_session_state(configured_repo)
    assert state["schema_version"] == 2
    assert "done_base" in state["sessions"]["session-1"]


def test_prompt_capture_is_idempotent_and_preserves_preexisting_dirty_work(
    configured_repo,
):
    _write(configured_repo, "app.py", "value = 7\n")
    assert _hook(configured_repo, "session-start")[1] is None
    first = hook_cmd._load_session_state(configured_repo)["sessions"]["session-1"][
        "done_base"
    ]
    _write(configured_repo, "app.py", "value = 9\n")
    assert _hook(configured_repo, "session-start")[1] is None
    second = hook_cmd._load_session_state(configured_repo)["sessions"]["session-1"][
        "done_base"
    ]
    assert first == second
    from skylos.done.session import open_session_comparison

    comparison = open_session_comparison(configured_repo, "session-1")
    assert comparison.base_text("app.py") == "value = 7\n"
    assert comparison.head_text("app.py") == "value = 9\n"


def test_cursor_prompt_capture_has_explicit_continue_contract(configured_repo):
    assert _hook(configured_repo, "session-start", client="cursor")[1] == {
        "continue": True
    }


def test_schema1_migration_preserves_existing_findings(configured_repo):
    legacy = {
        "files": {"app.py": {"introduced": ["old-finding"]}},
        "last_stop_digest": "old",
    }
    _write(
        configured_repo,
        ".skylos/agent-session.json",
        json.dumps({"schema_version": 1, "sessions": {"session-1": legacy}}),
    )
    _hook(configured_repo, "session-start")
    state = hook_cmd._load_session_state(configured_repo)
    assert state["schema_version"] == 2
    assert state["sessions"]["session-1"]["files"] == legacy["files"]
    assert state["sessions"]["session-1"]["last_stop_digest"] == "old"
    assert "done_base" in state["sessions"]["session-1"]


def test_stop_retries_are_bounded_and_exhaustion_does_not_make_receipt_pass(
    configured_repo, monkeypatch
):
    calls = _mock_run(monkeypatch, _result(configured_repo, status="incomplete"))
    for count in (1, 2):
        _, output = _hook(configured_repo, "stop")
        assert output["decision"] == "block"
        assert _latest(configured_repo)["stop_blocks"] == count
    _, output = _hook(configured_repo, "stop")
    assert "decision" not in output
    assert "remains incomplete" in output["systemMessage"]
    assert "receipt is not passing" in output["systemMessage"]
    receipt = _latest(configured_repo)
    assert receipt["verdict"] == "incomplete"
    assert receipt["stop_blocks"] == 2
    assert len(calls) == 2


def test_real_workspace_change_gets_new_retry_budget(configured_repo, monkeypatch):
    _mock_run(monkeypatch, _result(configured_repo))
    _hook(configured_repo, "stop")
    _hook(configured_repo, "stop")
    assert "decision" not in _hook(configured_repo, "stop")[1]
    _write(configured_repo, "app.py", "value = 2\n")
    _mock_run(monkeypatch, _result(configured_repo, message="a different test failed"))
    assert _hook(configured_repo, "stop")[1]["decision"] == "block"
    assert _latest(configured_repo)["stop_blocks"] == 1


def test_success_resets_retry_budget_for_later_regression(configured_repo, monkeypatch):
    _mock_run(monkeypatch, _result(configured_repo))
    _hook(configured_repo, "stop")
    _hook(configured_repo, "stop")
    _write(configured_repo, "app.py", "value = 2\n")
    _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    assert _hook(configured_repo, "stop")[1] == {}
    assert _latest(configured_repo)["verdict"] == "pass"
    _mock_run(monkeypatch, _result(configured_repo))
    assert _hook(configured_repo, "stop")[1]["decision"] == "block"
    assert _latest(configured_repo)["stop_blocks"] == 1


def test_stop_message_has_at_most_ten_concrete_reasons(configured_repo, monkeypatch):
    findings = [
        Finding("SKY-A113", "test_app.py", n, f"failed test {n}") for n in range(1, 16)
    ]
    findings.append(
        Finding("SKY-A101", "test_app.py", 20, "advisory only", blocking=False)
    )
    _mock_run(monkeypatch, _result(configured_repo, findings=findings))
    _, output = _hook(configured_repo, "stop")
    assert output["reason"].count("\n- ") == 10
    assert "5 additional reason(s)" in output["reason"]
    assert "advisory only" not in output["reason"]
    assert "--session session-1" in output["reason"]


def test_recheck_hint_quotes_untrusted_session_identifier():
    assert hook_cmd._done_recheck("session with spaces") == (
        "skylos done --session 'session with spaces'"
    )


def test_done_error_warns_and_replaces_earlier_passing_receipt(
    configured_repo, monkeypatch
):
    _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _hook(configured_repo, "stop")
    assert _latest(configured_repo)["verdict"] == "pass"

    def broken(*args, **kwargs):
        raise RuntimeError("do not expose raw exception contents")

    monkeypatch.setattr("skylos.done.engine.run", broken)
    code, output = _hook(configured_repo, "stop")
    assert code == 0
    assert "decision" not in output
    assert "unfinished" in output["systemMessage"]
    assert "raw exception" not in output["systemMessage"]
    receipt = _latest(configured_repo)
    assert receipt["verdict"] == "incomplete"
    assert receipt["checks"][0]["mode"] == "block"
    assert receipt["checks"][0]["status"] == "incomplete"


@pytest.mark.parametrize("event", ["post-edit", "stop"])
def test_invalid_agent_policy_replaces_passing_done_receipt(
    configured_repo, monkeypatch, event
):
    _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _hook(configured_repo, "stop")
    assert _latest(configured_repo)["verdict"] == "pass"
    _write(configured_repo, ".skylos/agent-standards.json", "{")
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    code, output = _hook(configured_repo, event)
    assert code == 0
    assert output["decision"] == "block"
    assert "standards policy is invalid" in output["reason"]
    assert calls == []
    receipt = _latest(configured_repo)
    assert receipt["verdict"] == "incomplete"
    assert receipt["checks"][0]["mode"] == "block"
    assert receipt["checks"][0]["status"] == "incomplete"


def test_invalid_policy_invalidates_latest_when_failure_receipt_cannot_be_saved(
    configured_repo, monkeypatch
):
    _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _hook(configured_repo, "stop")
    assert _latest(configured_repo)["verdict"] == "pass"
    _write(configured_repo, ".skylos/agent-standards.json", "{")

    def broken(*args, **kwargs):
        raise OSError("failure receipt cannot be saved")

    monkeypatch.setattr(hook_cmd, "_write_done_error_receipt", broken)
    _, output = _hook(configured_repo, "stop")
    assert output["decision"] == "block"
    assert (
        read_receipt(configured_repo / ".skylos" / "receipts" / "latest.json") is None
    )


def test_capture_failure_does_not_execute_stop_handler(configured_repo, monkeypatch):
    def broken(*args, **kwargs):
        raise DoneError("baseline unavailable")

    monkeypatch.setattr("skylos.done.session.capture_session", broken)
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _, output = _hook(configured_repo, "stop")
    assert calls == []
    assert "unfinished" in output["systemMessage"]
    assert _latest(configured_repo)["verdict"] == "incomplete"


def test_unrecoverable_git_failure_invalidates_latest_but_preserves_history(
    configured_repo, monkeypatch
):
    _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _hook(configured_repo, "stop")
    receipt = _latest(configured_repo)
    directory = configured_repo / ".skylos" / "receipts"
    historical = (
        directory / f"{receipt['head']['sha'][:12]}-{receipt['base']['sha'][:12]}.json"
    )
    saved_history = historical.read_bytes()

    def broken(*args, **kwargs):
        raise DoneError("Git comparison is unavailable")

    monkeypatch.setattr("skylos.done.session.open_comparison", broken)
    monkeypatch.setattr("skylos.done.base.open_comparison", broken)
    _, output = _hook(configured_repo, "stop")
    assert "decision" not in output
    assert "unfinished" in output["systemMessage"]
    assert read_receipt(directory / "latest.json") is None
    assert historical.read_bytes() == saved_history


def test_cursor_exhaustion_warns_without_requesting_another_turn(
    configured_repo, monkeypatch, capsys
):
    calls = _mock_run(monkeypatch, _result(configured_repo))
    assert "followup_message" in _hook(configured_repo, "stop", client="cursor")[1]
    assert "followup_message" in _hook(configured_repo, "stop", client="cursor")[1]
    assert _hook(configured_repo, "stop", client="cursor")[1] == {}
    assert len(calls) == 2
    assert "receipt is not passing" in capsys.readouterr().err
    assert _latest(configured_repo)["verdict"] == "fail"


def test_volatile_problem_messages_do_not_reset_stop_budget(
    configured_repo, monkeypatch
):
    calls = []

    def run(root, *, session_id):
        calls.append(session_id)
        return _result(root, message=f"test failed after {len(calls)} seconds")

    monkeypatch.setattr("skylos.done.engine.run", run)
    for _ in range(2):
        assert _hook(configured_repo, "stop")[1]["decision"] == "block"
    for _ in range(3):
        assert "decision" not in _hook(configured_repo, "stop")[1]
    assert calls == ["session-1", "session-1"]
    assert _latest(configured_repo)["verdict"] == "fail"


def test_exhaustion_cannot_reuse_another_sessions_passing_receipt(
    configured_repo, monkeypatch
):
    _mock_run(monkeypatch, _result(configured_repo))
    for _ in range(2):
        _hook(configured_repo, "stop")
    _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _hook(configured_repo, "stop", session="different-session")
    assert _latest(configured_repo)["verdict"] == "pass"
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _, output = _hook(configured_repo, "stop")
    assert calls == []
    assert (
        "unfinished" in output["systemMessage"]
        or "incomplete" in output["systemMessage"]
    )
    receipt = _latest(configured_repo)
    assert receipt["verdict"] == "incomplete"
    assert receipt["agent"]["session_id"] == "session-1"


def test_unconfigured_legacy_stop_does_not_run_done(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _write(tmp_path, "app.py", "value = 1\n")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-qm", "initial")
    calls = _mock_run(monkeypatch, _result(tmp_path))
    assert _hook(tmp_path, "stop")[1] == {}
    assert calls == []
    assert not (tmp_path / ".skylos" / "receipts" / "latest.json").exists()


def test_uncommitted_configuration_cannot_enable_done(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _write(tmp_path, "app.py", "value = 1\n")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-qm", "initial")
    _write(tmp_path, "pyproject.toml", "[tool.skylos.done]\n")
    calls = _mock_run(monkeypatch, _result(tmp_path))
    assert _hook(tmp_path, "stop")[1] == {}
    assert calls == []


def test_unconfigured_invalid_agent_policy_keeps_legacy_block_without_done_receipt(
    tmp_path, monkeypatch
):
    _git(tmp_path, "init", "-q")
    _write(tmp_path, "app.py", "value = 1\n")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-qm", "initial")
    _write(tmp_path, ".skylos/agent-standards.json", "{")
    calls = _mock_run(monkeypatch, _result(tmp_path, status="pass"))
    _, output = _hook(tmp_path, "stop")
    assert output["decision"] == "block"
    assert "standards policy is invalid" in output["reason"]
    assert calls == []
    assert not (tmp_path / ".skylos" / "receipts" / "latest.json").exists()


@pytest.mark.parametrize(
    ("capture_before_edit", "introduce_regression", "expected"),
    [(True, False, "pass"), (True, True, "fail"), (False, False, "incomplete")],
)
def test_real_stop_pipeline_records_actual_test_evidence(
    configured_repo, capture_before_edit, introduce_regression, expected
):
    # This small trusted fixture exercises the real session, engine and pytest
    # subprocess, rather than supplying an agent's claimed test result.
    command = shlex.join([sys.executable, "-m", "pytest", "-q"])
    _write(
        configured_repo,
        "pyproject.toml",
        "[tool.skylos.done]\n"
        f"test_command = {json.dumps(command)}\n"
        "[tool.skylos.done.checks]\n"
        "unknown_imports = 'off'\n"
        "changed_lines_checked = 'off'\n",
    )
    _write(
        configured_repo,
        "test_app.py",
        "from app import value\n\ndef test_value():\n    assert value == 1\n",
    )
    _git(configured_repo, "add", "pyproject.toml", "test_app.py")
    _git(configured_repo, "commit", "-qm", "configure test command")
    if capture_before_edit:
        _hook(configured_repo, "session-start")
    if introduce_regression:
        _write(configured_repo, "app.py", "value = 2\n")
    code, output = _hook(configured_repo, "stop")
    assert code == 0
    receipt = _latest(configured_repo)
    assert receipt["verdict"] == expected
    if expected == "pass":
        assert output == {}
    else:
        assert output["decision"] == "block"


_UNSAFE_APP = "import os\n\n@app.get('/run')\ndef run(cmd):\n    os.system(cmd)\n"


class _EditVerifier:
    def __init__(self, rule="SKY-D212", *, category="security"):
        self.rule = rule
        self.category = category
        self.calls = []
        self.open = True

    def __call__(self, target, **kwargs):
        self.calls.append(Path(target))
        findings = (
            [
                {
                    "rule_id": self.rule,
                    "category": self.category,
                    "severity": "HIGH",
                    "message": "Introduced edit still violates the policy",
                    "range": {"file": Path(target).name, "start_line": 5},
                }
            ]
            if self.open
            else []
        )
        return {"status": "fail" if findings else "pass", "findings": findings}


def _record_issue(root, *, rule="SKY-D212", category="security"):
    if category == "quality":
        _write(root, "STANDARDS.md", "# Project standards\n")
        _write(
            root,
            ".skylos/agent-standards.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "standards_file": "STANDARDS.md",
                    "enforce_rule_ids": [rule],
                }
            ),
        )
    _hook(root, "session-start")
    _write(root, "app.py", _UNSAFE_APP)
    verify = _EditVerifier(rule, category=category)
    _, output = _hook(
        root,
        "post-edit",
        extra={"tool_name": "Write", "tool_input": {"file_path": str(root / "app.py")}},
        deps=HookDeps(verify=verify),
    )
    assert output["decision"] == "block"
    verify.calls.clear()
    return verify


def _checks(receipt):
    return {check["id"]: check for check in receipt["checks"]}


@pytest.mark.parametrize(
    ("rule", "category"), [("SKY-D212", "security"), ("SKY-Q301", "quality")]
)
def test_recorded_edit_guards_block_before_done_even_when_core_would_pass(
    configured_repo, monkeypatch, rule, category
):
    verify = _record_issue(configured_repo, rule=rule, category=category)
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _, output = _hook(configured_repo, "stop", deps=HookDeps(verify=verify))
    assert output["decision"] == "block"
    assert f"app.py:5 {rule}" in output["reason"]
    assert "hook recheck app.py" in output["reason"]
    assert calls == []
    assert verify.calls == [configured_repo / "app.py"]
    receipt = _latest(configured_repo)
    assert receipt["verdict"] == "fail"
    checks = _checks(receipt)
    assert checks["agent_edits"]["mode"] == "block"
    assert checks["agent_edits"]["status"] == "fail"
    assert checks["agent_edits"]["rule"] is None
    assert checks["agent_edits"]["findings"][0]["rule"] == rule
    assert checks["tests_pass"]["status"] == "incomplete"
    assert checks["tests_pass"]["evidence"]["blocked_by"] == "agent_edits"


def test_resolved_recorded_issue_allows_done_without_trusting_cached_failure(
    configured_repo, monkeypatch
):
    verify = _record_issue(configured_repo)
    _write(configured_repo, "app.py", "value = 1\n")
    verify.open = False
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    assert _hook(configured_repo, "stop", deps=HookDeps(verify=verify))[1] == {}
    assert calls == [(configured_repo, "session-1")]
    assert verify.calls == [configured_repo / "app.py"]
    receipt = _latest(configured_repo)
    assert receipt["verdict"] == "pass"
    assert _checks(receipt)["agent_edits"]["status"] == "pass"
    assert _checks(receipt)["agent_edits"]["evidence"]["scope"] == "recorded edits"


def test_blocking_recorded_edits_keep_bounded_nonpassing_stop_receipt(
    configured_repo, monkeypatch
):
    verify = _record_issue(configured_repo)
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    for _ in range(2):
        _, output = _hook(configured_repo, "stop", deps=HookDeps(verify=verify))
        assert output["decision"] == "block"
    _, output = _hook(configured_repo, "stop", deps=HookDeps(verify=verify))
    assert "decision" not in output
    assert "receipt is not passing" in output["systemMessage"]
    assert "Recorded edit guards: " in output["systemMessage"]
    assert "hook recheck app.py" in output["systemMessage"]
    assert calls == []
    assert len(verify.calls) == 3
    assert _latest(configured_repo)["verdict"] == "fail"


def _change_recorded_path(root, relative):
    def update(session):
        session["files"] = {relative: session["files"]["app.py"]}

    assert hook_cmd._mutate_session(root, "session-1", update)


@pytest.mark.parametrize(
    "relative", ["../outside.py", "/outside.py", "dir\\outside.py"]
)
def test_unsafe_cached_path_cannot_be_rechecked_or_made_passing(
    configured_repo, monkeypatch, relative
):
    verify = _record_issue(configured_repo)
    _change_recorded_path(configured_repo, relative)
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _, output = _hook(configured_repo, "stop", deps=HookDeps(verify=verify))
    assert "unfinished" in output["systemMessage"]
    assert calls == []
    assert verify.calls == []
    assert _latest(configured_repo)["verdict"] == "incomplete"


@pytest.mark.parametrize("parent_link", [False, True])
def test_symlink_recorded_file_or_parent_never_rechecks_external_code(
    configured_repo, tmp_path_factory, monkeypatch, parent_link
):
    verify = _record_issue(configured_repo)
    outside = tmp_path_factory.mktemp("outside-recorded-edit")
    _write(outside, "app.py", _UNSAFE_APP)
    if parent_link:
        (configured_repo / "linked").symlink_to(outside, target_is_directory=True)
        _change_recorded_path(configured_repo, "linked/app.py")
    else:
        (configured_repo / "app.py").unlink()
        (configured_repo / "app.py").symlink_to(outside / "app.py")
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _, output = _hook(configured_repo, "stop", deps=HookDeps(verify=verify))
    assert "unfinished" in output["systemMessage"]
    assert verify.calls == []
    assert calls == []
    assert _latest(configured_repo)["verdict"] == "incomplete"


def test_nonregular_recorded_file_remains_unfinished(configured_repo, monkeypatch):
    verify = _record_issue(configured_repo)
    (configured_repo / "app.py").unlink()
    (configured_repo / "app.py").mkdir()
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    _, output = _hook(configured_repo, "stop", deps=HookDeps(verify=verify))
    assert "unfinished" in output["systemMessage"]
    assert calls == []
    assert verify.calls == []
    assert _latest(configured_repo)["verdict"] == "incomplete"


@pytest.mark.parametrize("reason", ["noncheckable", "unreadable", "parse_incomplete"])
def test_uncheckable_recorded_file_cannot_be_treated_as_resolved(
    configured_repo, monkeypatch, reason
):
    verify = _record_issue(configured_repo)
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    if reason == "unreadable":
        from skylos.core.safe_cache_io import read_project_text_no_symlink

        def unreadable(root, path, **kwargs):
            if Path(path) == configured_repo / "app.py":
                return None
            return read_project_text_no_symlink(root, path, **kwargs)

        monkeypatch.setattr(
            "skylos.core.safe_cache_io.read_project_text_no_symlink",
            unreadable,
        )
    else:
        current = (
            {"findings": [{"rule_id": hook_cmd.PARSE_INCOMPLETE_RULE}]}
            if reason == "parse_incomplete"
            else None
        )
        monkeypatch.setattr(hook_cmd, "_current_findings", lambda *args: current)
    _, output = _hook(configured_repo, "stop", deps=HookDeps(verify=verify))
    assert "unfinished" in output["systemMessage"]
    assert calls == []
    assert _latest(configured_repo)["verdict"] == "incomplete"


def test_deleted_recorded_file_is_resolved_only_when_absent_from_snapshot(
    configured_repo, monkeypatch
):
    verify = _record_issue(configured_repo)
    (configured_repo / "app.py").unlink()
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))
    assert _hook(configured_repo, "stop", deps=HookDeps(verify=verify))[1] == {}
    assert calls == [(configured_repo, "session-1")]
    assert verify.calls == []
    assert _latest(configured_repo)["verdict"] == "pass"
    assert _checks(_latest(configured_repo))["agent_edits"]["status"] == "pass"


def test_change_during_recorded_recheck_cannot_publish_pass(
    configured_repo, monkeypatch
):
    _record_issue(configured_repo)
    calls = _mock_run(monkeypatch, _result(configured_repo, status="pass"))

    def changing(*args):
        _write(configured_repo, "app.py", "value = 42\n")
        return {"findings": [], "update": {"findings": []}}

    monkeypatch.setattr(hook_cmd, "_current_findings", changing)
    _, output = _hook(configured_repo, "stop")
    assert "unfinished" in output["systemMessage"]
    assert calls == []
    assert _latest(configured_repo)["verdict"] == "incomplete"


def test_session_recheck_rejects_unsafe_cached_path(configured_repo, monkeypatch):
    verify = _record_issue(configured_repo)
    _change_recorded_path(configured_repo, "../outside.py")
    monkeypatch.chdir(configured_repo)
    stdout = io.StringIO()
    assert (
        hook_cmd.run_recheck(
            ["--session"],
            stdout=stdout,
            deps=HookDeps(
                verify=verify, env={"CLAUDE_PROJECT_DIR": str(configured_repo)}
            ),
        )
        == 2
    )
    assert "unsafe recorded edit path" in stdout.getvalue()
    assert verify.calls == []
