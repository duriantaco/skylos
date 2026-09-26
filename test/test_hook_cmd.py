from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from skylos.commands import hook_cmd
from skylos.commands.hook_cmd import HookDeps, run_hook_command
from skylos.commands.install_hooks_cmd import (
    install_hooks,
    run_install_hooks_command,
    uninstall_hooks,
)
from skylos.rules.ai_defect.install_command import (
    check_install_command,
    install_command_packages,
)

AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_KEY_ID = "AKIAIOSFODNN7ABCDEFG"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


class FakeVerify:
    """Stands in for verify_change_path; findings keyed by file name."""

    def __init__(self, findings_by_name=None, error=None):
        self.findings_by_name = findings_by_name or {}
        self.error = error
        self.calls = []

    def __call__(self, target, **kwargs):
        self.calls.append((target, kwargs))
        if self.error is not None:
            raise self.error
        name = Path(target).name
        findings = [
            {
                "rule_id": rule,
                "severity": "CRITICAL",
                "category": "security",
                "message": message,
                "suggested_fix": "Use subprocess.run([...]) without a shell.",
                "range": {"file": name, "start_line": line},
            }
            for line, rule, message in self.findings_by_name.get(name, [])
        ]
        return {"status": "fail" if findings else "pass", "findings": findings}


def _run(tmp_path, event, payload, *, client=None, deps=None, raw=None):
    argv = [event] + (["--client", client] if client else [])
    stdout = io.StringIO()
    deps = deps or HookDeps()
    # Hermetic env: the test process may itself run under an agent.
    deps.env = {"CLAUDE_PROJECT_DIR": str(tmp_path)}
    (tmp_path / ".git").mkdir(exist_ok=True)  # hook state lives in-repo only
    stdin = io.StringIO(raw if raw is not None else json.dumps(payload))
    code = run_hook_command(argv, stdin=stdin, stdout=stdout, deps=deps)
    text = stdout.getvalue().strip()
    return code, (json.loads(text) if text else None), text


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] callers supply fixture paths under pytest tmp_path
        text, encoding="utf-8"
    )
    return path


def _edit_payload(path: Path, new_string: str, session="s1", **extra):
    return {
        "session_id": session,
        "cwd": str(path.parent),
        "hook_event_name": "PostToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": str(path),
            "old_string": "placeholder",
            "new_string": new_string,
        },
        **extra,
    }


def _log_lines(tmp_path):
    log = tmp_path / ".skylos" / "hook.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


# Line 5 runs a web-route parameter through os.system: a real untrusted source.
APP = (
    "import os\n\n@app.get('/run')\ndef run(cmd):\n    os.system(cmd)\n\n\n"
    "def ok():\n    return 1\n"
)


# --------------------------------------------------------------------------
# post-edit
# --------------------------------------------------------------------------


def test_post_edit_fail_blocks_with_changed_line_findings_only(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify(
        {
            "app.py": [
                (
                    5,
                    "SKY-D212",
                    "Possible command injection (os.system): tainted input.",
                ),
                (9, "SKY-D999", "Pre-existing issue outside the edit"),
            ]
        }
    )
    code, out, _ = _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "def run(cmd):\n    os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )

    assert code == 0
    assert out["decision"] == "block"
    reason = out["reason"]
    assert "app.py:5 SKY-D212 Possible command injection" in reason
    assert "-> Use subprocess.run" in reason
    assert "SKY-D999" not in reason
    assert "hook recheck app.py" in reason
    assert "skylos verify" not in reason
    kwargs = verify.calls[0][1]
    assert kwargs["include_security_findings"] is True
    assert kwargs["behavior_comparison"] is False


def test_post_edit_pass_is_silent_and_records_session(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    code, out, text = _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "def ok():\n    return 1"),
        client="claude",
        deps=HookDeps(verify=FakeVerify()),
    )
    assert code == 0
    assert text == ""
    session = json.loads((tmp_path / ".skylos" / "agent-session.json").read_text())
    assert "app.py" in session["sessions"]["s1"]["files"]
    assert _log_lines(tmp_path)[-1]["outcome"] == "pass"


def test_post_edit_write_checks_whole_file(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify({"app.py": [(5, "SKY-D212", "issue")]})
    payload = {
        "session_id": "s1",
        "tool_name": "Write",
        "tool_input": {"file_path": str(app), "content": APP},
        "tool_response": {"type": "create", "filePath": str(app)},
    }
    _, out, _ = _run(
        tmp_path, "post-edit", payload, client="claude", deps=HookDeps(verify=verify)
    )
    assert out["decision"] == "block"
    assert "app.py:5" in out["reason"]


def test_post_edit_uses_structured_patch_added_lines(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify(
        {
            "app.py": [
                (4, "SKY-D212", "context line"),
                (5, "SKY-D212", "added line"),
            ]
        }
    )
    payload = _edit_payload(app, "os.system(cmd)")
    payload["tool_response"] = {
        "filePath": str(app),
        "structuredPatch": [
            {
                "oldStart": 4,
                "oldLines": 2,
                "newStart": 4,
                "newLines": 2,
                "lines": [" def run(cmd):", "-    pass", "+    os.system(cmd)"],
            }
        ],
    }
    _, out, _ = _run(
        tmp_path, "post-edit", payload, client="claude", deps=HookDeps(verify=verify)
    )
    assert "app.py:5 SKY-D212 added line" in out["reason"]
    assert "context line" not in out["reason"]


def test_post_edit_caps_items_and_strips_secret_previews(tmp_path):
    body = "".join(f"x{i} = 1\n" for i in range(20))
    app = _write(tmp_path / "app.py", body)
    findings = [
        (i + 1, "SKY-S101", "Potential AWS key detected (redacted: wJal…EKEY)")
        for i in range(15)
    ]
    payload = {
        "session_id": "s1",
        "tool_name": "Write",
        "tool_input": {"file_path": str(app)},
    }
    _, out, _ = _run(
        tmp_path,
        "post-edit",
        payload,
        client="claude",
        deps=HookDeps(verify=FakeVerify({"app.py": findings})),
    )
    reason = out["reason"]
    assert reason.count("\n- ") == 11  # 10 items + "...and 5 more"
    assert "...and 5 more" in reason
    assert "wJal" not in reason and "redacted" not in reason


def test_post_edit_non_code_file_runs_secret_scan(tmp_path):
    cfg = _write(
        tmp_path / "config" / "settings.yaml", f"aws_secret_access_key: {AWS_SECRET}\n"
    )
    payload = {
        "session_id": "s1",
        "tool_name": "Write",
        "tool_input": {"file_path": str(cfg)},
    }
    verify = FakeVerify()
    _, out, text = _run(
        tmp_path, "post-edit", payload, client="claude", deps=HookDeps(verify=verify)
    )
    assert out["decision"] == "block"
    assert "config/settings.yaml:1 SKY-S101" in out["reason"]
    assert AWS_SECRET not in text and AWS_SECRET[:4] not in text
    assert verify.calls == []


def test_post_edit_ignores_other_tools_and_outside_files(tmp_path, tmp_path_factory):
    outside = _write(tmp_path_factory.mktemp("outside") / "x.py", APP)
    verify = FakeVerify({"x.py": [(5, "SKY-D212", "issue")]})
    _, _, text = _run(
        tmp_path,
        "post-edit",
        _edit_payload(outside, "os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )
    assert text == ""
    _, _, text = _run(
        tmp_path,
        "post-edit",
        {"tool_name": "Read", "tool_input": {"file_path": str(tmp_path / "a.py")}},
        client="claude",
        deps=HookDeps(verify=verify),
    )
    assert text == ""
    assert verify.calls == []


def test_post_edit_codex_apply_patch(tmp_path):
    _write(tmp_path / "app.py", APP)
    new = _write(tmp_path / "pkg" / "new.py", "import os\nos.system(input())\n")
    patch = (
        "*** Begin Patch\n"
        "*** Update File: app.py\n"
        "@@ def run(cmd):\n"
        "-    pass\n"
        "+    os.system(cmd)\n"
        "*** Add File: pkg/new.py\n"
        "+import os\n"
        "+os.system(input())\n"
        "*** End Patch\n"
    )
    verify = FakeVerify(
        {
            "app.py": [(5, "SKY-D212", "app issue"), (9, "SKY-D3", "untouched")],
            "new.py": [(2, "SKY-D203", "new file issue")],
        }
    )
    payload = {
        "session_id": "c1",
        "turn_id": "t1",
        "cwd": str(tmp_path),
        "hook_event_name": "PostToolUse",
        "tool_name": "apply_patch",
        "tool_input": {"command": patch},
    }
    _, out, _ = _run(tmp_path, "post-edit", payload, deps=HookDeps(verify=verify))
    assert out["decision"] == "block"
    assert "app.py:5 SKY-D212" in out["reason"]
    assert "pkg/new.py:2 SKY-D203" in out["reason"]
    assert "SKY-D3" not in out["reason"]
    assert new.exists()


def test_cursor_after_file_edit_is_silent_then_stop_follows_up(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify({"app.py": [(5, "SKY-D212", "issue")]})
    edit = {
        "conversation_id": "cur1",
        "hook_event_name": "afterFileEdit",
        "cursor_version": "2.0",
        "workspace_roots": [str(tmp_path)],
        "file_path": str(app),
        "edits": [{"old_string": "pass", "new_string": "os.system(cmd)"}],
    }
    _, _, text = _run(
        tmp_path, "post-edit", edit, client="cursor", deps=HookDeps(verify=verify)
    )
    assert text == ""

    stop = {
        "conversation_id": "cur1",
        "hook_event_name": "stop",
        "status": "completed",
        "loop_count": 0,
    }
    _, out, _ = _run(
        tmp_path, "stop", stop, client="cursor", deps=HookDeps(verify=verify)
    )
    assert "app.py:5 SKY-D212" in out["followup_message"]


# --------------------------------------------------------------------------
# stop
# --------------------------------------------------------------------------


def test_stop_blocks_while_introduced_issue_open_then_allows_after_fix(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify({"app.py": [(5, "SKY-D212", "Possible command injection")]})
    _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )

    _, out, _ = _run(
        tmp_path,
        "stop",
        {"session_id": "s1", "stop_hook_active": False},
        client="claude",
        deps=HookDeps(verify=verify),
    )
    assert out["decision"] == "block"
    assert "app.py:5 SKY-D212" in out["reason"]

    # Agent fixes the line: file changes on disk, verify is re-run by stop.
    app.write_text(
        APP.replace("os.system(cmd)", "subprocess.run([cmd])"), encoding="utf-8"
    )
    fixed = FakeVerify()
    _, out, _ = _run(
        tmp_path,
        "stop",
        {"session_id": "s1", "stop_hook_active": True},
        client="claude",
        deps=HookDeps(verify=fixed),
    )
    assert out == {}
    assert len(fixed.calls) == 1


def test_stop_ignores_pre_existing_issues_in_edited_file(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify({"app.py": [(9, "SKY-D3", "pre-existing")]})
    _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )
    _, out, _ = _run(
        tmp_path,
        "stop",
        {"session_id": "s1"},
        client="claude",
        deps=HookDeps(verify=verify),
    )
    assert out == {}


def test_stop_does_not_loop_on_unchanged_issues(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify({"app.py": [(5, "SKY-D212", "issue")]})
    _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )
    _, first, _ = _run(
        tmp_path,
        "stop",
        {"session_id": "s1", "stop_hook_active": False},
        client="claude",
        deps=HookDeps(verify=verify),
    )
    _, second, _ = _run(
        tmp_path,
        "stop",
        {"session_id": "s1", "stop_hook_active": True},
        client="claude",
        deps=HookDeps(verify=verify),
    )
    assert first["decision"] == "block"
    assert "decision" not in second
    assert "still open" in second["systemMessage"]


def test_stop_other_session_and_empty_session_allow(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify({"app.py": [(5, "SKY-D212", "issue")]})
    _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )
    _, out, _ = _run(
        tmp_path,
        "stop",
        {"session_id": "other"},
        client="codex",
        deps=HookDeps(verify=verify),
    )
    assert out == {}


# --------------------------------------------------------------------------
# pre-read (real secrets scanner)
# --------------------------------------------------------------------------


SECRET_FILE = (
    "import os\n\n\n"
    "def run():\n"
    "    return 1\n\n\n"
    f'AWS_SECRET_ACCESS_KEY = "{AWS_SECRET}"\n'
    f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"\n'
)


def _read_payload(path: Path, **tool_input):
    return {
        "session_id": "s1",
        "tool_name": "Read",
        "tool_input": {"file_path": str(path), **tool_input},
    }


def test_pre_read_denies_file_with_secrets_without_leaking_them(tmp_path):
    app = _write(tmp_path / "creds.py", SECRET_FILE)
    code, out, text = _run(tmp_path, "pre-read", _read_payload(app), client="claude")
    assert code == 0
    spec = out["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse"
    assert spec["permissionDecision"] == "deny"
    assert "creds.py" in spec["permissionDecisionReason"]
    assert "8, 9" in spec["permissionDecisionReason"]
    for leaked in (AWS_SECRET, AWS_KEY_ID, AWS_SECRET[:4], AWS_KEY_ID[-4:]):
        assert leaked not in text
    log_text = (tmp_path / ".skylos" / "hook.log").read_text()
    assert AWS_SECRET[:4] not in log_text and AWS_KEY_ID not in log_text


def test_pre_read_allows_window_that_skips_secret_lines(tmp_path):
    app = _write(tmp_path / "creds.py", SECRET_FILE)
    _, _, text = _run(
        tmp_path, "pre-read", _read_payload(app, offset=1, limit=5), client="claude"
    )
    assert text == ""


def test_pre_read_clean_file_and_cursor_shapes(tmp_path):
    clean = _write(tmp_path / "clean.py", "x = 1\n")
    _, _, text = _run(tmp_path, "pre-read", _read_payload(clean), client="claude")
    assert text == ""  # never "allow": that would skip Claude's permission prompt

    _, out, _ = _run(
        tmp_path,
        "pre-read",
        {
            "hook_event_name": "beforeReadFile",
            "file_path": str(clean),
            "content": "x = 1\n",
        },
        client="cursor",
    )
    assert out == {"permission": "allow"}

    secret = _write(tmp_path / "creds.py", SECRET_FILE)
    _, out, text = _run(
        tmp_path,
        "pre-read",
        {
            "hook_event_name": "beforeReadFile",
            "file_path": str(secret),
            "content": SECRET_FILE,
        },
        client="cursor",
    )
    assert out["permission"] == "deny"
    assert "creds.py" in out["user_message"]
    assert AWS_SECRET not in text


# --------------------------------------------------------------------------
# pre-bash
# --------------------------------------------------------------------------


class FakeInstallChecker:
    def __init__(self, findings=None):
        self.findings = findings or []
        self.calls = []

    def __call__(self, command, root):
        self.calls.append(command)
        return {
            "packages": [{"name": "x"}],
            "findings": self.findings,
            "unverified": [],
        }


def _bash(command):
    return {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": command}}


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git commit -m 'pip install foo'",
        "pytest -q",
        "echo npm",
        "go test ./...",
    ],
)
def test_pre_bash_unrelated_commands_allowed(tmp_path, command, monkeypatch):
    def no_network(*_args, **_kwargs):
        raise AssertionError("unrelated commands must not hit a registry")

    monkeypatch.setattr(
        "skylos.rules.ai_defect.install_command.check_install_package_status",
        no_network,
    )
    code, _, text = _run(tmp_path, "pre-bash", _bash(command), client="claude")
    assert code == 0 and text == ""
    assert _log_lines(tmp_path)[-1]["outcome"] in {"skip", "pass"}


def test_pre_bash_blocks_hallucinated_package(tmp_path):
    checker = FakeInstallChecker(
        [
            {
                "message": "PyPI package 'fastapi-authz' does not exist on PyPI (likely hallucinated)."
            }
        ]
    )
    _, out, _ = _run(
        tmp_path,
        "pre-bash",
        _bash("pip install fastapi-authz"),
        client="claude",
        deps=HookDeps(install_checker=checker),
    )
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny"
    assert "fastapi-authz" in spec["permissionDecisionReason"]

    _, out, _ = _run(
        tmp_path,
        "pre-bash",
        {
            "hook_event_name": "beforeShellExecution",
            "command": "pip install fastapi-authz",
        },
        client="cursor",
        deps=HookDeps(install_checker=checker),
    )
    assert out["permission"] == "deny"
    assert "fastapi-authz" in out["agent_message"]


def test_pre_bash_real_packages_allowed(tmp_path):
    checker = FakeInstallChecker()
    _, _, text = _run(
        tmp_path,
        "pre-bash",
        _bash("npm install lodash"),
        client="claude",
        deps=HookDeps(install_checker=checker),
    )
    assert text == "" and checker.calls == ["npm install lodash"]


def test_install_command_packages_parsing():
    parsed = install_command_packages(
        "pip install requests reqeusts==1.0 -r req.txt && npm i -D lodash @types/node@20 "
        "left-pad@1.3.0 ./local && go get github.com/gorilla/mux@v1.8.0 ./... && ls"
    )
    names = {(p["ecosystem"], p["name"], p["version"]) for p in parsed}
    assert names == {
        ("PyPI", "requests", ""),
        ("PyPI", "reqeusts", "1.0"),
        ("npm", "lodash", ""),
        ("npm", "@types/node", ""),
        ("npm", "left-pad", "1.3.0"),
        ("Go", "github.com/gorilla/mux", ""),
    }
    assert install_command_packages("git commit -m 'pip install foo'") == []
    assert (
        install_command_packages("pip install -e . && pip install ./dist/x.whl") == []
    )
    private = install_command_packages(
        "PIP_INDEX_URL=https://corp.example/simple pip install internal"
    )
    assert private[0]["private"] is True


def test_check_install_command_statuses_without_network(tmp_path):
    statuses = {
        "real-pkg": "present",
        "fake-pkg": "missing_package",
        "reqests": "present",
    }
    seen = []

    def checker(ecosystem, name, version, cache):
        seen.append(name)
        return statuses.get(name, "unknown")

    result = check_install_command(
        "pip install real-pkg fake-pkg reqests offline-pkg",
        tmp_path,
        status_checker=checker,
    )
    by_name = {f["name"]: f for f in result["findings"]}
    assert by_name["fake-pkg"]["state"] == "missing_package"
    assert by_name["reqests"]["state"] == "suspicious_existing"
    assert "requests" in by_name["reqests"]["message"]
    assert "real-pkg" not in by_name
    assert [u["name"] for u in result["unverified"]] == ["offline-pkg"]

    # Authoritative answers are cached per project; unknown ones are retried.
    seen.clear()
    check_install_command(
        "pip install real-pkg fake-pkg offline-pkg", tmp_path, status_checker=checker
    )
    assert seen == ["offline-pkg"]

    private = check_install_command(
        "pip install --index-url https://corp.example/simple fake-pkg",
        tmp_path,
        status_checker=checker,
    )
    assert private["findings"] == []
    assert private["unverified"][0]["reason"] == "private registry"


# --------------------------------------------------------------------------
# fail open
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event,client,expected",
    [
        ("post-edit", "claude", None),
        ("pre-read", "claude", None),
        ("pre-bash", "claude", None),
        ("stop", "claude", {}),
        ("stop", "codex", {}),
        ("pre-read", "cursor", {"permission": "allow"}),
        ("pre-bash", "cursor", {"permission": "allow"}),
    ],
)
@pytest.mark.parametrize("raw", ["not json {", "", "[1, 2]", '{"tool_input": "oops"}'])
def test_malformed_input_fails_open(tmp_path, event, client, expected, raw):
    code, out, _ = _run(tmp_path, event, None, client=client, raw=raw)
    assert code == 0
    assert out == expected


def test_internal_error_fails_open_and_is_logged(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify(error=RuntimeError("analyzer exploded"))
    code, _, text = _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )
    assert code == 0 and text == ""
    entry = _log_lines(tmp_path)[-1]
    assert entry["outcome"] == "error" and entry["error"] == "RuntimeError"


def test_unknown_event_and_bad_client_fail_open(tmp_path):
    code, out, _ = _run(tmp_path, "nope", {"a": 1}, client="claude")
    assert code == 0 and out is None
    stdout = io.StringIO()
    assert (
        run_hook_command(
            ["stop", "--client"],
            stdin=io.StringIO("{}"),
            stdout=stdout,
            deps=HookDeps(env={"CLAUDE_PROJECT_DIR": str(tmp_path)}),
        )
        == 0
    )


def test_disable_env_turns_hook_off(tmp_path):
    app = _write(tmp_path / "creds.py", SECRET_FILE)
    (tmp_path / ".git").mkdir()
    stdout = io.StringIO()
    deps = HookDeps(
        env={
            "CLAUDE_PROJECT_DIR": str(tmp_path),
            "SKYLOS_HOOKS_DISABLE": "pre-read,stop",
        }
    )
    run_hook_command(
        ["pre-read", "--client", "claude"],
        stdin=io.StringIO(json.dumps(_read_payload(app))),
        stdout=stdout,
        deps=deps,
    )
    assert stdout.getvalue() == ""
    assert _log_lines(tmp_path)[-1]["outcome"] == "disabled"


def test_hook_is_registered_as_early_cli_command():
    from skylos.cli_core.dispatch import EARLY_COMMAND_HANDLERS
    import skylos.cli as cli

    assert EARLY_COMMAND_HANDLERS["hook"] == "_run_hook_command"
    assert callable(getattr(cli, "_run_hook_command"))
    parser = cli._build_agent_parser()
    args = parser.parse_args(["install-hooks", "--cursor", "--user", "--uninstall"])
    assert (args.agent, args.scope, args.uninstall) == ("cursor", "user", True)


def test_verify_change_path_can_skip_behavior_comparison(tmp_path):
    from skylos.verify_change import verify_change_path

    app = _write(tmp_path / "app.py", "x = 1\n")
    result = verify_change_path(
        app,
        analyze_func=lambda *_a, **_k: {},
        include_dependency_hallucinations=False,
        behavior_comparison=False,
    )
    assert "behavior" not in result
    assert result["status"] in {"pass", "incomplete"}


# --------------------------------------------------------------------------
# install-hooks
# --------------------------------------------------------------------------


def _args(tmp_path, **overrides):
    values = dict(
        agent=None,
        scope=None,
        uninstall=False,
        path=str(tmp_path),
        skylos_bin=BIN,
        dry_run=False,
        check_bin=True,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


BIN = "/usr/local/bin/skylos"


def _cmd(name, client, bin_=BIN, fallback="exit 0"):
    return f"{bin_} hook {name} --client {client} || {fallback}"


def _install(tmp_path, probe=lambda _cmd: "9.9.9", **overrides):
    printed = []
    code = run_install_hooks_command(
        _args(tmp_path, **overrides),
        print_func=printed.append,
        home=tmp_path / "home",
        which=lambda _name: BIN,
        probe=probe,
    )
    return code, printed


EXISTING_CLAUDE = {
    "permissions": {"allow": ["Bash(npm test)"]},
    "hooks": {
        "PostToolUse": [
            {
                "matcher": "Edit|Write",
                "hooks": [{"type": "command", "command": "npx prettier --write"}],
            }
        ],
        "Stop": [{"hooks": [{"type": "command", "command": "say done"}]}],
    },
}


def test_install_hooks_claude_merges_and_is_idempotent(tmp_path):
    settings = _write(
        tmp_path / ".claude" / "settings.json", json.dumps(EXISTING_CLAUDE)
    )
    code, _ = _install(tmp_path)
    assert code == 0
    first = json.loads(settings.read_text())
    assert first["permissions"] == EXISTING_CLAUDE["permissions"]
    post = first["hooks"]["PostToolUse"]
    assert post[0]["hooks"][0]["command"] == "npx prettier --write"
    assert post[1]["matcher"] == "Edit|Write|MultiEdit"
    assert post[1]["hooks"][0]["command"] == _cmd("post-edit", "claude")
    assert {g["matcher"] for g in first["hooks"]["PreToolUse"]} == {
        "Read",
        "Bash|PowerShell",
    }
    assert [h["command"] for g in first["hooks"]["Stop"] for h in g["hooks"]] == [
        "say done",
        _cmd("stop", "claude", fallback="echo '{}'"),
    ]

    code, printed = _install(tmp_path)
    assert code == 0 and "no change" in printed[-1]
    assert json.loads(settings.read_text()) == first

    code, _ = _install(tmp_path, uninstall=True)
    assert code == 0
    assert json.loads(settings.read_text()) == EXISTING_CLAUDE


def test_install_hooks_uninstall_on_fresh_file_removes_hooks_key(tmp_path):
    _install(tmp_path)
    settings = tmp_path / ".claude" / "settings.json"
    assert "hooks" in json.loads(settings.read_text())
    _install(tmp_path, uninstall=True)
    assert json.loads(settings.read_text()) == {}


def test_install_hooks_refuses_invalid_json(tmp_path):
    settings = _write(tmp_path / ".claude" / "settings.json", "{ not json")
    code, printed = _install(tmp_path)
    assert code == 1 and "invalid JSON" in printed[0]
    assert settings.read_text() == "{ not json"


def test_install_hooks_cursor_and_codex_shapes(tmp_path):
    _write(
        tmp_path / ".cursor" / "hooks.json",
        json.dumps(
            {"version": 1, "hooks": {"afterFileEdit": [{"command": "./format.sh"}]}}
        ),
    )
    _install(tmp_path, agent="cursor")
    _install(tmp_path, agent="cursor")
    cursor = json.loads((tmp_path / ".cursor" / "hooks.json").read_text())
    assert cursor["version"] == 1
    assert [e["command"] for e in cursor["hooks"]["afterFileEdit"]] == [
        "./format.sh",
        _cmd("post-edit", "cursor"),
    ]
    # Cursor treats empty output from a permission hook as deny.
    assert cursor["hooks"]["beforeReadFile"][0]["command"] == _cmd(
        "pre-read", "cursor", fallback="""echo '{"permission":"allow"}'"""
    )
    assert cursor["hooks"]["stop"][0]["loop_limit"] == 3

    _install(tmp_path, agent="codex", scope="user")
    codex = json.loads((tmp_path / "home" / ".codex" / "hooks.json").read_text())
    assert codex["hooks"]["PostToolUse"][0]["matcher"] == "apply_patch|Edit|Write"
    assert codex["hooks"]["PreToolUse"][0]["hooks"][0]["statusMessage"]
    assert "Read" not in json.dumps(
        codex["hooks"]["PreToolUse"]
    )  # Codex has no Read tool


def test_install_hooks_dry_run_and_custom_bin(tmp_path):
    code, printed = _install(tmp_path, dry_run=True, skylos_bin="/opt/venv/bin/skylos")
    assert code == 0
    config = json.loads(printed[-1])
    assert config["hooks"]["Stop"][0]["hooks"][0]["command"] == _cmd(
        "stop", "claude", "/opt/venv/bin/skylos", "echo '{}'"
    )
    assert not (tmp_path / ".claude" / "settings.json").exists()
    # Custom-bin entries are still recognised as ours on reinstall/uninstall.
    cleaned, removed = uninstall_hooks(config, "claude")
    assert removed == 4 and cleaned == {}


def test_install_hooks_pure_functions_keep_foreign_entries():
    merged, removed, added = install_hooks(EXISTING_CLAUDE, "claude", "skylos")
    assert (removed, added) == (0, 4)
    again, removed, added = install_hooks(merged, "claude", "skylos")
    assert again == merged and (removed, added) == (4, 4)
    assert hook_cmd.EVENTS == ("post-edit", "pre-read", "pre-bash", "stop")


def test_system_exit_inside_analysis_still_fails_open(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify(error=SystemExit(2))
    code, _, text = _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )
    assert code == 0 and text == ""
    assert _log_lines(tmp_path)[-1]["error"] == "SystemExit"


# --------------------------------------------------------------------------
# Blocking policy (QA: ordinary helpers must not block the agent)
# --------------------------------------------------------------------------

import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

from skylos.commands.hook_policy import classify_findings, dedupe_by_line  # noqa: E402

QA_SOURCE = """import json
import os
import pickle
import subprocess
import urllib.request
from pathlib import Path


def load_config(path):
    with open(path) as fh:
        return fh.read()


def load_json(path):
    return json.load(open(path))


def read_text(path):
    return Path(path).read_text()


def fetch(url):
    return urllib.request.urlopen(url, timeout=5)


def save(path, data):
    with open(path, "w") as fh:
        fh.write(data)


def clear_screen():
    os.system("clear")


def run_cmd(request):
    os.system(request.GET["cmd"])


def read_name(request):
    name = request.GET.get("name")
    return open(name).read()


def load_blob(data):
    return pickle.loads(data)


def run_eval(expr):
    return eval(expr)


def shell(cmd):
    subprocess.run(cmd, shell=True)
"""
QA_HELPER_LINES = {11, 15, 19, 23, 27, 32}  # open/json.load/read_text/urlopen/write/"clear"
QA_BLOCKING_LINES = {36, 41, 45, 49, 53}


def _finding(line, rule, category="security", severity="HIGH", **extra):
    return {
        "path": "app.py",
        "line": line,
        "rule_id": rule,
        "category": category,
        "severity": severity,
        "message": f"{rule} message",
        **extra,
    }


@pytest.mark.parametrize(
    "line,rule,blocking",
    [
        (11, "SKY-D215", False),  # def f(path): open(path)
        (15, "SKY-D215", False),  # json.load(open(path))
        (19, "SKY-D215", False),  # Path(path).read_text()
        (23, "SKY-D216", False),  # urlopen(url) of a helper parameter
        (27, "SKY-D215", False),  # open(path, "w")
        (27, "SKY-D324", False),  # symlink-following write
        (32, "SKY-D203", False),  # os.system("clear")
        (36, "SKY-D203", True),  # os.system(request.GET[...])
        (36, "SKY-D212", True),
        (41, "SKY-D215", True),  # open(name) where name = request.GET.get()
        (45, "SKY-D205", True),  # pickle.loads: dangerous regardless of input
        (49, "SKY-D201", True),  # eval(non-constant)
        (53, "SKY-D209", True),  # shell=True with a non-constant command
        (53, "SKY-D212", False),  # ...but no real source: D209 carries the block
    ],
)
def test_policy_blocks_only_real_sources_and_dangerous_sinks(line, rule, blocking):
    finding = _finding(line, rule)
    classify_findings([finding], Path("app.py"), QA_SOURCE)
    assert finding["blocking"] is blocking, finding["why"]


def test_policy_blocks_route_cli_and_env_sources():
    source = (
        "import os, sys\n"
        "@app.get('/x')\n"
        "def route(cmd: str):\n"
        "    os.system(cmd)\n"
        "@click.command()\n"
        "def cli(path):\n"
        "    return open(path).read()\n"
        "def env():\n"
        "    target = os.environ['TARGET']\n"
        "    return open(target).read()\n"
        "def argv():\n"
        "    return open(sys.argv[1]).read()\n"
        "def fastapi(req: Request):\n"
        "    return open(req.query_params['p']).read()\n"
    )
    findings = [
        _finding(4, "SKY-D212"),
        _finding(7, "SKY-D215"),
        _finding(10, "SKY-D215"),
        _finding(12, "SKY-D215"),
        _finding(14, "SKY-D215"),
    ]
    classify_findings(findings, Path("app.py"), source)
    assert [f["blocking"] for f in findings] == [True] * 5


def test_policy_secrets_and_hallucinations_always_block_others_are_notes():
    findings = [
        _finding(1, "SKY-S101", category="secret"),
        _finding(2, "SKY-D222", category="ai_defect"),
        _finding(3, "SKY-L012", category="ai_defect"),
        _finding(4, "SKY-X1", category="ai_defect", vibe="api_signature_hallucination"),
        _finding(5, "SKY-L030", category="ai_defect"),  # swallowed error
        _finding(6, "SKY-D251"),  # sensitive data in logs
        _finding(7, "SKY-D212"),  # non-Python, no evidence
        _finding(
            8,
            "SKY-D212",
            metadata={"security_evidence": {"source": "req.query.cmd"}},
        ),
    ]
    classify_findings(findings, Path("app.ts"), "")
    assert [f["blocking"] for f in findings] == [
        True, True, True, True, False, False, False, True,
    ]  # fmt: skip


def test_dedupe_merges_same_line_findings():
    merged = dedupe_by_line(
        [
            _finding(5, "SKY-D203", blocking=True, why="dangerous-sink"),
            _finding(5, "SKY-D212", blocking=True, why="untrusted-source"),
            _finding(9, "SKY-S101", category="secret", blocking=True),
            _finding(9, "SKY-S101", category="secret", blocking=True),
        ]
    )
    assert sorted(f["rule_id"] for f in merged) == ["SKY-D212/SKY-D203", "SKY-S101"]


def test_post_edit_real_analyzer_qa_helpers_are_notes_not_blocks(tmp_path):
    app = _write(tmp_path / "app.py", QA_SOURCE)
    payload = {
        "session_id": "qa",
        "tool_name": "Write",
        "tool_input": {"file_path": str(app)},
        "tool_response": {"type": "create"},
    }
    _, out, _ = _run(tmp_path, "post-edit", payload, client="claude")
    reason = out["reason"]
    blocked = {
        int(line.split(":")[1].split()[0])
        for line in reason.split("Check again")[0].splitlines()
        if line.startswith("- app.py:")
    }
    assert blocked == QA_BLOCKING_LINES
    assert "hook recheck app.py" in reason
    assert "Skylos notes (not blocking" in reason
    # One item per line: D203+D212 on line 36 is merged.
    assert reason.count("app.py:36") == 1


def test_post_edit_notes_only_is_additional_context_and_never_blocks_stop(tmp_path):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify({"app.py": [(9, "SKY-D215", "Possible path traversal")]})
    payload = {
        "session_id": "n1",
        "tool_name": "Write",
        "tool_input": {"file_path": str(app)},
        "tool_response": {"type": "create"},
    }
    _, out, _ = _run(
        tmp_path, "post-edit", payload, client="claude", deps=HookDeps(verify=verify)
    )
    spec = out["hookSpecificOutput"]
    assert spec["hookEventName"] == "PostToolUse"
    assert "app.py:9 SKY-D215" in spec["additionalContext"]
    assert "decision" not in out
    _, codex_out, text = _run(
        tmp_path, "post-edit", payload, client="codex", deps=HookDeps(verify=verify)
    )
    assert text == ""
    _, stop, _ = _run(
        tmp_path, "stop", {"session_id": "n1"}, client="claude", deps=HookDeps(verify=verify)
    )
    assert stop == {}


# --------------------------------------------------------------------------
# recheck: the command the block message recommends
# --------------------------------------------------------------------------


def test_recheck_matches_hook_verdict(tmp_path, monkeypatch):
    app = _write(tmp_path / "app.py", APP)
    verify = FakeVerify({"app.py": [(5, "SKY-D212", "injection"), (9, "SKY-D215", "n")]})
    _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "os.system(cmd)"),
        client="claude",
        deps=HookDeps(verify=verify),
    )
    monkeypatch.chdir(tmp_path)
    deps = HookDeps(verify=verify, env={"CLAUDE_PROJECT_DIR": str(tmp_path)})
    stdout = io.StringIO()
    assert run_hook_command(["recheck", "app.py"], stdout=stdout, deps=deps) == 1
    assert "app.py:5 SKY-D212" in stdout.getvalue()
    assert len(stdout.getvalue()) < 1000

    app.write_text(APP.replace("os.system(cmd)", "print(cmd)"), encoding="utf-8")
    fixed = HookDeps(verify=FakeVerify({"app.py": [(9, "SKY-D215", "n")]}), env=deps.env)
    stdout = io.StringIO()
    assert run_hook_command(["recheck", "app.py"], stdout=stdout, deps=fixed) == 0
    assert "no blocking issues" in stdout.getvalue()
    assert "1 non-blocking note" in stdout.getvalue()

    stdout = io.StringIO()
    assert run_hook_command(["recheck"], stdout=stdout, deps=fixed) == 2
    assert run_hook_command(["recheck", "missing.py"], stdout=io.StringIO(), deps=fixed) == 2


# --------------------------------------------------------------------------
# Secrets: pre-read in test files, gitignored .env writes
# --------------------------------------------------------------------------

STRIPE_LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def test_pre_read_scans_test_files(tmp_path):
    conftest = _write(
        tmp_path / "tests" / "conftest.py", f'STRIPE_KEY = "{STRIPE_LIVE}"\n'
    )
    _, out, text = _run(tmp_path, "pre-read", _read_payload(conftest), client="claude")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert STRIPE_LIVE not in text


def _git(tmp_path, *args):
    subprocess.run(
        ["git", *args], cwd=tmp_path, check=True, capture_output=True, timeout=30
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_post_edit_allows_secret_in_gitignored_env_but_not_tracked_files(tmp_path):
    _git(tmp_path, "init", "-q")
    _write(tmp_path / ".gitignore", ".env\n")
    env = _write(tmp_path / ".env", f"STRIPE_KEY={STRIPE_LIVE}\n")
    example = _write(tmp_path / ".env.example", f"STRIPE_KEY={STRIPE_LIVE}\n")
    for path, blocked in ((env, False), (example, True)):
        payload = {
            "session_id": "e1",
            "tool_name": "Write",
            "tool_input": {"file_path": str(path)},
        }
        _, out, text = _run(tmp_path, "post-edit", payload, client="claude")
        assert (out is not None and out.get("decision") == "block") is blocked, path
        assert STRIPE_LIVE not in text


# --------------------------------------------------------------------------
# State and log location
# --------------------------------------------------------------------------


def test_non_git_root_keeps_state_and_log_in_user_cache(tmp_path, monkeypatch):
    project = tmp_path / "not-a-repo"
    project.mkdir()
    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    app = _write(project / "app.py", APP)
    stdout = io.StringIO()
    run_hook_command(
        ["post-edit", "--client", "claude"],
        stdin=io.StringIO(json.dumps(_edit_payload(app, "os.system(cmd)"))),
        stdout=stdout,
        deps=HookDeps(
            verify=FakeVerify({"app.py": [(5, "SKY-D212", "i")]}),
            env={"CLAUDE_PROJECT_DIR": str(project)},
        ),
    )
    assert json.loads(stdout.getvalue())["decision"] == "block"
    assert not (project / ".skylos").exists()
    assert list(cache.glob("skylos/projects/*/.skylos/hook.log"))
    assert list(cache.glob("skylos/projects/*/.skylos/agent-session.json"))


# --------------------------------------------------------------------------
# Install: absolute, verified, fail-safe command
# --------------------------------------------------------------------------


def test_install_resolves_relative_bin_and_refuses_unsupported(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = []

    def probe(cmd):
        seen.append(cmd)
        return "9.9.9"

    code, printed = _install(tmp_path, probe=probe, dry_run=True, skylos_bin="venv/bin/skylos")
    assert code == 0
    absolute = str(tmp_path / "venv" / "bin" / "skylos")
    assert seen == [[absolute]]
    assert absolute in printed[-1]

    code, printed = _install(tmp_path, probe=lambda _cmd: None)
    assert code == 1
    assert "Refusing to install" in printed[-1]
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_install_default_uses_current_interpreter(tmp_path):
    code, printed = _install(tmp_path, dry_run=True, skylos_bin=None)
    assert code == 0
    command = json.loads(printed[-1])["hooks"]["Stop"][0]["hooks"][0]["command"]
    assert "-m skylos.entry hook stop --client claude" in command
    assert command.split()[0].strip("'") == sys.executable
    # Reinstall/uninstall still recognises the interpreter form as ours.
    assert uninstall_hooks(json.loads(printed[-1]), "claude")[1] == 4


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell wrapper")
@pytest.mark.parametrize(
    "script,stdout_expected",
    [
        # Released skylos without `hook`: argparse usage + exit 2.
        ("#!/bin/sh\necho 'usage: skylos [-h]' >&2\nexit 2\n", ""),
        (None, ""),  # binary missing on this machine
    ],
)
def test_installed_command_never_exits_2_on_old_or_missing_binary(
    tmp_path, script, stdout_expected
):
    binary = tmp_path / "old-skylos"
    if script is not None:
        binary.write_text(script)
        binary.chmod(0o755)
    from skylos.commands.install_hooks_cmd import hook_command

    for name, client, expected in (
        ("pre-read", "claude", ""),
        ("post-edit", "claude", ""),
        ("stop", "codex", "{}"),
        ("pre-bash", "cursor", '{"permission":"allow"}'),
    ):
        proc = subprocess.run(
            ["/bin/sh", "-c", hook_command(str(binary), name, client)],
            input="{}",
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == expected


def test_install_gitignores_hook_state_idempotently(tmp_path):
    (tmp_path / ".git").mkdir()
    gitignore = _write(tmp_path / ".gitignore", "node_modules/")
    code, printed = _install(tmp_path)
    assert code == 0
    text = gitignore.read_text()
    assert text.startswith("node_modules/\n")
    for entry in (".skylos/cache/", ".skylos/agent-session.*", ".skylos/hook.log*"):
        assert entry in text.splitlines()
    _install(tmp_path, uninstall=True)
    _install(tmp_path)
    assert gitignore.read_text() == text


def test_install_without_gitignore_writes_local_skylos_gitignore(tmp_path):
    (tmp_path / ".git").mkdir()
    _install(tmp_path)
    local = (tmp_path / ".skylos" / ".gitignore").read_text()
    assert "cache/" in local and "agent-session.*" in local
    assert not (tmp_path / ".gitignore").exists()


# --------------------------------------------------------------------------
# pre-bash typosquat allowlists
# --------------------------------------------------------------------------


def test_install_check_allows_known_legitimate_and_user_allowlisted(tmp_path):
    def present(ecosystem, name, version, cache):
        return "present"

    result = check_install_command(
        "npm install preact react-dom reactt", tmp_path, status_checker=present
    )
    assert [f["name"] for f in result["findings"]] == ["reactt"]

    pip = check_install_command("pip install pyaml", tmp_path, status_checker=present)
    assert pip["findings"] == []

    _write(
        tmp_path / "pyproject.toml",
        '[tool.skylos]\nhooks_allow_packages = ["npm:reactt", "internal-pkg"]\n',
    )
    missing = check_install_command(
        "npm install reactt internal-pkg",
        tmp_path,
        status_checker=lambda *a: "missing_package",
    )
    assert missing["findings"] == []
    assert {u["reason"] for u in missing["unverified"]} == {"allowlisted"}


# --------------------------------------------------------------------------
# Disabled security controls always block (TLS / JWT verification)
# --------------------------------------------------------------------------

TLS_JWT_SOURCE = """import jwt
import requests


def get(url):
    return requests.get(url, verify=False, timeout=5)


def ok(url):
    return requests.get(url, timeout=5)


def decode(token, key):
    return jwt.decode(token, options={"verify_signature": False})


def decode_ok(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
"""


@pytest.mark.parametrize("rule", ["SKY-D210", "SKY-G210", "SKY-D232", "SKY-D246"])
def test_policy_disabled_verification_always_blocks(rule):
    finding = _finding(3, rule)
    classify_findings([finding], Path("helper.py"), "x = 1\n\n\ny = 2\n")
    assert finding["blocking"] is True


def test_post_edit_real_analyzer_blocks_disabled_tls_and_jwt_only(tmp_path):
    app = _write(tmp_path / "net.py", TLS_JWT_SOURCE)
    payload = {
        "session_id": "tls",
        "tool_name": "Write",
        "tool_input": {"file_path": str(app)},
        "tool_response": {"type": "create"},
    }
    _, out, _ = _run(tmp_path, "post-edit", payload, client="claude")
    blocked = {
        int(line.split(":")[1].split()[0])
        for line in out["reason"].split("Check again")[0].splitlines()
        if line.startswith("- net.py:")
    }
    assert {6, 14} <= blocked  # verify=False, verify_signature=False
    assert not blocked & {10, 18}  # verified request / verified decode


def test_non_git_root_keeps_analyzer_caches_out_of_the_project(tmp_path, monkeypatch):
    project = tmp_path / "scratch"
    project.mkdir()
    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    app = _write(project / "app.py", QA_SOURCE)
    stdout = io.StringIO()
    run_hook_command(
        ["post-edit", "--client", "claude"],
        stdin=io.StringIO(
            json.dumps(
                {
                    "session_id": "u1",
                    "tool_name": "Write",
                    "tool_input": {"file_path": str(app)},
                    "tool_response": {"type": "create"},
                }
            )
        ),
        stdout=stdout,
        deps=HookDeps(env={"CLAUDE_PROJECT_DIR": str(project)}),  # real verify
    )
    assert json.loads(stdout.getvalue())["decision"] == "block"
    assert not (project / ".skylos").exists()
    cached = {p.name for p in cache.glob("skylos/projects/*/.skylos/cache/*.json")}
    assert "module-facts.json" in cached


def test_cache_redirect_only_applies_inside_block(tmp_path):
    from skylos.core.safe_cache_io import (
        load_project_json_cache,
        redirect_project_caches,
        save_project_json_cache,
    )

    project, store = tmp_path / "p", tmp_path / "s"
    (project / "sub").mkdir(parents=True)
    store.mkdir()
    rel = Path(".skylos") / "cache" / "x.json"
    with redirect_project_caches(project, store):
        assert save_project_json_cache(project / "sub", rel, {"a": 1})
        assert load_project_json_cache(project, rel) == {"a": 1}
    assert (store / rel).exists() and not (project / ".skylos").exists()
    assert load_project_json_cache(project, rel) == {}


# --------------------------------------------------------------------------
# Stop re-verifies files with open issues even when only another file changed
# --------------------------------------------------------------------------


def _stop(tmp_path, deps, active=False, session="s1"):
    return _run(
        tmp_path,
        "stop",
        {"session_id": session, "stop_hook_active": active},
        client="claude",
        deps=deps,
    )


def test_stop_allows_issue_fixed_in_another_file_fake_verify(tmp_path):
    items = _write(tmp_path / "items.py", "from app import crud\ncrud.delete_item()\n")
    crud = _write(tmp_path / "crud.py", "X = 1\n")
    missing = FakeVerify({"items.py": [(2, "SKY-L012", "delete_item is not defined")]})
    _, out, _ = _run(
        tmp_path,
        "post-edit",
        _edit_payload(items, "crud.delete_item()"),
        client="claude",
        deps=HookDeps(verify=missing),
    )
    assert out["decision"] == "block"

    # The definition lands in crud.py; items.py itself is untouched.
    crud.write_text("def delete_item():\n    pass\n", encoding="utf-8")
    defined = FakeVerify()
    _run(
        tmp_path,
        "post-edit",
        _edit_payload(crud, "def delete_item():"),
        client="claude",
        deps=HookDeps(verify=defined),
    )
    _, out, _ = _stop(tmp_path, HookDeps(verify=defined))
    assert out == {}
    assert any(Path(c[0]).name == "items.py" for c in defined.calls)
    _, out, _ = _stop(tmp_path, HookDeps(verify=defined), active=True)
    assert out == {}


def test_stop_and_recheck_agree_after_cross_file_fix_real_verify(tmp_path, monkeypatch):
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    crud = _write(
        tmp_path / "app" / "crud.py", "def get_item(item_id):\n    return item_id\n"
    )
    items = _write(
        tmp_path / "app" / "routers" / "items.py",
        "from app import crud\n\n\ndef read(item_id):\n"
        "    return crud.get_item(item_id)\n\n\ndef delete(item_id):\n"
        "    return crud.delete_item(item_id)\n",
    )
    real = HookDeps()  # real verify
    _, out, _ = _run(
        tmp_path,
        "post-edit",
        _edit_payload(items, "    return crud.delete_item(item_id)"),
        client="claude",
        deps=real,
    )
    assert out["decision"] == "block"
    assert "SKY-L012" in out["reason"]
    _, out, _ = _stop(tmp_path, HookDeps())
    assert out["decision"] == "block"

    crud.write_text(
        crud.read_text() + "\n\ndef delete_item(item_id):\n    return item_id\n",
        encoding="utf-8",
    )
    _run(
        tmp_path,
        "post-edit",
        _edit_payload(crud, "def delete_item(item_id):"),
        client="claude",
        deps=HookDeps(),
    )
    monkeypatch.chdir(tmp_path)
    env = {"CLAUDE_PROJECT_DIR": str(tmp_path)}
    stdout = io.StringIO()
    code = run_hook_command(
        ["recheck", "app/routers/items.py"], stdout=stdout, deps=HookDeps(env=env)
    )
    assert code == 0, stdout.getvalue()
    _, out, _ = _stop(tmp_path, HookDeps(), active=True)
    assert out == {}


def test_stop_hint_lists_every_file_or_points_to_session_recheck(tmp_path, monkeypatch):
    names = [f"m{i}.py" for i in range(7)]
    verify = FakeVerify({n: [(2, "SKY-D212", "injection")] for n in names})
    for name in names:
        path = _write(tmp_path / name, "import os\nos.system(input())\n")
        _run(
            tmp_path,
            "post-edit",
            _edit_payload(path, "os.system(input())"),
            client="claude",
            deps=HookDeps(verify=verify),
        )
    _, out, _ = _stop(tmp_path, HookDeps(verify=verify))
    hint = out["reason"].split("Check again with:")[1]
    assert "hook recheck --session" in hint
    assert "all 7 files" in hint and "and 2 more" in hint

    few = hook_cmd._rerun_hint(
        [{"path": str(tmp_path / n)} for n in names[:4]], tmp_path
    )
    assert all(n in few for n in names[:4]) and "--session" not in few

    monkeypatch.chdir(tmp_path)
    deps = HookDeps(verify=verify, env={"CLAUDE_PROJECT_DIR": str(tmp_path)})
    stdout = io.StringIO()
    assert run_hook_command(["recheck", "--session"], stdout=stdout, deps=deps) == 1
    assert "7 blocking issue(s)" in stdout.getvalue()
    assert len(verify.calls) == 7 * 3  # post-edit, stop, recheck --session

    for name in names:
        (tmp_path / name).write_text("import os\nprint(1)\n", encoding="utf-8")
    clean = HookDeps(verify=FakeVerify(), env=deps.env)
    stdout = io.StringIO()
    assert run_hook_command(["recheck", "--session"], stdout=stdout, deps=clean) == 0
    assert "no blocking issues in 7 file(s)" in stdout.getvalue()
    bad = io.StringIO()
    assert run_hook_command(["recheck", "--session", "m0.py"], stdout=bad, deps=clean) == 2


def test_pre_bash_deny_mentions_allowlist_escape_hatch(tmp_path):
    checker = FakeInstallChecker(
        [{"message": "PyPI package 'reqeusts' looks like a typosquat of 'requests'."}]
    )
    _, out, _ = _run(
        tmp_path,
        "pre-bash",
        _bash("pip install reqeusts"),
        client="claude",
        deps=HookDeps(install_checker=checker),
    )
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert (
        "If this package is correct, add it to [tool.skylos] hooks_allow_packages"
        in reason
    )


def test_post_edit_env_generic_key_secret_blocks_without_leaking(tmp_path):
    value = "ak_live_" + "7Hq2Lm9Xv4Rt8Wz1Np6Ks3Jd"
    env = _write(tmp_path / ".env", f"ACME_BILLING_KEY={value}\n")
    payload = {"session_id": "k1", "tool_name": "Write", "tool_input": {"file_path": str(env)}}
    _, out, text = _run(tmp_path, "post-edit", payload, client="claude")
    assert out["decision"] == "block"
    assert ".env:1 SKY-S101" in out["reason"]
    assert value not in text


# --------------------------------------------------------------------------
# unparseable files are incomplete, never a silent pass
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "source", "edited"),
    [
        ("broken.ts", "export function ok() { return 1 }\nconst x = ;\n", "ok()"),
        ("broken.js", "function ok() { return 1 }\nfunction f( {\n", "ok()"),
        ("broken.py", "def ok():\n    return 1\n\ndef f(:\n    pass\n", "ok()"),
    ],
)
def test_post_edit_unparseable_file_is_incomplete_not_pass(
    tmp_path, name, source, edited
):
    target = _write(tmp_path / name, source)
    _, out, _ = _run(
        tmp_path, "post-edit", _edit_payload(target, edited), client="claude"
    )

    context = out["hookSpecificOutput"]["additionalContext"]
    assert f"{name}:? SKY-ANALYSIS-INCOMPLETE" in context
    assert "could not parse" in context
    assert "decision" not in out  # a note, not a block
    assert _log_lines(tmp_path)[-1]["outcome"] == "incomplete"


def test_post_edit_incomplete_without_parse_error_stays_pass(tmp_path):
    app = _write(tmp_path / "app.py", APP)

    def verify(target, **kwargs):
        return {
            "status": "incomplete",
            "findings": [],
            "coverage": {"checks": [{"reasons": [{"code": "unresolved_import"}]}]},
        }

    _, out, _ = _run(
        tmp_path,
        "post-edit",
        _edit_payload(app, "def ok():"),
        client="claude",
        deps=HookDeps(verify=verify),
    )
    assert "SKY-ANALYSIS-INCOMPLETE" not in json.dumps(out)
    assert _log_lines(tmp_path)[-1]["outcome"] == "pass"
