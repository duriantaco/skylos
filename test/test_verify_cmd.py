from __future__ import annotations

import io
import json
import sys
from functools import partial

import pytest

from skylos.commands.verify_cmd import run_verify_command
from skylos.verify_change import verify_change_path


def _unexpected_analysis(*_args, **_kwargs):
    pytest.fail("Invalid verification targets must be rejected before analysis")


@pytest.mark.parametrize("terminal", [False, True])
@pytest.mark.parametrize("no_fail", [False, True])
def test_missing_target_is_an_input_error(
    monkeypatch, capsys, tmp_path, terminal, no_fail
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: terminal)
    args = ["app.py"]
    if no_fail:
        args.append("--no-fail")

    with pytest.raises(SystemExit) as exc:
        run_verify_command(
            args,
            verify_change_path_func=partial(
                verify_change_path, analyze_func=_unexpected_analysis
            ),
        )

    output = capsys.readouterr()
    assert exc.value.code == 2
    assert output.out == ""
    assert "does not exist" in output.err
    assert str(tmp_path / "app.py") in output.err


@pytest.mark.parametrize("project_context", [False, True])
def test_missing_selected_file_is_an_input_error(capsys, tmp_path, project_context):
    (tmp_path / "existing.py").write_text("def existing():\n    return None\n")
    args = [str(tmp_path), "--file", "missing.py"]
    if project_context:
        args.append("--project-context")

    with pytest.raises(SystemExit) as exc:
        run_verify_command(
            args,
            verify_change_path_func=partial(
                verify_change_path, analyze_func=_unexpected_analysis
            ),
        )

    output = capsys.readouterr()
    assert exc.value.code == 2
    assert output.out == ""
    assert "does not exist" in output.err
    assert str(tmp_path / "missing.py") in output.err


@pytest.mark.parametrize("project_context", [False, True])
def test_selected_directory_is_an_input_error(capsys, tmp_path, project_context):
    selected_directory = tmp_path / "sources"
    selected_directory.mkdir()
    (selected_directory / "app.py").write_text("def run():\n    return None\n")
    args = [str(tmp_path), "--file", "sources"]
    if project_context:
        args.append("--project-context")

    with pytest.raises(SystemExit) as exc:
        run_verify_command(
            args,
            verify_change_path_func=partial(
                verify_change_path, analyze_func=_unexpected_analysis
            ),
        )

    output = capsys.readouterr()
    assert exc.value.code == 2
    assert output.out == ""
    assert "--file must select a file" in output.err
    assert str(selected_directory) in output.err


def _behavior_payload():
    from skylos.verification.behavior import compare_python_behavior

    comparison = compare_python_behavior(
        {"app.py": "def run(callback, value):\n    return callback(value)\n"},
        {"app.py": "def run(callback, value):\n    callback(value)\n    return None\n"},
        file="app.py",
        symbol="run",
    )
    return {
        "tool": "verify_change",
        "status": "incomplete",
        "findings": [],
        "behavior": {"status": "different", "comparisons": [comparison]},
    }


def test_terminal_explains_behavior_change_without_flags(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    code = run_verify_command(
        ["app.py"], verify_change_path_func=lambda *args, **kwargs: _behavior_payload()
    )
    output = capsys.readouterr().out
    assert code == 2
    assert output.startswith("Verification needs review")
    assert "app.py:1" in output and "run" in output
    assert "Callback result discarded" in output
    assert "callback(value)" in output and "None" in output
    assert '"schema_version"' not in output


def test_stdin_keeps_json_even_in_a_terminal(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"file":"app.py","code":"pass"}'))
    code = run_verify_command(
        ["--stdin"],
        verify_change_stdin_payload_func=lambda *args, **kwargs: _behavior_payload(),
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert (
        payload["behavior"]["comparisons"][0]["differences"][0]["explanation"]["title"]
        == "Callback result discarded"
    )


@pytest.mark.parametrize("relative_path", [False, True])
@pytest.mark.parametrize("existing_output", [False, True])
def test_output_file_keeps_json_even_in_a_terminal(
    monkeypatch, capsys, tmp_path, relative_path, existing_output
):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.chdir(tmp_path)
    output_path = tmp_path / "report.json"
    if existing_output:
        output_path.write_text("old report contents\n" * 1000, encoding="utf-8")
    destination = output_path.name if relative_path else str(output_path)
    code = run_verify_command(
        ["app.py", "--output", destination],
        verify_change_path_func=lambda *args, **kwargs: _behavior_payload(),
    )
    payload = json.loads(output_path.read_text())
    assert code == 2
    assert payload["behavior"]["status"] == "different"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("no_fail", [False, True])
@pytest.mark.parametrize("destination_kind", ["directory", "missing_parent"])
def test_output_write_failure_is_a_cli_error(
    monkeypatch, capsys, tmp_path, no_fail, destination_kind
):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    output_path = (
        tmp_path
        if destination_kind == "directory"
        else tmp_path / "missing" / "report.json"
    )
    args = ["app.py", "--output", str(output_path)]
    if no_fail:
        args.append("--no-fail")

    with pytest.raises(SystemExit) as exc:
        run_verify_command(
            args,
            verify_change_path_func=lambda *args, **kwargs: {
                "status": "pass",
                "findings": [],
            },
        )

    output = capsys.readouterr()
    assert exc.value.code == 2
    assert output.out == ""
    assert "Cannot safely write output" in output.err
    assert str(output_path) in output.err
    assert "Traceback" not in output.err
    assert list(tmp_path.iterdir()) == []


def test_run_verify_command_prints_json_and_preserves_args(capsys):
    seen = {}

    def fake_verify(path, **kwargs):
        seen["path"] = path
        seen["kwargs"] = kwargs
        return {
            "schema_version": 1,
            "tool": "verify_change",
            "status": "pass",
            "target": {"path": path, "file": "app.py", "range": None},
            "findings": [],
            "summary": "No AI-code issues found",
        }

    exit_code = run_verify_command(
        [
            "repo",
            "--file",
            "app.py",
            "--range",
            "2:5",
            "--project-context",
            "--contract",
            ".skylos/ai-contract.yml",
            "--dependency-hallucinations",
            "--exclude-folder",
            "build",
            "-c",
            "75",
        ],
        verify_change_path_func=fake_verify,
        parse_exclude_folders_func=lambda **_kwargs: ("venv",),
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["tool"] == "verify_change"
    assert seen["path"] == "repo"
    assert seen["kwargs"] == {
        "file": "app.py",
        "line_range": "2:5",
        "confidence": 75,
        "exclude_folders": ["venv", "build"],
        "project_context": True,
        "include_dependency_hallucinations": True,
        "contract_path": ".skylos/ai-contract.yml",
    }


def test_run_verify_command_can_disable_contract_discovery(capsys):
    seen = {}

    def fake_verify(path, **kwargs):
        seen["path"] = path
        seen["kwargs"] = kwargs
        return {
            "schema_version": 1,
            "tool": "verify_change",
            "status": "pass",
            "target": {"path": path, "file": None, "range": None},
            "findings": [],
            "summary": "No AI-code issues found",
        }

    exit_code = run_verify_command(
        ["repo", "--no-contract"],
        verify_change_path_func=fake_verify,
        parse_exclude_folders_func=lambda **_kwargs: (),
    )

    _ = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert seen["kwargs"]["contract_enabled"] is False


def test_run_verify_command_fails_on_findings_unless_disabled(capsys):
    def fake_verify(_path, **_kwargs):
        return {
            "schema_version": 1,
            "tool": "verify_change",
            "status": "fail",
            "target": {"path": ".", "file": None, "range": None},
            "findings": [{"rule_id": "SKY-L012"}],
            "summary": "1 AI-code issue found",
        }

    fail_code = run_verify_command(
        ["."],
        verify_change_path_func=fake_verify,
        parse_exclude_folders_func=lambda **_kwargs: (),
    )
    _ = capsys.readouterr()

    no_fail_code = run_verify_command(
        [".", "--no-fail"],
        verify_change_path_func=fake_verify,
        parse_exclude_folders_func=lambda **_kwargs: (),
    )
    _ = capsys.readouterr()

    assert fail_code == 1
    assert no_fail_code == 0


def test_run_verify_command_uses_distinct_incomplete_exit_code(capsys):
    payload = {
        "schema_version": 2,
        "tool": "verify_change",
        "status": "incomplete",
        "target": {"path": ".", "file": None, "range": None},
        "findings": [],
        "summary": "Verification incomplete: 1 reference could not be proven",
    }

    exit_code = run_verify_command(
        ["."],
        verify_change_path_func=lambda *args, **kwargs: payload,
        parse_exclude_folders_func=lambda **_kwargs: (),
    )

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "incomplete"


def test_run_verify_command_reads_stdin_manifest(monkeypatch, capsys):
    seen = {}

    def fake_stdin(payload, **kwargs):
        seen["payload"] = payload
        seen["kwargs"] = kwargs
        return {
            "schema_version": 1,
            "tool": "verify_change",
            "status": "pass",
            "target": {"path": payload["path"], "file": payload["file"], "range": None},
            "findings": [],
            "summary": "No AI-code issues found",
        }

    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"code": "def handler():\n    pass\n"})),
    )

    exit_code = run_verify_command(
        [
            "repo",
            "--stdin",
            "--file",
            "app.py",
            "--range",
            "2:2",
            "--contract",
            ".skylos/ai-contract.yml",
            "-c",
            "80",
        ],
        verify_change_path_func=lambda *_args, **_kwargs: None,
        verify_change_stdin_payload_func=fake_stdin,
        parse_exclude_folders_func=lambda **_kwargs: ("venv",),
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["tool"] == "verify_change"
    assert seen["payload"] == {
        "code": "def handler():\n    pass\n",
        "path": "repo",
        "file": "app.py",
        "range": "2:2",
        "contract_path": ".skylos/ai-contract.yml",
    }
    assert seen["kwargs"] == {
        "confidence": 80,
        "exclude_folders": ["venv"],
    }


def test_run_verify_command_sets_stdin_contract_opt_out(monkeypatch, capsys):
    seen = {}

    def fake_stdin(payload, **kwargs):
        seen["payload"] = payload
        seen["kwargs"] = kwargs
        return {
            "schema_version": 1,
            "tool": "verify_change",
            "status": "pass",
            "target": {"path": payload["path"], "file": None, "range": None},
            "findings": [],
            "summary": "No AI-code issues found",
        }

    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"code": "pass\n"})),
    )

    exit_code = run_verify_command(
        ["repo", "--stdin", "--no-contract"],
        verify_change_stdin_payload_func=fake_stdin,
        parse_exclude_folders_func=lambda **_kwargs: (),
    )

    _ = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert seen["payload"]["contract_enabled"] is False


def _pass_payload(path):
    return {
        "schema_version": 2,
        "tool": "verify_change",
        "status": "pass",
        "target": {"path": path, "file": None, "range": None},
        "findings": [],
        "summary": "No AI-code issues found",
    }


def test_run_verify_command_leaves_security_checks_on_by_default(capsys):
    seen = {}

    def fake_verify(path, **kwargs):
        seen["kwargs"] = kwargs
        return _pass_payload(path)

    run_verify_command(
        ["repo"],
        verify_change_path_func=fake_verify,
        parse_exclude_folders_func=lambda **_kwargs: (),
    )

    _ = json.loads(capsys.readouterr().out)
    assert "include_security_findings" not in seen["kwargs"]


def test_run_verify_command_no_security_opts_out(capsys):
    seen = {}

    def fake_verify(path, **kwargs):
        seen["kwargs"] = kwargs
        return _pass_payload(path)

    run_verify_command(
        ["repo", "--no-security"],
        verify_change_path_func=fake_verify,
        parse_exclude_folders_func=lambda **_kwargs: (),
    )

    _ = json.loads(capsys.readouterr().out)
    assert seen["kwargs"]["include_security_findings"] is False


def test_run_verify_command_no_security_sets_stdin_opt_out(monkeypatch, capsys):
    seen = {}

    def fake_stdin(payload, **kwargs):
        seen["payload"] = payload
        return _pass_payload(payload["path"])

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"code": "pass\n"})))

    run_verify_command(
        ["repo", "--stdin", "--no-security"],
        verify_change_stdin_payload_func=fake_stdin,
        parse_exclude_folders_func=lambda **_kwargs: (),
    )

    _ = json.loads(capsys.readouterr().out)
    assert seen["payload"]["include_security_findings"] is False


def test_run_verify_command_fails_on_real_command_injection(tmp_path, capsys):
    app = tmp_path / "app.py"
    app.write_text(
        "import os\nimport sys\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\n"
        "run(sys.argv[1])\n",
        encoding="utf-8",
    )

    exit_code = run_verify_command(
        [str(app), "--no-dependency-hallucinations"],
        parse_exclude_folders_func=lambda **_kwargs: (),
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["status"] == "fail"
    assert any(f["category"] == "security" for f in payload["findings"])

    exit_code = run_verify_command(
        [str(app), "--no-dependency-hallucinations", "--no-security"],
        parse_exclude_folders_func=lambda **_kwargs: (),
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["status"] == "pass"


# --------------------------------------------------------------------------
# --diff, --format short, --no-behavior, repo-relative range.file
# --------------------------------------------------------------------------

import shutil  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

from skylos.verify_change import parse_added_lines, verify_change_diff  # noqa: E402

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git missing")


def _git(root, *args):
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=30,
    )


def _findings_on_every_line(target, **_kwargs):
    """Fake analyzer: one quality-free AI finding on every line of each file."""
    path = Path(target)
    files = [path] if path.is_file() else sorted(path.rglob("*.py"))
    return {
        "ai_defects": [
            {
                "rule_id": "SKY-L012",
                "file": str(f),
                "line": n,
                "message": f"line {n}",
                "severity": "HIGH",
            }
            for f in files
            for n in range(1, len(f.read_text().splitlines()) + 1)
        ]
    }


def test_parse_added_lines():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1,0 +2,2 @@\n+x\n+y\n@@ -5 +7 @@\n-a\n+b\n"
        "diff --git a/gone.py b/gone.py\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-z\n"
        "diff --git a/d.py b/d.py\n--- a/d.py\n+++ b/d.py\n@@ -3 +2,0 @@\n-q\n"
    )
    assert parse_added_lines(diff) == {"a.py": [(2, 3), (7, 7)], "d.py": []}


@needs_git
def test_verify_diff_covers_committed_staged_unstaged_and_untracked(tmp_path):
    _git(tmp_path, "init", "-q")
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("one = 1\ntwo = 2\nthree = 3\n")
    (src / "b.py").write_text("b = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    _git(tmp_path, "tag", "base")
    (src / "a.py").write_text("one = 1\ntwo = 22\nthree = 3\n")  # committed after base
    _git(tmp_path, "commit", "-qam", "c2")
    (src / "b.py").write_text("b = 1\nstaged = 2\n")
    _git(tmp_path, "add", "src/b.py")
    (src / "a.py").write_text("one = 1\ntwo = 22\nthree = 33\n")  # unstaged
    (src / "new.py").write_text("n = 1\n")  # untracked

    result = verify_change_diff(
        tmp_path, ref="base", analyze_func=_findings_on_every_line
    )
    got = sorted((f["range"]["file"], f["range"]["start_line"]) for f in result["findings"])
    assert got == [("src/a.py", 2), ("src/a.py", 3), ("src/b.py", 2), ("src/new.py", 1)]
    assert result["status"] == "fail"
    assert result["target"]["diff"]["ref"] == "base"

    head = verify_change_diff(tmp_path, analyze_func=_findings_on_every_line)
    got = sorted((f["range"]["file"], f["range"]["start_line"]) for f in head["findings"])
    assert got == [("src/a.py", 3), ("src/b.py", 2), ("src/new.py", 1)]

    with pytest.raises(ValueError):
        verify_change_diff(tmp_path, ref="--output=/tmp/x")
    with pytest.raises(ValueError):
        verify_change_diff(tmp_path, ref="does-not-exist")


@needs_git
def test_single_file_range_file_is_repo_relative(tmp_path):
    _git(tmp_path, "init", "-q")
    app = tmp_path / "pkg" / "app.py"
    app.parent.mkdir()
    app.write_text("x = 1\n")
    result = verify_change_path(
        app, analyze_func=_findings_on_every_line, behavior_comparison=False
    )
    assert result["findings"][0]["range"]["file"] == "pkg/app.py"


def test_cli_diff_short_and_no_behavior_options(capsys, tmp_path):
    calls = {}

    def fake_diff(path, **kwargs):
        calls["diff"] = (path, kwargs)
        return {
            "status": "fail",
            "summary": "1 issue(s) on lines changed since HEAD~1",
            "findings": [
                {
                    "rule_id": "SKY-D212",
                    "severity": "CRITICAL",
                    "message": "Possible command injection",
                    "range": {"file": "src/app.py", "start_line": 4},
                }
            ],
        }

    def fake_path(path, **kwargs):
        calls["path"] = kwargs
        return {"status": "pass", "summary": "No AI-code issues found", "findings": []}

    code = run_verify_command(
        [str(tmp_path), "--diff", "HEAD~1", "--format", "short"],
        verify_change_diff_func=fake_diff,
    )
    out = capsys.readouterr().out
    assert code == 1
    assert calls["diff"][1]["ref"] == "HEAD~1"
    assert out.splitlines() == [
        "src/app.py:4 SKY-D212 [CRITICAL] Possible command injection",
        "FAIL: 1 issue(s) on lines changed since HEAD~1",
    ]

    run_verify_command([str(tmp_path), "--diff"], verify_change_diff_func=fake_diff)
    assert calls["diff"][1]["ref"] == "HEAD"
    capsys.readouterr()

    app = tmp_path / "app.py"
    app.write_text("x = 1\n")
    code = run_verify_command(
        [str(app), "--no-behavior", "--format", "short"],
        verify_change_path_func=fake_path,
    )
    assert code == 0
    assert calls["path"]["behavior_comparison"] is False
    assert capsys.readouterr().out.strip() == "PASS: No AI-code issues found"

    with pytest.raises(SystemExit):
        run_verify_command(
            [str(tmp_path), "--diff", "--range", "1:2"],
            verify_change_diff_func=fake_diff,
        )
