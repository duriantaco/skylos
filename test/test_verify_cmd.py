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
