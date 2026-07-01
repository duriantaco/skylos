from __future__ import annotations

import io
import json
import sys

from skylos.commands.verify_cmd import run_verify_command


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
