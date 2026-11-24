import base64
import hashlib
import json
import os
import subprocess
import sys

import pytest

from skylos import cli
from skylos.core.git_safety import read_only_git_environment


def _git(path, *args):
    return subprocess.run(
        [
            "git", "-c", "user.name=History Fixture",
            "-c", "user.email=history@invalid.local", "-c", f"core.hooksPath={os.devnull}",
            *args,
        ],
        cwd=path,
        env=read_only_git_environment(),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def deleted_credential(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "--quiet")
    password = "ghp_" + hashlib.sha256(b"retired unissued key for CLI test").hexdigest()[:36]
    config = root / ".env"
    config.write_text(f"API_TOKEN={password}\n", encoding="utf-8")
    _git(root, "add", "--", ".env")
    _git(root, "commit", "--quiet", "-m", "Add generated credential fixture")
    commit = _git(root, "rev-parse", "HEAD")
    config.write_text("ENABLED=true\n", encoding="utf-8")
    _git(root, "add", "--", ".env")
    _git(root, "commit", "--quiet", "-m", "Remove generated fixture")
    return root, commit, password


def _history_cli(monkeypatch, capsys, root, *args):
    monkeypatch.setattr(
        sys, "argv", ["skylos", "secrets-history", str(root), "--format", "json", *args]
    )
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    captured = capsys.readouterr()
    return stopped.value.code, json.loads(captured.out), captured


def test_history_cli_finds_removed_credential_and_masks_it(monkeypatch, capsys, deleted_credential):
    root, commit, password = deleted_credential
    exit_code, report, captured = _history_cli(monkeypatch, capsys, root, "--strict")
    assert exit_code == 1
    assert report["analysis_summary"]["git_history"]["status"] == "complete"
    assert any(
        finding["git_commit"] == commit and finding["file"] == ".env" and finding["line"] == 1
        for finding in report["secrets"]
    )
    assert password not in captured.out + captured.err


def test_history_cli_reports_truncation(monkeypatch, capsys, deleted_credential):
    root, _commit, _password = deleted_credential
    exit_code, report, _captured = _history_cli(
        monkeypatch, capsys, root, "--max-commits", "1"
    )
    assert exit_code == 2
    history = report["analysis_summary"]["git_history"]
    assert history["status"] == "incomplete"
    assert history["commits_scanned"] == 1


def test_history_help_is_available_before_scanning(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["skylos", "secrets-history", "--help"])
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == 0
    assert "skylos secrets-history" in capsys.readouterr().out


def test_history_local_view_keeps_aws_identifiers_in_strict_checks(
    monkeypatch, capsys, tmp_path
):
    monkeypatch.setattr(cli, "_is_ci", lambda: False)
    _git(tmp_path, "init", "--quiet")
    material = base64.b32encode(hashlib.sha256(b"history identifier control").digest())
    identifier = "AK" + "IA" + material[:16].decode("ascii")
    (tmp_path / ".env").write_text(f"AWS_ACCESS_KEY_ID={identifier}\n", encoding="utf-8")
    _git(tmp_path, "add", "--", ".env")
    _git(tmp_path, "commit", "--quiet", "-m", "Add generated identifier")

    exit_code, display, _captured = _history_cli(monkeypatch, capsys, tmp_path, "--strict")
    assert exit_code == 1
    assert display["secrets"] == []
    assert display["analysis_summary"]["aws_access_key_identifiers_hidden"] == 1

    exit_code, inclusive, captured = _history_cli(
        monkeypatch, capsys, tmp_path, "--secrets-include-aws-key-ids"
    )
    assert exit_code == 0
    assert [finding["provider"] for finding in inclusive["secrets"]] == ["aws_access_key_id"]
    assert identifier not in captured.out + captured.err
