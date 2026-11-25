import json
import subprocess
import sys
from pathlib import Path

import pytest

from skylos import cli
from skylos.commands.lint_cmd import run_lint_command


def test_lint_defaults_to_current_directory(tmp_path, monkeypatch, capsys):
    for package in ("billing", "accounts"):
        path = tmp_path / package
        path.mkdir()
        (path / "__init__.py").touch()
        (path / "api.py").write_text("def total():\n    return 0\n")
    (tmp_path / "billing" / "invoice.py").write_text("from accounts.api import total\n")
    (tmp_path / "accounts" / "summary.py").write_text("from billing.api import total\n")
    (tmp_path / "pyproject.toml").write_text(
        "[tool.skylos.architecture]\n"
        'layers = [{name = "billing", patterns = ["billing"]}, '
        '{name = "accounts", patterns = ["accounts"]}]\n'
        'rules = [{from = "billing", deny = ["accounts"]}]\n'
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["skylos", "lint"])

    with pytest.raises(SystemExit) as exit_info:
        cli.main()

    assert exit_info.value.code == 1
    output = capsys.readouterr().out
    assert "SKY-Q805" in output
    assert "SKY-Q807" in output
    assert f"{Path('billing', 'invoice.py')}:1" in output
    assert f"{Path('accounts', 'summary.py')}:1" in output


def test_lint_diff_reports_cycle_closed_in_secondary_file(tmp_path, capsys):
    (tmp_path / "a.py").write_text("import b\n\ndef name():\n    return b.__name__\n")
    (tmp_path / "b.py").write_text("def name():\n    return __name__\n")
    for args in (
        ("init", "-q"),
        ("add", "a.py", "b.py"),
        (
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "user.name=Fixture",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "Fixture base",
        ),
    ):
        subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, check=True)
    (tmp_path / "b.py").write_text("import a\n\ndef name():\n    return a.__name__\n")

    status = run_lint_command([str(tmp_path), "--diff", "HEAD", "--format", "json"])

    assert status == 1
    report = json.loads(capsys.readouterr().out)
    [cycle] = report["findings"]
    assert cycle["rule_id"] == "SKY-CIRC"
    assert Path(cycle["file"]).name == "a.py"
    assert {Path(row["file"]).name for row in cycle["related_locations"]} == {
        "a.py",
        "b.py",
    }


def test_lint_reports_incomplete_analysis_in_json(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("def incomplete(:\n    pass\n")

    status = run_lint_command([str(tmp_path), "--format", "json"])

    assert status == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "error"
    assert report["findings"] == []
    assert "incomplete" in report["error"].lower()
