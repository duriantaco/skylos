"""skylos.toml in `skylos done` and the risk review: settings come from the
base commit's root config, and edits to skylos.toml count as gate tampering."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from skylos.cicd.approval import parse_approval_config
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext, check_gate_tampering
from skylos.done.config import DoneConfig, base_config_text, parse_done_config


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest fixture under tmp_path


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    _git(root, "config", "commit.gpgsign", "false")
    _write(root, "src/index.ts", "export const x = 1;\n")
    _write(
        root,
        "skylos.toml",
        'exclude = ["dist"]\n[done]\ntest_command = "npm test"\n'
        "[approval]\nlarge_diff_lines = 5000\n",
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "switch", "-qc", "feature")
    return root


def test_done_and_approval_settings_read_from_skylos_toml():
    text = '[done]\ntest_command = "npm test"\n[approval]\nlarge_diff_lines = 5000\n'
    assert parse_done_config(text).test_command == ("npm", "test")
    assert parse_approval_config(text).large_diff_lines == 5000


def test_pyproject_without_skylos_table_has_no_done_settings():
    assert not parse_done_config("[project]\nname = 'x'\n").configured
    assert not parse_approval_config("[project]\nname = 'x'\n").configured


def test_base_config_text_prefers_skylos_toml_at_the_base(repo: Path):
    _write(repo, "skylos.toml", '[done]\ntest_command = "rm -rf /"\n')
    _git(repo, "commit", "-qam", "weaken")
    comparison = open_comparison(repo, "main")

    config = parse_done_config(base_config_text(comparison))

    # The change never supplies its own settings.
    assert config.test_command == ("npm", "test")


def test_editing_skylos_toml_is_gate_tampering(repo: Path):
    _write(repo, "skylos.toml", 'exclude = ["dist", "src"]\n')
    _git(repo, "commit", "-qam", "exclude src")

    result = check_gate_tampering(
        CheckContext(open_comparison(repo, "main"), DoneConfig())
    )

    assert result.status == "fail"
    assert any("skylos.toml" in f.message for f in result.findings)


def test_adding_a_package_skylos_toml_is_gate_tampering(repo: Path):
    _write(repo, "packages/api/.skylos.toml", 'exclude = ["**"]\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "package config")

    result = check_gate_tampering(
        CheckContext(open_comparison(repo, "main"), DoneConfig())
    )

    assert [f.file for f in result.findings] == ["packages/api/.skylos.toml"]
    assert "changes Skylos settings (.skylos.toml)" in result.findings[0].message


def test_unrelated_change_is_not_gate_tampering(repo: Path):
    _write(repo, "src/index.ts", "export const x = 2;\n")
    _git(repo, "commit", "-qam", "code")

    result = check_gate_tampering(
        CheckContext(open_comparison(repo, "main"), DoneConfig())
    )

    assert result.findings == []
