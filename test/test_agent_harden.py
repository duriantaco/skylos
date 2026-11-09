"""``skylos agent harden``: prints each agent's own settings, writes only
from a terminal after a yes. Network and registry are faked as in
``test_hook_agent_configs``."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from skylos.commands.agent_harden_cmd import (
    add_agent_harden_parser,
    run_agent_harden_command,
)
from test.test_hook_agent_configs import FakeSources, mcp_json, needs_engine


@pytest.fixture(autouse=True)
def registry(monkeypatch):
    monkeypatch.setattr("skylos.commands.hook_install_parse._global_bin_dirs", list)
    monkeypatch.setattr(
        "skylos.rules.ai_defect.install_command.check_install_package_status",
        lambda ecosystem, name, version, cache: "present",
    )


@pytest.fixture
def project(tmp_path) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    (tmp_path / "h").mkdir()
    return root


class Terminal(io.StringIO):
    def isatty(self):
        return True


def harden(project, *extra, stdin=None):


    parser = argparse.ArgumentParser()
    add_agent_harden_parser(parser.add_subparsers(dest="cmd"))
    args = parser.parse_args(["harden", "--path", str(project), *extra])
    stdout = io.StringIO()
    code = run_agent_harden_command(args, stdin=stdin or io.StringIO(), stdout=stdout,
                                    env={"HOME": str(project.parent / "h")}, sources=FakeSources())  # fmt: skip
    return code, stdout.getvalue()


@needs_engine
def test_harden_prints_pinned_allowlist_and_writes_nothing(project):
    (project / ".mcp.json").write_text(mcp_json({
        "a": {"command": "npx", "args": ["-y", "some-mcp@1.4.2"]},
        "b": {"command": "npx", "args": ["-y", "some-mcp"]},
        "bad": {"command": "npx", "args": ["-y", "evil-mcp"]},
        "r": {"type": "http", "url": "https://mcp.example.com/mcp"}}))  # fmt: skip
    code, out = harden(project)
    assert code == 0
    assert '"serverCommand": [\n        "npx",\n        "-y",\n        "some-mcp@1.4.2"' in out
    assert '"serverUrl": "https://mcp.example.com/mcp"' in out
    assert "'bad': left out" in out and "known malware" in out
    assert '"path": "~/.ssh"' in out and '"mode": "deny"' in out and "Read(./.env)" in out
    assert "not protection" in out and "readBoundary" in out
    assert not (project / ".claude").exists() and not (project.parent / "h" / ".claude").exists()


@needs_engine
def test_harden_write_needs_a_terminal_and_a_yes(project):
    code, out = harden(project, "--write")
    assert code == 2 and "needs you at a terminal" in out
    assert not (project / ".claude").exists()
    (project / ".claude").mkdir()
    (project / ".claude/settings.json").write_text(json.dumps({"model": "x", "permissions": {"deny": ["Bash(rm *)"]}}))
    code, _out = harden(project, "--write", stdin=Terminal("y\n"))
    assert code == 0
    merged = json.loads((project / ".claude/settings.json").read_text())
    assert merged["model"] == "x"
    assert merged["permissions"]["deny"][0] == "Bash(rm *)" and "Read(./.env)" in merged["permissions"]["deny"]
    user = json.loads((project.parent / "h/.claude/settings.json").read_text())
    assert user["sandbox"]["failIfUnavailable"] is True
    assert json.loads((project / ".cursor/sandbox.json").read_text()) == {"readBoundary": "workspace"}
