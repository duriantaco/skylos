import json
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from skylos.commands import open_cmd, setup_cmd


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "shop"
    root.mkdir()
    (root / "shop.py").write_text("def total(items):\n    return sum(items)\n\n\ndef checkout(items):\n    return total(items)\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "start")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: None)
    return root


def _run(root, *argv):
    buffer = StringIO()
    code = setup_cmd.run_setup_command([str(root), *argv], console=Console(file=buffer, width=200, highlight=False))
    return code, buffer.getvalue()


def test_setup_writes_agent_steps_mcp_and_ci_then_is_idempotent(repo):
    (repo / "CLAUDE.md").write_text("# Shop\n\nRun the tests with pytest.\n")

    code, output = _run(repo)

    assert code == 0
    claude = (repo / "CLAUDE.md").read_text()
    assert claude.startswith("# Shop\n\nRun the tests with pytest.\n\n<!-- skylos:start -->")
    assert "skylos done --base main" in claude
    assert (repo / "AGENTS.md").read_text() == setup_cmd.agent_block("main")
    assert json.loads((repo / ".mcp.json").read_text()) == {"mcpServers": {"skylos": {"command": "skylos", "args": ["mcp"]}}}
    assert (repo / ".github/workflows/skylos.yml").is_file()
    assert "Codex          not installed; when you install it run: codex mcp add skylos --" in output
    assert "2 functions and classes in 1 files" in output
    assert "Commit " in output and "AGENTS.md" in output and ".skylos/graph/.gitignore" in output
    assert "Next" in output and "skylos open" in output

    before = {name: (repo / name).read_text() for name in ("CLAUDE.md", "AGENTS.md", ".mcp.json", ".github/workflows/skylos.yml")}
    code, output = _run(repo)

    assert code == 0
    assert {name: (repo / name).read_text() for name in before} == before
    assert "CLAUDE.md, AGENTS.md: up to date" in output
    assert ".mcp.json: Skylos tools already connected" in output
    assert "skylos.yml: up to date" in output


def test_setup_replaces_only_its_own_block_and_respects_agents_import(repo):
    (repo / "AGENTS.md").write_text("intro\n<!-- skylos:start -->\nold text\n<!-- skylos:end -->\noutro\n")
    (repo / "CLAUDE.md").write_text("@AGENTS.md\n")

    code, output = _run(repo, "--no-ci", "--base", "origin/develop")

    assert code == 0
    agents = (repo / "AGENTS.md").read_text()
    assert agents.startswith("intro\n<!-- skylos:start -->\n## Skylos")
    assert agents.endswith("<!-- skylos:end -->\noutro\n")
    assert "old text" not in agents
    assert "skylos done --base origin/develop" in agents
    assert (repo / "CLAUDE.md").read_text() == "@AGENTS.md\n"
    assert "AGENTS.md: Skylos steps updated" in output
    assert not (repo / ".github").exists()


def test_setup_keeps_other_mcp_servers_and_leaves_broken_json_alone(repo):
    (repo / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}, "extra": 1}))

    assert _run(repo, "--no-ci")[0] == 0
    assert json.loads((repo / ".mcp.json").read_text()) == {
        "mcpServers": {"other": {"command": "x"}, "skylos": {"command": "skylos", "args": ["mcp"]}},
        "extra": 1,
    }

    (repo / ".mcp.json").write_text("{not json")
    code, output = _run(repo, "--no-ci")

    assert code == 1
    assert (repo / ".mcp.json").read_text() == "{not json"
    assert ".mcp.json is not valid JSON" in output


def test_setup_adds_codex_once(repo, monkeypatch):
    calls = []
    state = {"added": False}

    def fake_run(args, **kwargs):
        calls.append(args[1:])
        if args[2] == "get":
            registered = json.dumps({"transport": {"type": "stdio", "command": state.get("command", ""), "args": ["mcp"]}})
            return subprocess.CompletedProcess(args, 0 if state["added"] else 1, registered, "")
        state["added"] = True
        state["command"] = args[5]
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: "/usr/local/bin/codex" if name == "codex" else "/venv/bin/skylos")
    monkeypatch.setattr(setup_cmd, "_run_quiet", lambda args: fake_run(args))
    monkeypatch.setattr(sys, "argv", ["pytest"])

    _, first = _run(repo, "--no-ci")
    _, second = _run(repo, "--no-ci")

    state["command"] = "/opt/homebrew/bin/skylos"
    code, third = _run(repo, "--no-ci")

    assert calls == [
        ["mcp", "get", "skylos", "--json"],
        ["mcp", "add", "skylos", "--", "/venv/bin/skylos", "mcp"],
        ["mcp", "get", "skylos", "--json"],
        ["mcp", "get", "skylos", "--json"],
    ]
    assert "Codex          Skylos tools connected" in first
    assert "Codex          Skylos tools already connected" in second
    assert code == 1
    assert "connected to a different Skylos (/opt/homebrew/bin/skylos)" in third
    assert "codex mcp remove skylos && codex mcp add skylos -- /venv/bin/skylos mcp" in third


def test_setup_refuses_outside_a_git_repository(tmp_path):
    code, output = _run(tmp_path)

    assert code == 1
    assert "run it inside a git repository" in output
    assert list(tmp_path.iterdir()) == []


def test_default_base_prefers_origin_head_then_main(repo):
    assert setup_cmd.default_base(repo) == "main"
    _git(repo, "update-ref", "refs/remotes/origin/trunk", "HEAD")
    _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
    assert setup_cmd.default_base(repo) == "origin/trunk"


def test_open_compares_with_the_detected_base(repo, monkeypatch):
    seen = []
    monkeypatch.setattr("skylos.commands.graph_cmd.run_graph_command", lambda argv, console=None: seen.append(argv) or 0)
    buffer = StringIO()
    console = Console(file=buffer, width=200, highlight=False)

    _git(repo, "checkout", "-q", "-b", "agent/work")
    assert open_cmd.run_open_command([str(repo), "--no-browser"], console=console) == 0
    _git(repo, "checkout", "-q", "main")
    assert open_cmd.run_open_command([str(repo), "--no-browser"], console=console) == 0

    assert seen[0][:5] == ["open", "--path", str(repo.resolve()), "--since", "main"]
    assert seen[1][:5] == ["open", "--path", str(repo.resolve()), "--since", "HEAD"]
    assert "Showing changes since this branch left main." in buffer.getvalue()
    assert "Showing uncommitted changes." in buffer.getvalue()


def test_setup_and_open_are_registered_commands():
    from skylos.cli_core.dispatch import EARLY_COMMAND_HANDLERS
    import skylos.cli as cli

    assert callable(getattr(cli, EARLY_COMMAND_HANDLERS["setup"]))
    assert callable(getattr(cli, EARLY_COMMAND_HANDLERS["open"]))


def test_setup_warns_when_path_starts_a_different_skylos(repo, monkeypatch):
    monkeypatch.setattr(setup_cmd, "skylos_command", lambda: "/venv/bin/skylos")
    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: {"skylos": "/opt/homebrew/bin/skylos"}.get(name))

    code, output = _run(repo, "--no-ci")

    assert code == 1
    assert "your PATH starts /opt/homebrew/bin/skylos, not this Skylos" in output
    assert json.loads((repo / ".mcp.json").read_text())["mcpServers"]["skylos"] == {"command": "skylos", "args": ["mcp"]}

    monkeypatch.setattr(setup_cmd.shutil, "which", lambda name: {"skylos": "/venv/bin/skylos"}.get(name))
    code, output = _run(repo, "--no-ci")
    assert code == 0
    assert "your PATH starts" not in output
