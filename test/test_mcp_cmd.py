import json
from pathlib import Path

import pytest

import skylos.cli as cli
from skylos.cli_core.dispatch import EARLY_COMMAND_HANDLERS, NATIVE_HELP_COMMANDS
from skylos.commands import mcp_cmd
from skylos.ui.help import COMMANDS

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def server_calls(monkeypatch):
    calls = []
    import skylos_mcp.server

    monkeypatch.setattr(skylos_mcp.server, "main", lambda: calls.append("main"))
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    return calls


def test_mcp_command_is_dispatched_to_a_real_handler():
    assert EARLY_COMMAND_HANDLERS["mcp"] == "_run_mcp_command"
    assert callable(getattr(cli, "_run_mcp_command"))
    assert "mcp" in NATIVE_HELP_COMMANDS


def test_mcp_command_starts_the_server_without_writing_to_stdout(server_calls, capsys):
    assert mcp_cmd.run_mcp_command([]) == 0
    assert server_calls == ["main"]
    # stdout is the MCP protocol stream on stdio.
    assert capsys.readouterr().out == ""


def test_mcp_transport_flag_sets_the_server_environment(server_calls, monkeypatch):
    mcp_cmd.run_mcp_command(["--transport", "streamable-http"])
    import os

    assert os.environ["MCP_TRANSPORT"] == "streamable-http"
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)


def test_mcp_without_flag_keeps_an_existing_transport(server_calls, monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "sse")
    mcp_cmd.run_mcp_command([])
    import os

    assert os.environ["MCP_TRANSPORT"] == "sse"


def test_mcp_rejects_an_unknown_transport(server_calls):
    with pytest.raises(SystemExit):
        mcp_cmd.run_mcp_command(["--transport", "carrier-pigeon"])
    assert server_calls == []


def test_mcp_help_exits_cleanly(server_calls):
    with pytest.raises(SystemExit) as excinfo:
        mcp_cmd.run_mcp_command(["--help"])
    assert excinfo.value.code == 0
    assert server_calls == []


def test_mcp_command_is_listed_in_help():
    names = [item["name"] for item in COMMANDS]
    assert any(name.startswith("skylos mcp") for name in names)


def test_registry_entry_starts_the_mcp_server_not_the_cli():
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    package = next(p for p in server["packages"] if p["identifier"] == "skylos")
    assert package["transport"] == {"type": "stdio"}
    assert package["runtimeHint"] == "uvx"
    assert [arg["value"] for arg in package["packageArguments"]] == ["mcp"]
