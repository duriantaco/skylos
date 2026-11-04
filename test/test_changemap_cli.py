import asyncio
import io
import json
import subprocess

import pytest
from rich.console import Console

from skylos.commands.done_cmd import run_done_command


def git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Skylos Test", "-c", "user.email=test@example.invalid", *args],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout.strip()


def removed_auth_repo(root):
    (root / "auth.py").write_text("def require_auth(user):\n    if not user:\n        raise PermissionError\n")
    (root / "app.py").write_text(  # skylos: ignore[SKY-D324] fixed paths under a fresh pytest tmp_path
        "from auth import require_auth\n\ndef handler(user):\n    require_auth(user)\n    return 1\n"
    )
    git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    (root / "app.py").write_text("from auth import require_auth\n\ndef handler(user):\n    return 1\n")
    return root


def run(argv):
    buffer = io.StringIO()
    code = run_done_command(argv, console=Console(file=buffer, width=200, highlight=False))
    return code, buffer.getvalue()


def test_done_map_text_puts_the_removed_auth_check_first(tmp_path):
    code, text = run(["map", str(removed_auth_repo(tmp_path))])
    assert code == 0
    assert "READ FIRST" in text
    assert "1. handler  modified  FLAGGED  app.py:3" in text
    assert "Removed security checks: auth.require_auth" in text


def test_done_map_json_is_the_change_map(tmp_path, capsys):
    code, _ = run(["map", str(removed_auth_repo(tmp_path)), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["schema_version"] == 1
    assert data["flagged"] == ["app.py::handler"]


def test_done_map_markdown_has_the_pull_request_layout(tmp_path, capsys):
    code, _ = run(["map", str(removed_auth_repo(tmp_path)), "--format", "markdown"])
    assert code == 0
    assert capsys.readouterr().out.startswith("### Skylos change map")


def test_done_map_with_unknown_base_exits_2_with_a_reason(tmp_path, capsys):
    code, _ = run(["map", str(removed_auth_repo(tmp_path)), "--base", "no-such-ref"])
    assert code == 2
    assert "Could not resolve the base ref 'no-such-ref'" in capsys.readouterr().err


def test_done_with_map_flag_keeps_the_verdict_and_adds_the_map(tmp_path):
    root = removed_auth_repo(tmp_path)
    plain_code, plain = run([str(root), "--no-tests"])
    mapped_code, mapped = run([str(root), "--no-tests", "--map"])
    assert mapped_code == plain_code
    assert "Skylos change map" not in plain
    assert mapped.index("Receipt:") < mapped.index("Skylos change map")
    assert "1. handler  modified  FLAGGED  app.py:3" in mapped


def test_a_failing_change_map_never_changes_the_done_exit_code(tmp_path, monkeypatch):
    root = removed_auth_repo(tmp_path)
    plain_code, _ = run([str(root), "--no-tests"])

    def broken(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("skylos.changemap.build_change_map", broken)
    code, text = run([str(root), "--no-tests", "--map"])
    assert code == plain_code
    assert "Change map unavailable: boom" in text


def test_mcp_change_map_tool_returns_the_map(tmp_path, monkeypatch):
    pytest.importorskip("mcp.server.fastmcp")
    from mcp.server.fastmcp import FastMCP

    import skylos_mcp.server as server

    monkeypatch.setattr(server, "_gate", lambda name: None)
    mcp = FastMCP("test")
    server._register_tools(mcp)
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    assert "change_map" in tools
    assert "Works without SKYLOS_API_KEY and has no daily limit" in tools["change_map"].description
    assert "graph_changes" not in tools
    result = asyncio.run(mcp.call_tool("change_map", {"path": str(removed_auth_repo(tmp_path)), "base": "HEAD"}))
    content = result[0] if isinstance(result, tuple) else result
    data = json.loads(content[0].text)
    assert data["flagged"] == ["app.py::handler"]


def test_local_map_tools_need_no_key_while_scanner_tools_still_do(tmp_path, monkeypatch):
    import skylos_mcp.auth as auth
    import skylos_mcp.server as server

    monkeypatch.setattr(auth, "_session", auth.AuthSession(authenticated=False))
    monkeypatch.setattr(server, "_REQUIRE_MCP_CLIENT_AUTH_CONTEXT", False)
    for _ in range(auth.UNAUTH_DAILY_LIMIT + 3):
        assert server._gate("change_map") is None
        assert server._gate("graph_show") is None
    assert "requires authentication" in json.loads(server._gate("security_scan"))["error"]
    assert "requires authentication" in json.loads(server._gate("remediate"))["error"]
    assert server._gate("analyze") is None


def test_done_map_still_prints_when_the_review_cannot_be_saved(tmp_path, capsys, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def broken(name, *args, **kwargs):
        if name == "skylos.graph.pipeline":
            raise ModuleNotFoundError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken)
    root = removed_auth_repo(tmp_path)
    code = run_done_command(["map", str(root), "--format", "markdown"], console=Console(file=io.StringIO()))
    assert code == 0
    assert "### Skylos change map" in capsys.readouterr().out
