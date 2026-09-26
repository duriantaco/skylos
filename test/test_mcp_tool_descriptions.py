"""MCP tool descriptions and auth errors must be honest about SKYLOS_API_KEY."""

import asyncio
import json

import pytest

pytest.importorskip("mcp.server.fastmcp")

from mcp.server.fastmcp import FastMCP  # noqa: E402

import skylos_mcp.auth as auth_mod  # noqa: E402
from skylos_mcp.auth import (  # noqa: E402
    UNAUTH_DAILY_LIMIT,
    UNAUTHENTICATED_TOOLS,
    AuthSession,
)
from skylos_mcp.server import _gate, _register_tools  # noqa: E402


@pytest.fixture(scope="module")
def tools():
    server = FastMCP("test")
    _register_tools(server)
    return {tool.name: tool for tool in asyncio.run(server.list_tools())}


def test_every_gated_tool_description_says_it_needs_a_key(tools):
    gated = [name for name in tools if name not in UNAUTHENTICATED_TOOLS]
    assert len(gated) >= 10
    for name in gated:
        description = tools[name].description
        assert "Requires SKYLOS_API_KEY" in description, name
        assert "skylos verify" in description, name


def test_ungated_tool_description_says_it_works_without_a_key(tools):
    for name in UNAUTHENTICATED_TOOLS:
        description = tools[name].description
        assert "Works without SKYLOS_API_KEY" in description
        assert f"{UNAUTH_DAILY_LIMIT} calls/day" in description
        assert "Requires SKYLOS_API_KEY" not in description


def test_existing_docstrings_are_kept(tools):
    assert tools["verify_change"].description.startswith(
        "Verify a changed file/range"
    )


def test_unauthenticated_error_explains_how_to_get_a_key(monkeypatch):
    monkeypatch.setattr(auth_mod, "_session", AuthSession(authenticated=False))
    error = json.loads(_gate("verify_change"))["error"]
    assert "requires authentication" in error
    assert "SKYLOS_API_KEY" in error
    assert "/dashboard/settings" in error
    assert "skylos verify" in error
    assert "install-hooks" in error
    assert f"{UNAUTH_DAILY_LIMIT} calls/day" in error


def test_unauthenticated_analyze_still_allowed(monkeypatch):
    monkeypatch.setattr(auth_mod, "_session", AuthSession(authenticated=False))
    assert _gate("analyze") is None


def test_tool_backends_import():
    # provenance_scan and the triage tools previously imported modules that
    # do not exist and always returned an ImportError payload.
    from skylos.agents.service import AgentServiceController  # noqa: F401
    from skylos.reporting.provenance import analyze_provenance  # noqa: F401


def test_provenance_scan_tool_runs_when_authenticated(tools, monkeypatch, tmp_path):
    import skylos_mcp.server as server_mod

    monkeypatch.setattr(server_mod, "_gate", lambda name: None)
    monkeypatch.setattr(server_mod, "_store_result", lambda *a, **k: "run")
    server = FastMCP("test")
    _register_tools(server)
    result = asyncio.run(
        server.call_tool("provenance_scan", {"path": str(tmp_path)})
    )
    text = result[0][0].text if isinstance(result, tuple) else result[0].text
    payload = json.loads(text)
    assert "No module named" not in payload.get("error", "")
