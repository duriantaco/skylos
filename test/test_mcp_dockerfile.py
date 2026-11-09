"""The MCP image listens where a published container port can reach it."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

DOCKERFILE = Path(__file__).resolve().parents[1] / "skylos_mcp" / "Dockerfile"


def _env(text):
    values = {}
    for line in text.splitlines():
        if line.startswith("ENV "):
            key, _, value = line[4:].partition("=")
            values[key.strip()] = value.strip()
    return values


def test_network_image_binds_every_interface_and_requires_a_client_token():
    text = DOCKERFILE.read_text(encoding="utf-8")
    env = _env(text)

    assert env["MCP_TRANSPORT"] == "sse"
    assert env["MCP_BIND"] == "0.0.0.0"
    assert env["PORT"] == "8080"
    assert "EXPOSE 8080" in text
    assert "SKYLOS_MCP_TOKEN" not in env


def test_image_can_build_the_dart_grammar_from_the_all_extra():
    text = DOCKERFILE.read_text(encoding="utf-8")
    install = text.index('pip install --no-cache-dir -e ".[all]"')

    assert (
        text.index("apt-get install -y --no-install-recommends gcc libc6-dev") < install
    )


@pytest.mark.parametrize(
    ("env", "expected"),
    [({}, "127.0.0.1"), ({"MCP_BIND": "0.0.0.0"}, "0.0.0.0")],
)
def test_server_binds_to_mcp_bind(monkeypatch, env, expected):
    from skylos_mcp import server

    seen = {}

    class FakeFastMCP:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def run(self, transport):
            seen["transport"] = transport

    fake_module = types.ModuleType("mcp.server.fastmcp")
    fake_module.FastMCP = FakeFastMCP
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake_module)
    monkeypatch.setattr(
        server,
        "_REQUIRE_MCP_CLIENT_AUTH_CONTEXT",
        server._REQUIRE_MCP_CLIENT_AUTH_CONTEXT,
    )
    monkeypatch.setattr(server, "initialize_auth", lambda: None)
    monkeypatch.setattr(server, "_register_tools", lambda _server: None)
    monkeypatch.setenv("MCP_TRANSPORT", "sse")
    monkeypatch.setenv("SKYLOS_MCP_TOKEN", "x" * 32)
    monkeypatch.delenv("MCP_BIND", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    server.main()

    assert seen["host"] == expected
    assert seen["transport"] == "sse"
