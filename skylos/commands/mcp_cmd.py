"""``skylos mcp``: start the Skylos MCP server for MCP clients."""

from __future__ import annotations

import argparse
import os

TRANSPORTS = ("stdio", "sse", "streamable-http")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos mcp",
        description=(
            "Start the Skylos MCP server so Claude Code, Cursor and other MCP "
            "clients can call Skylos tools. Speaks MCP over stdio by default. "
            "Without SKYLOS_API_KEY only the analyze tool is available."
        ),
    )
    parser.add_argument(
        "--transport",
        choices=TRANSPORTS,
        default=None,
        help=(
            "MCP transport (default: stdio, or MCP_TRANSPORT if set). Network "
            "transports bind to MCP_BIND (127.0.0.1) and PORT (8080)."
        ),
    )
    return parser


def run_mcp_command(argv) -> int:
    args = build_parser().parse_args(list(argv))
    # The server reads its transport from the environment; a flag overrides it.
    if args.transport:
        os.environ["MCP_TRANSPORT"] = args.transport

    # Nothing may be printed to stdout before this: on stdio it is the protocol.
    from skylos_mcp.server import main as run_server

    run_server()
    return 0
