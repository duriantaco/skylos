"""``skylos open``: one page with the map of the code, what changed and every check run."""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.markup import escape


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos open",
        description=(
            "Open one local page for this repository: the diagram of your code, what changed on this "
            "branch in plain English and what it affects, and every check run (with a button to check "
            "the change again). Compares with the branch pull requests merge into. Local only."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository (default: .)")
    parser.add_argument("--base", metavar="REF", help="Compare with REF, e.g. origin/main (default: detected; HEAD when there is none)")
    parser.add_argument("--port", type=int, default=0, help="Port on 127.0.0.1 (default: any free port)")
    parser.add_argument("--no-browser", action="store_true", help="Print the link instead of opening a browser")
    return parser


def run_open_command(argv: list[str], *, console: Console | None = None) -> int:
    from skylos.commands.graph_cmd import run_graph_command
    from skylos.commands.setup_cmd import current_branch, default_base, repo_root

    out = console or Console(highlight=False)
    args = build_parser().parse_args(list(argv))
    root = repo_root(args.path)
    path = args.path
    base = args.base
    if root is not None:
        path = str(root)
        if not base:
            base = default_base(root)
        if base and base == current_branch(root):
            base = "HEAD"
    if not base:
        base = "HEAD"
    if base == "HEAD":
        out.print("[dim]Showing uncommitted changes. Use --base to compare with a branch.[/dim]")
    else:
        out.print(f"[dim]Showing changes since this branch left {escape(base)}.[/dim]")
    graph_argv = ["open", "--path", path, "--since", base, "--port", str(args.port)]
    if args.no_browser:
        graph_argv.append("--no-browser")
    return run_graph_command(graph_argv, console=out)
