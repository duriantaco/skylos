from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from skylos.core.result_cache import RUN_CACHE_DIR, clear_run_cache


def run_cache_command(argv: list[str], *, console_factory=Console) -> int:
    parser = argparse.ArgumentParser(
        prog="skylos cache",
        description="Manage Skylos analysis caches.",
    )
    subparsers = parser.add_subparsers(dest="cache_command")

    clear_parser = subparsers.add_parser("clear", help="Clear cached run data.")
    clear_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project path whose .skylos/cache/runs directory should be removed.",
    )

    args = parser.parse_args(argv)
    console = console_factory()

    if args.cache_command != "clear":
        parser.print_help()
        return 0

    root = Path(args.path).resolve()
    if root.is_file():
        root = root.parent
    removed = clear_run_cache(root)
    cache_path = root / RUN_CACHE_DIR
    if removed:
        console.print(f"[green]Cleared run cache:[/green] {cache_path}")
    else:
        console.print(f"[dim]No run cache found:[/dim] {cache_path}")
    return 0
