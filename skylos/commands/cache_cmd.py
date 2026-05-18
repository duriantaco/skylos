from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.text import Text

from skylos.core.result_cache import RUN_CACHE_DIR, clear_run_cache, run_cache_stats


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

    stats_parser = subparsers.add_parser("stats", help="Show cached run data size.")
    stats_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project path whose .skylos/cache/runs directory should be inspected.",
    )
    stats_parser.add_argument(
        "--json",
        action="store_true",
        help="Print cache stats as JSON.",
    )

    args = parser.parse_args(argv)
    console = console_factory()

    if args.cache_command is None:
        parser.print_help()
        return 0

    root = Path(args.path).resolve()
    if root.is_file():
        root = root.parent

    if args.cache_command == "stats":
        stats = run_cache_stats(root)
        if args.json:
            _write_json(console, stats)
        else:
            _print_cache_stats(console, stats)
        return 0

    if args.cache_command != "clear":
        parser.print_help()
        return 0

    removed = clear_run_cache(root)
    cache_path = root / RUN_CACHE_DIR
    if removed:
        console.print(
            Text.assemble(("Cleared run cache: ", "green"), _safe_terminal_text(cache_path))
        )
    else:
        console.print(
            Text.assemble(("No run cache found: ", "dim"), _safe_terminal_text(cache_path))
        )
    return 0


def _print_cache_stats(console, stats: dict) -> None:
    path = _safe_terminal_text(stats.get("path", ""))
    if not stats.get("exists"):
        console.print(Text.assemble(("No run cache found: ", "dim"), path))
        return

    console.print(Text.assemble(("Run cache: ", "bold"), path))
    console.print(f"  Files:       {int(stats.get('files', 0))}")
    console.print(f"  Directories: {int(stats.get('directories', 0))}")
    console.print(f"  Size:        {_format_bytes(int(stats.get('bytes', 0)))}")
    if stats.get("symlinks") or stats.get("other_entries") or stats.get("skipped"):
        console.print(f"  Symlinks:    {int(stats.get('symlinks', 0))}")
        console.print(f"  Skipped:     {int(stats.get('skipped', 0))}")
    if stats.get("errors"):
        console.print(f"  Errors:      {int(stats.get('errors', 0))}")
    if stats.get("truncated"):
        console.print(
            f"  [yellow]Truncated after {int(stats.get('max_entries', 0))} entries[/yellow]"
        )
    if stats.get("error"):
        console.print(
            Text.assemble(("  Error:       ", "red"), _safe_terminal_text(stats["error"]))
        )


def _write_json(console, payload: dict) -> None:
    output = json.dumps(payload, sort_keys=True) + "\n"
    stream = getattr(console, "file", None)
    if stream is not None and hasattr(stream, "write"):
        stream.write(output)
        stream.flush()
    else:
        console.print(output, markup=False, end="")


def _safe_terminal_text(value) -> str:
    text = str(value)
    return "".join(
        ch if (ch >= " " and ch != "\x7f") else f"\\x{ord(ch):02x}" for ch in text
    )


def _format_bytes(size: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(max(size, 0))
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
