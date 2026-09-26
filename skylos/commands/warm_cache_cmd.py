"""``skylos agent warm-cache``: prebuild the caches agent edit hooks use.

The first ``skylos hook post-edit`` in a project builds the project-wide
module index (``.skylos/cache/module-facts.json``) synchronously, which on a
large repo takes as long as a full local-API scan. Running this once after
``skylos agent install-hooks`` moves that cost out of the agent loop. It is
optional: without it the first edit check pays the cost, later ones don't.
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from pathlib import Path


def add_warm_cache_parser(agent_sub) -> None:
    parser = agent_sub.add_parser(
        "warm-cache",
        help="Prebuild the project index that keeps agent edit hooks fast",
        description=(
            "Build .skylos/cache/module-facts.json (the per-file module index "
            "the post-edit hook reuses) so the first agent edit check is as "
            "fast as later ones."
        ),
    )
    parser.add_argument(
        "path", nargs="?", default=".", help="Project directory (default: .)."
    )


def run_warm_cache_command(
    args: argparse.Namespace,
    *,
    print_func: Callable[[str], None] = print,
) -> int:
    from skylos.commands.hook_cmd import _git_root, hook_verify
    from skylos.constants import parse_exclude_folders
    from skylos.core.file_discovery import discover_source_files
    from skylos.rules.ai_defect.module_facts_index import CACHE_PATH

    start = Path(args.path).expanduser()
    if not start.is_dir():
        print_func(f"Not a directory: {start}")
        return 1
    root = _git_root(start.resolve())
    files = discover_source_files(
        root,
        {".py", ".pyi", ".pyw"},
        exclude_folders=list(parse_exclude_folders(use_defaults=True)),
    )
    if not files:
        print_func(f"No Python files under {root}; nothing to warm.")
        return 0

    started = time.monotonic()
    # Any file works: verifying one builds the index for the whole project.
    hook_verify(files[0], root)
    elapsed = time.monotonic() - started
    print_func(
        f"Indexed {len(files)} Python file(s) in {elapsed:.1f}s -> "
        f"{root / CACHE_PATH}. Agent edit checks now re-parse only changed files."
    )
    return 0
