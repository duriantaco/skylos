#!/usr/bin/env python3
"""Compare a completed Jev research run with a frozen scanner baseline."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.jev_compare import compare_jev_to_scanner  # noqa: E402
from skylos.benchmarks.jev_dead_code import JevBenchmarkError  # noqa: E402
from skylos.core.safe_cache_io import (  # noqa: E402
    read_text_no_symlink,
    write_text_no_symlink,
)


MAX_INPUT_BYTES = 16_000_000


def _read_json(path: str) -> dict:
    raw = read_text_no_symlink(path, max_bytes=MAX_INPUT_BYTES)
    if raw is None:
        raise JevBenchmarkError(f"cannot safely read JSON report: {path}")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise JevBenchmarkError(f"invalid JSON report: {path}") from exc
    if not isinstance(value, dict):
        raise JevBenchmarkError(f"JSON report must be an object: {path}")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline, label-by-label Jev vs scanner comparison. No API key needed."
    )
    parser.add_argument("--manifest", required=True, help="Frozen golden manifest")
    parser.add_argument("--jev-report", required=True, help="Completed Jev JSON report")
    parser.add_argument(
        "--scanner-summary", required=True, help="Golden benchmark scanner summary JSON"
    )
    parser.add_argument("--threshold", type=float, default=0.8)
    parser.add_argument(
        "--arm", choices=("original", "neutralized"), default="original"
    )
    parser.add_argument("--output", help="Write comparison JSON to a new file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        comparison = compare_jev_to_scanner(
            _read_json(args.jev_report),
            _read_json(args.scanner_summary),
            args.manifest,
            threshold=args.threshold,
            arm=args.arm,
        )
        content = json.dumps(comparison, indent=2, sort_keys=True) + "\n"
        if args.output:
            output = Path(os.path.abspath(Path(args.output).expanduser()))
            if output.exists() or output.is_symlink():
                raise JevBenchmarkError(f"output already exists: {output}")
            if not write_text_no_symlink(output, content):
                raise JevBenchmarkError(f"cannot safely write comparison: {output}")
        else:
            print(content, end="")
        return 0
    except (JevBenchmarkError, OSError, ValueError) as exc:
        print(f"Jev comparison error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
