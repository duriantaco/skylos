#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.jev_dead_code import (  # noqa: E402
    JevBenchmarkError,
    build_plan,
    format_plan,
    format_report,
    run_jev_manifest,
)
from skylos.core.safe_cache_io import write_text_no_symlink  # noqa: E402


DEFAULT_MANIFEST = REPO_ROOT / "benchmarks" / "dead_code" / "manifest.json"
DEFAULT_OUTPUT = REPO_ROOT / "jev-dead-code-results.json"


def _write_report(path: Path, report: dict) -> None:
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if not write_text_no_symlink(path, content):
        raise JevBenchmarkError(
            f"cannot safely write {path}; use an existing, non-symlink parent directory"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Blindly score pinned Jev decisions against Skylos dead-code ground truth. "
            "Without --live, this only prints the request plan."
        )
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Send fixture source to the official TypeSafe API and incur API usage.",
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help=(
            "Checked-in or frozen skylos-golden-benchmark/v1 ground truth "
            "(default: main benchmark manifest)."
        ),
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run one case id. Repeat to select more than one case.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Checkpoint/result JSON path for a live run (default: repo root).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the plan or final report as JSON.",
    )
    return parser


def _run(args: argparse.Namespace) -> int:
    selected = set(args.case)
    if not args.live:
        plan = build_plan(args.manifest, selected)
        print(json.dumps(plan, indent=2) if args.json else format_plan(plan))
        if not args.json:
            print(
                "\nLive run: set TYPESAFE_API_KEY in the environment, then run "
                "this command with --live."
            )
        return 0

    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    if not api_key.strip():
        raise JevBenchmarkError(
            "TYPESAFE_API_KEY is missing. Set it in the environment; do not "
            "pass it as a command-line argument or commit it."
        )
    output = Path(os.path.abspath(Path(args.output).expanduser()))

    def checkpoint(report: dict) -> None:
        _write_report(output, report)

    report = run_jev_manifest(
        args.manifest,
        api_key=api_key,
        selected_cases=selected,
        checkpoint=checkpoint,
    )
    print(json.dumps(report, indent=2) if args.json else format_report(report))
    if not args.json:
        print(f"Full result: {output}")
    return 0 if report["status"] == "complete" else 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except (JevBenchmarkError, OSError, ValueError) as exc:
        print(f"Jev benchmark error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
