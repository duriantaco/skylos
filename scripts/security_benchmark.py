#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.security import format_summary, run_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Skylos deterministic security benchmark suite."
    )
    parser.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "benchmarks" / "security" / "manifest.json"),
        help="Path to the security benchmark manifest JSON file.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run only the specified benchmark case id. Repeat for multiple ids.",
    )
    parser.add_argument(
        "--scanner",
        choices=("skylos", "bandit"),
        default="skylos",
        help="Security scanner to score against the same benchmark labels.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of the text summary.",
    )
    args = parser.parse_args()

    summary = run_manifest(
        args.manifest,
        selected_cases=set(args.case),
        scanner=args.scanner,
    )
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_summary(summary))
    return 1 if summary["failure_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
