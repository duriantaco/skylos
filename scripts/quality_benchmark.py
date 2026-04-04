#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.quality_benchmark import format_summary, run_manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Skylos quality benchmark suite."
    )
    parser.add_argument(
        "--manifest",
        default=str(Path("quality_benchmarks") / "manifest.json"),
        help="Path to the quality benchmark manifest JSON file.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run only the specified benchmark case id. Repeat for multiple ids.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of the text summary.",
    )
    args = parser.parse_args()

    summary = run_manifest(args.manifest, selected_cases=set(args.case))
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_summary(summary))
    return 1 if summary["failure_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
