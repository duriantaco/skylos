#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.framework_corpus import (  # noqa: E402
    format_summary,
    run_manifest,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the pinned real-repo framework accuracy corpus."
    )
    parser.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "benchmarks" / "framework_corpus" / "manifest.json"),
        help="Path to the framework corpus manifest JSON file.",
    )
    parser.add_argument(
        "--checkout-root",
        default=None,
        help="Directory containing pinned repo checkouts named by target checkout/id.",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Run only the specified target id. Repeat for multiple targets.",
    )
    parser.add_argument(
        "--require-checkouts",
        action="store_true",
        help="Fail instead of skipping when a target checkout is missing.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of the text summary.",
    )
    args = parser.parse_args()

    summary = run_manifest(
        args.manifest,
        checkout_root=args.checkout_root,
        selected_targets=set(args.target),
        require_checkouts=args.require_checkouts,
    )

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_summary(summary))
    if summary["failure_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
