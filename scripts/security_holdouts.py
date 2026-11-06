#!/usr/bin/env python3
"""Check selected facts in caller-supplied upstream snapshots, offline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.security_holdouts import format_summary, run_manifest  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "benchmarks/holdouts/manifest.json",
    )
    parser.add_argument(
        "--checkout-root",
        required=True,
        type=Path,
        help="Directory containing already-present pinned clean checkouts; nothing is fetched",
    )
    parser.add_argument("--target", action="append", dest="targets")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Include full native reports and guard receipts",
    )
    args = parser.parse_args(argv)
    try:
        result = run_manifest(
            args.manifest,
            checkout_root=args.checkout_root,
            selected_targets=args.targets,
        )
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Holdout input error: {exc}\n")
    print(json.dumps(result, indent=2) if args.json else format_summary(result))
    return 1 if result["failure_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
