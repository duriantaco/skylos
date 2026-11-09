#!/usr/bin/env python3
"""Run static Terraform declaration-policy corpus contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.cloud import format_summary, run_manifest  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", default=str(REPO_ROOT / "benchmarks/cloud/manifest.json")
    )
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    summary = run_manifest(args.manifest, selected_cases=args.case)
    print(json.dumps(summary, indent=2) if args.json else format_summary(summary))
    return int(bool(summary["failure_count"]))


if __name__ == "__main__":
    raise SystemExit(main())
