#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.research.dead_code import ResearchVariant, run_ablation  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run research-only dead-code ablation variants."
    )
    parser.add_argument("path", help="Project or fixture root to analyze.")
    parser.add_argument(
        "--variant",
        choices=[variant.value for variant in ResearchVariant],
        default=ResearchVariant.ROOTS_REACHABILITY.value,
        help="Research variant to run.",
    )
    parser.add_argument(
        "--output",
        help="Optional JSON output path. Prints to stdout when omitted.",
    )
    args = parser.parse_args()

    result = run_ablation(args.path, variant=args.variant)
    payload = result.to_dict()
    text = json.dumps(payload, indent=2)

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
