#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.agent_review_benchmark import format_summary, run_manifest
from skylos.llm.runtime import resolve_llm_runtime


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Skylos agent review benchmark suite."
    )
    parser.add_argument(
        "--manifest",
        default=str(Path("agent_review_benchmarks") / "manifest.json"),
        help="Path to the agent review benchmark manifest JSON file.",
    )
    parser.add_argument("--model", default="gpt-4.1")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    provider, api_key, base_url, is_local = resolve_llm_runtime(
        model=args.model,
        provider_override=args.provider,
        base_url_override=args.base_url,
        console=None,
        allow_prompt=False,
    )
    if args.api_key:
        api_key = args.api_key

    if not api_key and not is_local:
        message = (
            "No API key configured for agent review benchmark. "
            "Pass --api-key, run `skylos key`, or configure a local provider with --base-url."
        )
        if args.json:
            print(json.dumps({"error": message}, indent=2))
        else:
            print(message)
        return 2

    summary = run_manifest(
        args.manifest,
        model=args.model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
        selected_cases=set(args.case),
    )

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_summary(summary))
    return 1 if summary["failure_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
