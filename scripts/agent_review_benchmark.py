#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.agent_review import format_summary, run_manifest  # noqa: E402
from skylos.llm.runtime import resolve_llm_runtime  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Skylos agent review benchmark suite."
    )
    parser.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "benchmarks" / "agent_review" / "manifest.json"),
        help="Path to the agent review benchmark manifest JSON file.",
    )
    parser.add_argument("--model", default="gpt-4.1")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write the full JSON summary.",
    )
    parser.add_argument(
        "--progress-jsonl",
        default=None,
        help="Optional path to append per-case progress JSONL.",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Print per-case progress to stderr.",
    )
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

    progress_path = Path(args.progress_jsonl) if args.progress_jsonl else None

    def progress_callback(record: dict) -> None:
        case = record.get("case", {}) or {}
        if args.progress:
            status = "PASS" if not case.get("failures") else "FAIL"
            print(
                f"{status} {case.get('id', '<unknown>')} "
                f"score={case.get('scores', {}).get('overall_score', 0.0)} "
                f"tokens={case.get('tokens_used', 0)}",
                file=sys.stderr,
                flush=True,
            )
        if progress_path:
            progress_path.parent.mkdir(parents=True, exist_ok=True)
            with progress_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    summary = run_manifest(
        args.manifest,
        model=args.model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
        selected_cases=set(args.case),
        progress_callback=progress_callback
        if args.progress or progress_path is not None
        else None,
    )

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_summary(summary))
    return 1 if summary["failure_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
