#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from skylos.benchmarks.deep_audit_logic import (
    DEFAULT_EXPECTED_PATH,
    DeepAuditLogicBenchmarkError,
    format_summary,
    run_manifest,
)
from skylos.llm.runtime import resolve_llm_runtime


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the live Skylos Deep Audit cross-file logic benchmark."
    )
    parser.add_argument("--expected", default=str(DEFAULT_EXPECTED_PATH))
    parser.add_argument("--model", default="gpt-4.1")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--output", default=None)
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
        print(
            "No configured LLM credential. Run `skylos key`, pass --api-key, "
            "or select a local provider."
        )
        return 2

    try:
        summary = run_manifest(
            args.expected,
            model=args.model,
            api_key=api_key,
            provider=provider,
            base_url=base_url,
            selected_cases=set(args.case),
            require_model_usage=True,
        )
    except DeepAuditLogicBenchmarkError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        return 2

    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2) if args.json else format_summary(summary))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
