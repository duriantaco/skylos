#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.research.dead_code import ResearchVariant  # noqa: E402
from skylos.research.dead_code.benchmark_adapter import (  # noqa: E402
    default_result_dir,
    evaluate_benchmark_manifest,
    write_benchmark_evaluation,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run research dead-code variants on the Python "
            "class/function/method/variable subset of a Skylos benchmark manifest."
        )
    )
    parser.add_argument(
        "--benchmark-root",
        default=str(REPO_ROOT.parent / "skylos-benchmarks"),
        help="Path to the independent benchmark artifact directory.",
    )
    parser.add_argument(
        "--manifest",
        default="manifests/dead_code.dev.json",
        help="Benchmark manifest path, absolute or relative to benchmark root.",
    )
    parser.add_argument(
        "--variant",
        action="append",
        choices=[variant.value for variant in ResearchVariant],
        help="Variant to score. Repeat to score multiple variants.",
    )
    parser.add_argument(
        "--output",
        help="Optional summary JSON output path. Prints to stdout when omitted.",
    )
    parser.add_argument(
        "--write-results",
        action="store_true",
        help="Retain summary, raw ablation JSON, and scored JSON under results/.",
    )
    parser.add_argument(
        "--results-dir",
        help="Explicit result directory for --write-results.",
    )
    args = parser.parse_args()

    evaluation = evaluate_benchmark_manifest(
        args.benchmark_root,
        args.manifest,
        variants=args.variant,
    )
    payload = evaluation.to_dict()

    if args.write_results:
        output_dir = (
            Path(args.results_dir)
            if args.results_dir
            else default_result_dir(args.benchmark_root, source_manifest=args.manifest)
        )
        retained = write_benchmark_evaluation(evaluation, output_dir)
        payload["retained_result_dir"] = str(retained)

    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
