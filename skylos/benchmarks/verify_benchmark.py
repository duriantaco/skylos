from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Sequence

from skylos.benchmarks.verify_benchmark_eval import summarize_results
from skylos.benchmarks.verify_benchmark_report import format_report, format_summary
from skylos.benchmarks.verify_benchmark_runner import (
    load_manifest,
    manifest_cases,
    run_case,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "benchmarks" / "verify_benchmark" / "manifest.json"

__all__ = [
    "DEFAULT_MANIFEST",
    "format_report",
    "format_summary",
    "main",
    "run_benchmark",
]


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    selected_cases = _selected_cases(args.case)
    summary = run_benchmark(
        Path(args.manifest),
        tool_command=args.tool_command,
        selected_cases=selected_cases,
    )

    if args.report is not None:
        report_path = Path(args.report)
        report_path.write_text(format_report(summary), encoding="utf-8")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_summary(summary))

    if summary["failed_cases"]:
        return 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the neutral-label benchmark for skylos verify."
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="Path to the verify benchmark manifest.",
    )
    parser.add_argument(
        "--tool-command",
        default="skylos",
        help="Verify-capable CLI command to run as a black-box tool.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run one case id. Repeat to run multiple cases.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON.",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Write a markdown report to this path.",
    )
    return parser


def _selected_cases(case_ids: list[str]) -> set[str] | None:
    if not case_ids:
        return None

    selected: set[str] = set()
    for case_id in case_ids:
        selected.add(case_id)
    return selected


def run_benchmark(
    manifest_path: Path,
    *,
    tool_command: str,
    selected_cases: set[str] | None = None,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path, repo_root=REPO_ROOT)
    cases = manifest_cases(manifest)
    manifest_root = manifest_path.resolve().parent
    case_summaries: list[dict[str, Any]] = []
    started = time.perf_counter()

    for case in cases:
        if selected_cases is not None:
            if case["id"] not in selected_cases:
                continue
        case_summary = run_case(manifest_root, case, tool_command, repo_root=REPO_ROOT)
        case_summaries.append(case_summary)

    elapsed = time.perf_counter() - started
    return summarize_results(manifest, case_summaries, elapsed)
