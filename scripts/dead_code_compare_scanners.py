#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skylos.benchmarks.dead_code import run_manifest  # noqa: E402


DEFAULT_SCANNERS = ("skylos", "vulture", "ruff")


def _row(summary: dict[str, Any]) -> dict[str, Any]:
    counts = summary["counts"]
    scores = summary["scores"]
    return {
        "scanner": summary["scanner"],
        "cases": summary["case_count"],
        "skipped": summary.get("skipped_case_count", 0),
        "failures": summary["failure_count"],
        "TP": counts["true_positives"],
        "FP": counts["false_positives"],
        "FN": counts["false_negatives"],
        "TN": counts["true_negatives"],
        "precision": scores["precision"],
        "recall": scores["recall"],
        "f1": scores["f1"],
        "score": scores["overall_score"],
        "unlabeled": sum(
            int(case["unlabeled_finding_count"]) for case in summary["cases"]
        ),
    }


def _format_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No scanner results."

    columns = [
        "scanner",
        "cases",
        "skipped",
        "failures",
        "TP",
        "FP",
        "FN",
        "TN",
        "precision",
        "recall",
        "f1",
        "score",
        "unlabeled",
    ]
    widths = {
        column: max(len(column), *(len(str(row[column])) for row in rows))
        for column in columns
    }
    header = "  ".join(column.ljust(widths[column]) for column in columns)
    rule = "  ".join("-" * widths[column] for column in columns)
    body = [
        "  ".join(str(row[column]).ljust(widths[column]) for column in columns)
        for row in rows
    ]
    return "\n".join([header, rule, *body])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare dead-code scanners against the same golden labels."
    )
    parser.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "benchmarks" / "dead_code" / "manifest.json"),
        help="Path to the internal dead-code benchmark manifest JSON file.",
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run only the specified benchmark case id. Repeat for multiple ids.",
    )
    parser.add_argument(
        "--scanner",
        action="append",
        choices=("skylos", "vulture", "ruff"),
        default=[],
        help="Scanner to include. Defaults to skylos, vulture, and ruff.",
    )
    parser.add_argument(
        "--loose-labels",
        action="store_true",
        help="Do not count unlabeled scanner findings as false positives.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of a comparison table.",
    )
    args = parser.parse_args()

    scanners = tuple(args.scanner or DEFAULT_SCANNERS)
    summaries = []
    errors = []
    for scanner in scanners:
        try:
            summaries.append(
                run_manifest(
                    args.manifest,
                    selected_cases=set(args.case),
                    scanner=scanner,
                    strict_labels=not args.loose_labels,
                )
            )
        except RuntimeError as exc:
            errors.append({"scanner": scanner, "error": str(exc)})

    payload = {
        "manifest": str(Path(args.manifest).resolve()),
        "strict_labels": not args.loose_labels,
        "rows": [_row(summary) for summary in summaries],
        "errors": errors,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Dead-code scanner comparison (strict_labels={payload['strict_labels']})")
        print(_format_table(payload["rows"]))
        for error in errors:
            print(f"SKIP {error['scanner']}: {error['error']}")

    skylos_summary = next(
        (summary for summary in summaries if summary["scanner"] == "skylos"),
        None,
    )
    if skylos_summary is None:
        return 1
    return 1 if skylos_summary["failure_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
