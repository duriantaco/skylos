"""Inspect a saved static finding without rescanning or executing its project."""

import argparse
import json
import sys

from rich.console import Console

from skylos.cicd.evidence import sanitize_untrusted_text
from skylos.security.trace_report import (
    load_security_findings,
    recorded_trace,
    select_findings,
)
from skylos.ui.security_trace import follow_trace, show_trace


def _positive_int(value):
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Expected a positive integer.") from error
    if number < 1:
        raise argparse.ArgumentTypeError("Expected a positive integer.")
    return number


def run_explain_command(argv, *, console_factory=Console):
    parser = argparse.ArgumentParser(
        prog="skylos explain",
        description="Follow analyzer-recorded static security steps in a saved JSON report. No target code executes.",
    )
    parser.add_argument("report", help="Skylos JSON report saved with --output")
    parser.add_argument("--rule", help="Exact security rule ID")
    parser.add_argument("--file", help="Exact file path or path suffix")
    parser.add_argument("--line", type=_positive_int, help="Finding source line")
    parser.add_argument(
        "--finding", type=_positive_int, help="1-based index in the filtered list"
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Navigate recorded steps with next/back/source",
    )
    parser.add_argument(
        "--root", help="Explicit project root for hash-verified source viewing"
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    console = console_factory()
    if args.interactive and (args.format == "json" or not sys.stdin.isatty()):
        console.print(
            "Interactive navigation requires a terminal and --format text.",
            markup=False,
        )
        return 2
    try:
        findings = select_findings(
            load_security_findings(args.report),
            rule=args.rule,
            file=args.file,
            line=args.line,
        )
    except (ValueError, RecursionError, OSError) as error:
        console.print(str(error), markup=False)
        return 2
    if not findings:
        console.print("No matching security findings in this report.", markup=False)
        return 1
    if args.finding is not None:
        if args.finding > len(findings):
            console.print("Finding index is outside the filtered list.", markup=False)
            return 2
        finding = findings[args.finding - 1]
    elif len(findings) == 1:
        finding = findings[0]
    else:
        if args.format == "json":
            print(json.dumps({"findings": findings}, ensure_ascii=True, indent=2))
        else:
            console.print(
                "Choose a finding with --finding NUMBER (indices apply after filtering):",
                markup=False,
            )
            for index, row in enumerate(findings[:40], 1):
                location = f"{row.get('file', '')}:{row.get('line', 0)}"
                label = f"{index}. {row.get('rule_id', '')} {location}"
                console.print(
                    sanitize_untrusted_text(label, max_length=500), markup=False
                )
            if len(findings) > 40:
                console.print(
                    f"{len(findings)} matches; use --rule/--file/--line to narrow the list.",
                    markup=False,
                )
        return 0
    trace = recorded_trace(finding)
    if args.format == "json":
        print(
            json.dumps(
                {"finding": finding, "trace": trace}, ensure_ascii=True, indent=2
            )
        )
        return 0
    show_trace(console, finding, trace)
    if args.interactive:
        follow_trace(console, trace, root=args.root)
    return 0
