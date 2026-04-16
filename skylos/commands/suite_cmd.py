from __future__ import annotations

import argparse
from pathlib import Path

from skylos.suite import format_suite_json, format_suite_table, run_suite


def run_suite_command(
    argv: list[str],
    *,
    console_factory,
    progress_factory,
    parse_exclude_folders_func,
    load_config_func,
    run_analyze_func,
    get_git_root_func,
) -> int:
    suite_parser = argparse.ArgumentParser(
        prog="skylos suite",
        description=(
            "Run the full local Skylos suite: static analysis, technical debt, "
            "AI defense, and provenance summary"
        ),
    )
    suite_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    suite_parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    suite_parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    suite_parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Additional folders to exclude",
    )
    suite_parser.add_argument(
        "--confidence",
        "-c",
        type=int,
        default=60,
        help="Confidence threshold for static dead-code findings (0-100)",
    )
    suite_parser.add_argument(
        "--diff-base",
        default=None,
        help="Base ref for provenance detection (default: auto-detect)",
    )
    suite_parser.add_argument(
        "--no-provenance",
        action="store_true",
        help="Disable automatic AI provenance summary",
    )

    suite_args = suite_parser.parse_args(argv)
    console = console_factory()

    target = Path(suite_args.path).resolve()
    if not target.exists():
        console.print(f"[red]Error: path does not exist: {target}[/red]")
        return 1
    if not target.is_dir():
        console.print(
            f"[red]Error: suite expects a directory, got file: {target}. "
            "Use `skylos <file>` for single-file static analysis.[/red]"
        )
        return 1

    exclude = set(
        parse_exclude_folders_func(
            use_defaults=True,
            config_exclude_folders=load_config_func(target).get("exclude"),
        )
    )
    if suite_args.exclude:
        exclude.update(suite_args.exclude)

    try:
        report = run_suite(
            target,
            conf=suite_args.confidence,
            exclude_folders=sorted(exclude),
            run_analyze_func=run_analyze_func,
            progress_factory=progress_factory,
            console=console,
            output_json=suite_args.output_json,
            no_provenance=suite_args.no_provenance,
            diff_base=suite_args.diff_base,
            get_git_root_func=get_git_root_func,
        )
    except (FileNotFoundError, ValueError, ImportError) as exc:
        console.print(f"[bold red]Suite error: {exc}[/bold red]")
        return 1

    output = (
        format_suite_json(report)
        if suite_args.output_json
        else format_suite_table(report)
    )

    if suite_args.output_file:
        try:
            Path(suite_args.output_file).write_text(output, encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Error writing output file: {exc}[/red]")
            return 1
        console.print(f"[green]Output written to {suite_args.output_file}[/green]")
    elif suite_args.output_json:
        print(output)
    else:
        console.print(output)

    return 0
