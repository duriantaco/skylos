import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from skylos.analyzer import analyze as run_analyze
from skylos.config import load_config
from skylos.constants import parse_exclude_folders


def run_city_command(argv: list[str]) -> int:
    city_parser = argparse.ArgumentParser(
        prog="skylos city",
        description="Generate Code City topology from codebase analysis",
    )
    city_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    city_parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output raw topology JSON"
    )
    city_parser.add_argument(
        "--quality", action="store_true", help="Include complexity data in output"
    )
    city_parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    city_parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Additional folders to exclude",
    )
    city_parser.add_argument(
        "--confidence",
        type=int,
        default=60,
        help="Confidence threshold (default: 60)",
    )
    city_args = city_parser.parse_args(argv)
    console = Console()

    target = Path(city_args.path).resolve()
    if not target.exists():
        console.print(f"[red]Error: path does not exist: {target}[/red]")
        return 1

    from skylos.city import format_rich_summary, generate_topology

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Analyzing codebase...", total=None)

        exclude_folders = list(
            parse_exclude_folders(
                config_exclude_folders=load_config(target).get("exclude")
            )
        )
        if city_args.exclude:
            exclude_folders.extend(city_args.exclude)

        result_json = run_analyze(
            str(target),
            conf=city_args.confidence,
            exclude_folders=exclude_folders,
            enable_quality=city_args.quality,
        )
        result = json.loads(result_json)

    topology = generate_topology(result)

    if city_args.output_json:
        output = json.dumps(topology, indent=2)
    else:
        output = format_rich_summary(topology)

    if city_args.output_file:
        try:
            Path(city_args.output_file).write_text(output, encoding="utf-8")
        except OSError as e:
            console.print(f"[red]Error writing output file: {e}[/red]")
            return 1
        console.print(f"[green]Output written to {city_args.output_file}[/green]")
    elif city_args.output_json:
        print(output)
    else:
        console.print(output)

    return 0
