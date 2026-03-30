import argparse
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn


def run_discover_command(argv: list[str]) -> int:
    disc_parser = argparse.ArgumentParser(
        prog="skylos discover",
        description="Discover LLM integrations in a codebase",
    )
    disc_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    disc_parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    disc_parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    disc_parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Additional folders to exclude",
    )
    disc_args = disc_parser.parse_args(argv)
    console = Console()

    from skylos.discover.detector import _collect_python_files, detect_integrations
    from skylos.discover.report import format_json, format_table

    target = Path(disc_args.path).resolve()
    if not target.exists():
        console.print(f"[red]Error: path does not exist: {target}[/red]")
        return 1
    if not target.is_dir():
        console.print(f"[red]Error: path is not a directory: {target}[/red]")
        return 1

    exclude = {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
    }
    if disc_args.exclude:
        exclude.update(disc_args.exclude)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Discovering LLM integrations...", total=None)
        files = _collect_python_files(target, exclude)
        integrations, graph = detect_integrations(target, exclude_folders=exclude)

    if disc_args.output_json:
        output = format_json(integrations, graph, len(files), str(target))
    else:
        output = format_table(integrations, len(files), str(target))

    if disc_args.output_file:
        try:
            Path(disc_args.output_file).write_text(output, encoding="utf-8")
        except OSError as e:
            console.print(f"[red]Error writing output file: {e}[/red]")
            return 1
        console.print(f"[green]Output written to {disc_args.output_file}[/green]")
    elif disc_args.output_json:
        print(output)
    else:
        console.print(output)

    return 0
