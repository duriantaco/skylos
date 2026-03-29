import argparse
import json
from pathlib import Path

from rich.panel import Panel
from rich.progress import SpinnerColumn, TextColumn
from rich.table import Table


def run_provenance_command(
    argv: list[str],
    *,
    console_factory,
    progress_factory,
    get_git_root_func,
) -> int:
    prov_parser = argparse.ArgumentParser(
        prog="skylos provenance",
        description="Detect AI-authored code provenance in PR changes",
    )
    prov_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    prov_parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    prov_parser.add_argument(
        "--diff-base",
        default=None,
        help="Base ref to diff against (default: auto-detect from CI or origin/main)",
    )
    prov_parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    prov_parser.add_argument(
        "--with-risk",
        action="store_true",
        help="Cross-reference with discover+defend for local risk analysis",
    )

    prov_args = prov_parser.parse_args(argv)
    console = console_factory()

    from skylos.provenance import analyze_provenance

    target = Path(prov_args.path).resolve()
    git_root = get_git_root_func() or str(target)

    with progress_factory(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
        disable=prov_args.output_json,
    ) as progress:
        progress.add_task("Analyzing provenance...", total=None)
        report = analyze_provenance(git_root, base_ref=prov_args.diff_base)

    risk_data = None
    if prov_args.with_risk:
        from skylos.provenance import compute_risk_intersections

        with progress_factory(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
            disable=prov_args.output_json,
        ) as progress:
            progress.add_task("Computing risk intersections...", total=None)
            risk_data = compute_risk_intersections(git_root, report)

    if prov_args.output_json:
        out_dict = report.to_dict()
        if risk_data:
            out_dict["risk_intersection"] = risk_data.to_dict()
        output = json.dumps(out_dict, indent=2)
        if prov_args.output_file:
            Path(prov_args.output_file).write_text(output)
            console.print(f"[green]Written to {prov_args.output_file}[/green]")
        else:
            print(output)
        return 0

    summary = report.summary
    console.print()
    console.print(
        Panel(
            f"[bold]AI Provenance Report[/bold]\n"
            f"Confidence: [{'green' if report.confidence == 'low' else 'yellow' if report.confidence == 'medium' else 'red'}]{report.confidence}[/]",
            border_style="cyan",
        )
    )

    table = Table(title="File Breakdown", show_lines=False)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("Total files changed", str(summary.get("total_files", 0)))
    table.add_row("[red]AI-authored[/red]", str(summary.get("agent_count", 0)))
    table.add_row("[green]Human-only[/green]", str(summary.get("human_count", 0)))
    console.print(table)

    agents = summary.get("agents_seen", [])
    if agents:
        console.print(f"\n[bold]Agents detected:[/bold] {', '.join(agents)}")

    if report.agent_files:
        console.print("\n[bold]AI-authored files:[/bold]")
        for agent_file in report.agent_files:
            file_provenance = report.files.get(agent_file)
            agent_label = (
                f" ({file_provenance.agent_name})"
                if file_provenance and file_provenance.agent_name
                else ""
            )
            ranges = ""
            if file_provenance and file_provenance.agent_lines:
                range_strs = [f"L{s}-{e}" for s, e in file_provenance.agent_lines[:5]]
                if len(file_provenance.agent_lines) > 5:
                    range_strs.append(
                        f"...+{len(file_provenance.agent_lines) - 5} more"
                    )
                ranges = f" [{', '.join(range_strs)}]"
            console.print(f"  [red]•[/red] {agent_file}{agent_label}{ranges}")

    if risk_data:
        console.print()
        risk_table = Table(title="Risk Intersection", show_lines=False)
        risk_table.add_column("File", style="bold")
        risk_table.add_column("Agent")
        risk_table.add_column("Risk Level", justify="center")
        risk_table.add_column("Reasons")

        for entry in risk_data.high_risk:
            risk_table.add_row(
                entry["file_path"],
                entry.get("agent_name") or "unknown",
                "[red bold]HIGH[/red bold]",
                ", ".join(entry["reasons"]),
            )
        for entry in risk_data.medium_risk:
            risk_table.add_row(
                entry["file_path"],
                entry.get("agent_name") or "unknown",
                "[yellow]MEDIUM[/yellow]",
                ", ".join(entry["reasons"]),
            )

        if risk_data.high_risk or risk_data.medium_risk:
            console.print(risk_table)
        else:
            console.print(
                Panel(
                    "[green]No risk intersections found[/green]",
                    title="Risk Intersection",
                    border_style="green",
                )
            )

        console.print(
            f"  Summary: [red]{risk_data.summary['high']} high[/red], "
            f"[yellow]{risk_data.summary['medium']} medium[/yellow] "
            f"(of {risk_data.summary['total_ai_files']} AI files)"
        )

    if prov_args.output_file:
        out_dict = report.to_dict()
        if risk_data:
            out_dict["risk_intersection"] = risk_data.to_dict()
        output = json.dumps(out_dict, indent=2)
        Path(prov_args.output_file).write_text(output)
        console.print(f"\n[green]Written to {prov_args.output_file}[/green]")

    console.print()
    return 0
