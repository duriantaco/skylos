import json

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from skylos.analyzer import analyze as run_analyze
from skylos.codemods import (
    comment_out_unused_function_cst,
    comment_out_unused_import_cst,
    remove_unused_function_cst,
    remove_unused_import_cst,
)


def run_clean_command(argv: list[str]) -> int:
    console = Console()
    path = argv[0] if argv else "."

    console.print(
        Panel(
            "[bold]Skylos Clean[/bold] — Interactive Dead Code Removal",
            border_style="blue",
        )
    )
    console.print(f"Scanning [bold]{path}[/bold]...\n")

    result = json.loads(run_analyze(path))

    findings = []
    for fn in result.get("unused_functions", []):
        findings.append(
            {
                "type": "function",
                "name": fn.get("name", ""),
                "file": fn.get("file", ""),
                "line": fn.get("line", 0),
                "confidence": fn.get("confidence", 100),
            }
        )
    for imp in result.get("unused_imports", []):
        findings.append(
            {
                "type": "import",
                "name": imp.get("name", ""),
                "file": imp.get("file", ""),
                "line": imp.get("line", 0),
                "confidence": imp.get("confidence", 100),
            }
        )
    for var in result.get("unused_variables", []):
        findings.append(
            {
                "type": "variable",
                "name": var.get("name", ""),
                "file": var.get("file", ""),
                "line": var.get("line", 0),
                "confidence": var.get("confidence", 100),
            }
        )
    for cls in result.get("unused_classes", []):
        findings.append(
            {
                "type": "class",
                "name": cls.get("name", ""),
                "file": cls.get("file", ""),
                "line": cls.get("line", 0),
                "confidence": cls.get("confidence", 100),
            }
        )

    findings.sort(key=lambda f: -f["confidence"])

    if not findings:
        console.print("[green]No dead code found. Your codebase is clean![/green]")
        return 0

    console.print(f"Found [bold]{len(findings)}[/bold] potential dead code items.\n")

    to_remove = []
    to_comment = []
    skipped = 0

    for i, finding in enumerate(findings, 1):
        console.print(Rule(style="dim"))
        console.print(
            f"[bold][{i}/{len(findings)}][/bold] Unused {finding['type']} "
            f"[bold cyan]{finding['name']}[/bold cyan] at {finding['file']}:{finding['line']}"
        )
        console.print(f"         Confidence: [bold]{finding['confidence']}%[/bold]")

        try:
            choice = (
                input("\n  [R]emove  [C]omment-out  [S]kip  [Q]uit > ").strip().lower()
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Interrupted.[/dim]")
            break

        if choice in ("r", "remove"):
            to_remove.append(finding)
            console.print("  [green]Marked for removal[/green]")
        elif choice in ("c", "comment", "comment-out"):
            to_comment.append(finding)
            console.print("  [yellow]Marked for comment-out[/yellow]")
        elif choice in ("q", "quit"):
            console.print("[dim]Stopping early.[/dim]")
            break
        else:
            skipped += 1
            console.print("  [dim]Skipped[/dim]")

    if not to_remove and not to_comment:
        console.print("\n[dim]No changes to apply.[/dim]")
        return 0

    console.print(Rule(style="blue"))
    console.print(
        f"\n[bold]Summary:[/bold] {len(to_remove)} to remove, "
        f"{len(to_comment)} to comment out, {skipped} skipped\n"
    )

    try:
        confirm = input("Apply changes? (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled.[/dim]")
        return 0

    if confirm not in ("y", "yes"):
        console.print("[dim]No changes applied.[/dim]")
        return 0

    applied = 0

    for finding in to_remove:
        try:
            if finding["type"] == "import":
                remove_unused_import_cst(finding["file"], finding["name"])
                applied += 1
            elif finding["type"] == "function":
                remove_unused_function_cst(finding["file"], finding["name"])
                applied += 1
        except Exception as e:
            console.print(f"  [red]Failed to remove {finding['name']}: {e}[/red]")

    for finding in to_comment:
        try:
            if finding["type"] == "import":
                comment_out_unused_import_cst(finding["file"], finding["name"])
                applied += 1
            elif finding["type"] == "function":
                comment_out_unused_function_cst(finding["file"], finding["name"])
                applied += 1
        except Exception as e:
            console.print(f"  [red]Failed to comment out {finding['name']}: {e}[/red]")

    console.print(
        f"\n[green]Done![/green] Applied {applied} changes "
        f"({len(to_remove)} removed, {len(to_comment)} commented out)."
    )
    return 0
