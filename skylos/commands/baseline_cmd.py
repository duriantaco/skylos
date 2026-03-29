import json

from rich.console import Console

from skylos import analyze as run_analyze
from skylos.baseline import save_baseline


def run_baseline_command(argv: list[str]) -> int:
    path = argv[0] if argv else "."

    console = Console()
    console.print(f"[bold]Creating baseline for {path}...[/bold]")

    result = json.loads(run_analyze(path))
    baseline_path = save_baseline(path, result)
    total = sum(
        len(result.get(key, []))
        for key in [
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
            "danger",
            "quality",
            "secrets",
        ]
    )

    console.print(
        f"[good]Baseline saved to {baseline_path} ({total} existing findings captured)[/good]"
    )
    console.print(
        "[muted]Future runs with --baseline will only report new findings[/muted]"
    )
    return 0
