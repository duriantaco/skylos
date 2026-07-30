from __future__ import annotations

import importlib.util
import subprocess
import sys
from collections.abc import Callable, Sequence

from rich.console import Console
from rich.markup import escape


def _ruff_is_available(find_spec_func: Callable[[str], object | None]) -> bool:
    try:
        return find_spec_func("ruff") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def run_lint_command(
    argv: Sequence[str],
    *,
    console_factory: Callable[[], Console] = Console,
    find_spec_func: Callable[[str], object | None] = importlib.util.find_spec,
    run_func: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    executable: str | None = None,
) -> int:
    """Run Ruff with arguments passed as a list, never through a shell."""
    console = console_factory()
    if not _ruff_is_available(find_spec_func):
        console.print("[bold red]Ruff is not installed.[/bold red]")
        install_command = escape('pip install "skylos[lint]"')
        console.print(f"Install lint support with: [bold]{install_command}[/bold]")
        return 2

    command = [
        executable or sys.executable,
        "-m",
        "ruff",
        "check",
        *(list(argv) if argv else ["."]),
    ]
    try:
        completed = run_func(command, check=False)
    except OSError as exc:
        console.print(f"[bold red]Could not start Ruff:[/bold red] {exc}")
        return 2

    return int(completed.returncode)
