import argparse
import json
import platform
from pathlib import Path

import skylos
from rich.console import Console
from rich.panel import Panel

from skylos.config import load_config


def _rust_available() -> bool:
    try:
        import skylos_rust  # noqa: F401

        return True
    except ImportError:
        return False


def _llm_available() -> bool:
    try:
        from skylos.llm.analyzer import AnalyzerConfig, SkylosLLM  # noqa: F401

        return True
    except ImportError:
        return False


def _interactive_available() -> bool:
    try:
        import inquirer  # noqa: F401

        return True
    except ImportError:
        return False


def _go_engine_status() -> dict[str, str]:
    from skylos.engines.go_runner import get_go_engine_status

    return get_go_engine_status()


def _doctor_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skylos doctor", add_help=False)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _doctor_json_report(py_ver: str, py_ok: bool, go_status: dict) -> dict:
    rust_available = _rust_available()
    llm_available = _llm_available()
    interactive_available = _interactive_available()
    degraded = go_status.get("status") != "available"
    return {
        "schema_version": 1,
        "tool": "doctor",
        "status": "fail" if not py_ok else ("degraded" if degraded else "ok"),
        "checks": {
            "python": {
                "status": "ok" if py_ok else "fail",
                "version": py_ver,
                "minimum_version": "3.10",
            },
            "skylos": {"status": "ok", "version": str(skylos.__version__)},
            "go_engine": dict(go_status),
            "rust_acceleration": {
                "status": "available" if rust_available else "unavailable"
            },
            "llm_support": {"status": "available" if llm_available else "unavailable"},
            "interactive": {
                "status": "available" if interactive_available else "unavailable"
            },
        },
    }


def _print_availability(
    console: Console,
    available: bool,
    available_message: str,
    unavailable_message: str,
) -> None:
    console.print(available_message if available else unavailable_message)


def _print_runtime_status(
    console: Console,
    py_ver: str,
    py_ok: bool,
    go_status: dict[str, str],
) -> None:
    console.print(
        f"  {'[green]OK[/green]' if py_ok else '[red]FAIL[/red]'}  Python {py_ver}"
        + ("" if py_ok else " [red](requires 3.10+)[/red]")
    )
    console.print(f"  [green]OK[/green]  Skylos {skylos.__version__}")
    _print_availability(
        console,
        go_status.get("status") == "available",
        "  [green]OK[/green]  Go engine available",
        "  [yellow]--[/yellow]  Go engine unavailable "
        "[dim](Go dead-code and security checks will be incomplete)[/dim]",
    )


def _print_optional_status(console: Console) -> None:
    _print_availability(
        console,
        _rust_available(),
        "  [green]OK[/green]  skylos\\[fast] installed (Rust acceleration)",
        "  [yellow]--[/yellow]  skylos\\[fast] not installed "
        "[dim](optional: pip install skylos\\[fast])[/dim]",
    )
    _print_availability(
        console,
        _llm_available(),
        "  [green]OK[/green]  LLM support available",
        "  [yellow]--[/yellow]  LLM support not available "
        "[dim](optional: pip install litellm)[/dim]",
    )
    _print_availability(
        console,
        _interactive_available(),
        "  [green]OK[/green]  Interactive mode available",
        "  [yellow]--[/yellow]  Interactive mode not available "
        "[dim](optional: pip install inquirer)[/dim]",
    )


def _print_credit_status(console: Console, token: str) -> None:
    try:
        from skylos.api import get_credit_balance

        balance_data = get_credit_balance(token)
    except Exception:
        console.print("  [yellow]--[/yellow]  Cloud credit balance unavailable")
        return
    if not balance_data:
        return
    plan = balance_data.get("plan", "free")
    balance = balance_data.get("balance", 0)
    if plan == "enterprise":
        console.print(f"  [green]OK[/green]  Plan: {plan} (unlimited credits)")
        return
    color = "green" if balance > 0 else "red"
    console.print(f"  [{color}]OK[/{color}]  Plan: {plan} | Credits: {balance:,}")


def _print_cloud_status(console: Console) -> None:
    from skylos.api import get_project_token

    token = get_project_token()
    if not token:
        console.print(
            "  [yellow]--[/yellow]  Cloud not connected [dim](optional: skylos login)[/dim]"
        )
        return
    console.print("  [green]OK[/green]  Cloud connected (SKYLOS_TOKEN set)")
    _print_credit_status(console, token)


def _print_project_config(console: Console, cwd: Path) -> None:
    pyproject = cwd / "pyproject.toml"
    if not pyproject.exists():
        console.print("  [yellow]--[/yellow]  No pyproject.toml in current directory")
        return
    try:
        config = load_config(cwd)
    except Exception:
        console.print(
            "  [yellow]--[/yellow]  pyproject.toml exists but could not parse config"
        )
        return
    has_skylos_config = bool(
        config.get("whitelist")
        or config.get("exclude")
        or config.get("gate")
        or config.get("masking")
    )
    _print_availability(
        console,
        has_skylos_config,
        "  [green]OK[/green]  pyproject.toml [tool.skylos] config found",
        "  [yellow]--[/yellow]  pyproject.toml exists but no [tool.skylos] section",
    )


def _print_workflow_status(console: Console, cwd: Path) -> None:
    workflow = cwd / ".github" / "workflows" / "skylos.yml"
    _print_availability(
        console,
        workflow.exists(),
        "  [green]OK[/green]  GitHub Actions workflow found",
        "  [yellow]--[/yellow]  No CI/CD workflow [dim](run: skylos cicd init)[/dim]",
    )


def _print_rule_status(console: Console) -> None:
    rules_dir = Path.home() / ".skylos" / "rules"
    rule_files = list(rules_dir.glob("*.yml")) if rules_dir.exists() else []
    if rule_files:
        console.print(
            f"  [green]OK[/green]  {len(rule_files)} community rule pack(s) installed"
        )
        return
    console.print(
        "  [yellow]--[/yellow]  No community rules "
        "[dim](optional: skylos rules install <pack>)[/dim]"
    )


def _print_local_status(console: Console) -> None:
    cwd = Path.cwd()
    _print_project_config(console, cwd)
    _print_workflow_status(console, cwd)
    _print_rule_status(console)


def run_doctor_command(argv: list[str] | None = None) -> int:
    args = _doctor_parser().parse_args(argv or [])
    py_ver = platform.python_version()
    py_ok = tuple(int(x) for x in py_ver.split(".")[:2]) >= (3, 10)
    go_status = _go_engine_status()
    if args.format == "json":
        print(json.dumps(_doctor_json_report(py_ver, py_ok, go_status), indent=2))
        return 0

    console = Console()
    console.print()
    console.print(Panel.fit("[bold]Skylos Doctor[/bold]", border_style="cyan"))
    console.print()
    _print_runtime_status(console, py_ver, py_ok, go_status)
    _print_optional_status(console)
    _print_cloud_status(console)
    _print_local_status(console)
    console.print()
    return 0
