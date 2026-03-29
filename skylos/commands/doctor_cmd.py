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


def run_doctor_command() -> int:
    console = Console()

    console.print()
    console.print(Panel.fit("[bold]Skylos Doctor[/bold]", border_style="cyan"))
    console.print()

    py_ver = platform.python_version()
    py_ok = tuple(int(x) for x in py_ver.split(".")[:2]) >= (3, 10)
    console.print(
        f"  {'[green]OK[/green]' if py_ok else '[red]FAIL[/red]'}  Python {py_ver}"
        + ("" if py_ok else " [red](requires 3.10+)[/red]")
    )

    console.print(f"  [green]OK[/green]  Skylos {skylos.__version__}")

    if _rust_available():
        console.print("  [green]OK[/green]  skylos\\[fast] installed (Rust acceleration)")
    else:
        console.print(
            "  [yellow]--[/yellow]  skylos\\[fast] not installed [dim](optional: pip install skylos\\[fast])[/dim]"
        )

    if _llm_available():
        console.print("  [green]OK[/green]  LLM support available")
    else:
        console.print(
            "  [yellow]--[/yellow]  LLM support not available [dim](optional: pip install litellm)[/dim]"
        )

    if _interactive_available():
        console.print("  [green]OK[/green]  Interactive mode available")
    else:
        console.print(
            "  [yellow]--[/yellow]  Interactive mode not available [dim](optional: pip install inquirer)[/dim]"
        )

    from skylos.api import get_project_token

    token = get_project_token()
    if token:
        console.print("  [green]OK[/green]  Cloud connected (SKYLOS_TOKEN set)")
        try:
            from skylos.api import get_credit_balance

            balance_data = get_credit_balance(token)
            if balance_data:
                plan = balance_data.get("plan", "free")
                balance = balance_data.get("balance", 0)
                if plan == "enterprise":
                    console.print(
                        f"  [green]OK[/green]  Plan: {plan} (unlimited credits)"
                    )
                else:
                    color = "green" if balance > 0 else "red"
                    console.print(
                        f"  [{color}]OK[/{color}]  Plan: {plan} | Credits: {balance:,}"
                    )
        except Exception:
            pass
    else:
        console.print(
            "  [yellow]--[/yellow]  Cloud not connected [dim](optional: skylos login)[/dim]"
        )

    cwd = Path.cwd()
    pyproject = cwd / "pyproject.toml"
    if pyproject.exists():
        try:
            config = load_config(cwd)
            has_skylos_config = bool(
                config.get("whitelist")
                or config.get("exclude")
                or config.get("gate")
                or config.get("masking")
            )
            if has_skylos_config:
                console.print(
                    "  [green]OK[/green]  pyproject.toml [tool.skylos] config found"
                )
            else:
                console.print(
                    "  [yellow]--[/yellow]  pyproject.toml exists but no [tool.skylos] section"
                )
        except Exception:
            console.print(
                "  [yellow]--[/yellow]  pyproject.toml exists but could not parse config"
            )
    else:
        console.print("  [yellow]--[/yellow]  No pyproject.toml in current directory")

    workflow = cwd / ".github" / "workflows" / "skylos.yml"
    if workflow.exists():
        console.print("  [green]OK[/green]  GitHub Actions workflow found")
    else:
        console.print(
            "  [yellow]--[/yellow]  No CI/CD workflow [dim](run: skylos cicd init)[/dim]"
        )

    rules_dir = Path.home() / ".skylos" / "rules"
    if rules_dir.exists():
        rule_files = list(rules_dir.glob("*.yml"))
        if rule_files:
            console.print(
                f"  [green]OK[/green]  {len(rule_files)} community rule pack(s) installed"
            )
        else:
            console.print(
                "  [yellow]--[/yellow]  No community rules [dim](optional: skylos rules install <pack>)[/dim]"
            )
    else:
        console.print(
            "  [yellow]--[/yellow]  No community rules [dim](optional: skylos rules install <pack>)[/dim]"
        )

    console.print()
    return 0
