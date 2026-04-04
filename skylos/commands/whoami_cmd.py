from rich.console import Console

from skylos.api import get_project_info, get_project_token


def run_whoami_command() -> int:
    console = Console()
    token = get_project_token()
    if not token:
        console.print("[red]Not connected.[/red] Run [bold]skylos login[/bold] first.")
        return 1

    info = get_project_info(token)
    if not info or not info.get("ok"):
        console.print("[red]Could not fetch account info.[/red]")
        return 1

    project = info.get("project", {})
    org = info.get("organization", {}) or info.get("org", {})
    console.print()
    console.print(f"[bold]{org.get('name', 'Unknown')}[/bold]")
    console.print(f"  Project:  {project.get('name', 'Unknown')}")
    console.print(f"  Plan:     {info.get('plan', 'free')}")
    console.print()
    return 0
