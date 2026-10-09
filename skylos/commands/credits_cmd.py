from rich.console import Console
from rich.markup import escape

from skylos.api import BASE_URL, get_project_token, print_credit_status

# Cloud stores the paid plan as "pro"; customers see it as "Workspace".
PLAN_DISPLAY_NAMES = {"free": "Free", "pro": "Workspace", "enterprise": "Enterprise"}


def run_credits_command() -> int:
    console = Console()
    token = get_project_token()
    if not token:
        console.print("[red]Not connected.[/red] Run [bold]skylos login[/bold] first.")
        return 1

    data = print_credit_status(token)
    if data is None:
        console.print("[red]Could not fetch credit balance.[/red]")
        return 1

    balance = data.get("balance", 0)
    plan = data.get("plan", "free")
    org_name = data.get("org_name", "")

    console.print()
    if org_name:
        plan_name = PLAN_DISPLAY_NAMES.get(plan, str(plan).title())
        console.print(f"[bold]{escape(str(org_name))}[/bold] ({escape(plan_name)} plan)")
    if plan == "enterprise":
        console.print("[green]Unlimited credits[/green]")
    else:
        console.print(f"Balance: [bold]{balance:,}[/bold] credits")

    recent = data.get("recent_transactions", [])
    if recent:
        console.print()
        console.print("[bold]Recent activity:[/bold]")
        for tx in recent[:5]:
            amt = tx.get("amount", 0)
            desc = tx.get("description", "")

            if amt > 0:
                sign = "+"
            else:
                sign = ""

            if amt > 0:
                color = "green"
            else:
                color = "red"

            console.print(f"  [{color}]{sign}{amt}[/{color}]  {desc}")

    if plan != "enterprise":
        console.print()
        console.print(
            f"Buy credits: [link={BASE_URL}/dashboard/billing]{BASE_URL}/dashboard/billing[/link]"
        )

    return 0
