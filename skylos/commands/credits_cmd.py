import math

from rich.console import Console
from rich.markup import escape

from skylos.api import BASE_URL, get_project_token, print_credit_status
from skylos.cloud.plan_names import plan_display_name


def _is_credit_amount(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value))
    )


def run_credits_command() -> int:
    console = Console()
    token = get_project_token()
    if not token:
        console.print("[red]Not connected.[/red] Run [bold]skylos login[/bold] first.")
        return 1

    data = print_credit_status(token, quiet=True)
    if not isinstance(data, dict) or not data:
        console.print("[red]Could not fetch credit balance.[/red]")
        return 1

    balance = data.get("balance")
    plan = data.get("plan", "free")
    org_name = data.get("org_name", "")
    recent = data.get("recent_transactions", [])
    if recent is None:
        recent = []
    if (
        not _is_credit_amount(balance)
        or not isinstance(plan, str)
        or not isinstance(recent, list)
        or any(
            not isinstance(tx, dict) or not _is_credit_amount(tx.get("amount"))
            for tx in recent
        )
    ):
        console.print("[red]Could not fetch credit balance: invalid response.[/red]")
        return 1

    console.print()
    if org_name:
        plan_name = plan_display_name(plan)
        console.print(f"[bold]{escape(str(org_name))}[/bold] ({escape(plan_name)} plan)")
    if plan == "enterprise":
        console.print("[green]Unlimited credits[/green]")
    else:
        console.print(f"Balance: [bold]{balance:,}[/bold] credits")
        if balance < 10:
            console.print("[yellow]Low credits![/yellow]")

    if recent:
        console.print()
        console.print("[bold]Recent activity:[/bold]")
        for tx in recent[:5]:
            amt = tx.get("amount", 0)
            desc = escape(str(tx.get("description", "")))

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
