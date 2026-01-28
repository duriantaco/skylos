# skylos/commands/key_cmd.py
import os

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from skylos.credentials import PROVIDERS, get_key, save_key, delete_key


def run_key_command(argv):
    console = Console()

    subcommand = ""
    if argv and len(argv) > 0:
        subcommand = str(argv[0]).strip().lower()

    if subcommand == "" or subcommand == "menu":
        return _menu(console)

    if subcommand == "list" or subcommand == "ls":
        _render_key_list(console)
        return 0

    if subcommand == "add" or subcommand == "set":
        provider = ""
        if len(argv) > 1:
            provider = str(argv[1]).strip().lower()
        return _add_key(console, provider)

    if subcommand == "remove" or subcommand == "rm" or subcommand == "delete" or subcommand == "del":
        provider = ""
        if len(argv) > 1:
            provider = str(argv[1]).strip().lower()
        return _remove_key(console, provider)

    console.print("[red]Unknown subcommand:[/red] " + subcommand)
    console.print("[dim]Usage: skylos key [list|add|remove][/dim]")
    return 2


def _sorted_providers():
    keys = list(PROVIDERS.keys())
    keys.sort()
    return keys


def _get_env_var(provider):
    if not provider:
        return None
    return PROVIDERS.get(provider)


def _is_env_set(env_var):
    if not env_var:
        return False
    value = os.getenv(env_var)
    if value:
        return True
    return False


def _has_keyring_key(provider):
    value = get_key(provider)
    if value:
        return True
    return False


def _render_key_list(console):
    table = Table(title="Skylos API Keys", expand=True)
    table.add_column("Provider", style="bold")
    table.add_column("Env Var", style="dim")
    table.add_column("Status")

    providers = _sorted_providers()
    for provider in providers:
        env_var = _get_env_var(provider)

        if provider == "ollama":
            status = "[dim]local (no key)[/dim]"
            table.add_row(provider, "-", status)
            continue

        if _is_env_set(env_var):
            status = "[green]set via env[/green]"
            table.add_row(provider, env_var or "-", status)
            continue

        if _has_keyring_key(provider):
            status = "[green]saved in keyring[/green]"
            table.add_row(provider, env_var or "-", status)
            continue

        status = "[yellow]missing[/yellow]"
        table.add_row(provider, env_var or "-", status)

    console.print(table)


def _menu(console):
    while True:
        console.print()
        console.print(Panel.fit("[bold]Skylos Login[/bold]\nManage your provider keys.", border_style="cyan"))
        console.print("1) List key status")
        console.print("2) Add / update a key")
        console.print("3) Remove a stored key")
        console.print("4) Exit")
        console.print()

        choice = input("Choose (1-4): ").strip()

        if choice == "1":
            _render_key_list(console)
            continue

        if choice == "2":
            provider = _prompt_provider(console, allow_ollama=False)
            if provider:
                _add_key(console, provider)
            continue

        if choice == "3":
            provider = _prompt_provider(console, allow_ollama=False)
            if provider:
                _remove_key(console, provider)
            continue

        if choice == "4":
            return 0

        console.print("[yellow]Invalid choice.[/yellow]")


def _prompt_provider(console, allow_ollama):
    providers = _sorted_providers()

    filtered = []
    for p in providers:
        if p == "ollama" and not allow_ollama:
            continue
        filtered.append(p)

    console.print()
    console.print("[bold]Providers:[/bold] " + ", ".join(filtered))
    provider = input("Provider: ").strip().lower()

    if provider == "":
        console.print("[yellow]No provider entered.[/yellow]")
        return None

    if provider not in filtered:
        console.print("[red]Unknown provider:[/red] " + provider)
        return None

    return provider


def _add_key(console, provider):
    if not provider:
        provider = _prompt_provider(console, allow_ollama=False)
        if not provider:
            return 1

    env_var = _get_env_var(provider)
    if not env_var:
        console.print("[red]Unknown provider:[/red] " + provider)
        return 1

    if _is_env_set(env_var):
        console.print("[yellow]" + env_var + " is set in your environment.[/yellow]")
        console.print("[dim]Unset it if you want Skylos to use the keyring instead.[/dim]")
        return 0

    console.print()
    key_value = input("Enter API key for " + provider + ": ").strip()

    if key_value == "":
        console.print("[yellow]No key entered. Cancelled.[/yellow]")
        return 1

    save_key(provider, key_value)
    console.print("[green]✓ Saved key for '" + provider + "' to system keyring.[/green]")
    return 0


def _remove_key(console, provider):
    if not provider:
        provider = _prompt_provider(console, allow_ollama=False)
        if not provider:
            return 1

    existing = get_key(provider)
    if not existing:
        console.print("[dim]No stored key found for '" + provider + "'.[/dim]")
        return 0

    confirm = input("Remove stored key for '" + provider + "'? (y/N): ").strip().lower()
    if confirm != "y":
        console.print("[dim]Cancelled.[/dim]")
        return 0

    removed = delete_key(provider)
    if removed:
        console.print("[green]✓ Removed stored key for '" + provider + "'.[/green]")
    else:
        console.print("[dim]Nothing to remove.[/dim]")
    return 0
