from __future__ import annotations

from collections.abc import Callable, Mapping

from rich.console import Console


EARLY_COMMAND_HANDLERS = {
    "commands": "_run_commands_command",
    "tour": "_run_tour_command",
    "key": "_run_key_command",
    "credits": "_run_credits_command",
    "baseline": "_run_baseline_command",
    "init": "_run_init_command",
    "badge": "_run_badge_command",
    "whitelist": "_run_whitelist_command",
    "clean": "_run_clean_command",
    "cache": "_run_cache_command",
    "doctor": "_run_doctor_command",
    "whoami": "_run_whoami_command",
    "login": "_run_login_command",
    "sync": "_run_sync_command",
    "project": "_run_project_command",
    "sonar": "_run_sonar_command",
    "city": "_run_removed_city_command",
    "suite": "run_suite_command",
    "verify": "_run_verify_command",
    "discover": "_run_discover_command",
    "defend": "run_defend_command",
    "debt": "run_debt_command",
    "ingest": "run_ingest_command",
    "provenance": "run_provenance_command",
    "rules": "_handle_rules_command",
    "cicd": "run_cicd_command",
}


def is_first_level_help_request(argv) -> bool:
    return len(argv) == 2 and argv[1] in {"-h", "--help"}


def run_early_command_help(
    command: str,
    *,
    console_factory: Callable[[], Console] = Console,
) -> int:
    from skylos.ui.help import COMMANDS

    console = console_factory()
    matches = [
        item
        for item in COMMANDS
        if item.get("name", "").split()[:2] == ["skylos", command]
    ]
    if not matches:
        console.print(f"[bold]Usage:[/bold] skylos {command} [options]")
        console.print("\nRun [bold]skylos commands[/bold] for all commands.")
        return 0

    console.print("[bold]Usage:[/bold]")
    for item in matches:
        console.print(f"  {item['name']}")

    console.print("\n[bold]Description:[/bold]")
    for item in matches:
        console.print(f"  {item['desc']}")

    console.print("\nRun [bold]skylos commands[/bold] for all commands.")
    return 0


def dispatch_early_command(
    argv,
    namespace: Mapping[str, Callable],
    *,
    console_factory: Callable[[], Console] = Console,
):
    if not argv:
        return namespace["_run_command_overview"]([])

    handler_name = EARLY_COMMAND_HANDLERS.get(argv[0])
    if handler_name is None:
        return None

    if is_first_level_help_request(argv):
        return run_early_command_help(argv[0], console_factory=console_factory)

    return namespace[handler_name](argv[1:])
