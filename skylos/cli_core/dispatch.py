from __future__ import annotations

from collections.abc import Callable, Mapping

from rich.console import Console
from rich.markup import escape


EARLY_COMMAND_HANDLERS = {
    "commands": "_run_commands_command",
    "tour": "_run_tour_command",
    "key": "_run_key_command",
    "credits": "_run_credits_command",
    "baseline": "_run_baseline_command",
    "sbom": "_run_sbom_command",
    "init": "_run_init_command",
    "badge": "_run_badge_command",
    "whitelist": "_run_whitelist_command",
    "clean": "_run_clean_command",
    "lint": "_run_lint_command",
    "cache": "_run_cache_command",
    "contract": "_handle_contract_command",
    "doctor": "_run_doctor_command",
    "whoami": "_run_whoami_command",
    "login": "_run_login_command",
    "sync": "_run_sync_command",
    "project": "_run_project_command",
    "sonar": "_run_sonar_command",
    "compare": "_run_compare_command",
    "city": "_run_removed_city_command",
    "suite": "run_suite_command",
    "verify": "_run_verify_command",
    "preflight": "_run_preflight_command",
    "review": "_run_review_command",
    "discover": "_run_discover_command",
    "defend": "run_defend_command",
    "debt": "run_debt_command",
    "ingest": "run_ingest_command",
    "image": "_run_image_command",
    "provenance": "run_provenance_command",
    "rules": "_handle_rules_command",
    "cicd": "run_cicd_command",
}

# These commands own enough flags and execution semantics that their argparse
# help is the source of truth. Parsing --help exits before target analysis,
# artifact inspection, scanner execution, uploads, or file edits can start.
NATIVE_HELP_COMMANDS = frozenset(
    {"clean", "defend", "image", "preflight", "suite", "verify"}
)


def is_first_level_help_request(argv) -> bool:
    return len(argv) == 2 and argv[1] in {"-h", "--help"}


def run_early_command_help(
    command: str,
    *,
    console_factory: Callable[[], Console] = Console,
) -> int:
    from skylos.ui.help import COMMANDS
    from rich.padding import Padding

    console = console_factory()
    matches = [
        item
        for item in COMMANDS
        if item.get("name", "").split()[:2] == ["skylos", command]
    ]
    if not matches:
        console.print(
            f"[bold]Usage:[/bold] {escape(f'skylos {command} [options]')}"
        )
        console.print("\nRun [bold]skylos commands[/bold] for all commands.")
        return 0

    console.print("[bold]Usage:[/bold]")
    for item in matches:
        console.print(Padding(escape(item["name"]), (0, 0, 0, 2)))

    console.print("\n[bold]Description:[/bold]")
    for item in matches:
        console.print(Padding(escape(item["desc"]), (0, 0, 0, 2)))

    detail_lines = []
    for item in matches:
        for detail in item.get("details", []):
            detail_lines.append(detail)
    if detail_lines:
        console.print("\n[bold]Details:[/bold]")
        for detail in detail_lines:
            console.print(Padding(f"• {escape(detail)}", (0, 0, 0, 2)))

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

    if len(argv) == 1 and argv[0] in {"-h", "--help"}:
        return namespace["_run_command_overview"]([])

    handler_name = EARLY_COMMAND_HANDLERS.get(argv[0])
    if handler_name is None:
        return None

    if is_first_level_help_request(argv):
        if argv[0] in NATIVE_HELP_COMMANDS:
            # ``image`` has one operation. Show its actionable scan flags at
            # the family-level help entry instead of stopping at a one-row
            # subcommand list.
            help_argv = ["scan", argv[1]] if argv[0] == "image" else argv[1:]
            return namespace[handler_name](help_argv)
        return run_early_command_help(argv[0], console_factory=console_factory)

    return namespace[handler_name](argv[1:])
