from rich.console import Console

from skylos.cloud.login import run_login


def run_login_command() -> int:
    console = Console()
    result = run_login(console=console)
    if result:
        # Pick up the organization's agent guardrail policy right away so the
        # hooks don't wait for their background refresh.
        from skylos.commands.guardrails_cmd import refresh_quietly

        from rich.markup import escape

        refresh_quietly(print_func=lambda line: console.print(escape(line)))
        return 0
    return 1
