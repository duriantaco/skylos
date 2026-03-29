from rich.console import Console

from skylos.login import run_login


def run_login_command() -> int:
    console = Console()
    result = run_login(console=console)
    if result:
        return 0
    return 1
