
import sys


STEPS = [
    {
        "title": "Welcome to Skylos",
        "step": 1,
        "body": (
            "[bold]Skylos[/bold] finds dead code, security vulnerabilities, and quality\n"
            "issues in [bold cyan]Python[/bold cyan], [bold cyan]TypeScript[/bold cyan], and [bold cyan]Go[/bold cyan] codebases.\n"
            "\n"
            "It combines static analysis with optional LLM verification\n"
            "for results that match human-level accuracy."
        ),
    },
    {
        "title": "Quick Scan",
        "step": 2,
        "body": (
            "[bold]Basic scan[/bold] (dead code only):\n"
            "  [bold cyan]skylos .[/bold cyan]\n"
            "\n"
            "[bold]Full scan[/bold] (dead code + security + secrets + quality):\n"
            "  [bold cyan]skylos . -a[/bold cyan]\n"
            "\n"
            "[bold]Scan specific paths[/bold]:\n"
            "  [bold cyan]skylos src/ lib/[/bold cyan]\n"
            "\n"
            "[dim]Output formats: --json, --sarif, --tree, --tui[/dim]"
        ),
    },
    {
        "title": "AI Agent",
        "step": 3,
        "body": (
            "[bold]LLM-verified dead code[/bold] (100% accuracy on benchmarks):\n"
            "  [bold cyan]skylos agent verify .[/bold cyan]\n"
            "\n"
            "[bold]Auto-fix and create PR[/bold]:\n"
            "  [bold cyan]skylos agent remediate .[/bold cyan]\n"
            "\n"
            "[bold]Hybrid static + LLM scan[/bold]:\n"
            "  [bold cyan]skylos agent scan .[/bold cyan]\n"
            "\n"
            "[dim]Requires an API key: skylos key[/dim]"
        ),
    },
    {
        "title": "AI Defense",
        "step": 4,
        "body": (
            "[bold]Map LLM integrations[/bold] in your codebase:\n"
            "  [bold cyan]skylos discover .[/bold cyan]\n"
            "\n"
            "[bold]Check for missing defenses[/bold] (OWASP LLM Top 10):\n"
            "  [bold cyan]skylos defend .[/bold cyan]\n"
            "\n"
            "Detects prompt injection risks, missing PII filters,\n"
            "RAG isolation gaps, rate limiting, and more."
        ),
    },
    {
        "title": "CI/CD Integration",
        "step": 5,
        "body": (
            "[bold]Generate GitHub Actions workflow[/bold] (30-second setup):\n"
            "  [bold cyan]skylos cicd init[/bold cyan]\n"
            "\n"
            "[bold]Quality gate[/bold] (fail CI on findings):\n"
            "  [bold cyan]skylos cicd gate[/bold cyan]\n"
            "\n"
            "[bold]Post inline PR comments[/bold] with LLM-generated fixes:\n"
            "  [bold cyan]skylos cicd review[/bold cyan]"
        ),
    },
    {
        "title": "What's Next",
        "step": 6,
        "body": (
            "[bold]See all commands:[/bold]\n"
            "  [bold cyan]skylos commands[/bold cyan]\n"
            "\n"
            "[bold]Get help on any command:[/bold]\n"
            "  [bold cyan]skylos <command> --help[/bold cyan]\n"
            "\n"
            "[bold]Connect to Skylos Cloud:[/bold]\n"
            "  [bold cyan]skylos login[/bold cyan]\n"
            "\n"
            "[bold]Docs:[/bold] [blue]github.com/duriantaco/skylos[/blue]"
        ),
    },
]

TOTAL_STEPS = len(STEPS)


def run_tour(console):
    from rich.panel import Panel

    is_tty = sys.stdin.isatty()

    for i, step in enumerate(STEPS):
        title = f"[bold cyan][{step['step']}/{TOTAL_STEPS}] {step['title']}[/bold cyan]"

        console.print()
        console.print(Panel(
            step["body"],
            title=title,
            border_style="cyan",
            padding=(1, 2),
        ))

        if is_tty and i < len(STEPS) - 1:
            try:
                input("\n  Press Enter to continue...")
            except (EOFError, KeyboardInterrupt):
                console.print()
                return

    console.print()
    console.print("  [bold green]Tour complete![/bold green] Run [bold]skylos .[/bold] to start scanning.")
    console.print()
