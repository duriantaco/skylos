from rich.console import Console
from rich.panel import Panel


BADGE_MARKDOWN = "[![Analyzed with Skylos](https://img.shields.io/badge/Analyzed%20with-Skylos-2f80ed?style=flat&logo=python&logoColor=white)](https://github.com/duriantaco/skylos)"


def run_badge_command() -> int:
    console = Console()

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Add this badge to your README.md:[/bold cyan]\n\n"
            f"[yellow]{BADGE_MARKDOWN}[/yellow]\n\n"
            "[dim]Shows others you maintain clean, secure code with Skylos![/dim]\n\n"
            "[bold]Preview:[/bold]\n"
            "[![Analyzed with Skylos](2f80ed badge)](github.com/duriantaco/skylos)",
            title="[cyan]📛 Skylos Badge[/cyan]",
            border_style="cyan",
        )
    )
    console.print()
    console.print(
        "[dim]💡 Tip: Add this near your other badges at the top of README.md[/dim]"
    )
    console.print(
        "[dim]📢 Share your project: https://github.com/duriantaco/skylos#projects-using-skylos[/dim]"
    )
    console.print()

    try:
        import pyperclip

        pyperclip.copy(BADGE_MARKDOWN)
        console.print("[good]✅ Badge markdown copied to clipboard![/good]")
    except ImportError:
        console.print(
            "[muted]💡 Install pyperclip for auto-copy: pip install pyperclip[/muted]"
        )
    except Exception:
        pass

    return 0
