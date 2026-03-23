import skylos

COMMANDS = [
    {"name": "skylos <path>", "desc": "Dead code, security, and quality analysis", "group": "Core Analysis"},
    {"name": "skylos discover <path>", "desc": "Map LLM/AI integrations in your codebase", "group": "Core Analysis"},
    {"name": "skylos defend <path>", "desc": "Check LLM integrations for missing defenses", "group": "Core Analysis"},
    {"name": "skylos city <path>", "desc": "Visualize codebase as a Code City topology", "group": "Core Analysis"},

    {"name": "skylos agent scan <path>", "desc": "Hybrid static + LLM analysis", "group": "AI Agent"},
    {"name": "skylos agent verify <path>", "desc": "LLM-verify dead code (100% accuracy)", "group": "AI Agent"},
    {"name": "skylos agent remediate <path>", "desc": "Auto-fix issues and create PR", "group": "AI Agent"},
    {"name": "skylos agent watch <path>", "desc": "Continuous repo monitoring", "group": "AI Agent"},
    {"name": "skylos agent pre-commit <path>", "desc": "Analyze staged files (git hook)", "group": "AI Agent"},
    {"name": "skylos agent triage", "desc": "Manage finding triage (dismiss/snooze)", "group": "AI Agent"},

    {"name": "skylos cicd init", "desc": "Generate GitHub Actions workflow", "group": "CI/CD"},
    {"name": "skylos cicd gate", "desc": "Quality gate (CI exit code)", "group": "CI/CD"},
    {"name": "skylos cicd annotate", "desc": "Emit GitHub Actions annotations", "group": "CI/CD"},
    {"name": "skylos cicd review", "desc": "Post inline PR review comments", "group": "CI/CD"},

    {"name": "skylos login", "desc": "Connect to Skylos Cloud", "group": "Account"},
    {"name": "skylos whoami", "desc": "Show connected account info", "group": "Account"},
    {"name": "skylos key", "desc": "Manage API keys", "group": "Account"},
    {"name": "skylos credits", "desc": "Check credit balance", "group": "Account"},

    {"name": "skylos init", "desc": "Initialize config in pyproject.toml", "group": "Utility"},
    {"name": "skylos baseline <path>", "desc": "Save current findings as baseline", "group": "Utility"},
    {"name": "skylos whitelist <pattern>", "desc": "Manage whitelisted symbols", "group": "Utility"},
    {"name": "skylos badge", "desc": "Get badge markdown for README", "group": "Utility"},
    {"name": "skylos rules", "desc": "Install/manage community rule packs", "group": "Utility"},
    {"name": "skylos doctor", "desc": "Check installation health", "group": "Utility"},
    {"name": "skylos clean", "desc": "Remove cache and state files", "group": "Utility"},
    {"name": "skylos sync", "desc": "Sync config with Skylos Cloud", "group": "Utility"},
    {"name": "skylos ingest", "desc": "Ingest findings from external tools", "group": "Utility"},
    {"name": "skylos provenance", "desc": "Detect AI-authored code in PR changes", "group": "Utility"},
    {"name": "skylos run", "desc": "Start local web dashboard server", "group": "Utility"},
    {"name": "skylos commands", "desc": "List all commands (flat)", "group": "Utility"},
    {"name": "skylos tour", "desc": "Guided tour of capabilities", "group": "Utility"},
]

# NOTE: MUST UPDATE this list when adding new commands to cli.py

BANNER = (
    "[bold cyan]"
    " ███████ ██   ██ ██    ██ ██       ██████  ███████\n"
    " ██      ██  ██   ██  ██  ██      ██    ██ ██     \n"
    " ███████ █████     ████   ██      ██    ██ ███████\n"
    "      ██ ██  ██     ██    ██      ██    ██      ██\n"
    " ███████ ██   ██    ██    ███████  ██████  ███████"
    "[/bold cyan]"
)


def print_command_overview(console):
    from rich.panel import Panel

    lines = [
        BANNER,
        "",
        f"  [bold white]v{skylos.__version__}[/bold white]"
        "  [dim]|[/dim]  [blue]github.com/duriantaco/skylos[/blue]",
        "",
    ]

    groups = []
    seen = set()
    for cmd in COMMANDS:
        g = cmd["group"]
        if g not in seen:
            groups.append(g)
            seen.add(g)

    name_width = max(len(cmd["name"]) for cmd in COMMANDS) + 2

    for group in groups:
        lines.append(f"  [bold yellow]{group}[/bold yellow]")
        for cmd in COMMANDS:
            if cmd["group"] == group:
                padded = cmd["name"].ljust(name_width)
                lines.append(f"    [bold]{padded}[/bold][dim]{cmd['desc']}[/dim]")
        lines.append("")

    lines.append("  [dim]Run[/dim] [bold]skylos <command> --help[/bold] [dim]for details[/dim]")

    console.print(Panel(
        "\n".join(lines),
        border_style="cyan",
        padding=(1, 2),
    ))


def print_flat_commands(console):
    from rich.table import Table

    table = Table(
        title="[bold cyan]All Skylos Commands[/bold cyan]",
        show_header=True,
        header_style="bold",
        border_style="dim",
        pad_edge=True,
    )
    table.add_column("Command", style="bold")
    table.add_column("Description", style="dim")
    table.add_column("Group", style="yellow")

    for cmd in sorted(COMMANDS, key=lambda c: c["name"]):
        table.add_row(cmd["name"], cmd["desc"], cmd["group"])

    console.print()
    console.print(table)
    console.print()
