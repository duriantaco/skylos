import re
from pathlib import Path

from rich.console import Console

from skylos.config import load_config


def run_whitelist(pattern=None, reason=None, show=False):
    console = Console()
    path = Path("pyproject.toml")

    if not path.exists():
        console.print("[bad]No pyproject.toml found. Run 'skylos init' first.[/bad]")
        return

    cfg = load_config(path)

    if show:
        console.print("[bold]Current whitelist:[/bold]\n")

        names = cfg.get("whitelist", [])
        if names:
            console.print("[dim]names:[/dim]")
            for name in names:
                console.print(f"  • {name}")

        documented = cfg.get("whitelist_documented", {})
        if documented:
            console.print("\n[dim]documented:[/dim]")
            for name, rule_reason in documented.items():
                console.print(f"  • {name} → {rule_reason}")

        temporary = cfg.get("whitelist_temporary", {})
        if temporary:
            console.print("\n[dim]temporary:[/dim]")
            for name, conf in temporary.items():
                rule_reason = conf.get("reason", "")
                expires = conf.get("expires", "")
                console.print(f"  • {name} → {rule_reason} (expires: {expires})")

        if not any([names, documented, temporary]):
            console.print("[muted]No whitelist entries yet.[/muted]")
        return

    if not pattern:
        console.print("[warn]Usage: skylos whitelist <pattern> [--reason 'why'][/warn]")
        console.print("\nExamples:")
        console.print("  skylos whitelist 'handle_*'")
        console.print("  skylos whitelist dark_logic --reason 'Called via globals()'")
        console.print("  skylos whitelist --show")
        return

    content = path.read_text(encoding="utf-8")

    if reason:
        if "[tool.skylos.whitelist.documented]" in content:
            content = re.sub(
                r"(\[tool\.skylos\.whitelist\.documented\])",
                f'\\1\n"{pattern}" = "{reason}"',
                content,
            )
        else:
            content += (
                f'\n[tool.skylos.whitelist.documented]\n"{pattern}" = "{reason}"\n'
            )
        console.print(f"[good]✓ Added '{pattern}' to whitelist.documented[/good]")
    else:
        match = re.search(
            r"(\[tool\.skylos\.whitelist\][^\[]*?)(names\s*=\s*\[)", content, re.DOTALL
        )
        if match:
            end = match.end(2)
            content = content[:end] + f'\n    "{pattern}",' + content[end:]
        elif "[tool.skylos.whitelist]" in content:
            content = re.sub(
                r"(\[tool\.skylos\.whitelist\])",
                f'\\1\nnames = [\n    "{pattern}",\n]',
                content,
            )
        else:
            content += f'\n[tool.skylos.whitelist]\nnames = [\n    "{pattern}",\n]\n'
        console.print(f"[good]✓ Added '{pattern}' to whitelist.names[/good]")

    path.write_text(content, encoding="utf-8")
    console.print("[muted]Run 'skylos whitelist --show' to see all entries[/muted]")


def run_whitelist_command(argv: list[str]) -> int:
    pattern = None
    reason = None
    show = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("--show", "-s"):
            show = True
        elif arg in ("--reason", "-r") and i + 1 < len(argv):
            reason = argv[i + 1]
            i += 1
        elif not arg.startswith("-"):
            pattern = arg
        i += 1

    run_whitelist(pattern=pattern, reason=reason, show=show)
    return 0
