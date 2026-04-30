from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table


def run_rules_command(argv, *, console_factory=Console) -> int:
    console = console_factory()
    rules_dir = Path.home() / ".skylos" / "rules"

    rules_parser = argparse.ArgumentParser(
        prog="skylos rules", description="Manage community rules for Skylos"
    )
    rules_sub = rules_parser.add_subparsers(dest="rules_cmd")

    p_install = rules_sub.add_parser("install", help="Install a rule pack or YAML URL")
    p_install.add_argument("pack_or_url", help="Pack name or URL to a .yml/.yaml file")

    rules_sub.add_parser("list", help="List installed community rules")

    p_remove = rules_sub.add_parser("remove", help="Remove an installed rule pack")
    p_remove.add_argument("name", help="Name of the rule pack to remove")

    p_validate = rules_sub.add_parser("validate", help="Validate a YAML rule file")
    p_validate.add_argument("path", help="Path to the YAML rule file")

    if not argv:
        rules_parser.print_help()
        return 0

    rules_args = rules_parser.parse_args(argv)

    if rules_args.rules_cmd == "install":
        return install_rules(console, rules_dir, rules_args.pack_or_url)
    if rules_args.rules_cmd == "list":
        return list_rules(console, rules_dir)
    if rules_args.rules_cmd == "remove":
        return remove_rules(console, rules_dir, rules_args.name)
    if rules_args.rules_cmd == "validate":
        return validate_rules(console, rules_args.path)

    rules_parser.print_help()
    return 0


def install_rules(console, rules_dir, pack_or_url):
    import urllib.error
    import urllib.request

    try:
        import yaml
    except ImportError:
        console.print("[red]PyYAML is required. Install with: pip install pyyaml[/red]")
        return 1

    rules_dir.mkdir(parents=True, exist_ok=True)

    if pack_or_url.startswith("http://") or pack_or_url.startswith("https://"):
        url = pack_or_url
        name = Path(url).stem
    else:
        name = pack_or_url
        url = f"https://raw.githubusercontent.com/duriantaco/skylos-rules/main/packs/{name}.yml"

    dest = rules_dir / f"{name}.yml"

    console.print(f"[bold]Installing rule pack:[/bold] {name}")
    console.print(f"[dim]Source: {url}[/dim]")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "skylos-cli"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        console.print(f"[red]Download failed: HTTP {e.code}[/red]")
        return 1
    except Exception as e:
        console.print(f"[red]Download failed: {e}[/red]")
        return 1

    try:
        data = yaml.safe_load(content)
        if not data or "rules" not in data:
            console.print("[red]Invalid rule file: missing 'rules' key[/red]")
            return 1
        rule_count = len(data["rules"])
    except yaml.YAMLError as e:
        console.print(f"[red]Invalid YAML: {e}[/red]")
        return 1

    dest.write_text(content)
    console.print(f"[green]Installed {rule_count} rule(s) to {dest}[/green]")
    return 0


def list_rules(console, rules_dir):
    try:
        import yaml
    except ImportError:
        console.print("[red]PyYAML is required. Install with: pip install pyyaml[/red]")
        return 1

    if not rules_dir.exists():
        console.print("[dim]No community rules installed.[/dim]")
        console.print("Run [bold]skylos rules install <pack>[/bold] to get started.")
        return 0

    yml_files = sorted(rules_dir.glob("*.yml"))
    if not yml_files:
        console.print("[dim]No community rules installed.[/dim]")
        console.print("Run [bold]skylos rules install <pack>[/bold] to get started.")
        return 0

    table = Table(title="Installed Community Rules")
    table.add_column("Pack", style="bold")
    table.add_column("Rules", justify="right")
    table.add_column("Source")

    for f in yml_files:
        try:
            data = yaml.safe_load(f.read_text())
            rule_count = len(data.get("rules", [])) if data else 0
            table.add_row(f.stem, str(rule_count), str(f))
        except Exception:
            table.add_row(f.stem, "?", str(f))

    console.print(table)
    return 0


def remove_rules(console, rules_dir, name):
    dest = rules_dir / f"{name}.yml"
    if not dest.exists():
        console.print(f"[red]Rule pack '{name}' not found.[/red]")
        return 1

    dest.unlink()
    console.print(f"[green]Removed rule pack '{name}'[/green]")
    return 0


def validate_rules(console, path_str):
    try:
        import yaml
    except ImportError:
        console.print("[red]PyYAML is required. Install with: pip install pyyaml[/red]")
        return 1

    rule_path = Path(path_str)
    if not rule_path.exists():
        console.print(f"[red]File not found: {path_str}[/red]")
        return 1

    try:
        data = yaml.safe_load(rule_path.read_text())
    except yaml.YAMLError as e:
        console.print(f"[red]YAML parse error: {e}[/red]")
        return 1

    if not data or not isinstance(data, dict):
        console.print("[red]Invalid rule file: not a YAML mapping[/red]")
        return 1

    if "rules" not in data:
        console.print("[red]Invalid rule file: missing 'rules' key[/red]")
        return 1

    errors = []
    warnings = []
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    valid_pattern_types = {"function", "class", "call", "taint_flow"}

    for i, rule in enumerate(data["rules"]):
        prefix = f"Rule #{i + 1}"
        if not isinstance(rule, dict):
            errors.append(f"{prefix}: not a mapping")
            continue

        if "id" not in rule:
            errors.append(f"{prefix}: missing required field 'id'")
        if "name" not in rule:
            errors.append(f"{prefix}: missing required field 'name'")
        if "severity" not in rule:
            errors.append(f"{prefix}: missing required field 'severity'")
        elif rule["severity"] not in valid_severities:
            warnings.append(
                f"{prefix} ({rule.get('id', '?')}): severity '{rule['severity']}' "
                f"not in {valid_severities}"
            )

        pattern = rule.get("pattern")
        if not pattern:
            errors.append(f"{prefix} ({rule.get('id', '?')}): missing 'pattern'")
        elif not isinstance(pattern, dict):
            errors.append(
                f"{prefix} ({rule.get('id', '?')}): 'pattern' must be a mapping"
            )
        elif "type" not in pattern:
            errors.append(f"{prefix} ({rule.get('id', '?')}): missing 'pattern.type'")
        elif pattern["type"] not in valid_pattern_types:
            warnings.append(
                f"{prefix} ({rule.get('id', '?')}): unknown pattern type '{pattern['type']}'"
            )

        if (
            pattern
            and isinstance(pattern, dict)
            and pattern.get("type") == "taint_flow"
        ):
            if not pattern.get("sources"):
                errors.append(
                    f"{prefix} ({rule.get('id', '?')}): taint_flow requires 'sources'"
                )
            if not pattern.get("sinks"):
                errors.append(
                    f"{prefix} ({rule.get('id', '?')}): taint_flow requires 'sinks'"
                )

    if errors:
        console.print(f"[red]Validation failed with {len(errors)} error(s):[/red]")
        for err in errors:
            console.print(f"  [red]- {err}[/red]")
    if warnings:
        console.print(f"[yellow]{len(warnings)} warning(s):[/yellow]")
        for w in warnings:
            console.print(f"  [yellow]- {w}[/yellow]")
    if not errors:
        rule_count = len(data["rules"])
        console.print(f"[green]Valid: {rule_count} rule(s) in {rule_path.name}[/green]")
        return 0

    return 1
