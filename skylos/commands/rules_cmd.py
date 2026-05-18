from __future__ import annotations

import argparse
import json
import stat
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from skylos.rules.catalog import get_rule_catalog

MAX_RULE_PACK_BYTES = 1_000_000


def run_rules_command(argv, *, console_factory=Console) -> int:
    console = console_factory()
    rules_dir = Path.home() / ".skylos" / "rules"

    rules_parser = argparse.ArgumentParser(
        prog="skylos rules", description="Manage community rules for Skylos"
    )
    rules_sub = rules_parser.add_subparsers(dest="rules_cmd")

    p_install = rules_sub.add_parser("install", help="Install a rule pack or YAML URL")
    p_install.add_argument("pack_or_url", help="Pack name or URL to a .yml/.yaml file")

    p_list = rules_sub.add_parser("list", help="List built-in rules")
    p_list.add_argument(
        "terms",
        nargs="*",
        help="Optional rule search text, or 'json' for JSON output.",
    )
    p_list.add_argument("--json", action="store_true", help="Print rules as JSON")
    p_list.add_argument(
        "--packs",
        action="store_true",
        help="List installed community rule packs instead of built-in rules.",
    )

    p_remove = rules_sub.add_parser("remove", help="Remove an installed rule pack")
    p_remove.add_argument("name", help="Name of the rule pack to remove")

    p_validate = rules_sub.add_parser("validate", help="Validate a YAML rule file")
    p_validate.add_argument("path", help="Path to the YAML rule file")

    p_init = rules_sub.add_parser("init", help="Create a local starter rule pack")
    p_init.add_argument(
        "--path",
        default=".skylos/rules/local.yml",
        help="Path for the starter rule pack",
    )
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the rule pack if it already exists",
    )

    if not argv:
        rules_parser.print_help()
        return 0

    rules_args = rules_parser.parse_args(argv)

    if rules_args.rules_cmd == "install":
        return install_rules(console, rules_dir, rules_args.pack_or_url)
    if rules_args.rules_cmd == "list":
        list_terms = list(rules_args.terms or [])
        json_alias = False
        if not rules_args.json and list_terms and list_terms[-1].casefold() == "json":
            json_alias = True
            list_terms = list_terms[:-1]
        json_output = bool(rules_args.json or json_alias)
        query_terms = list_terms
        return list_rules(
            console,
            rules_dir,
            json_output=json_output,
            query=" ".join(query_terms),
            packs=bool(rules_args.packs),
        )
    if rules_args.rules_cmd == "remove":
        return remove_rules(console, rules_dir, rules_args.name)
    if rules_args.rules_cmd == "validate":
        return validate_rules(console, rules_args.path)
    if rules_args.rules_cmd == "init":
        return init_rules(console, rules_args.path, force=rules_args.force)

    rules_parser.print_help()
    return 0


def _resolve_local_rule_pack_path(path_str):
    root = Path.cwd().resolve()
    candidate = Path(path_str).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("Rule pack path must stay inside the current project") from exc

    return resolved


def init_rules(console, path_str, *, force=False):
    try:
        dest = _resolve_local_rule_pack_path(path_str)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1

    if dest.exists() and not force:
        console.print(
            f"[red]Rule pack already exists: {dest}. Use --force to overwrite.[/red]"
        )
        return 1

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(  # skylos: ignore[SKY-D215] validated by _resolve_local_rule_pack_path
        _starter_rule_pack().strip() + "\n",
        encoding="utf-8",
    )
    console.print(f"[green]Created starter rule pack: {dest}[/green]")
    console.print(f"[dim]Validate it with: skylos rules validate {dest}[/dim]")
    return 0


def _starter_rule_pack():
    return """
rules:
  - id: CUSTOM-VIBE-001
    name: Dynamic SQL built from request data
    severity: HIGH
    category: security
    message: Request data flows into a SQL execution sink. Use parameterized queries.
    pattern:
      type: taint_flow
      sources:
        - request.args
        - request.form
        - request.json
      sinks:
        - execute
        - raw
      sanitizers:
        - escape_sql
        - parameterize

  - id: CUSTOM-VIBE-002
    name: Route missing auth decorator
    severity: MEDIUM
    category: security
    message: Route handler has a route decorator but no auth decorator.
    pattern:
      type: function
      decorators:
        has_any:
          - route
        must_also_have_any:
          - login_required
          - require_auth
          - jwt_required
"""


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


def list_rules(console, rules_dir, *, json_output=False, query="", packs=False):
    if packs:
        return list_rule_packs(console, rules_dir, json_output=json_output)

    payload = _collect_builtin_rule_metadata(query)
    if json_output:
        _write_json(console, payload)
        return 0

    rules = payload["rules"]
    if not rules:
        console.print("[dim]No built-in rules matched.[/dim]")
        return 0

    table = Table(title="Built-in Rules")
    table.add_column("Rule", style="bold")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Severity")

    for rule in rules:
        table.add_row(
            Text(_safe_terminal_text(rule.get("id", ""))),
            Text(_safe_terminal_text(rule.get("name", ""))),
            Text(_safe_terminal_text(rule.get("category", ""))),
            Text(_safe_terminal_text(rule.get("severity") or "-")),
        )

    console.print(table)
    return 0


def list_rule_packs(console, rules_dir, *, json_output=False):
    try:
        import yaml
    except ImportError:
        console.print("[red]PyYAML is required. Install with: pip install pyyaml[/red]")
        return 1

    payload = _collect_rule_pack_metadata(rules_dir, yaml)
    if json_output:
        _write_json(console, payload)
        return 0

    if not rules_dir.exists():
        console.print("[dim]No community rules installed.[/dim]")
        console.print("Run [bold]skylos rules install <pack>[/bold] to get started.")
        return 0

    if not payload["packs"]:
        console.print("[dim]No community rules installed.[/dim]")
        console.print("Run [bold]skylos rules install <pack>[/bold] to get started.")
        return 0

    table = Table(title="Installed Community Rules")
    table.add_column("Pack", style="bold")
    table.add_column("Rules", justify="right")
    table.add_column("Status")
    table.add_column("Source")

    for pack in payload["packs"]:
        rule_count = pack.get("rules")
        table.add_row(
            Text(_safe_terminal_text(pack.get("name", ""))),
            Text("?" if rule_count is None else str(rule_count)),
            Text(_safe_terminal_text(pack.get("status", ""))),
            Text(_safe_terminal_text(pack.get("path", ""))),
        )

    console.print(table)
    return 0


def _collect_builtin_rule_metadata(query=""):
    safe_query = _safe_query(query)
    rules = get_rule_catalog(safe_query)
    return {
        "query": safe_query,
        "rules": rules,
        "source": "builtin",
        "total_rules": len(rules),
    }


def _safe_query(query) -> str:
    text = " ".join(str(query or "").split())
    return text[:200]


def _collect_rule_pack_metadata(rules_dir, yaml_module):
    payload = {
        "rules_dir": str(rules_dir),
        "packs": [],
        "total_packs": 0,
        "total_rules": 0,
    }
    try:
        root = Path(rules_dir).resolve(strict=True)
    except FileNotFoundError:
        return payload
    except OSError as exc:
        payload["error"] = str(exc)
        return payload

    try:
        entries = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        payload["error"] = str(exc)
        return payload

    for path in entries:
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        pack = _inspect_rule_pack(path, root, yaml_module)
        payload["packs"].append(pack)
        if pack["status"] == "ok":
            payload["total_packs"] += 1
            payload["total_rules"] += int(pack.get("rules") or 0)

    return payload


def _inspect_rule_pack(path, rules_root, yaml_module):
    pack = {
        "name": path.stem,
        "path": str(path),
        "rules": None,
        "status": "ok",
    }

    try:
        file_stat = path.lstat()
    except OSError as exc:
        pack["status"] = "read_error"
        pack["error"] = str(exc)
        return pack

    if path.is_symlink():
        pack["status"] = "skipped_symlink"
        return pack

    try:
        path.resolve(strict=True).relative_to(rules_root)
    except (OSError, ValueError):
        pack["status"] = "skipped_unsafe_path"
        return pack

    if not stat.S_ISREG(file_stat.st_mode):
        pack["status"] = "skipped_non_file"
        return pack

    if file_stat.st_size > MAX_RULE_PACK_BYTES:
        pack["status"] = "skipped_too_large"
        pack["bytes"] = file_stat.st_size
        return pack

    try:
        data = yaml_module.safe_load(path.read_text(encoding="utf-8"))
    except yaml_module.YAMLError as exc:
        pack["status"] = "invalid_yaml"
        pack["error"] = str(exc)
        return pack
    except (OSError, UnicodeDecodeError) as exc:
        pack["status"] = "read_error"
        pack["error"] = str(exc)
        return pack

    rules = data.get("rules", []) if isinstance(data, dict) else []
    if not isinstance(rules, list):
        pack["status"] = "invalid_rules"
        pack["error"] = "rules must be a list"
        return pack

    pack["rules"] = sum(1 for rule in rules if isinstance(rule, dict))
    return pack


def _write_json(console, payload):
    output = json.dumps(payload, sort_keys=True) + "\n"
    stream = getattr(console, "file", None)
    if stream is not None and hasattr(stream, "write"):
        stream.write(output)
        stream.flush()
    else:
        console.print(output, markup=False, end="")


def _safe_terminal_text(value) -> str:
    text = str(value)
    return "".join(
        ch if (ch >= " " and ch != "\x7f") else f"\\x{ord(ch):02x}" for ch in text
    )


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
