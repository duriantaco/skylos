from __future__ import annotations

import argparse
from pathlib import Path


def run_sonar_command(argv: list[str], *, console_factory) -> int:
    parser = argparse.ArgumentParser(
        prog="skylos sonar",
        description="Migrate a SonarQube/SonarCloud project configuration into Skylos.",
    )
    subparsers = parser.add_subparsers(dest="command")

    import_parser = subparsers.add_parser(
        "import",
        help="Import sonar-project.properties and generate a Skylos migration plan.",
    )
    import_parser.add_argument(
        "properties_file",
        nargs="?",
        default="sonar-project.properties",
        help="Path to sonar-project.properties",
    )
    import_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write migration report JSON to this path.",
    )
    import_parser.add_argument(
        "--write-config",
        action="store_true",
        help=(
            "Write the mapped exclusions to a new skylos.toml next to the Sonar "
            "properties file. Existing Skylos settings are never changed."
        ),
    )
    import_parser.add_argument(
        "--config-output",
        default=None,
        help="Write the new .toml file here instead (used with --write-config).",
    )

    args = parser.parse_args(argv)
    if args.command != "import":
        parser.print_help()
        return 2

    from skylos.integrations.sonar import (
        build_sonar_migration_plan,
        format_migration_plan_json,
        parse_sonar_properties,
    )

    console = console_factory()
    properties_path = Path(args.properties_file).resolve()
    if not properties_path.exists() or not properties_path.is_file():
        console.print(f"[red]Sonar properties file not found: {properties_path}[/red]")
        return 1

    properties = parse_sonar_properties(properties_path)
    plan = build_sonar_migration_plan(properties)
    report_json = format_migration_plan_json(plan)

    if args.output:
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_json + "\n", encoding="utf-8")
        console.print(f"[green]Sonar migration report written:[/green] {output_path}")
    else:
        console.print(report_json, markup=False, highlight=False, soft_wrap=True)

    if args.write_config:
        return _write_local_config(console, args, properties_path, plan)

    return 0


def _write_local_config(console, args, properties_path, plan) -> int:
    from rich.markup import escape

    from skylos.config import CONFIG_FILE_NAMES
    from skylos.integrations.sonar import (
        existing_skylos_config,
        skylos_toml_text,
        write_skylos_toml_config,
    )

    if args.config_output:
        config_path = Path(args.config_output).resolve()
    else:
        config_path = properties_path.parent / "skylos.toml"
    if config_path.suffix != ".toml" or config_path.name == "pyproject.toml":
        console.print(
            "[red]--config-output must name a new .toml file such as skylos.toml.[/red]"
        )
        return 2

    blocker = None
    if config_path.exists() or config_path.is_symlink():
        blocker = config_path
    elif config_path.name in CONFIG_FILE_NAMES:
        blocker = existing_skylos_config(config_path.parent)
    if blocker is None:
        try:
            write_skylos_toml_config(config_path, plan["skylos"]["config"])
        except FileExistsError:
            blocker = config_path
        else:
            console.print(
                f"[green]Skylos config written:[/green] {escape(str(config_path))}"
            )
            return 0

    console.print(
        "[yellow]Not written: Skylos settings already apply here "
        f"({escape(str(blocker))}), and Skylos never changes them.[/yellow]",
        soft_wrap=True,
    )
    console.print(
        "Add this to [tool.skylos] in pyproject.toml, or at the top level of "
        "skylos.toml, merged with any exclude list you already have:",
        markup=False,
        soft_wrap=True,
    )
    console.print(skylos_toml_text(plan["skylos"]["config"]), markup=False, end="")
    return 1
