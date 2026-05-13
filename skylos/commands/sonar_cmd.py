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
        help="Write mapped Skylos config to .skylos/config.yaml next to the Sonar properties file.",
    )
    import_parser.add_argument(
        "--config-output",
        default=None,
        help="Override the Skylos config output path used with --write-config.",
    )

    args = parser.parse_args(argv)
    if args.command != "import":
        parser.print_help()
        return 2

    from skylos.integrations.sonar import (
        build_sonar_migration_plan,
        format_migration_plan_json,
        parse_sonar_properties,
        write_skylos_yaml_config,
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
        console.print(report_json)

    if args.write_config:
        config_path = (
            Path(args.config_output).resolve()
            if args.config_output
            else properties_path.parent / ".skylos" / "config.yaml"
        )
        write_skylos_yaml_config(config_path, plan["skylos"]["config"])
        console.print(f"[green]Skylos config written:[/green] {config_path}")

    return 0

