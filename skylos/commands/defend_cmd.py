import argparse
import json
from pathlib import Path

from rich.progress import SpinnerColumn, TextColumn

from skylos.defend.owasp import (
    DEFAULT_OWASP_FRAMEWORK,
    compute_owasp_coverage,
    normalize_owasp_selection,
    supported_owasp_frameworks,
    validate_owasp_ids,
)


def _build_empty_defense_json(
    *,
    owasp_framework: str = DEFAULT_OWASP_FRAMEWORK,
    owasp_version: str | int | None = None,
) -> str:
    owasp_framework, owasp_version = normalize_owasp_selection(
        owasp_framework,
        owasp_version,
    )
    return json.dumps(
        {
            "version": "1.0",
            "owasp_framework": owasp_framework,
            "owasp_version": owasp_version,
            "summary": {
                "integrations_found": 0,
                "total_checks": 0,
                "passed": 0,
                "failed": 0,
                "score_pct": 100,
                "risk_rating": "SECURE",
            },
            "findings": [],
            "owasp_coverage": compute_owasp_coverage(
                [],
                framework=owasp_framework,
                version=owasp_version,
            ),
            "ops_score": {
                "passed": 0,
                "total": 0,
                "score_pct": 100,
                "rating": "EXCELLENT",
            },
        },
        indent=2,
    )


def run_defend_command(
    argv: list[str],
    *,
    console_factory,
    progress_factory,
) -> int:
    def_parser = argparse.ArgumentParser(
        prog="skylos defend",
        description="Check LLM integrations for missing defenses",
    )
    def_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    def_parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    def_parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    def_parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to include",
    )
    def_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit 1 if any finding at or above this severity",
    )
    def_parser.add_argument(
        "--min-score",
        type=int,
        help="Exit 1 if weighted score percentage below this value (0-100)",
    )
    def_parser.add_argument(
        "--policy",
        dest="policy_file",
        help="Path to skylos-defend.yaml policy file",
    )
    def_parser.add_argument(
        "--owasp",
        dest="owasp_filter",
        help="Comma-separated OWASP IDs to filter (e.g. LLM01,LLM04 or ASI02)",
    )
    def_parser.add_argument(
        "--owasp-framework",
        choices=supported_owasp_frameworks(),
        default=DEFAULT_OWASP_FRAMEWORK,
        type=str.lower,
        help="OWASP framework to report against",
    )
    def_parser.add_argument(
        "--owasp-version",
        help="OWASP framework version (llm: 2024/2025, agentic: 2026)",
    )
    def_parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Additional folders to exclude",
    )
    def_parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload defense results to Skylos Cloud dashboard",
    )

    def_args = def_parser.parse_args(argv)
    console = console_factory()

    from skylos.defend.engine import run_defense_checks
    from skylos.defend.policy import load_policy
    from skylos.defend.report import format_defense_json, format_defense_table
    from skylos.discover.detector import _collect_ai_files, detect_integrations

    target = Path(def_args.path).resolve()
    if not target.exists():
        console.print(f"[red]Error: path does not exist: {target}[/red]")
        return 1
    if not target.is_dir():
        console.print(f"[red]Error: path is not a directory: {target}[/red]")
        return 1

    if def_args.min_score is not None and not 0 <= def_args.min_score <= 100:
        console.print(
            f"[red]Error: --min-score must be 0-100, got {def_args.min_score}[/red]"
        )
        return 1

    try:
        owasp_framework, owasp_version = normalize_owasp_selection(
            def_args.owasp_framework,
            def_args.owasp_version,
        )
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1

    exclude = {
        "node_modules",
        ".git",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".turbo",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
    }
    if def_args.exclude:
        exclude.update(def_args.exclude)

    policy = None
    try:
        policy = load_policy(def_args.policy_file)
    except (FileNotFoundError, ValueError, ImportError) as e:
        console.print(f"[bold red]Policy error: {e}[/bold red]")
        return 1

    owasp_filter = None
    if def_args.owasp_filter:
        try:
            owasp_filter = validate_owasp_ids(
                def_args.owasp_filter.split(","),
                framework=owasp_framework,
                version=owasp_version,
            )
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            return 1

    with progress_factory(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning for LLM integrations...", total=None)
        files = _collect_ai_files(target, exclude)
        integrations, graph = detect_integrations(target, exclude_folders=exclude)

    if not integrations:
        if def_args.output_json:
            empty = _build_empty_defense_json(
                owasp_framework=owasp_framework,
                owasp_version=owasp_version,
            )
            if def_args.output_file:
                Path(def_args.output_file).write_text(empty, encoding="utf-8")
            else:
                print(empty)
        else:
            console.print("[dim]No LLM integrations found.[/dim]")
        if def_args.upload:
            console.print("[dim]No integrations found — skipping upload.[/dim]")
        return 0

    results, score, ops_score = run_defense_checks(
        integrations,
        graph,
        policy=policy,
        min_severity=def_args.min_severity,
        owasp_filter=owasp_filter,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
    )

    owasp_coverage = compute_owasp_coverage(
        results,
        framework=owasp_framework,
        version=owasp_version,
    )

    json_output = None
    if def_args.output_json or def_args.upload:
        json_output = format_defense_json(
            results,
            score,
            len(integrations),
            len(files),
            str(target),
            owasp_coverage,
            ops_score,
            integrations=integrations,
            owasp_framework=owasp_framework,
            owasp_version=owasp_version,
        )

    if def_args.output_json:
        output = json_output
    else:
        output = format_defense_table(
            results,
            score,
            len(integrations),
            len(files),
            owasp_coverage,
            ops_score,
            owasp_framework=owasp_framework,
            owasp_version=owasp_version,
        )

    if def_args.output_file:
        try:
            Path(def_args.output_file).write_text(output, encoding="utf-8")
        except OSError as e:
            console.print(f"[red]Error writing output file: {e}[/red]")
            return 1
        console.print(f"[green]Output written to {def_args.output_file}[/green]")
    elif def_args.output_json:
        print(output)
    else:
        console.print(output)

    upload_failed = False
    if def_args.upload:
        if not def_args.output_json:
            from skylos.upload_manifest import (
                build_defense_manifest,
                print_upload_manifest,
            )

            print_upload_manifest(console, [build_defense_manifest()])

        from skylos.api import upload_defense_report

        upload_result = upload_defense_report(
            json_output,
            quiet=def_args.output_json,
        )
        if not upload_result.get("success"):
            upload_failed = True
            if not def_args.output_json:
                console.print(
                    f"[red]Upload failed: {upload_result.get('error', 'Unknown')}[/red]"
                )

    exit_code = 1 if upload_failed else 0

    fail_on = def_args.fail_on
    if policy and policy.gate_fail_on and not fail_on:
        fail_on = policy.gate_fail_on

    if fail_on:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        threshold = severity_order.get(fail_on, 0)
        for result in results:
            if result.category != "defense":
                continue
            if (
                not result.passed
                and severity_order.get(result.severity, 0) >= threshold
            ):
                exit_code = 1
                break

    min_score = def_args.min_score
    if policy and policy.gate_min_score is not None and min_score is None:
        min_score = policy.gate_min_score

    if min_score is not None and score.score_pct < min_score:
        exit_code = 1

    return exit_code
