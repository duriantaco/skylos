import argparse
import json
from pathlib import Path

from rich.progress import SpinnerColumn, TextColumn


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
        help="Comma-separated OWASP LLM IDs to filter (e.g. LLM01,LLM04)",
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
    from skylos.defend.policy import compute_owasp_coverage, load_policy
    from skylos.defend.report import format_defense_json, format_defense_table
    from skylos.discover.detector import _collect_python_files, detect_integrations

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

    exclude = {
        "node_modules",
        ".git",
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
        from skylos.defend.policy import OWASP_LLM_MAPPING

        owasp_filter = [s.strip().upper() for s in def_args.owasp_filter.split(",")]
        for oid in owasp_filter:
            if oid not in OWASP_LLM_MAPPING:
                console.print(
                    f"[red]Error: unknown OWASP ID '{oid}'. "
                    f"Valid: {', '.join(sorted(OWASP_LLM_MAPPING))}[/red]"
                )
                return 1

    with progress_factory(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning for LLM integrations...", total=None)
        files = _collect_python_files(target, exclude)
        integrations, graph = detect_integrations(target, exclude_folders=exclude)

    if not integrations:
        if def_args.output_json:
            empty = json.dumps(
                {
                    "version": "1.0",
                    "summary": {
                        "integrations_found": 0,
                        "total_checks": 0,
                        "passed": 0,
                        "failed": 0,
                        "score_pct": 100,
                        "risk_rating": "SECURE",
                    },
                    "findings": [],
                    "ops_score": {
                        "passed": 0,
                        "total": 0,
                        "score_pct": 100,
                        "rating": "EXCELLENT",
                    },
                },
                indent=2,
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
    )

    owasp_coverage = compute_owasp_coverage(results)

    if def_args.output_json:
        output = format_defense_json(
            results,
            score,
            len(integrations),
            len(files),
            str(target),
            owasp_coverage,
            ops_score,
            integrations=integrations,
        )
    else:
        output = format_defense_table(
            results,
            score,
            len(integrations),
            len(files),
            owasp_coverage,
            ops_score,
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

    if def_args.upload:
        from skylos.api import upload_defense_report

        json_for_upload = format_defense_json(
            results,
            score,
            len(integrations),
            len(files),
            str(target),
            owasp_coverage,
            ops_score,
            integrations=integrations,
        )
        upload_result = upload_defense_report(json_for_upload)
        if not upload_result.get("success"):
            console.print(
                f"[red]Upload failed: {upload_result.get('error', 'Unknown')}[/red]"
            )

    exit_code = 0

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
