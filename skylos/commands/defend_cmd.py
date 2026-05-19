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


DEFAULT_DEFEND_EXCLUDES = {
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

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


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


def _build_defend_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos defend",
        description="Check LLM integrations for missing defenses",
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to include",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit 1 if any finding at or above this severity",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        help="Exit 1 if weighted score percentage below this value (0-100)",
    )
    parser.add_argument(
        "--policy",
        dest="policy_file",
        help="Path to skylos-defend.yaml policy file",
    )
    parser.add_argument(
        "--owasp",
        dest="owasp_filter",
        help="Comma-separated OWASP IDs to filter (e.g. LLM01,LLM04 or ASI02)",
    )
    parser.add_argument(
        "--owasp-framework",
        choices=supported_owasp_frameworks(),
        default=DEFAULT_OWASP_FRAMEWORK,
        type=str.lower,
        help="OWASP framework to report against",
    )
    parser.add_argument(
        "--owasp-version",
        help="OWASP framework version (llm: 2024/2025, agentic: 2026)",
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Additional folders to exclude",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload defense results to Skylos Cloud dashboard",
    )
    return parser


def _validate_defend_target(console, target: Path) -> bool:
    if not target.exists():
        console.print(f"[red]Error: path does not exist: {target}[/red]")
        return False

    if not target.is_dir():
        console.print(f"[red]Error: path is not a directory: {target}[/red]")
        return False

    return True


def _validate_min_score(console, min_score: int | None) -> bool:
    if min_score is not None and not 0 <= min_score <= 100:
        console.print(
            f"[red]Error: --min-score must be 0-100, got {min_score}[/red]"
        )
        return False

    return True


def _normalize_defend_owasp(console, framework: str, version: str | None):
    try:
        return normalize_owasp_selection(framework, version)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return None


def _build_defend_excludes(extra_excludes: list[str] | None) -> set[str]:
    excludes = set(DEFAULT_DEFEND_EXCLUDES)
    if extra_excludes:
        excludes.update(extra_excludes)
    return excludes


def _load_explicit_policy(console, policy_file: str | None):
    if not policy_file:
        return None, 0

    try:
        from skylos.defend.policy import load_policy

        return load_policy(policy_file), 0
    except (FileNotFoundError, ValueError, ImportError) as e:
        console.print(f"[bold red]Policy error: {e}[/bold red]")
        return None, 1


def _validate_owasp_filter(
    console,
    raw_filter: str | None,
    *,
    framework: str,
    version: str,
):
    if not raw_filter:
        return None, 0

    try:
        return validate_owasp_ids(
            raw_filter.split(","),
            framework=framework,
            version=version,
        ), 0
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return None, 1


def _discover_defend_inputs(
    target: Path,
    exclude: set[str],
    *,
    console,
    progress_factory,
):
    from skylos.discover.detector import _collect_ai_files, detect_integrations

    with progress_factory(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning for LLM integrations...", total=None)
        files = _collect_ai_files(target, exclude)
        integrations, graph = detect_integrations(target, exclude_folders=exclude)

    return files, integrations, graph


def _write_empty_defend_output(
    args: argparse.Namespace,
    console,
    *,
    owasp_framework: str,
    owasp_version: str,
) -> int:
    if args.output_json:
        empty = _build_empty_defense_json(
            owasp_framework=owasp_framework,
            owasp_version=owasp_version,
        )
        if args.output_file:
            Path(args.output_file).write_text(  # skylos: ignore[SKY-D215] user-selected defend output path
                empty,
                encoding="utf-8",
            )
        else:
            print(empty)
    else:
        console.print("[dim]No LLM integrations found.[/dim]")

    if args.upload:
        console.print("[dim]No integrations found — skipping upload.[/dim]")

    return 0


def _format_defend_output(
    args: argparse.Namespace,
    *,
    target: Path,
    results,
    score,
    ops_score,
    integrations,
    files,
    owasp_coverage,
    owasp_framework: str,
    owasp_version: str,
):
    from skylos.defend.report import format_defense_json, format_defense_table

    json_output = None
    if args.output_json or args.upload:
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

    if args.output_json:
        return json_output, json_output

    table_output = format_defense_table(
        results,
        score,
        len(integrations),
        len(files),
        owasp_coverage,
        ops_score,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
    )
    return table_output, json_output


def _write_defend_output(args: argparse.Namespace, console, output: str) -> int:
    if args.output_file:
        try:
            Path(args.output_file).write_text(  # skylos: ignore[SKY-D215] user-selected defend output path
                output,
                encoding="utf-8",
            )
        except OSError as e:
            console.print(f"[red]Error writing output file: {e}[/red]")
            return 1
        console.print(f"[green]Output written to {args.output_file}[/green]")
    elif args.output_json:
        print(output)
    else:
        console.print(output)

    return 0


def _upload_defend_output(args: argparse.Namespace, console, json_output: str) -> bool:
    if not args.upload:
        return False

    if not args.output_json:
        from skylos.cloud.upload_manifest import (
            build_defense_manifest,
            print_upload_manifest,
        )

        print_upload_manifest(console, [build_defense_manifest()])

    from skylos.api import upload_defense_report

    upload_result = upload_defense_report(json_output, quiet=args.output_json)
    if upload_result.get("success"):
        return False

    if not args.output_json:
        console.print(
            f"[red]Upload failed: {upload_result.get('error', 'Unknown')}[/red]"
        )
    return True


def _defend_exit_code(
    args: argparse.Namespace,
    *,
    policy,
    results,
    score,
    upload_failed: bool,
) -> int:
    exit_code = 1 if upload_failed else 0

    fail_on = args.fail_on
    if policy and policy.gate_fail_on and not fail_on:
        fail_on = policy.gate_fail_on

    if fail_on:
        threshold = SEVERITY_ORDER.get(fail_on, 0)
        for result in results:
            if result.category != "defense":
                continue
            if (
                not result.passed
                and SEVERITY_ORDER.get(result.severity, 0) >= threshold
            ):
                exit_code = 1
                break

    min_score = args.min_score
    if policy and policy.gate_min_score is not None and min_score is None:
        min_score = policy.gate_min_score

    if min_score is not None and score.score_pct < min_score:
        exit_code = 1

    return exit_code


def run_defend_command(
    argv: list[str],
    *,
    console_factory,
    progress_factory,
) -> int:
    """
    Run the AI defense command and render or upload defense findings.

    Calls: skylos/commands/defend_cmd.py _discover_defend_inputs;
        skylos/defend/engine.py run_defense_checks;
        skylos/commands/defend_cmd.py _format_defend_output;
        skylos/commands/defend_cmd.py _upload_defend_output.

    Called from: skylos/cli.py run_defend_command.
    """
    parser = _build_defend_parser()
    args = parser.parse_args(argv)
    console = console_factory()

    target = Path(args.path).resolve()
    if not _validate_defend_target(console, target):
        return 1

    if not _validate_min_score(console, args.min_score):
        return 1

    owasp_selection = _normalize_defend_owasp(
        console,
        args.owasp_framework,
        args.owasp_version,
    )
    if owasp_selection is None:
        return 1
    owasp_framework, owasp_version = owasp_selection

    exclude = _build_defend_excludes(args.exclude)
    policy, policy_error = _load_explicit_policy(console, args.policy_file)
    if policy_error:
        return policy_error

    owasp_filter, owasp_error = _validate_owasp_filter(
        console,
        args.owasp_filter,
        framework=owasp_framework,
        version=owasp_version,
    )
    if owasp_error:
        return owasp_error

    files, integrations, graph = _discover_defend_inputs(
        target,
        exclude,
        console=console,
        progress_factory=progress_factory,
    )

    if not integrations:
        return _write_empty_defend_output(
            args,
            console,
            owasp_framework=owasp_framework,
            owasp_version=owasp_version,
        )

    from skylos.defend.engine import run_defense_checks

    results, score, ops_score = run_defense_checks(
        integrations,
        graph,
        policy=policy,
        min_severity=args.min_severity,
        owasp_filter=owasp_filter,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
    )

    owasp_coverage = compute_owasp_coverage(
        results,
        framework=owasp_framework,
        version=owasp_version,
    )
    output, json_output = _format_defend_output(
        args,
        target=target,
        results=results,
        score=score,
        ops_score=ops_score,
        integrations=integrations,
        files=files,
        owasp_coverage=owasp_coverage,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
    )

    write_result = _write_defend_output(args, console, output)
    if write_result:
        return write_result

    upload_failed = _upload_defend_output(args, console, json_output)
    return _defend_exit_code(
        args,
        policy=policy,
        results=results,
        score=score,
        upload_failed=upload_failed,
    )
