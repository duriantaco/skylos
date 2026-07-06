import argparse
import json
import logging
import os
import stat
from pathlib import Path

from rich.progress import SpinnerColumn, TextColumn

from skylos.defend.owasp import (
    DEFAULT_OWASP_FRAMEWORK,
    compute_owasp_coverage,
    normalize_owasp_selection,
    supported_owasp_frameworks,
    validate_owasp_ids,
)

DEFEND_FORMATS = ("table", "json", "md", "sarif")
MAX_GITHUB_STEP_SUMMARY_BYTES = 1_000_000
logger = logging.getLogger(__name__)


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

def _build_empty_defense_json(
    *,
    owasp_framework: str = DEFAULT_OWASP_FRAMEWORK,
    owasp_version: str | int | None = None,
    project: str = ".",
    attestation: dict | None = None,
    framework_evidence: dict | None = None,
) -> str:
    from datetime import datetime, timezone

    from skylos import __version__ as skylos_version

    owasp_framework, owasp_version = normalize_owasp_selection(
        owasp_framework,
        owasp_version,
    )
    return json.dumps(
        {
            "version": "1.1",
            "skylos_version": skylos_version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "project": project,
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
            **({"attestation": attestation} if attestation is not None else {}),
            **(
                {"framework_evidence": framework_evidence}
                if framework_evidence is not None
                else {}
            ),
        },
        indent=2,
    )


def _build_defend_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos defend",
        description=(
            "Verify AI-agent guardrails before deployment "
            "(static pre-deployment agent verification)"
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    parser.add_argument(
        "--format",
        choices=DEFEND_FORMATS,
        default=None,
        help=(
            "Output format: table, json, md (evidence report), or sarif "
            "(default: table; --json is an alias for --format json)"
        ),
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


def _resolve_defend_format(console, args: argparse.Namespace) -> str | None:
    if args.format and args.output_json and args.format != "json":
        console.print(
            f"[red]Error: --json conflicts with --format {args.format}[/red]"
        )
        return None
    return args.format or ("json" if args.output_json else "table")


def _effective_gate_settings(
    args: argparse.Namespace, policy
) -> tuple[str | None, int | None]:
    fail_on = args.fail_on
    if policy and policy.gate_fail_on and not fail_on:
        fail_on = policy.gate_fail_on

    min_score = args.min_score
    if policy and policy.gate_min_score is not None and min_score is None:
        min_score = policy.gate_min_score

    return fail_on, min_score


def _sarif_path_prefix(target: Path) -> str:
    try:
        rel = os.path.relpath(target, Path.cwd())
    except ValueError:
        return ""
    if rel == "." or rel.startswith(".."):
        return ""
    return Path(rel).as_posix()


def _build_defend_attestation(
    args: argparse.Namespace,
    *,
    target: Path,
    files,
    results,
    integrations=None,
    score=None,
    ops_score=None,
    owasp_coverage=None,
    framework_evidence=None,
    policy,
    owasp_framework: str,
    owasp_version: str,
    owasp_filter,
) -> dict:
    from skylos.defend.attestation import build_attestation
    from skylos.defend.engine import resolve_active_plugin_ids

    return build_attestation(
        target=target,
        files=files,
        results=results,
        plugin_ids=resolve_active_plugin_ids(policy),
        policy_path=args.policy_file,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
        min_severity=args.min_severity,
        owasp_filter=owasp_filter,
        integrations=integrations,
        score=score,
        ops_score=ops_score,
        owasp_coverage=owasp_coverage,
        framework_evidence=framework_evidence,
    )


def _github_step_summary_path(raw_path: str) -> Path | None:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        return None

    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        return None

    candidate = parent / path.name
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        try:
            candidate.relative_to(Path(runner_temp).expanduser().resolve(strict=True))
        except (OSError, ValueError):
            return None
    return candidate


def _append_github_step_summary(path: Path, markdown: str) -> bool:
    payload = (markdown + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] GitHub summary path is absolute, bounded, regular, and opened no-follow
            path, flags, 0o600
        )
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            return False
        if stat_result.st_size + len(payload) > MAX_GITHUB_STEP_SUMMARY_BYTES:
            return False
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            fd = None
            handle.write(payload.decode("utf-8"))
        return True
    except (OSError, UnicodeError):
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _write_defend_github_summary(build_markdown) -> None:
    """
    Append a defend summary to $GITHUB_STEP_SUMMARY when running in CI.

    Strict no-op without the env var; best-effort otherwise — the summary
    must never affect command output or exit codes.
    """
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return

    summary_path = _github_step_summary_path(path)
    if summary_path is None:
        logger.debug("Skipping GitHub step summary: unsafe summary path")
        return

    try:
        markdown = build_markdown()
    except Exception as exc:
        logger.debug("Could not render GitHub step summary: %s", exc)
        return

    if not _append_github_step_summary(summary_path, markdown):
        logger.debug("Could not append GitHub step summary")
        return


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
    fmt: str,
    target: Path,
    files,
    policy,
    owasp_framework: str,
    owasp_version: str,
    owasp_filter,
) -> int:
    if fmt == "table":
        console.print("[dim]No LLM integrations found.[/dim]")
    else:
        from skylos.defend.frameworks import compute_framework_evidence
        from skylos.defend.scoring import (
            compute_defense_score,
            compute_ops_score,
        )

        score = compute_defense_score([])
        ops_score = compute_ops_score([])
        owasp_coverage = compute_owasp_coverage(
            [],
            framework=owasp_framework,
            version=owasp_version,
        )
        framework_evidence = compute_framework_evidence([])
        attestation = _build_defend_attestation(
            args,
            target=target,
            files=files,
            results=[],
            integrations=[],
            score=score,
            ops_score=ops_score,
            owasp_coverage=owasp_coverage,
            framework_evidence=framework_evidence,
            policy=policy,
            owasp_framework=owasp_framework,
            owasp_version=owasp_version,
            owasp_filter=owasp_filter,
        )

        if fmt == "json":
            output = _build_empty_defense_json(
                owasp_framework=owasp_framework,
                owasp_version=owasp_version,
                project=str(target),
                attestation=attestation,
                framework_evidence=framework_evidence,
            )
        elif fmt == "md":
            from skylos.defend.report import format_defense_markdown

            output = format_defense_markdown(
                [],
                score,
                integrations=[],
                files_scanned=len(files),
                target=str(target),
                owasp_coverages=[
                    (owasp_framework, owasp_version, owasp_coverage)
                ],
                ops_score=ops_score,
                framework_evidence=framework_evidence,
                attestation=attestation,
                policy_path=args.policy_file,
            )
        else:
            from skylos.defend.report import format_defense_sarif

            output = format_defense_sarif(
                [],
                attestation=attestation,
                path_prefix=_sarif_path_prefix(target),
            )

        write_result = _write_defend_output(args, console, output, fmt)
        if write_result:
            return write_result

    _write_defend_github_summary(
        lambda: "## Skylos Agent Verification\n\nNo LLM integrations detected.\n"
    )

    if args.upload:
        console.print("[dim]No integrations found — skipping upload.[/dim]")

    return 0


def _format_defend_output(
    args: argparse.Namespace,
    *,
    fmt: str,
    target: Path,
    results,
    score,
    ops_score,
    integrations,
    files,
    owasp_coverage,
    owasp_framework: str,
    owasp_version: str,
    policy=None,
    owasp_filter=None,
):
    from skylos.defend.report import format_defense_json, format_defense_table

    framework_evidence = None
    if fmt != "table" or args.upload:
        from skylos.defend.frameworks import compute_framework_evidence

        framework_evidence = compute_framework_evidence(results)

    attestation = None
    if fmt != "table" or args.upload:
        attestation = _build_defend_attestation(
            args,
            target=target,
            files=files,
            results=results,
            integrations=integrations,
            score=score,
            ops_score=ops_score,
            owasp_coverage=owasp_coverage,
            framework_evidence=framework_evidence,
            policy=policy,
            owasp_framework=owasp_framework,
            owasp_version=owasp_version,
            owasp_filter=owasp_filter,
        )

    json_output = None
    if fmt == "json" or args.upload:
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
            attestation=attestation,
            framework_evidence=framework_evidence,
        )

    if fmt == "json":
        return json_output, json_output

    if fmt == "md":
        from skylos.defend.report import format_defense_markdown
        from skylos.defend.scoring import evaluate_gate

        owasp_coverages = [(owasp_framework, owasp_version, owasp_coverage)]
        other_framework, other_version = (
            ("agentic", "2026") if owasp_framework == "llm" else ("llm", "2025")
        )
        owasp_coverages.append(
            (
                other_framework,
                other_version,
                compute_owasp_coverage(
                    results,
                    framework=other_framework,
                    version=other_version,
                ),
            )
        )

        gate_fail_on, gate_min_score = _effective_gate_settings(args, policy)
        gate_info = None
        if gate_fail_on or gate_min_score is not None:
            gate_info = {
                "fail_on": gate_fail_on,
                "min_score": gate_min_score,
                "passed": evaluate_gate(
                    results,
                    score,
                    fail_on=gate_fail_on,
                    min_score=gate_min_score,
                ),
            }

        md_output = format_defense_markdown(
            results,
            score,
            integrations=integrations,
            files_scanned=len(files),
            target=str(target),
            owasp_coverages=owasp_coverages,
            ops_score=ops_score,
            framework_evidence=framework_evidence,
            attestation=attestation,
            policy_path=args.policy_file,
            gate=gate_info,
        )
        return md_output, json_output

    if fmt == "sarif":
        from skylos.defend.report import format_defense_sarif

        sarif_output = format_defense_sarif(
            results,
            attestation=attestation,
            path_prefix=_sarif_path_prefix(target),
        )
        return sarif_output, json_output

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


def _write_defend_output(
    args: argparse.Namespace, console, output: str, fmt: str
) -> int:
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
    elif fmt != "table":
        # Plain print: rich would interpret markdown/JSON braces as markup.
        print(output)
    else:
        console.print(output)

    return 0


def _upload_defend_output(
    args: argparse.Namespace, console, json_output: str, fmt: str
) -> bool:
    if not args.upload:
        return False

    if fmt == "table":
        from skylos.cloud.upload_manifest import (
            build_defense_manifest,
            print_upload_manifest,
        )

        print_upload_manifest(console, [build_defense_manifest()])

    from skylos.api import upload_defense_report

    upload_result = upload_defense_report(json_output, quiet=fmt != "table")
    if upload_result.get("success"):
        return False

    if fmt == "table":
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
    from skylos.defend.scoring import evaluate_gate

    exit_code = 1 if upload_failed else 0

    fail_on, min_score = _effective_gate_settings(args, policy)
    if not evaluate_gate(results, score, fail_on=fail_on, min_score=min_score):
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

    fmt = _resolve_defend_format(console, args)
    if fmt is None:
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
            fmt=fmt,
            target=target,
            files=files,
            policy=policy,
            owasp_framework=owasp_framework,
            owasp_version=owasp_version,
            owasp_filter=owasp_filter,
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
        fmt=fmt,
        target=target,
        results=results,
        score=score,
        ops_score=ops_score,
        integrations=integrations,
        files=files,
        owasp_coverage=owasp_coverage,
        owasp_framework=owasp_framework,
        owasp_version=owasp_version,
        policy=policy,
        owasp_filter=owasp_filter,
    )

    write_result = _write_defend_output(args, console, output, fmt)
    if write_result:
        return write_result

    upload_failed = _upload_defend_output(args, console, json_output, fmt)
    exit_code = _defend_exit_code(
        args,
        policy=policy,
        results=results,
        score=score,
        upload_failed=upload_failed,
    )

    def _build_summary() -> str:
        from skylos.defend.report import format_defense_github_summary
        from skylos.defend.scoring import evaluate_gate

        fail_on, min_score = _effective_gate_settings(args, policy)
        gate_passed = None
        if fail_on or min_score is not None:
            gate_passed = evaluate_gate(
                results,
                score,
                fail_on=fail_on,
                min_score=min_score,
            )
        return format_defense_github_summary(
            results,
            score,
            ops_score,
            owasp_coverage,
            gate_passed=gate_passed,
            owasp_framework=owasp_framework,
            owasp_version=owasp_version,
        )

    _write_defend_github_summary(_build_summary)
    return exit_code
