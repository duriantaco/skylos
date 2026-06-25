from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import time
from typing import Any, Callable

from rich.console import Console
from rich.table import Table


UploadAgentRun = Callable[..., None]


def add_agent_verify_parser(
    agent_sub,
    *,
    add_model_arg,
    add_output_arg,
    add_quiet_arg,
    add_provider_arg,
    add_base_url_arg,
) -> None:
    parser = agent_sub.add_parser(
        "verify",
        help="LLM-verify dead code findings (reduce false positives, catch more dead code)",
    )
    parser.add_argument("path", help="File or directory to analyze")
    add_model_arg(parser)
    parser.add_argument(
        "--conf",
        type=int,
        default=60,
        help="Static analysis confidence threshold",
    )
    parser.add_argument(
        "--max-verify",
        type=int,
        default=50,
        help="Max findings to verify with LLM (default: 50)",
    )
    parser.add_argument(
        "--max-challenge",
        type=int,
        default=20,
        help="Max survivors to challenge with LLM (default: 20)",
    )
    parser.add_argument(
        "--no-entry-discovery",
        action="store_true",
        help="Skip entry point discovery pass",
    )
    parser.add_argument(
        "--no-survivor-challenge",
        action="store_true",
        help="Skip survivor challenge pass",
    )
    parser.add_argument(
        "--verification-mode",
        choices=["judge_all", "production"],
        default="judge_all",
        help=(
            "Dead-code verifier mode: judge_all sends nearly every refs==0 "
            "candidate to the LLM"
        ),
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )
    add_output_arg(parser)
    add_quiet_arg(parser)
    add_provider_arg(parser)
    add_base_url_arg(parser)
    parser.add_argument(
        "--grep-workers",
        type=int,
        default=4,
        help="Number of parallel grep workers (default: 4)",
    )
    parser.add_argument(
        "--parallel-grep",
        action="store_true",
        help="Enable parallel grep execution for faster verification",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Generate removal patches for confirmed dead code",
    )
    parser.add_argument(
        "--fix-mode",
        choices=["delete", "comment"],
        default="delete",
        help="Fix mode: delete removes code, comment comments it out (default: delete)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply generated patches (use with --fix)",
    )
    parser.add_argument(
        "--pr",
        action="store_true",
        help="Create a branch, apply patches, and commit (use with --fix)",
    )


def run_agent_verify_command(
    args,
    console: Console,
    *,
    model: str,
    api_key: str | None,
    provider: str | None,
    base_url: str | None,
    exclude_folders: list[str],
    upload_agent_run: UploadAgentRun,
) -> int:
    path = pathlib.Path(args.path)
    if not path.exists():
        console.print(f"[bad]Path not found: {path}[/bad]")
        return 1

    console.print("[brand]Step 1/2: Running static analysis...[/brand]")
    static_result = _run_static_dead_code_scan(
        path,
        conf=args.conf,
        exclude_folders=exclude_folders,
    )
    all_findings = _collect_dead_code_findings(static_result)
    defs_map = static_result.get("definitions", {})

    if not all_findings:
        console.print("[good]No dead code findings to verify![/good]")
        return 0

    console.print(f"  Found {len(all_findings)} dead code findings")
    console.print("\n[brand]Step 2/2: LLM verification (4-pass)...[/brand]")

    result = _run_verification_harness(
        args,
        path,
        findings=all_findings,
        defs_map=defs_map,
        model=model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
    )
    stats = result["stats"]
    verified = result["verified_findings"]
    new_dead = result["new_dead_code"]

    _write_or_print_verify_result(args, console, result)
    _print_verify_summary(args, console, result, stats, verified, new_dead)
    _print_net_result(console, stats)

    if getattr(args, "fix", False):
        _handle_verify_fixes(
            args,
            console,
            path,
            defs_map=defs_map,
            verified=verified,
            new_dead=new_dead,
        )

    upload_agent_run(
        "verify",
        {
            "total_findings": stats["total_findings"],
            "verified_true_positive": stats["verified_true_positive"],
            "verified_false_positive": stats["verified_false_positive"],
            "entry_points_discovered": stats["entry_points_discovered"],
            "llm_calls": stats["llm_calls"],
            "elapsed_seconds": stats["elapsed_seconds"],
        },
        model=model,
        provider=provider,
        duration_seconds=stats.get("elapsed_seconds"),
    )
    return 0


def _run_static_dead_code_scan(
    path: pathlib.Path,
    *,
    conf: int,
    exclude_folders: list[str],
) -> dict[str, Any]:
    from skylos.analyzer import analyze as run_static

    raw = run_static(
        str(path),
        conf=conf,
        enable_danger=False,
        enable_quality=False,
        enable_secrets=False,
        exclude_folders=exclude_folders,
    )
    return json.loads(raw) if isinstance(raw, str) else raw


def _collect_dead_code_findings(static_result: dict[str, Any]) -> list[dict[str, Any]]:
    from skylos.deadcode.collect import collect_dead_code_findings

    return collect_dead_code_findings(static_result)


def _run_verification_harness(
    args,
    path: pathlib.Path,
    *,
    findings: list[dict[str, Any]],
    defs_map: dict[str, Any],
    model: str,
    api_key: str | None,
    provider: str | None,
    base_url: str | None,
) -> dict[str, Any]:
    from skylos.llm.harness import run_verification_harness

    harness_result = run_verification_harness(
        findings=findings,
        defs_map=defs_map,
        project_root=str(_project_root_for_path(path)),
        model=model,
        api_key=api_key,
        provider=provider,
        base_url=base_url,
        max_verify=args.max_verify,
        max_challenge=args.max_challenge,
        enable_entry_discovery=not args.no_entry_discovery,
        enable_survivor_challenge=not args.no_survivor_challenge,
        quiet=getattr(args, "quiet", False),
        verification_mode=getattr(args, "verification_mode", "judge_all"),
        grep_workers=getattr(args, "grep_workers", 4),
        parallel_grep=bool(
            getattr(args, "parallel_grep", False) or getattr(args, "fix", False)
        ),
    )
    result = harness_result.output
    harness_summary = harness_result.run.summary_dict()
    result["harness"] = harness_summary
    return result


def _write_or_print_verify_result(args, console: Console, result: dict[str, Any]) -> None:
    if args.format != "json":
        return

    output = json.dumps(result, indent=2, default=str)
    if args.output:
        pathlib.Path(args.output).write_text(  # skylos: ignore[SKY-D215] user-selected CLI output path
            output,
            encoding="utf-8",
        )
        console.print(f"[dim]Written to {args.output}[/dim]")
    else:
        print(output)


def _print_verify_summary(
    args,
    console: Console,
    result: dict[str, Any],
    stats: dict[str, Any],
    verified: list[dict[str, Any]],
    new_dead: list[dict[str, Any]],
) -> None:
    if args.format == "json":
        return

    console.print("\n[brand]Verification Summary[/brand]")
    summary_table = Table(expand=False)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="bold")
    summary_table.add_row("Total findings", str(stats["total_findings"]))
    summary_table.add_row(
        "Confirmed dead (TRUE_POSITIVE)",
        f"[red]{stats['verified_true_positive']}[/red]",
    )
    summary_table.add_row(
        "False positives removed",
        f"[green]{stats['verified_false_positive']}[/green]",
    )
    summary_table.add_row("Uncertain", str(stats["uncertain"]))
    summary_table.add_row(
        "Entry points discovered",
        str(stats["entry_points_discovered"]),
    )
    summary_table.add_row(
        "Survivors challenged",
        str(stats["survivors_challenged"]),
    )
    summary_table.add_row(
        "New dead code found",
        f"[red]{stats['survivors_reclassified_dead']}[/red]",
    )
    summary_table.add_row("LLM calls", str(stats["llm_calls"]))
    summary_table.add_row("Time", f"{stats['elapsed_seconds']}s")
    console.print(summary_table)

    harness_artifact = _harness_artifact_dir(result)
    if harness_artifact:
        console.print(f"\n[dim]Harness run: {harness_artifact}[/dim]")

    _print_false_positives(console, verified)
    _print_new_dead_code(console, new_dead)
    _print_entry_points(console, result)


def _harness_artifact_dir(result: dict[str, Any]) -> str | None:
    harness_summary = result.get("harness")
    if not isinstance(harness_summary, dict) or not harness_summary.get("state_path"):
        return None
    return str(pathlib.Path(harness_summary["state_path"]).parent)


def _print_false_positives(
    console: Console,
    verified: list[dict[str, Any]],
) -> None:
    fps = [f for f in verified if f.get("_llm_verdict") == "FALSE_POSITIVE"]
    if not fps:
        return

    console.print(f"\n[green]False positives removed ({len(fps)}):[/green]")
    table = Table(expand=True)
    table.add_column("Name", style="green")
    table.add_column("File", style="dim")
    table.add_column("Rationale", overflow="fold")
    for finding in fps[:30]:
        table.add_row(
            finding.get("name", "?"),
            f"{finding.get('file', '?')}:{finding.get('line', '?')}",
            finding.get("_llm_rationale", "")[:100],
        )
    console.print(table)


def _print_new_dead_code(
    console: Console,
    new_dead: list[dict[str, Any]],
) -> None:
    if not new_dead:
        return

    console.print(f"\n[red]New dead code discovered ({len(new_dead)}):[/red]")
    table = Table(expand=True)
    table.add_column("Name", style="red")
    table.add_column("File", style="dim")
    table.add_column("Rationale", overflow="fold")
    for finding in new_dead[:30]:
        table.add_row(
            finding.get("full_name", finding.get("name", "?")),
            f"{finding.get('file', '?')}:{finding.get('line', '?')}",
            finding.get("_llm_rationale", "")[:100],
        )
    console.print(table)


def _print_entry_points(console: Console, result: dict[str, Any]) -> None:
    entry_points = result.get("entry_points", [])
    if not entry_points:
        return

    console.print(f"\n[cyan]Entry points discovered ({len(entry_points)}):[/cyan]")
    for entry_point in entry_points:
        console.print(
            f"  - {entry_point['name']} (from {entry_point['source']})"
        )


def _print_net_result(console: Console, stats: dict[str, Any]) -> None:
    total_removed = stats["verified_false_positive"]
    total_added = stats["survivors_reclassified_dead"]
    net = stats["total_findings"] - total_removed + total_added
    console.print(
        f"\n[brand]Net result:[/brand] {stats['total_findings']} findings "
        f"-> [green]-{total_removed} FP[/green] "
        f"[red]+{total_added} new[/red] "
        f"= {net} verified findings"
    )


def _handle_verify_fixes(
    args,
    console: Console,
    path: pathlib.Path,
    *,
    defs_map: dict[str, Any],
    verified: list[dict[str, Any]],
    new_dead: list[dict[str, Any]],
) -> None:
    dead_findings = _confirmed_dead_findings(verified, new_dead)
    if not dead_findings:
        console.print("\n[dim]No confirmed dead code to fix[/dim]")
        return

    project_root = str(_project_root_for_path(path))
    patches = _generate_verify_patches(args, defs_map, dead_findings, project_root)
    if not patches:
        console.print("\n[dim]No patches generated[/dim]")
        return

    errors = _validate_and_print_patch_warnings(console, patches, project_root)
    summary = _print_generated_fix_plan(console, patches, project_root)
    _run_requested_fix_action(args, console, patches, project_root, summary, errors)


def _confirmed_dead_findings(
    verified: list[dict[str, Any]],
    new_dead: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        finding for finding in verified if finding.get("_llm_verdict") == "TRUE_POSITIVE"
    ] + (new_dead or [])


def _generate_verify_patches(
    args,
    defs_map: dict[str, Any],
    dead_findings: list[dict[str, Any]],
    project_root: str,
) -> list[Any]:
    from skylos.remediation.fixgen import (
        generate_removal_plan,
    )

    return generate_removal_plan(
        dead_findings,
        defs_map,
        project_root,
        mode=getattr(args, "fix_mode", "delete"),
    )


def _validate_and_print_patch_warnings(
    console: Console,
    patches: list[Any],
    project_root: str,
) -> list[str]:
    from skylos.remediation.fixgen import validate_patches

    errors = validate_patches(patches, project_root)
    if errors:
        console.print("\n[warn]Patch validation warnings:[/warn]")
        for error in errors:
            console.print(f"  [yellow]! {error}[/yellow]")
    return errors


def _print_generated_fix_plan(
    console: Console,
    patches: list[Any],
    project_root: str,
) -> dict[str, Any]:
    from skylos.remediation.fixgen import generate_fix_summary, generate_unified_diff

    summary = generate_fix_summary(patches)
    _print_fix_plan(console, summary)
    _print_unified_diff(console, generate_unified_diff(patches, project_root))
    return summary


def _run_requested_fix_action(
    args,
    console: Console,
    patches: list[Any],
    project_root: str,
    summary: dict[str, Any],
    errors: list[str],
) -> None:
    from skylos.remediation.fixgen import apply_patches

    if getattr(args, "pr", False) and not errors:
        _create_fix_branch(console, patches, project_root, summary)
    elif getattr(args, "apply", False) and not errors:
        apply_patches(patches, project_root, dry_run=False)
        console.print("\n[good]Patches applied successfully![/good]")
    elif (getattr(args, "apply", False) or getattr(args, "pr", False)) and errors:
        console.print("\n[warn]Skipping apply due to validation errors[/warn]")


def _print_fix_plan(console: Console, summary: dict[str, Any]) -> None:
    console.print("\n[brand]Fix Plan:[/brand]")
    console.print(f"  Patches: {summary['total_patches']}")
    console.print(f"  Files affected: {summary['files_affected']}")
    console.print(f"  Lines to remove: {summary['total_lines_removed']}")
    console.print(f"  Avg safety: {summary['avg_safety_score']}")


def _print_unified_diff(console: Console, diff: str) -> None:
    if not diff:
        return
    console.print("\n[brand]Unified Diff:[/brand]")
    print(diff)


def _create_fix_branch(
    console: Console,
    patches: list[Any],
    project_root: str,
    summary: dict[str, Any],
) -> None:
    from skylos.remediation.fixgen import apply_patches

    branch_name = f"skylos/fix-deadcode-{int(time.time())}"
    try:
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        )
        apply_patches(patches, project_root, dry_run=False)
        subprocess.run(
            ["git", "add", "-A"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        )
        commit_msg = (
            f"fix: remove {summary['total_patches']} dead code items "
            f"({summary['total_lines_removed']} lines)"
        )
        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        )
        _print_pr_guidance(console, branch_name, commit_msg)
    except subprocess.CalledProcessError as exc:
        console.print(f"\n[warn]Git operation failed: {exc.stderr or exc}[/warn]")


def _print_pr_guidance(console: Console, branch_name: str, commit_msg: str) -> None:
    console.print(f"\n[good]Branch created: {branch_name}[/good]")
    console.print(f"[good]Committed: {commit_msg}[/good]")
    if shutil.which("gh"):
        console.print(
            f"\n[brand]Create PR with:[/brand]\n"
            f'  gh pr create --title "{commit_msg}" '
            f'--body "Automated dead code removal by Skylos"'
        )
    else:
        console.print(
            f"\n[dim]Push and create PR:[/dim]\n"
            f"  git push -u origin {branch_name}\n"
            f"  # then open PR on GitHub"
        )


def _project_root_for_path(path: pathlib.Path) -> pathlib.Path:
    return path if path.is_dir() else path.parent
