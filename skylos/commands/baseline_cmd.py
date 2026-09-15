import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from skylos import analyze as run_analyze
from skylos.config import load_config, resolve_config_file_path
from skylos.constants import parse_exclude_folders
from skylos.core.baseline import save_baseline
from skylos.core.gatekeeper import _analysis_incomplete_reasons
from skylos.core.sca_baseline import dependency_scan_complete


def _build_baseline_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos baseline",
        description="Save existing findings so --baseline reports only new issues.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "path", nargs="?", default=".", help="File or directory to scan (default: .)"
    )
    parser.add_argument(
        "--sca",
        action="store_true",
        help=(
            "Include dependency vulnerabilities. Queries OSV for public package "
            "names and versions; an incomplete scan will not replace the baseline."
        ),
    )
    return parser


def _baseline_scan_roots(path: str) -> tuple[Path, Path]:
    target = Path(path).expanduser().resolve()
    scan_root = target.parent if target.is_file() else target
    from skylos.core.file_discovery import find_git_root

    return target, find_git_root(scan_root) or scan_root


def run_baseline_command(argv: list[str]) -> int:
    args = _build_baseline_parser().parse_args(argv)
    path = args.path
    target, project_root = _baseline_scan_roots(path)
    # Normal scans load from their scan target, not necessarily the Git root.
    # A subdirectory baseline must not replace a repository-wide baseline.
    baseline_root = target.parent if target.is_file() else target

    config_file = resolve_config_file_path()
    project_config = load_config(project_root, config_file=config_file)
    exclude_folders = parse_exclude_folders(
        config_exclude_folders=project_config.get("exclude"),
    )

    from skylos.core.review_decisions import (
        apply_trusted_review_decisions,
        review_scan_requirements,
    )

    include_review_context, include_review_proofs = review_scan_requirements(
        project_root
    )
    analyze_kwargs = {
        "enable_danger": True,
        "enable_quality": True,
        "enable_secrets": True,
        "enable_ai_defects": True,
        "exclude_folders": sorted(exclude_folders),
    }
    if config_file is not None:
        analyze_kwargs["config_file"] = config_file
    if include_review_context:
        analyze_kwargs["include_review_context"] = True
    if include_review_proofs:
        analyze_kwargs["include_review_proofs"] = True
    if args.sca:
        analyze_kwargs["enable_sca"] = True

    console = Console()
    console.print(f"[bold]Creating baseline for {escape(path)}...[/bold]")

    try:
        result = json.loads(run_analyze(path, **analyze_kwargs))
    except (OSError, RuntimeError, TypeError, ValueError):
        console.print(
            "[red]Baseline not saved: the scan did not return a usable result. "
            "Any existing baseline was left unchanged.[/red]"
        )
        return 2
    if not isinstance(result, dict):
        console.print(
            "[red]Baseline not saved: the scan did not return a usable result. "
            "Any existing baseline was left unchanged.[/red]"
        )
        return 2

    incomplete_reasons = _analysis_incomplete_reasons(result)
    if args.sca and not dependency_scan_complete(result):
        summary = result.get("analysis_summary")
        receipt = summary.get("sca_coverage") if isinstance(summary, dict) else None
        if (
            isinstance(receipt, dict)
            and receipt.get("status") == "no_supported_manifests"
        ):
            incomplete_reasons.append(
                "No supported dependency files were found for --sca"
            )
        else:
            incomplete_reasons.append(
                "Dependency scanning did not confirm a complete scan"
            )
    if incomplete_reasons:
        console.print(
            "[red]Baseline not saved: the scan was incomplete. "
            "Any existing baseline was left unchanged.[/red]"
        )
        for reason in incomplete_reasons:
            console.print(f"[red]{escape(reason)}[/red]")
        return 2

    result = apply_trusted_review_decisions(
        result,
        project_root,
    )
    try:
        baseline_path = save_baseline(str(baseline_root), result)
    except (OSError, ValueError):
        console.print(
            "[red]Baseline not saved: the baseline file could not be safely written.[/red]"
        )
        return 2
    total = sum(
        len(result.get(key, []))
        for key in [
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
            "unused_files",
            "danger",
            "reliability",
            "ai_defects",
            "quality",
            "secrets",
            "dependency_vulnerabilities",
        ]
    )

    console.print(
        f"[good]Baseline saved to {escape(str(baseline_path))} "
        f"({total} existing findings captured)[/good]"
    )
    console.print(
        "[muted]Future runs with --baseline will only report new findings[/muted]"
    )
    return 0
