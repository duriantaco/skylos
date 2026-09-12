import json
from pathlib import Path

from rich.console import Console

from skylos import analyze as run_analyze
from skylos.config import load_config, resolve_config_file_path
from skylos.constants import parse_exclude_folders
from skylos.core.baseline import save_baseline


def _baseline_scan_roots(path: str) -> tuple[Path, Path]:
    target = Path(path).expanduser().resolve()
    scan_root = target.parent if target.is_file() else target
    from skylos.core.file_discovery import find_git_root

    return target, find_git_root(scan_root) or scan_root


def run_baseline_command(argv: list[str]) -> int:
    path = argv[0] if argv else "."
    _target, project_root = _baseline_scan_roots(path)

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

    console = Console()
    console.print(f"[bold]Creating baseline for {path}...[/bold]")

    result = apply_trusted_review_decisions(
        json.loads(run_analyze(path, **analyze_kwargs)),
        project_root,
    )
    baseline_path = save_baseline(path, result)
    total = sum(
        len(result.get(key, []))
        for key in [
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
            "danger",
            "reliability",
            "ai_defects",
            "quality",
            "secrets",
        ]
    )

    console.print(
        f"[good]Baseline saved to {baseline_path} ({total} existing findings captured)[/good]"
    )
    console.print(
        "[muted]Future runs with --baseline will only report new findings[/muted]"
    )
    return 0
