from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from contextlib import redirect_stdout
from pathlib import Path

from skylos.ui.paths import shown_path

_RULES = frozenset({"SKY-CIRC", "SKY-Q805", "SKY-Q807"})
_SECTIONS = ("circular_dependencies", "quality")
_LANGUAGES = {"Python", "TypeScript", "JavaScript"}
_SOURCE_SUFFIXES = {
    ".py",
    ".pyi",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mts",
    ".cts",
    ".mjs",
    ".cjs",
}


def scan_architecture(target: Path) -> dict:
    """Collect native architecture findings for lint and baseline generation."""
    from skylos.analyzer import analyze
    from skylos.config import load_config, resolve_config_file_path
    from skylos.constants import parse_exclude_folders
    from skylos.core.cli_shared import quiet_analyzer_logs

    if not target.is_dir():
        raise ValueError(f"Architecture lint requires a project directory: {target}")
    config_file = resolve_config_file_path()
    config = load_config(target, config_file=config_file)
    excluded = sorted(
        parse_exclude_folders(config_exclude_folders=config.get("exclude"))
    )
    try:
        with quiet_analyzer_logs(), redirect_stdout(sys.stderr):
            result = json.loads(
                analyze(
                    str(target),
                    exclude_folders=excluded,
                    enable_quality=True,
                    enable_dependency_hallucinations=False,
                    grep_verify=False,
                    trace_file=False,
                    skip_generated=not config.get("include_generated", False),
                    config_file=config_file,
                    project_config_overrides={
                        "architecture": {"check_package_cycles": True}
                    },
                )
            )
    except Exception as exc:
        raise RuntimeError(
            f"Architecture scan failed ({type(exc).__name__}): {exc}"
        ) from exc

    errors = [
        error
        for error in result.get("analysis_errors", [])
        if not error.get("file")
        or Path(error["file"]).suffix.lower() in _SOURCE_SUFFIXES
    ]
    if errors:
        detail = errors[0].get("message") or errors[0].get("file") or "unknown error"
        raise ValueError(
            f"Architecture scan incomplete ({len(errors)} errors). {detail}"
        )
    if not _LANGUAGES.intersection(result["analysis_summary"].get("languages", {})):
        raise ValueError(
            "Architecture lint found no Python, TypeScript or JavaScript files."
        )
    if not result.get("architecture_metrics"):
        raise ValueError(
            "Architecture scan incomplete. Dependency metrics are unavailable."
        )

    return {
        section: [
            row for row in result.get(section, []) if row.get("rule_id") in _RULES
        ]
        for section in _SECTIONS
    }


def _in_diff(result: dict, target: Path, base: str) -> dict:
    from skylos.cicd.review import filter_findings_to_diff, get_changed_line_ranges
    from skylos.core.file_discovery import find_git_root

    root = find_git_root(target) or target
    changed = get_changed_line_ranges(
        base,
        cwd=root,
        raise_on_error=True,
        include_deletion_anchors=False,
        include_working_tree=True,
    )
    # SKY-Q805 represents a module-level dependency and is anchored at line 1.
    module_ranges = [{**entry, "start": 1} for entry in changed]
    package_cycles = [row for row in result["quality"] if row["rule_id"] == "SKY-Q807"]
    layers = [row for row in result["quality"] if row["rule_id"] == "SKY-Q805"]
    return {
        "circular_dependencies": filter_findings_to_diff(
            result["circular_dependencies"], changed, project_root=root
        ),
        "quality": filter_findings_to_diff(package_cycles, changed, project_root=root)
        + filter_findings_to_diff(layers, module_ranges, project_root=root),
    }


def run_lint_command(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="skylos lint",
        description="Run local static checks for import cycles and configured layers.",
        allow_abbrev=False,
    )
    parser.add_argument("path", nargs="?", default=".", help="project directory")
    parser.add_argument("--format", choices=("concise", "json"), default="concise")
    parser.add_argument(
        "--diff", metavar="REF", help="report findings touching changes since REF"
    )
    parser.add_argument(
        "--baseline", action="store_true", help="filter previously recorded findings"
    )
    args = parser.parse_args(argv)
    try:
        target = Path(args.path).expanduser().resolve(strict=True)
        result = scan_architecture(target)
        if args.baseline:
            from skylos.core.baseline import filter_new_findings, load_baseline

            baseline = load_baseline(target)
            if baseline is None:
                raise ValueError(
                    "No usable baseline. Run 'skylos baseline PATH --architecture'."
                )
            result = filter_new_findings(result, baseline, project_root=target)
        if args.diff:
            result = _in_diff(result, target, args.diff)
    except (OSError, ValueError, RuntimeError) as exc:
        if args.format == "json":
            print(json.dumps({"status": "error", "error": str(exc), "findings": []}))
        else:
            print(str(exc), file=sys.stderr)
        return 2

    findings = sorted(
        (row for section in _SECTIONS for row in result[section]),
        key=lambda row: (
            row.get("file", ""),
            row.get("line", 0),
            row["rule_id"],
            row["message"],
        ),
    )
    if args.format == "json":
        print(
            json.dumps(
                {"status": "fail" if findings else "pass", "findings": findings},
                indent=2,
            )
        )
    else:
        for row in findings:
            location = shown_path(row["file"]) if row.get("file") else "?"
            print(
                f"{location}:{row.get('line', 0)}  {row['rule_id']}  {row['message']}"
            )
            for related in row.get("related_locations", []):
                path = shown_path(related["file"])
                print(f"  {path}:{related['start_line']}  {related['message']}")
    return int(bool(findings))
