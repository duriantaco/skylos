from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path

from skylos.core.suite import format_suite_json, format_suite_table, run_suite

_VALID_UPLOAD_FAMILIES = ("static", "defense", "debt")
_VALID_STATIC_UPLOAD_CATEGORIES = (
    "danger",
    "ai_defects",
    "quality",
    "secrets",
    "dead_code",
    "dependency",
)


def _parse_csv_selection(raw: str | None, valid_values: tuple[str, ...]) -> list[str]:
    if not raw:
        return list(valid_values)

    selected = []
    seen = set()
    valid_set = set(valid_values)
    for item in str(raw).split(","):
        normalized = item.strip().lower()
        if not normalized:
            continue
        if normalized not in valid_set:
            valid_text = ", ".join(valid_values)
            raise ValueError(
                f"Invalid selection '{normalized}'. Expected one of: {valid_text}"
            )
        if normalized not in seen:
            seen.add(normalized)
            selected.append(normalized)
    return selected


def _build_static_upload_result(
    static_result: dict,
    static_categories: list[str],
) -> dict:
    category_set = set(static_categories)
    payload = {
        "analysis_summary": static_result.get("analysis_summary") or {},
    }
    if "provenance" in static_result:
        payload["provenance"] = static_result.get("provenance")
    if static_result.get("provenance_summary") is not None:
        payload["provenance_summary"] = static_result.get("provenance_summary")
    if static_result.get("ai_security_stats") is not None:
        payload["ai_security_stats"] = static_result.get("ai_security_stats")

    if "danger" in category_set:
        payload["danger"] = list(static_result.get("danger") or [])
    if "ai_defects" in category_set:
        payload["ai_defects"] = list(static_result.get("ai_defects") or [])
    if "quality" in category_set:
        payload["quality"] = list(static_result.get("quality") or [])
        if static_result.get("architecture_metrics") is not None:
            payload["architecture_metrics"] = static_result.get("architecture_metrics")
    if "secrets" in category_set:
        payload["secrets"] = list(static_result.get("secrets") or [])
    if "dependency" in category_set:
        payload["dependency_vulnerabilities"] = list(
            static_result.get("dependency_vulnerabilities") or []
        )
    if "dead_code" in category_set:
        for key in (
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
            "unused_parameters",
            "unused_files",
        ):
            payload[key] = list(static_result.get(key) or [])

    return payload


def _static_upload_failed_quality_gate(upload_result: dict) -> bool:
    passed = upload_result.get("quality_gate_passed")
    if passed is None:
        passed = (upload_result.get("quality_gate") or {}).get("passed", True)
    return passed is False


def _build_suite_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos suite",
        description=(
            "Run the full local Skylos suite: static analysis, technical debt, "
            "AI defense, and provenance summary"
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Additional folders to exclude",
    )
    parser.add_argument(
        "--confidence",
        "-c",
        type=int,
        default=60,
        help="Confidence threshold for static dead-code findings (0-100)",
    )
    parser.add_argument(
        "--diff-base",
        default=None,
        help="Base ref for provenance detection (default: auto-detect)",
    )
    parser.add_argument(
        "--no-provenance",
        action="store_true",
        help="Disable automatic AI provenance summary",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload selected scan families to Skylos Cloud as separate scans in one suite bundle",
    )
    parser.add_argument(
        "--families",
        default="static,defense,debt",
        help=(
            "Comma-separated upload families for --upload. Choices: static,defense,debt"
        ),
    )
    parser.add_argument(
        "--static-categories",
        default="danger,ai_defects,quality,secrets,dead_code,dependency",
        help=(
            "Comma-separated code-scan categories to upload inside the static family. "
            "Choices: danger,ai_defects,quality,secrets,dead_code,dependency"
        ),
    )
    return parser


def _validate_suite_target(console, target: Path) -> bool:
    if not target.exists():
        console.print(f"[red]Error: path does not exist: {target}[/red]")
        return False

    if not target.is_dir():
        console.print(
            f"[red]Error: suite expects a directory, got file: {target}. "
            "Use `skylos <file>` for single-file static analysis.[/red]"
        )
        return False

    return True


def _build_suite_excludes(
    args: argparse.Namespace,
    target: Path,
    *,
    parse_exclude_folders_func,
    load_config_func,
) -> set[str]:
    exclude = set(
        parse_exclude_folders_func(
            use_defaults=True,
            config_exclude_folders=load_config_func(target).get("exclude"),
        )
    )
    if args.exclude:
        exclude.update(args.exclude)
    return exclude


def _parse_suite_upload_selections(args: argparse.Namespace, console):
    try:
        selected_families = _parse_csv_selection(
            args.families,
            _VALID_UPLOAD_FAMILIES,
        )
        selected_static_categories = _parse_csv_selection(
            args.static_categories,
            _VALID_STATIC_UPLOAD_CATEGORIES,
        )
    except ValueError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        return None, None, 1

    return selected_families, selected_static_categories, 0


def _run_suite_report(
    args: argparse.Namespace,
    target: Path,
    exclude: set[str],
    *,
    console,
    progress_factory,
    run_analyze_func,
    get_git_root_func,
):
    try:
        report = run_suite(
            target,
            conf=args.confidence,
            exclude_folders=sorted(exclude),
            run_analyze_func=run_analyze_func,
            progress_factory=progress_factory,
            console=console,
            output_json=args.output_json,
            no_provenance=args.no_provenance,
            diff_base=args.diff_base,
            get_git_root_func=get_git_root_func,
        )
    except (FileNotFoundError, ValueError, ImportError) as exc:
        console.print(f"[bold red]Suite error: {exc}[/bold red]")
        return None, 1

    return report, 0


def _format_suite_output(args: argparse.Namespace, report: dict) -> str:
    if args.output_json:
        return format_suite_json(report)
    return format_suite_table(report)


def _write_suite_output(args: argparse.Namespace, console, output: str) -> int:
    if args.output_file:
        try:
            Path(args.output_file).write_text(  # skylos: ignore[SKY-D215] user-selected suite output path
                output,
                encoding="utf-8",
            )
        except OSError as exc:
            console.print(f"[red]Error writing output file: {exc}[/red]")
            return 1
        console.print(f"[green]Output written to {args.output_file}[/green]")
    elif args.output_json:
        print(output)
    else:
        console.print(output)

    return 0


def _build_suite_upload_manifests(
    report: dict,
    selected_families: list[str],
    selected_static_categories: list[str],
) -> list[dict]:
    from skylos.cloud.upload_manifest import (
        build_code_scan_manifest,
        build_defense_manifest,
        build_debt_manifest,
    )

    manifest_families = []
    if "static" in selected_families:
        manifest_families.append(
            build_code_scan_manifest(
                selected_static_categories,
                provenance_attached=bool(
                    ((report.get("static") or {}).get("provenance"))
                ),
            )
        )
    if "defense" in selected_families:
        manifest_families.append(build_defense_manifest())
    if "debt" in selected_families:
        manifest_families.append(build_debt_manifest())
    return manifest_families


def _print_suite_upload_manifest(
    args: argparse.Namespace,
    console,
    report: dict,
    selected_families: list[str],
    selected_static_categories: list[str],
    *,
    scan_bundle_id: str | None,
) -> None:
    if args.output_json:
        return

    from skylos.cloud.upload_manifest import print_upload_manifest

    manifest_families = _build_suite_upload_manifests(
        report,
        selected_families,
        selected_static_categories,
    )
    print_upload_manifest(console, manifest_families, bundle_id=scan_bundle_id)


def _upload_static_suite_family(
    args: argparse.Namespace,
    console,
    report: dict,
    selected_static_categories: list[str],
    *,
    scan_bundle_id: str | None,
    upload_report_func,
) -> int:
    static_upload_result = _build_static_upload_result(
        report.get("static") or {},
        selected_static_categories,
    )
    static_upload = upload_report_func(
        static_upload_result,
        quiet=args.output_json,
        scan_bundle_id=scan_bundle_id,
    )
    if not static_upload.get("success"):
        if not args.output_json:
            console.print(
                f"[red]Static upload failed: {static_upload.get('error', 'Unknown')}[/red]"
            )
        return 1

    if _static_upload_failed_quality_gate(static_upload):
        if not args.output_json:
            console.print(
                "[red]Static upload failed the Skylos Cloud quality gate.[/red]"
            )
        return 1

    return 0


def _upload_defense_suite_family(
    args: argparse.Namespace,
    console,
    report: dict,
    *,
    scan_bundle_id: str | None,
    upload_defense_report_func,
) -> int:
    defense_upload = upload_defense_report_func(
        json.dumps(report.get("defense") or {}),
        quiet=args.output_json,
        scan_bundle_id=scan_bundle_id,
    )
    if defense_upload.get("success"):
        return 0

    if not args.output_json:
        console.print(
            f"[red]Defense upload failed: {defense_upload.get('error', 'Unknown')}[/red]"
        )
    return 1


def _upload_debt_suite_family(
    args: argparse.Namespace,
    console,
    report: dict,
    *,
    scan_bundle_id: str | None,
    upload_debt_report_func,
) -> int:
    debt_upload = upload_debt_report_func(
        report.get("debt") or {},
        quiet=args.output_json,
        scan_bundle_id=scan_bundle_id,
    )
    if debt_upload.get("success"):
        return 0

    if not args.output_json:
        console.print(
            f"[red]Debt upload failed: {debt_upload.get('error', 'Unknown')}[/red]"
        )
    return 1


def _upload_suite_report(
    args: argparse.Namespace,
    console,
    report: dict,
    selected_families: list[str],
    selected_static_categories: list[str],
    *,
    upload_report_func,
    upload_defense_report_func,
    upload_debt_report_func,
) -> int:
    if not args.upload:
        return 0

    upload_failures = 0
    scan_bundle_id = str(uuid.uuid4()) if len(selected_families) > 1 else None
    _print_suite_upload_manifest(
        args,
        console,
        report,
        selected_families,
        selected_static_categories,
        scan_bundle_id=scan_bundle_id,
    )

    if "static" in selected_families:
        upload_failures += _upload_static_suite_family(
            args,
            console,
            report,
            selected_static_categories,
            scan_bundle_id=scan_bundle_id,
            upload_report_func=upload_report_func,
        )

    if "defense" in selected_families:
        upload_failures += _upload_defense_suite_family(
            args,
            console,
            report,
            scan_bundle_id=scan_bundle_id,
            upload_defense_report_func=upload_defense_report_func,
        )

    if "debt" in selected_families:
        upload_failures += _upload_debt_suite_family(
            args,
            console,
            report,
            scan_bundle_id=scan_bundle_id,
            upload_debt_report_func=upload_debt_report_func,
        )

    if upload_failures:
        return 1

    return 0


def run_suite_command(
    argv: list[str],
    *,
    console_factory,
    progress_factory,
    parse_exclude_folders_func,
    load_config_func,
    run_analyze_func,
    get_git_root_func,
    upload_report_func,
    upload_defense_report_func,
    upload_debt_report_func,
) -> int:
    parser = _build_suite_parser()
    args = parser.parse_args(argv)
    console = console_factory()

    target = Path(args.path).resolve()
    if not _validate_suite_target(console, target):
        return 1

    exclude = _build_suite_excludes(
        args,
        target,
        parse_exclude_folders_func=parse_exclude_folders_func,
        load_config_func=load_config_func,
    )
    selected_families, selected_static_categories, selection_error = (
        _parse_suite_upload_selections(args, console)
    )
    if selection_error:
        return selection_error

    report, suite_error = _run_suite_report(
        args,
        target,
        exclude,
        console=console,
        progress_factory=progress_factory,
        run_analyze_func=run_analyze_func,
        get_git_root_func=get_git_root_func,
    )
    if suite_error:
        return suite_error

    output = _format_suite_output(args, report)
    write_error = _write_suite_output(args, console, output)
    if write_error:
        return write_error

    return _upload_suite_report(
        args,
        console,
        report,
        selected_families,
        selected_static_categories,
        upload_report_func=upload_report_func,
        upload_defense_report_func=upload_defense_report_func,
        upload_debt_report_func=upload_debt_report_func,
    )
