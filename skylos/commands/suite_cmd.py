from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path

from skylos.suite import format_suite_json, format_suite_table, run_suite

_VALID_UPLOAD_FAMILIES = ("static", "defense", "debt")
_VALID_STATIC_UPLOAD_CATEGORIES = (
    "danger",
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
    suite_parser = argparse.ArgumentParser(
        prog="skylos suite",
        description=(
            "Run the full local Skylos suite: static analysis, technical debt, "
            "AI defense, and provenance summary"
        ),
    )
    suite_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    suite_parser.add_argument(
        "--json", action="store_true", dest="output_json", help="Output as JSON"
    )
    suite_parser.add_argument(
        "-o", "--output", dest="output_file", help="Write output to file"
    )
    suite_parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        help="Additional folders to exclude",
    )
    suite_parser.add_argument(
        "--confidence",
        "-c",
        type=int,
        default=60,
        help="Confidence threshold for static dead-code findings (0-100)",
    )
    suite_parser.add_argument(
        "--diff-base",
        default=None,
        help="Base ref for provenance detection (default: auto-detect)",
    )
    suite_parser.add_argument(
        "--no-provenance",
        action="store_true",
        help="Disable automatic AI provenance summary",
    )
    suite_parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload selected scan families to Skylos Cloud as separate scans in one suite bundle",
    )
    suite_parser.add_argument(
        "--families",
        default="static,defense,debt",
        help=(
            "Comma-separated upload families for --upload. "
            "Choices: static,defense,debt"
        ),
    )
    suite_parser.add_argument(
        "--static-categories",
        default="danger,quality,secrets,dead_code,dependency",
        help=(
            "Comma-separated code-scan categories to upload inside the static family. "
            "Choices: danger,quality,secrets,dead_code,dependency"
        ),
    )

    suite_args = suite_parser.parse_args(argv)
    console = console_factory()

    target = Path(suite_args.path).resolve()
    if not target.exists():
        console.print(f"[red]Error: path does not exist: {target}[/red]")
        return 1
    if not target.is_dir():
        console.print(
            f"[red]Error: suite expects a directory, got file: {target}. "
            "Use `skylos <file>` for single-file static analysis.[/red]"
        )
        return 1

    exclude = set(
        parse_exclude_folders_func(
            use_defaults=True,
            config_exclude_folders=load_config_func(target).get("exclude"),
        )
    )
    if suite_args.exclude:
        exclude.update(suite_args.exclude)

    try:
        selected_families = _parse_csv_selection(
            suite_args.families,
            _VALID_UPLOAD_FAMILIES,
        )
        selected_static_categories = _parse_csv_selection(
            suite_args.static_categories,
            _VALID_STATIC_UPLOAD_CATEGORIES,
        )
    except ValueError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        return 1

    try:
        report = run_suite(
            target,
            conf=suite_args.confidence,
            exclude_folders=sorted(exclude),
            run_analyze_func=run_analyze_func,
            progress_factory=progress_factory,
            console=console,
            output_json=suite_args.output_json,
            no_provenance=suite_args.no_provenance,
            diff_base=suite_args.diff_base,
            get_git_root_func=get_git_root_func,
        )
    except (FileNotFoundError, ValueError, ImportError) as exc:
        console.print(f"[bold red]Suite error: {exc}[/bold red]")
        return 1

    output = (
        format_suite_json(report)
        if suite_args.output_json
        else format_suite_table(report)
    )

    if suite_args.output_file:
        try:
            Path(suite_args.output_file).write_text(output, encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Error writing output file: {exc}[/red]")
            return 1
        console.print(f"[green]Output written to {suite_args.output_file}[/green]")
    elif suite_args.output_json:
        print(output)
    else:
        console.print(output)

    if not suite_args.upload:
        return 0

    upload_failures = 0
    scan_bundle_id = (
        str(uuid.uuid4()) if len(selected_families) > 1 else None
    )

    if not suite_args.output_json:
        from skylos.upload_manifest import (
            build_code_scan_manifest,
            build_defense_manifest,
            build_debt_manifest,
            print_upload_manifest,
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
        print_upload_manifest(
            console,
            manifest_families,
            bundle_id=scan_bundle_id,
        )

    if "static" in selected_families:
        static_upload_result = _build_static_upload_result(
            report.get("static") or {},
            selected_static_categories,
        )
        static_upload = upload_report_func(
            static_upload_result,
            quiet=suite_args.output_json,
            scan_bundle_id=scan_bundle_id,
        )
        if not static_upload.get("success"):
            upload_failures += 1
            if not suite_args.output_json:
                console.print(
                    f"[red]Static upload failed: {static_upload.get('error', 'Unknown')}[/red]"
                )
        elif _static_upload_failed_quality_gate(static_upload):
            upload_failures += 1
            if not suite_args.output_json:
                console.print(
                    "[red]Static upload failed the Skylos Cloud quality gate.[/red]"
                )

    if "defense" in selected_families:
        defense_upload = upload_defense_report_func(
            json.dumps(report.get("defense") or {}),
            quiet=suite_args.output_json,
            scan_bundle_id=scan_bundle_id,
        )
        if not defense_upload.get("success"):
            upload_failures += 1
            if not suite_args.output_json:
                console.print(
                    f"[red]Defense upload failed: {defense_upload.get('error', 'Unknown')}[/red]"
                )

    if "debt" in selected_families:
        debt_upload = upload_debt_report_func(
            report.get("debt") or {},
            quiet=suite_args.output_json,
            scan_bundle_id=scan_bundle_id,
        )
        if not debt_upload.get("success"):
            upload_failures += 1
            if not suite_args.output_json:
                console.print(
                    f"[red]Debt upload failed: {debt_upload.get('error', 'Unknown')}[/red]"
                )

    if upload_failures:
        return 1

    return 0
