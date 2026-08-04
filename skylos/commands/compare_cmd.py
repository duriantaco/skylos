from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from skylos.core.safe_cache_io import write_text_no_symlink


_NON_SOURCE_REPORT_SUFFIXES = {".sarif"}


def _build_compare_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos compare",
        description=(
            "Run a non-blocking side-by-side assessment against an incumbent "
            "scanner report. The default scan makes no network queries."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository path to scan when --skylos-results is not supplied",
    )
    parser.add_argument(
        "--against",
        required=True,
        help="Incumbent SARIF, Sonar issues JSON, or normalized findings JSON",
    )
    parser.add_argument(
        "--skylos-results",
        help="Reuse an existing Skylos JSON report instead of scanning path",
    )
    parser.add_argument(
        "--confidence",
        type=int,
        default=60,
        help="Dead-code confidence threshold for a new scan (default: 60)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Folder to exclude from a new scan; repeat as needed",
    )
    parser.add_argument(
        "--sca",
        action="store_true",
        help=(
            "Opt in to bounded exact-pin direct-dependency OSV checks; "
            "package/version metadata may be queried and full SCA category "
            "coverage is not claimed"
        ),
    )
    parser.add_argument(
        "--external-revision",
        help="Revision described by the incumbent report when it lacks provenance",
    )
    parser.add_argument(
        "--skylos-revision",
        help="Revision described by --skylos-results when it lacks provenance",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="Report format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the complete comparison report as JSON",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help=(
            "Upload the bounded comparison receipt to the token-bound Skylos "
            "Cloud project; never enabled implicitly"
        ),
    )
    return parser


def run_compare_command(argv: list[str], *, console_factory) -> int:
    args = _build_compare_parser().parse_args(argv)

    console = console_factory()
    if not 0 <= args.confidence <= 100:
        console.print("[red]--confidence must be between 0 and 100[/red]")
        return 2

    try:
        report = _build_compare_report(args)
    except (OSError, ValueError, RecursionError) as exc:
        from rich.markup import escape

        console.print(f"[bold red]Comparison failed:[/bold red] {escape(str(exc))}")
        return 2

    try:
        report_json = _serialize_compare_report(report)
    except (TypeError, ValueError, RecursionError) as exc:
        from rich.markup import escape

        console.print(
            f"[bold red]Comparison failed:[/bold red] cannot serialize report: "
            f"{escape(str(exc))}"
        )
        return 2
    try:
        output_path = _write_compare_output(args, report_json)
    except (OSError, RuntimeError, ValueError) as exc:
        from rich.markup import escape

        console.print(
            f"[bold red]Comparison failed:[/bold red] cannot prepare output path: "
            f"{escape(str(exc))}"
        )
        return 2

    upload_result = _upload_compare_report(args, report)
    _render_compare_report(args, report, report_json, output_path, console)
    _render_upload_result(args, upload_result, console)

    upload_succeeded = upload_result is None or upload_result.get("success") is True
    return 0 if report.get("usable") and upload_succeeded else 2


def _build_compare_report(args: argparse.Namespace) -> dict:
    from skylos.integrations.shadow import (
        build_shadow_report,
        load_json_report,
        normalize_external_report,
    )

    external = normalize_external_report(load_json_report(args.against))
    _apply_external_revision(external, args.external_revision)
    skylos_result = _load_skylos_result(args, load_json_report)
    _apply_skylos_revision(skylos_result, args.skylos_revision)
    return build_shadow_report(external, skylos_result)


def _apply_external_revision(external: dict, revision: str | None) -> None:
    if not revision:
        return
    existing = {str(value) for value in external.get("revisions", []) if value}
    if existing and existing != {revision}:
        raise ValueError(
            "--external-revision conflicts with provenance in the incumbent report"
        )
    if not existing:
        external["revisions"] = [revision]
        external["revision_source"] = "cli"


def _load_skylos_result(args: argparse.Namespace, load_json_report) -> dict:
    if args.skylos_results:
        result = load_json_report(args.skylos_results)
        if not isinstance(result, dict):
            raise ValueError("Skylos result must be a JSON object")
        return result

    ignored_artifacts = [args.against]
    if args.output:
        ignored_artifacts.append(args.output)
    return _run_local_scan(
        args.path,
        confidence=args.confidence,
        exclude_folders=args.exclude,
        enable_sca=args.sca,
        ignore_dirty_paths=ignored_artifacts,
    )


def _skylos_revisions(result: dict, summary: dict) -> set[str]:
    keys = ("revision", "revision_id", "commit", "commit_sha", "git_commit")
    return {
        str(value)
        for source in (summary, result)
        for key in keys
        if (value := source.get(key))
    }


def _apply_skylos_revision(result: dict, revision: str | None) -> None:
    if not revision:
        return
    summary = result.get("analysis_summary")
    if not isinstance(summary, dict):
        raise ValueError(
            "--skylos-revision requires recognizable Skylos completion metadata"
        )
    existing = _skylos_revisions(result, summary)
    if existing and existing != {revision}:
        raise ValueError(
            "--skylos-revision conflicts with provenance in the Skylos report"
        )
    if not existing:
        summary["revision"] = revision
        summary["revision_source"] = "cli"


def _serialize_compare_report(report: dict) -> str:
    return json.dumps(report, indent=2)


def _write_compare_output(args: argparse.Namespace, report_json: str) -> Path | None:
    if not args.output:
        return None
    output_path = _prepare_output_path(args.output)
    input_paths = {Path(args.against).expanduser().resolve()}
    if args.skylos_results:
        input_paths.add(Path(args.skylos_results).expanduser().resolve())
    if output_path in input_paths:
        raise ValueError("output cannot overwrite an input report")
    if not _write_report_no_symlink(output_path, report_json + "\n"):
        raise ValueError(
            "output must be a regular, non-symlink file without hard links"
        )
    return output_path


def _upload_compare_report(args: argparse.Namespace, report: dict) -> dict | None:
    if not args.upload:
        return None
    try:
        from skylos.cloud.shadow_upload import upload_shadow_report

        return upload_shadow_report(report, project_path=args.path)
    except (OSError, ValueError, RecursionError) as exc:
        return {"success": False, "error": str(exc)}


def _render_compare_report(
    args: argparse.Namespace,
    report: dict,
    report_json: str,
    output_path: Path | None,
    console,
) -> None:
    if args.output_format == "json":
        print(report_json)
        return
    _print_text_report(report, console)
    if output_path is not None:
        from rich.markup import escape

        console.print(
            f"\n[green]Full JSON report written:[/green] {escape(str(output_path))}"
        )


def _render_upload_result(
    args: argparse.Namespace, upload_result: dict | None, console
) -> None:
    if upload_result is None:
        return
    from rich.markup import escape

    if upload_result.get("success"):
        view_url = str(upload_result.get("view_url") or "").strip()
        message = "Scanner Proof receipt uploaded"
        if view_url:
            message = f"{message}: {view_url}"
        if args.output_format == "json":
            print(message, file=sys.stderr)
        else:
            console.print(f"\n[green]{escape(message)}[/green]")
        return

    error = str(upload_result.get("error") or "Unknown upload error")
    message = f"Scanner Proof upload failed: {error}"
    upgrade_url = str(upload_result.get("upgrade_url") or "").strip()
    if upgrade_url:
        message = f"{message}\nUpgrade Workspace Governance: {upgrade_url}"
    if args.output_format == "json":
        print(message, file=sys.stderr)
    else:
        console.print(f"\n[bold red]{escape(message)}[/bold red]")


def _write_report_no_symlink(path: Path, text: str) -> bool:
    return write_text_no_symlink(path, text, encoding="utf-8")


def _prepare_output_path(value: str) -> Path:
    """Create an output parent without traversing symlinked directories."""
    raw_path = Path(value).expanduser()
    if not raw_path.is_absolute():
        raw_path = Path.cwd() / raw_path
    output_path = Path(os.path.abspath(raw_path))
    if not output_path.name:
        raise ValueError("output path must name a file")

    if os.name == "posix" and hasattr(os, "O_DIRECTORY"):
        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        directory_fd = os.open(output_path.anchor or os.sep, flags)
        try:
            for component in output_path.parent.parts[1:]:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
        finally:
            os.close(directory_fd)
        return output_path

    current = Path(output_path.anchor)
    for component in output_path.parent.parts[1:]:
        current /= component
        if current.is_symlink():
            raise ValueError("output parent must not contain symlinks")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return output_path


def _run_local_scan(
    path: str,
    *,
    confidence: int,
    exclude_folders: list[str],
    enable_sca: bool,
    ignore_dirty_paths: list[str] | None = None,
) -> dict:
    scan_path = Path(path).expanduser()
    if not scan_path.exists():
        raise ValueError(f"Scan path does not exist: {scan_path}")
    safe_ignored_paths = [
        value
        for value in (ignore_dirty_paths or [])
        if Path(value).suffix.lower() in _NON_SOURCE_REPORT_SUFFIXES
    ]
    revision, worktree_dirty, repository_root, repository_identity = _git_context(
        scan_path, ignore_paths=safe_ignored_paths
    )

    from skylos.analyzer import analyze

    raw = analyze(
        str(scan_path),
        conf=confidence,
        exclude_folders=exclude_folders or None,
        enable_secrets=False,
        enable_danger=True,
        enable_quality=True,
        enable_ai_defects=True,
        enable_sca=enable_sca,
        enable_dependency_hallucinations=False,
        grep_cache=False,
    )
    (
        post_revision,
        post_worktree_dirty,
        post_repository_root,
        post_repository_identity,
    ) = _git_context(scan_path, ignore_paths=safe_ignored_paths)
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Skylos scan did not return a JSON object")
    snapshot_stable = _comparison_snapshot_stable(
        (revision, worktree_dirty, repository_root, repository_identity),
        (
            post_revision,
            post_worktree_dirty,
            post_repository_root,
            post_repository_identity,
        ),
    )
    _annotate_comparison_scan(
        result,
        scan_path=scan_path,
        repository_root=repository_root,
        repository_identity=repository_identity,
        excluded_folders=exclude_folders,
        enable_sca=enable_sca,
        revision=revision,
        worktree_dirty=worktree_dirty,
        snapshot_stable=snapshot_stable,
        post_revision=post_revision,
    )
    return result


def _comparison_snapshot_stable(before: tuple, after: tuple) -> bool:
    return bool(before[0] and all(left == right for left, right in zip(before, after)))


def _annotate_comparison_scan(
    result: dict,
    *,
    scan_path: Path,
    repository_root: Path | None,
    repository_identity: str | None,
    excluded_folders: list[str],
    enable_sca: bool,
    revision: str | None,
    worktree_dirty: bool | None,
    snapshot_stable: bool,
    post_revision: str | None,
) -> None:
    summary = result.get("analysis_summary")
    if not isinstance(summary, dict):
        return
    from skylos import __version__ as skylos_version

    requested_categories = [
        "AI_DEFECT",
        "DEAD_CODE",
        "QUALITY",
        "RELIABILITY",
        "SECURITY",
    ]
    if enable_sca:
        requested_categories.append("DEPENDENCY")
    summary.update(
        {
            "skylos_version": str(skylos_version),
            "comparison_sca_requested": enable_sca,
            "comparison_requested_categories": requested_categories,
            "comparison_disabled_checks": ["dependency_hallucinations"],
            "comparison_scope": _comparison_scope(
                scan_path,
                repository_root=repository_root,
                repository_identity=repository_identity,
                excluded_folders=excluded_folders,
            ),
        }
    )
    if revision:
        summary.update(
            {
                "revision": revision,
                "revision_source": "git_head",
                "worktree_dirty": bool(worktree_dirty) or not snapshot_stable,
                "snapshot_stable": snapshot_stable,
                "revision_after_scan": post_revision,
            }
        )


def _git_context(
    scan_path: Path, *, ignore_paths: list[str]
) -> tuple[str | None, bool | None, Path | None, str | None]:
    repository_path = scan_path if scan_path.is_dir() else scan_path.parent
    try:
        revision = subprocess.check_output(
            ["git", "-C", str(repository_path), "rev-parse", "--verify", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        ).strip()
        repository_root = Path(
            subprocess.check_output(
                ["git", "-C", str(repository_path), "rev-parse", "--show-toplevel"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
            ).strip()
        )
        status = subprocess.check_output(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(repository_path),
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
            ],
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None, None, None
    try:
        repository_identity = subprocess.check_output(
            ["git", "-C", str(repository_root), "remote", "get-url", "origin"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        repository_identity = None
    generated_cache_paths = [
        repository_root / ".skylos" / "cache" / filename
        for filename in ("grep_results.json", "osv_cache.json", "pypi_exists.json")
    ]
    return (
        revision if revision else None,
        _has_relevant_worktree_changes(
            status,
            repository_root=repository_root,
            ignore_paths=[
                *ignore_paths,
                *(str(path) for path in generated_cache_paths),
            ],
        ),
        repository_root.resolve(strict=False),
        repository_identity or None,
    )


def _comparison_scope(
    scan_path: Path,
    *,
    repository_root: Path | None,
    repository_identity: str | None,
    excluded_folders: list[str],
) -> dict[str, object]:
    resolved_scan_path = scan_path.resolve(strict=False)
    if scan_path.is_symlink():
        kind = "symlink"
        complete_repository: bool | None = False
    elif scan_path.is_file():
        kind = "file"
        complete_repository = False
    elif repository_root is None:
        kind = "directory_without_repository_provenance"
        complete_repository = None
    elif (
        resolved_scan_path == repository_root.resolve(strict=False)
        and not excluded_folders
    ):
        kind = "repository_root"
        complete_repository = True
    elif resolved_scan_path == repository_root.resolve(strict=False):
        kind = "repository_root_with_exclusions"
        complete_repository = False
    else:
        kind = "subdirectory"
        complete_repository = False
    return {
        "kind": kind,
        "scan_path": str(resolved_scan_path),
        "repository_root": str(repository_root) if repository_root else None,
        "repository_identities": [repository_identity] if repository_identity else [],
        "complete_repository": complete_repository,
        "excluded_folders": list(excluded_folders),
    }


def _has_relevant_worktree_changes(
    porcelain: bytes, *, repository_root: Path, ignore_paths: list[str]
) -> bool:
    """Return whether status contains changes beyond explicit report artifacts."""
    ignored = {
        (Path.cwd() / candidate if not candidate.is_absolute() else candidate)
        .expanduser()
        .resolve(strict=False)
        for value in ignore_paths
        if (candidate := Path(value).expanduser())
    }
    records = porcelain.split(b"\0")
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            return True
        status = record[:2]
        changed_paths = [record[3:]]
        if status[:1] in {b"R", b"C"}:
            if index >= len(records) or not records[index]:
                return True
            changed_paths.append(records[index])
            index += 1
        resolved_paths = {
            (repository_root / os.fsdecode(path)).resolve(strict=False)
            for path in changed_paths
        }
        if status != b"??" or not resolved_paths.issubset(ignored):
            return True
    return False


def _print_text_report(report: dict, console) -> None:
    from rich.markup import escape
    from rich.panel import Panel
    from rich.table import Table

    external = report["external"]
    skylos = report["skylos"]
    comparison = report["comparison"]
    tools = escape(", ".join(external.get("tools") or []) or "incumbent scanner")

    table = Table(show_header=True, header_style="bold", border_style="dim")
    table.add_column("Signal")
    table.add_column("Count", justify="right")
    table.add_row("Active incumbent findings", str(external["total_findings"]))
    table.add_row(
        "Inactive/suppressed incumbent results excluded",
        str(external["excluded_findings_count"]),
    )
    table.add_row("Raw Skylos findings", str(skylos["total_findings"]))
    table.add_row(
        "Findings with same-location overlap", str(comparison["location_overlap"])
    )
    table.add_row("Incumbent-only findings", str(comparison["external_only"]))
    table.add_row("Raw Skylos-only findings", str(comparison["skylos_only"]))
    table.add_row(
        "Skylos-only in observed comparable categories",
        str(comparison["skylos_only_in_observed_comparable_categories"]),
    )
    table.add_row(
        "Incumbent findings in likely-dead code",
        str(comparison["external_in_likely_dead_code"]),
    )
    table.add_row(
        "Affected unused symbols",
        str(comparison["affected_likely_dead_symbols"]),
    )
    table.add_row(
        "Affected unused files",
        str(comparison["affected_unused_files"]),
    )
    table.add_row(
        "Reachability unknown",
        str(comparison["external_reachability_unknown"]),
    )
    candidates = report["benefit"]["review_or_deletion_candidates"]
    table.add_row(
        "Eligible deletion candidates",
        str(candidates) if candidates is not None else "withheld",
    )

    status = {
        "inputs_verified_same_revision": (
            "report inputs complete and bound to the same revision; detector "
            "coverage is not attested"
        ),
        "external_completeness_unknown": (
            "usable; incumbent export completeness unknown"
        ),
        "revision_unverified": "usable; same revision not verified",
        "scope_unverified": "usable; repository-wide scope not verified",
        "category_coverage_incomplete": (
            "usable with limits; one or more compared categories are incomplete"
        ),
        "incomplete": "incomplete; do not use for value claims",
    }.get(report.get("completeness_state"), "incomplete")
    console.print(
        Panel.fit(
            f"[bold]Skylos Scanner Proof[/bold]\n"
            f"Compared with {tools} · analysis {status}",
            border_style="cyan" if report.get("complete") else "yellow",
        )
    )
    console.print(table)
    console.print(f"\n[bold]Potential benefit:[/bold] {report['benefit']['statement']}")
    reasons = ", ".join(report.get("completeness_reasons") or [])
    if reasons:
        console.print(f"[dim]Scope notes: {escape(reasons)}[/dim]")
    console.print(f"[dim]Revision binding: {escape(report['revision']['state'])}[/dim]")
    console.print(
        "[dim]These are review/deletion candidates, not automatic false positives. "
        "Same-location overlap does not prove rule equivalence.[/dim]"
    )
