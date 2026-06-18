import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from skylos.remediation.codemods import (
    comment_out_unused_function_cst,
    comment_out_unused_import_cst,
    remove_unused_function_cst,
    remove_unused_import_cst,
)
from skylos.remediation.safety import resolve_remediation_path

SUPPORTED_FINDING_TYPES = {"function", "import"}
DEFAULT_NONINTERACTIVE_CONFIDENCE = 80
TYPE_ALIASES = {
    "function": "function",
    "functions": "function",
    "import": "import",
    "imports": "import",
}


def run_analyze(*args, **kwargs):
    from skylos.analyzer import analyze as run_analyze_impl

    return run_analyze_impl(*args, **kwargs)


def _apply_codemod(
    file_path, transform, *transform_args, root_path=None, **transform_kwargs
):
    path = resolve_remediation_path(file_path, root_path=root_path)
    src = path.read_text(encoding="utf-8")
    new_code, changed = transform(src, *transform_args, **transform_kwargs)
    if changed:
        path.write_text(new_code, encoding="utf-8")
    return changed


def _collect_findings(items, finding_type):
    return [
        {
            "type": finding_type,
            "name": item.get("name", ""),
            "file": item.get("file", ""),
            "line": item.get("line", 0),
            "confidence": item.get("confidence", 100),
        }
        for item in items
    ]


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="skylos clean",
        description="Interactively or deterministically clean dead code.",
    )
    parser.add_argument("path", nargs="?", default=".")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the edits Skylos would apply without writing files.",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Apply matching dead-code cleanup edits without prompting.",
    )
    parser.add_argument(
        "--confidence",
        type=int,
        default=None,
        help=(
            "Minimum confidence for actionable findings. Defaults to 80 in "
            "noninteractive mode and the analyzer default in interactive mode."
        ),
    )
    parser.add_argument(
        "--types",
        default=None,
        help="Comma-separated cleanup types to include: import,function.",
    )
    parser.add_argument(
        "--comment-out",
        action="store_true",
        help="Use comment-out transforms instead of removal in noninteractive mode.",
    )
    return parser


def _parse_types(raw_types):
    if raw_types is None:
        return set(SUPPORTED_FINDING_TYPES)

    selected = set()
    for raw_type in raw_types.split(","):
        type_name = raw_type.strip().lower()
        if not type_name:
            continue
        normalized = TYPE_ALIASES.get(type_name)
        if normalized is None:
            allowed = ", ".join(sorted(SUPPORTED_FINDING_TYPES))
            raise ValueError(f"Unsupported cleanup type: {type_name}. Use: {allowed}")
        selected.add(normalized)

    if not selected:
        raise ValueError("--types must include at least one cleanup type")
    return selected


def _effective_confidence(args, noninteractive):
    if args.confidence is not None:
        return args.confidence
    if noninteractive:
        return DEFAULT_NONINTERACTIVE_CONFIDENCE
    return None


def _analyze(path, confidence):
    if confidence is None:
        return json.loads(run_analyze(path))
    return json.loads(run_analyze(path, conf=confidence))


def _collect_all_findings(result):
    all_findings = []
    all_findings.extend(
        _collect_findings(result.get("unused_functions", []), "function")
    )
    all_findings.extend(_collect_findings(result.get("unused_imports", []), "import"))
    all_findings.extend(
        _collect_findings(result.get("unused_variables", []), "variable")
    )
    all_findings.extend(_collect_findings(result.get("unused_classes", []), "class"))
    all_findings.sort(key=lambda f: -f["confidence"])
    return all_findings


def _filter_findings(all_findings, selected_types, confidence):
    findings = []
    unsupported_findings = []
    filtered_findings = []

    for finding in all_findings:
        if finding["type"] not in SUPPORTED_FINDING_TYPES:
            unsupported_findings.append(finding)
            continue
        if finding["type"] not in selected_types:
            filtered_findings.append(finding)
            continue
        if confidence is not None and finding["confidence"] < confidence:
            filtered_findings.append(finding)
            continue
        findings.append(finding)

    return findings, unsupported_findings, filtered_findings


def _print_skipped_summary(console, unsupported_findings, filtered_findings):
    if unsupported_findings:
        unsupported_types = ", ".join(
            sorted({finding["type"] for finding in unsupported_findings})
        )
        count = len(unsupported_findings)
        console.print(
            f"[yellow]Skipping {count} unsupported dead code item{'s' if count != 1 else ''} "
            f"({unsupported_types}). Automatic edits currently support imports and functions only.[/yellow]\n"
        )

    if filtered_findings:
        count = len(filtered_findings)
        console.print(
            f"[dim]Skipping {count} dead code item{'s' if count != 1 else ''} "
            "outside the selected type or confidence filters.[/dim]\n"
        )


def _transform_for(finding_type, action):
    if action == "remove":
        if finding_type == "import":
            return remove_unused_import_cst
        if finding_type == "function":
            return remove_unused_function_cst
    if action == "comment":
        if finding_type == "import":
            return comment_out_unused_import_cst
        if finding_type == "function":
            return comment_out_unused_function_cst
    return None


def _apply_edits(edits_by_file, scan_root, console):
    applied = 0

    for file_edits in edits_by_file.values():
        file_edits.sort(key=lambda x: -x[0]["line"])
        for finding, action in file_edits:
            try:
                transform = _transform_for(finding["type"], action)
                if transform and _apply_codemod(
                    finding["file"],
                    transform,
                    finding["name"],
                    finding["line"],
                    root_path=scan_root,
                ):
                    applied += 1
            except Exception as e:
                verb = "remove" if action == "remove" else "comment out"
                console.print(f"  [red]Failed to {verb} {finding['name']}: {e}[/red]")

    return applied


def _edits_by_file(findings, action):
    edits_by_file = {}
    for finding in findings:
        edits_by_file.setdefault(finding["file"], []).append((finding, action))
    return edits_by_file


def _print_dry_run_plan(console, findings, action):
    verb = "comment out" if action == "comment" else "remove"
    console.print(
        f"[bold]Dry run:[/bold] would {verb} {len(findings)} dead code "
        f"item{'s' if len(findings) != 1 else ''}."
    )

    for file_path, file_edits in _edits_by_file(findings, action).items():
        console.print(f"\n[bold]{file_path}[/bold]")
        for finding, _action in sorted(file_edits, key=lambda x: x[0]["line"]):
            console.print(
                f"  L{finding['line']} {finding['type']} "
                f"{finding['name']} ({finding['confidence']}%)"
            )


def _run_noninteractive_clean(console, findings, scan_root, args):
    action = "comment" if args.comment_out else "remove"

    if args.dry_run:
        _print_dry_run_plan(console, findings, action)
        return 0

    edits_by_file = _edits_by_file(findings, action)
    applied = _apply_edits(edits_by_file, scan_root, console)
    verb = "commented out" if action == "comment" else "removed"
    console.print(f"\n[green]Done![/green] {verb.capitalize()} {applied} item(s).")
    return 0


def _run_interactive_clean(console, findings, scan_root):
    console.print(f"Found [bold]{len(findings)}[/bold] actionable dead code items.\n")

    to_remove = []
    to_comment = []
    skipped = 0

    for i, finding in enumerate(findings, 1):
        console.print(Rule(style="dim"))
        console.print(
            f"[bold][{i}/{len(findings)}][/bold] Unused {finding['type']} "
            f"[bold cyan]{finding['name']}[/bold cyan] at {finding['file']}:{finding['line']}"
        )
        console.print(f"         Confidence: [bold]{finding['confidence']}%[/bold]")

        try:
            choice = (
                input("\n  [R]emove  [C]omment-out  [S]kip  [Q]uit > ").strip().lower()
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Interrupted.[/dim]")
            break

        if choice in ("r", "remove"):
            to_remove.append(finding)
            console.print("  [green]Marked for removal[/green]")
        elif choice in ("c", "comment", "comment-out"):
            to_comment.append(finding)
            console.print("  [yellow]Marked for comment-out[/yellow]")
        elif choice in ("q", "quit"):
            console.print("[dim]Stopping early.[/dim]")
            break
        else:
            skipped += 1
            console.print("  [dim]Skipped[/dim]")

    if not to_remove and not to_comment:
        console.print("\n[dim]No changes to apply.[/dim]")
        return 0

    console.print(Rule(style="blue"))
    console.print(
        f"\n[bold]Summary:[/bold] {len(to_remove)} to remove, "
        f"{len(to_comment)} to comment out, {skipped} skipped\n"
    )

    try:
        confirm = input("Apply changes? (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled.[/dim]")
        return 0

    if confirm not in ("y", "yes"):
        console.print("[dim]No changes applied.[/dim]")
        return 0

    edits_by_file = {}
    for finding in to_remove:
        edits_by_file.setdefault(finding["file"], []).append((finding, "remove"))
    for finding in to_comment:
        edits_by_file.setdefault(finding["file"], []).append((finding, "comment"))

    applied = _apply_edits(edits_by_file, scan_root, console)
    console.print(
        f"\n[green]Done![/green] Applied {applied} changes "
        f"({len(to_remove)} removed, {len(to_comment)} commented out)."
    )
    return 0


def run_clean_command(argv: list[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    console = Console()
    noninteractive = args.dry_run or args.apply

    if args.comment_out and not noninteractive:
        console.print("[red]--comment-out requires --dry-run or --apply.[/red]")
        return 2

    try:
        selected_types = _parse_types(args.types)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    path = args.path
    scan_root = Path(path).resolve()
    if scan_root.is_file():
        scan_root = scan_root.parent

    console.print(
        Panel(
            "[bold]Skylos Clean[/bold] — Dead Code Cleanup",
            border_style="blue",
        )
    )
    console.print(f"Scanning [bold]{path}[/bold]...\n")

    confidence = _effective_confidence(args, noninteractive)
    result = _analyze(path, confidence)
    all_findings = _collect_all_findings(result)

    if not all_findings:
        console.print("[green]No dead code found. Your codebase is clean![/green]")
        return 0

    findings, unsupported_findings, filtered_findings = _filter_findings(
        all_findings, selected_types, confidence
    )
    _print_skipped_summary(console, unsupported_findings, filtered_findings)

    if not findings:
        console.print("[dim]No actionable dead code edits found.[/dim]")
        return 0

    if noninteractive:
        return _run_noninteractive_clean(console, findings, scan_root, args)
    return _run_interactive_clean(console, findings, scan_root)
