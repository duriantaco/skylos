from __future__ import annotations

import argparse
import json

from rich.console import Console
from rich.text import Text


def _local_report(report, include_aws_key_ids):
    from skylos.cli import _is_ci, _standalone_aws_access_key_id

    if include_aws_key_ids or _is_ci():
        return report
    raw_findings = report["secrets"]
    findings = [
        finding for finding in raw_findings if not _standalone_aws_access_key_id(finding)
    ]
    hidden = len(raw_findings) - len(findings)
    if not hidden:
        return report
    return {
        **report,
        "secrets": findings,
        "analysis_summary": {
            **report["analysis_summary"],
            "secrets_count": len(findings),
            "secrets_display_scope": "credential_material_only",
            "aws_access_key_identifiers_hidden": hidden,
        },
    }


def _render_history(report, console):
    summary = report["analysis_summary"]
    history = summary["git_history"]
    findings = report["secrets"]
    console.print(
        f"Git history scan {history['status']}. "
        f"{history['commits_scanned']} commits, {history['blobs_scanned']} blobs, "
        f"{len(findings)} findings."
    )
    hidden = summary.get("aws_access_key_identifiers_hidden", 0)
    if hidden:
        console.print(
            f"Credential material view hides {hidden} standalone AWS access-key IDs. "
            "Use --secrets-include-aws-key-ids to see them."
        )
    for finding in findings:
        console.print(
            Text(
                f"{finding['git_commit'][:12]} {finding['file']}:{finding['line']} "
                f"{finding['rule_id']} {finding.get('provider', 'credential')}"
            )
        )
    for error in report["analysis_errors"]:
        console.print(Text(error["message"]))


def run_secret_history_command(argv, *, console_factory=Console):
    parser = argparse.ArgumentParser(
        prog="skylos secrets-history",
        description="Scan stored credentials in a local Git repository's commit history.",
    )
    parser.add_argument(
        "path", nargs="?", default=".", help="Local repository path or subtree."
    )
    parser.add_argument(
        "--ref", default="HEAD", help="Local revision to scan from (default: HEAD)."
    )
    parser.add_argument(
        "--max-commits", type=int, help="Maximum number of reachable commits to read."
    )
    parser.add_argument("--format", choices=("rich", "json"), default="rich")
    parser.add_argument(
        "--secrets-include-aws-key-ids",
        action="store_true",
        help="Include standalone AWS access-key IDs in the local report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when a complete scan finds credentials.",
    )
    args = parser.parse_args(argv)
    options = {"ref": args.ref}
    if args.max_commits is not None:
        if args.max_commits < 1:
            parser.error("--max-commits must be positive")
        options["max_commits"] = args.max_commits

    from skylos.core.secret_history import scan_git_history

    try:
        report = scan_git_history(args.path, **options)
    except ValueError as error:
        parser.error(str(error))
    display = _local_report(report, args.secrets_include_aws_key_ids)
    if args.format == "json":
        print(json.dumps(display))
    else:
        _render_history(display, console_factory())
    if report["analysis_summary"]["git_history"]["status"] != "complete":
        return 2
    return int(bool(args.strict and report["secrets"]))
