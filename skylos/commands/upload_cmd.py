"""``skylos upload``: resend scans whose upload to Skylos Cloud did not finish."""

from __future__ import annotations

import argparse
import json
import time

from rich.console import Console
from rich.markup import escape

__all__ = ["build_upload_parser", "run_upload_command"]


def build_upload_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos upload",
        description=(
            "Resend scans whose upload to Skylos Cloud did not finish. A scan is "
            "saved in .skylos/pending-uploads/ when an upload fails because of the "
            "network, a timeout, a server error or rate limiting, or when the upload "
            "is interrupted. Saved scans expire after 7 days."
        ),
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--retry",
        action="store_true",
        help=(
            "Resend every saved scan with its original idempotency key, so Skylos "
            "Cloud does not save or charge a scan twice. Sent scans are deleted; "
            "scans Cloud rejects move to .skylos/pending-uploads/failed/."
        ),
    )
    action.add_argument(
        "--list",
        action="store_true",
        help="List saved scans without sending them (the default).",
    )
    parser.add_argument(
        "--json", action="store_true", help="Print a machine-readable summary."
    )
    return parser


def _saved_at(created_at: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(created_at))
    except (OverflowError, OSError, ValueError):
        return "unknown time"


def _list(console: Console, as_json: bool) -> int:
    from skylos.api import _get_repo_root_for_link
    from skylos.api._pending_uploads import list_pending_uploads, pending_uploads_dir

    directory = pending_uploads_dir(_get_repo_root_for_link())
    pending, unreadable = list_pending_uploads(directory)
    if as_json:
        print(
            json.dumps(
                {
                    "directory": str(directory) if directory else None,
                    "pending": [
                        {
                            "idempotency_key": item.idempotency_key,
                            "created_at": item.created_at,
                            "kind": item.record.get("kind"),
                            "mode": item.record.get("mode"),
                            "finding_count": item.finding_count,
                            "last_error_code": (item.record.get("last_error") or {}).get(
                                "code"
                            ),
                        }
                        for item in pending
                    ],
                    "unreadable": unreadable,
                },
                indent=2,
            )
        )
        return 0
    if not pending:
        console.print("No saved uploads.")
        return 0
    noun = "scan is" if len(pending) == 1 else "scans are"
    console.print(f"{len(pending)} {noun} waiting to be sent:")
    for item in pending:
        count = item.finding_count
        findings = f"{count:,} findings" if isinstance(count, int) else "findings"
        code = (item.record.get("last_error") or {}).get("code") or "unknown error"
        console.print(
            f"  {escape(_saved_at(item.created_at))}  {escape(findings)}  "
            f"[dim]({escape(str(code))}, key {escape(item.idempotency_key[:8])})[/dim]"
        )
    if unreadable:
        console.print(f"[dim]{unreadable} saved file(s) could not be read and were skipped.[/dim]")
    console.print("Run [bold]skylos upload --retry[/bold] to send them.")
    return 0


def _undelivered(summary) -> int:
    return summary["failed"] + summary["kept"] + summary["skipped"]


def _retry(console: Console, as_json: bool) -> int:
    from skylos.api import resend_pending_uploads

    summary = resend_pending_uploads(quiet=as_json)
    if as_json:
        print(json.dumps(summary, indent=2, default=str))
        return 1 if summary.get("error") or _undelivered(summary) else 0

    if summary.get("error"):
        console.print(f"[red]Upload failed:[/red] {escape(str(summary['error']))}")
        return 1
    if not summary["total"]:
        console.print("No saved uploads to send.")
        return 0
    for outcome in summary["results"]:
        status = outcome["status"]
        if status == "kept":
            console.print(
                f"[yellow]Upload failed:[/yellow] {escape(outcome.get('error') or '')} "
                "It is still saved; run 'skylos upload --retry' again later."
            )
        elif status == "failed":
            console.print(
                f"[red]Upload rejected:[/red] {escape(outcome.get('error') or '')}"
            )
            if outcome.get("failed_path"):
                console.print(
                    f"[dim]Moved to {escape(outcome['failed_path'])} with the reason.[/dim]"
                )
        elif status == "skipped":
            console.print(
                f"[yellow]Not sent:[/yellow] {escape(outcome.get('reason') or '')}"
            )
    parts = []
    for key, label in (
        ("sent", "sent"),
        ("already_saved", "already saved earlier"),
        ("kept", "still waiting"),
        ("failed", "rejected"),
        ("skipped", "not sent"),
    ):
        if summary[key]:
            parts.append(f"{summary[key]} {label}")
    console.print("Saved uploads: " + ", ".join(parts) + ".")
    if summary.get("contract_notice"):
        console.print(escape(summary["contract_notice"]))
    return 1 if _undelivered(summary) else 0


def run_upload_command(argv) -> int:
    args = build_upload_parser().parse_args(argv)
    console = Console()
    if args.retry:
        return _retry(console, args.json)
    return _list(console, args.json)
