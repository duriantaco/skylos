"""``skylos agent recap``: what the agent hooks stopped in this repository.

Reads only the local hook log (``.skylos/hook.log`` and its rotated copy
``hook.log.1``), which the hooks write on every run. Nothing is uploaded and no
network request is made. The log holds counts and outcomes only, never file
contents or commands, so the recap is counts only too.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

TS_FORMAT = "%Y-%m-%dT%H:%M:%S"
DEFAULT_DAYS = 7
# Two log files of at most ~512 KB each; anything bigger is not ours.
MAX_READ_BYTES = 4_000_000

CLIENT_NAMES = {"claude": "Claude Code", "codex": "Codex", "cursor": "Cursor"}

# (id, group, singular, plural). Groups print in this order.
CATEGORIES: tuple[tuple[str, str, str, str], ...] = (
    (
        "install_hallucinated",
        "blocked",
        "install of a package that looks hallucinated or typosquatted",
        "installs of packages that look hallucinated or typosquatted",
    ),
    (
        "install_unverified",
        "blocked",
        "install from a source Skylos can't verify",
        "installs from sources Skylos can't verify",
    ),
    ("secret_read", "blocked", "read of a file holding secrets", "reads of files holding secrets"),
    (
        "secret_shell",
        "blocked",
        "shell command that would print a secret",
        "shell commands that would print a secret",
    ),
    (
        "hook_bypass",
        "blocked",
        "attempt to skip Git hooks or checks",
        "attempts to skip Git hooks or checks",
    ),
    (
        "edit_issue",
        "sent_back",
        "edit that added a security issue",
        "edits that added a security issue",
    ),
    (
        "done_refused",
        "sent_back",
        '"done" while checks still failed',
        '"done" claims while checks still failed',
    ),
    ("install_ask", "asked", "install Skylos couldn't verify", "installs Skylos couldn't verify"),
)
GROUP_TITLES = {
    "blocked": "Blocked before it ran",
    "sent_back": "Sent back to the agent to fix",
    "asked": "Asked you first",
}
_GROUP_OF = {cid: group for cid, group, _, _ in CATEGORIES}


def add_agent_recap_parser(agent_sub) -> None:
    parser = agent_sub.add_parser(
        "recap",
        help="Show what the agent hooks blocked in this repository (local log only)",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository (default: .)")
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        help=f"How many days back to count (default {DEFAULT_DAYS}; 0 = everything in the log)",
    )
    parser.add_argument("--format", choices=["table", "json"], default="table")


def log_files(root: Path) -> list[Path]:
    """The hook log files for ``root``, oldest first; symlinks are never followed."""
    from skylos.commands.hook_cmd import LOG_PATH, _git_root, _state_root

    base = _state_root(_git_root(root.resolve()))
    log_dir = base / LOG_PATH.parent
    if log_dir.is_symlink():
        return []
    current = base / LOG_PATH
    files = []
    for path in (current.with_name(current.name + ".1"), current):
        if path.is_symlink() or not path.is_file():
            continue
        files.append(path)
    return files


def read_records(files: Iterable[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    budget = MAX_READ_BYTES
    for path in files:
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)  # skylos: ignore[SKY-D215] hook log under the project's .skylos/; no-follow open
            with os.fdopen(fd, "rb") as handle:
                data = handle.read(budget)
        except OSError:
            continue
        budget -= len(data)
        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                records.append(record)
        if budget <= 0:
            break
    return records


def _timestamp(record: dict[str, Any]) -> datetime | None:
    value = record.get("ts")
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, TS_FORMAT)
    except ValueError:
        return None


def _count(record: dict[str, Any], key: str) -> int:
    value = record.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def classify(record: dict[str, Any]) -> str | None:
    """The recap category of one hook run, or None when it stopped nothing."""
    event, outcome = record.get("event"), record.get("outcome")
    if event == "pre-bash":
        if outcome == "block-bypass":
            return "hook_bypass"
        if outcome == "ask":
            return "install_ask"
        if outcome != "block":
            return None
        if _count(record, "secret_sources") > 0:
            return "secret_shell"
        if _count(record, "findings") > 0 and "packages" in record:
            return "install_hallucinated"
        return "install_unverified"
    if event == "pre-read" and outcome == "block":
        return "secret_read"
    if event == "post-edit" and outcome == "block":
        return "edit_issue"
    if event == "stop" and outcome == "block":
        return "done_refused"
    return None


def summarize(records: list[dict[str, Any]], *, days: int, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now()
    since = now - timedelta(days=days) if days > 0 else None
    counts: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    events: Counter[str] = Counter()
    errors = 0
    first = last = None
    for record in records:
        ts = _timestamp(record)
        if ts is None or (since is not None and ts < since):
            continue
        first = ts if first is None or ts < first else first
        last = ts if last is None or ts > last else last
        events[str(record.get("event") or "unknown")] += 1
        client = record.get("client")
        clients[client if isinstance(client, str) and client else "unknown"] += 1
        if record.get("outcome") == "error":
            errors += 1
        category = classify(record)
        if category:
            counts[category] += 1
    totals = Counter()
    for cid, n in counts.items():
        totals[_GROUP_OF[cid]] += n
    return {
        "window_days": days,
        "runs": sum(events.values()),
        "errors": errors,
        "first_activity": first.strftime(TS_FORMAT) if first else None,
        "last_activity": last.strftime(TS_FORMAT) if last else None,
        "categories": {cid: counts.get(cid, 0) for cid, _, _, _ in CATEGORIES},
        "blocked_total": totals.get("blocked", 0),
        "sent_back_total": totals.get("sent_back", 0),
        "asked_total": totals.get("asked", 0),
        "clients": dict(clients.most_common()),
        "events": dict(events.most_common()),
    }


def _window(days: int) -> str:
    if days <= 0:
        return "everything in the log"
    return "the last day" if days == 1 else f"the last {days} days"


def render_text(summary: dict[str, Any], *, has_log: bool, where: str) -> str:
    days = summary["window_days"]
    lines = [f"Skylos agent hooks · {_window(days)} · {where}", ""]
    if not has_log:
        lines += [
            "No hook log here yet.",
            "Install the hooks with `skylos agent install-hooks`, or run this in the",
            "repository where they're installed.",
        ]
        return "\n".join(lines) + "\n"
    if summary["runs"] == 0:
        lines += [
            f"No hook activity in {_window(days)}.",
            "If an agent worked here in that time, run `skylos doctor` to check the hooks still work.",
        ]
        return "\n".join(lines) + "\n"

    stopped = summary["blocked_total"] + summary["sent_back_total"] + summary["asked_total"]
    if stopped == 0:
        lines.append(f"Nothing blocked in {_window(days)}.")
    for group, title in GROUP_TITLES.items():
        rows = [
            (summary["categories"][cid], singular, plural)
            for cid, g, singular, plural in CATEGORIES
            if g == group and summary["categories"][cid]
        ]
        if not rows:
            continue
        lines.append(title)
        for n, singular, plural in rows:
            lines.append(f"  {n:>4}  {singular if n == 1 else plural}")
    if stopped:
        lines.append("")

    runs = summary["runs"]
    checked = f"Checked: {runs} hook run{'s' if runs != 1 else ''}"
    errors = summary["errors"]
    if errors:
        checked += f" · {errors} allowed without a check (hook error): run `skylos doctor`"
    lines.append(checked)
    agents = " · ".join(f"{CLIENT_NAMES.get(c, c)} {n}" for c, n in summary["clients"].items())
    if agents:
        lines.append(f"Agents: {agents}")
    if summary["last_activity"]:
        lines.append(f"Last activity: {summary['last_activity'].replace('T', ' ')}")
    lines.append("Local log only (.skylos/hook.log). Nothing here was uploaded.")
    return "\n".join(lines) + "\n"


def run_agent_recap_command(args, stdout=None) -> int:
    import sys

    out = stdout or sys.stdout
    root = Path(getattr(args, "path", ".") or ".")
    if not root.is_dir():
        out.write(f"Not a directory: {root}\n")
        return 2
    days = max(int(getattr(args, "days", DEFAULT_DAYS) or 0), 0)
    files = log_files(root)
    summary = summarize(read_records(files), days=days)
    if getattr(args, "format", "table") == "json":
        out.write(json.dumps({**summary, "log_found": bool(files)}, indent=2) + "\n")
        return 0
    where = _display_path(root)
    out.write(render_text(summary, has_log=bool(files), where=where))
    return 0


def _display_path(root: Path) -> str:
    resolved = root.resolve()
    home = Path.home()
    try:
        return "~/" + str(resolved.relative_to(home)) if resolved != home else "~"
    except ValueError:
        return str(resolved)
