"""The first screen of a rich scan: the verdict, one total and the top risks."""

from __future__ import annotations

from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel

from skylos.reporting.issue_summary import category_label, issue_summary, total_text
from skylos.reporting.top_risks import TOP_RISK_LIMIT, rank_risks, scan_verdict

_SEVERITY_STYLES = {
    "CRITICAL": "bad",
    "HIGH": "bad",
    "MEDIUM": "warn",
    "WARN": "warn",
    "WARNING": "warn",
}
_VERDICT_STYLES = {
    "not_ready": "bad",
    "incomplete": "warn",
    "review": "warn",
    "ready": "good",
}
_NOT_CHECKED_REASONS = {
    "dependencies": "dependencies (no packages were looked up)",
}


def severity_style(severity) -> str:
    return _SEVERITY_STYLES.get(str(severity or "").upper(), "muted")


def _plural(count, singular, plural):
    if count == 1:
        return singular
    return plural


def not_checked_text(summary) -> str:
    missing = [
        _NOT_CHECKED_REASONS.get(category, category_label(category))
        for category in summary["not_checked"]
    ]
    if not missing:
        return ""
    return "Not checked: " + ", ".join(missing)


def render_scan_overview(
    console, result, *, root_path=None, config=None, files_label="?"
):
    """Verdict, the one issue total, then up to five risks with their fixes."""
    rows = rank_risks(result, project_root=root_path, config=config)
    verdict = scan_verdict(result, config=config, rows=rows)
    summary = issue_summary(result)
    style = _VERDICT_STYLES.get(verdict["status"], "muted")
    lines = [
        f"[brand]Static Analysis Results[/brand] [muted]· {escape(str(files_label))} files analysed[/muted]",
        f"[{style}]{escape(verdict['text'])}[/{style}]",
        escape(total_text(summary)),
    ]
    missing = not_checked_text(summary)
    if missing:
        lines.append(f"[warn]{escape(missing)}[/warn]")
    console.print(Panel.fit("\n".join(lines), border_style="brand"))
    render_top_risks(console, result, root_path=root_path, config=config, rows=rows)
    return verdict


def render_top_risks(console, result, *, root_path=None, config=None, rows=None):
    from skylos.reporting.top_risks import top_risks

    if rows is None:
        rows = rank_risks(result, project_root=root_path, config=config)
    top = top_risks(result, limit=TOP_RISK_LIMIT, rows=rows)
    if not top:
        return []
    console.print("[bold]Top risks[/bold] [muted](fix these first)[/muted]")
    for index, row in enumerate(top, 1):
        style = severity_style(row.severity)
        head = (
            f"{index}. [{style}]{escape(row.severity)}[/{style}] "
            f"[bold]{escape(row.title)}[/bold] "
            f"[muted][link={escape(row.docs_url)}]{escape(row.rule_id)}[/link][/muted]"
        )
        tags = []
        if row.blocking:
            tags.append("[bad]blocks the gate[/bad]")
        if row.in_tests:
            tags.append("[muted]test code[/muted]")
        if row.more:
            tags.append(f"[muted]+{row.more} more like this[/muted]")
        if tags:
            head = f"{head} · " + " · ".join(tags)
        console.print(head)
        body = "\n".join(
            [
                f"[brand]{escape(row.location)}[/brand]",
                f"Fix: {escape(row.fix)}",
                f"[muted][link={escape(row.docs_url)}]{escape(row.docs_url)}[/link][/muted]",
            ]
        )
        console.print(Padding(body, (0, 0, 0, 3)))
    remaining = len(rows) - sum(1 + row.more for row in top)
    if remaining > 0:
        noun = _plural(remaining, "risk finding", "risk findings")
        console.print(
            f"[muted]{remaining} more {noun} below, sorted by severity with "
            "production code first.[/muted]"
        )
    console.print()
    return top


def next_fix_line(result, *, root_path=None, config=None) -> str | None:
    """``fix SKY-D212 Command injection at path:line first`` for a CRITICAL or
    HIGH top risk, else None."""
    from skylos.reporting.top_risks import top_risks

    top = top_risks(result, project_root=root_path, config=config, limit=1)
    if not top or top[0].severity not in {"CRITICAL", "HIGH"}:
        return None
    row = top[0]
    text = f"fix {row.rule_id} {row.title} at {row.location} first"
    if row.blocking:
        text += " (it blocks the gate)"
    return text
