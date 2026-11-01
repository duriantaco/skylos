"""A one-page Markdown or HTML report for people who will not read a scan log.

It states the verdict, the five risks to fix first with their fixes, the one
issue total by category, what was suppressed or dismissed, what the scan
could not check, and when, where and with which version it ran. The HTML is
self-contained: no scripts, fonts, images or stylesheets are fetched.
"""

from __future__ import annotations

import html
import subprocess
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from skylos.reporting.issue_summary import (
    ISSUE_CATEGORIES,
    count_text,
    issue_summary,
    listed_severity_counts,
    total_text,
)
from skylos.reporting.top_risks import rank_risks, scan_verdict, top_risks

REPORT_FORMATS = ("md", "html")
_GIT_TIMEOUT_SECONDS = 10
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_COVERAGE_REASONS = {
    "ai_verification_incomplete": (
        "AI-code checks: some languages in this repository have no "
        "verification yet, so AI-code findings may be missing for them."
    ),
    "dead_code_verification_incomplete": (
        "Dead code: the text-search double-check did not finish; some "
        "candidates were not verified."
    ),
    "language_engine_incomplete": (
        "Languages: a language engine was unavailable or incomplete; files in "
        "that language were not fully analysed."
    ),
    "analysis_incomplete": (
        "Analysis: some files could not be analysed; their findings are missing."
    ),
    "selected_scan_scope": "Scope: only part of the repository was scanned.",
    "selected_rules": "Rules: only the selected rules were run.",
}
_ALWAYS_TRUE = (
    "Static analysis only: no code was run, so runtime behaviour, deployment "
    "and network exposure were not checked."
)


def _mapping(value):
    if isinstance(value, Mapping):
        return value
    return {}


def _plural(count, singular, plural):
    if count == 1:
        return singular
    return plural


def _git(project_root, args):
    from skylos.core.git_safety import read_only_git_command, read_only_git_environment

    try:
        output = subprocess.check_output(
            read_only_git_command(args),
            cwd=str(project_root),
            env=read_only_git_environment(),
            stderr=subprocess.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return output.decode("utf-8", "replace").strip()


def scan_metadata(project_root, *, now=None) -> dict:
    """Date, commit and version of this scan; unknown values stay None."""
    from skylos import __version__

    moment = now or datetime.now(timezone.utc)
    commit = None
    modified = None
    branch = None
    if project_root is not None:
        commit = _git(project_root, ["rev-parse", "--short=12", "HEAD"]) or None
        if commit:
            status = _git(
                project_root, ["status", "--porcelain", "--untracked-files=no"]
            )
            if status is not None:
                modified = bool(status)
            branch = _git(project_root, ["rev-parse", "--abbrev-ref", "HEAD"]) or None
    return {
        "date": moment.strftime("%Y-%m-%d %H:%M UTC"),
        "commit": commit,
        "branch": branch,
        "uncommitted_changes": modified,
        "version": __version__,
        "project": Path(str(project_root or ".")).resolve().name,
    }


def _coverage_gaps(result, summary) -> list[str]:
    gaps = []
    sca = _mapping(_mapping(result.get("analysis_summary")).get("sca_coverage"))
    if "dependencies" in summary["not_checked"]:
        unresolved = sca.get("unresolved_dependency_count")
        detail = "no packages were looked up for known vulnerabilities"
        if isinstance(unresolved, int) and unresolved > 0:
            detail += f" ({unresolved} manifest versions are ranges, not pins)"
        gaps.append(
            f"Dependency vulnerabilities: not checked; {detail}. Add a lockfile "
            "(uv.lock, poetry.lock or package-lock.json) and scan again."
        )
    for category in summary["not_checked"]:
        if category == "dependencies":
            continue
        label = dict(ISSUE_CATEGORIES).get(category, category)
        gaps.append(f"{label}: not checked in this scan.")
    coverage = _mapping(_mapping(result.get("assessment")).get("coverage"))
    for reason in coverage.get("reasons") or ():
        text = _COVERAGE_REASONS.get(str(reason))
        if reason == "ai_verification_incomplete":
            text = _ai_verification_gap(result) or text
        if text and text not in gaps:
            gaps.append(text)
    errors = result.get("analysis_errors")
    if isinstance(errors, list) and errors:
        noun = _plural(len(errors), "analysis error", "analysis errors")
        gaps.append(
            f"{len(errors)} {noun}: see the scan output for the files affected."
        )
    gaps.append(_ALWAYS_TRUE)
    return gaps


def _ai_verification_gap(result):
    verification = _mapping(
        _mapping(result.get("analysis_summary")).get("ai_verification")
    )
    languages = sorted(
        {
            str(entry.get("language"))
            for entry in verification.get("language_support") or ()
            if isinstance(entry, Mapping)
            and entry.get("status") == "unsupported"
            and entry.get("language")
        }
    )
    if not languages:
        return None
    return (
        "AI-code checks: not available for "
        + ", ".join(languages)
        + " files, so AI-code mistakes there are not reported."
    )


def _gate_status(result, config):
    from skylos.core.gatekeeper import check_gate

    try:
        passed, reasons = check_gate(result, config or {})
    except Exception:
        return None
    return {
        "passed": bool(passed),
        "reasons": [str(reason) for reason in reasons],
        "configured": isinstance(_mapping(config).get("gate"), Mapping),
    }


def _category_rows(result, summary) -> list[tuple[str, str]]:
    rows = []
    for category, label in ISSUE_CATEGORIES:
        value = summary["by_category"].get(category)
        if category == "custom_rules" and not value:
            continue
        text = count_text(value)
        if category == "security" and value:
            severities = listed_severity_counts(result, "security")
            parts = [
                f"{severities[severity]} {severity.lower()}"
                for severity in _SEVERITY_ORDER
                if severities.get(severity)
            ]
            if parts:
                text = f"{value} ({', '.join(parts)})"
        rows.append((label, text))
    return rows


def build_report(result, *, project_root=None, config=None, now=None) -> dict:
    """Everything the page shows, computed from the scan's own decisions."""
    result = _mapping(result)
    rows = rank_risks(result, project_root=project_root, config=config)
    summary = issue_summary(result)
    return {
        "meta": scan_metadata(project_root, now=now),
        "verdict": scan_verdict(result, config=config, rows=rows),
        "top_risks": top_risks(result, rows=rows),
        "risk_count": len(rows),
        "summary": summary,
        "categories": _category_rows(result, summary),
        "gate": _gate_status(result, config),
        "coverage_gaps": _coverage_gaps(result, summary),
        "files": _mapping(result.get("analysis_summary")).get("total_files"),
        "lines": _mapping(result.get("analysis_summary")).get("total_loc"),
    }


def _meta_line(report) -> str:
    meta = report["meta"]
    parts = [f"Scanned {meta['date']}"]
    if meta["commit"]:
        commit = f"commit {meta['commit']}"
        if meta["branch"] and meta["branch"] != "HEAD":
            commit += f" on {meta['branch']}"
        if meta["uncommitted_changes"]:
            commit += " plus uncommitted changes"
        parts.append(commit)
    else:
        parts.append("commit unknown (not a Git checkout)")
    parts.append(f"Skylos {meta['version']}")
    if isinstance(report["files"], int):
        parts.append(f"{report['files']:,} files")
    if isinstance(report["lines"], int):
        parts.append(f"{report['lines']:,} lines")
    return " · ".join(parts)


def _total_line(report) -> str:
    return total_text(report["summary"]) + "."


def _gate_line(report) -> str:
    gate = report["gate"]
    if gate is None:
        return "Not evaluated."
    limits = "the default gate limits"
    if gate["configured"]:
        limits = "this project's gate limits"
    if gate["passed"]:
        return f"Passes {limits}."
    reasons = "; ".join(gate["reasons"]) or "limits exceeded"
    return f"Fails {limits}: {reasons}."


def _held_back_lines(summary) -> list[str]:
    lines = []
    if summary["suppressed_by_ignore_comments"]:
        count = summary["suppressed_by_ignore_comments"]
        lines.append(
            f"{count} {_plural(count, 'finding', 'findings')} suppressed with "
            "`skylos: ignore` comments."
        )
    if summary["held_back_unproven"]:
        count = summary["held_back_unproven"]
        lines.append(
            f"{count} candidate {_plural(count, 'finding', 'findings')} held back "
            "by the detector because it could not prove them (listed in the JSON "
            "report under `suppressed`)."
        )
    if summary["dismissed"]:
        count = summary["dismissed"]
        lines.append(
            f"{count} {_plural(count, 'finding', 'findings')} dismissed with `skylos review`."
        )
    if summary["hidden_advice"]:
        count = summary["hidden_advice"]
        lines.append(
            f"{count} maintainability advice {_plural(count, 'finding', 'findings')} "
            "hidden by default and not counted (`--all-advice` lists them)."
        )
    if not lines:
        lines.append("Nothing was suppressed or dismissed.")
    return lines


def _md(text) -> str:
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
    )


def _code(text) -> str:
    return "`" + str(text).replace("`", "'").replace("|", "\\|") + "`"


def _risk_tags(row) -> list[str]:
    tags = []
    if row.blocking:
        tags.append("blocks the gate")
    if row.in_tests:
        tags.append("test code")
    if row.more:
        tags.append(f"+{row.more} more like this")
    return tags


def render_markdown(report) -> str:
    verdict = report["verdict"]
    lines = [
        f"# Skylos report: {_md(report['meta']['project'])}",
        "",
        f"**{_md(verdict['text'])}.** {_md(_total_line(report))}",
        "",
        _md(_meta_line(report)),
        "",
        "## Top risks",
        "",
    ]
    if report["top_risks"]:
        lines.extend(
            [
                "| # | Severity | Issue | Location | Fix |",
                "|---|----------|-------|----------|-----|",
            ]
        )
        for index, row in enumerate(report["top_risks"], 1):
            issue = f"[{_md(row.title)}]({row.docs_url}) {_code(row.rule_id)}"
            tags = _risk_tags(row)
            if tags:
                issue += " (" + ", ".join(tags) + ")"
            lines.append(
                f"| {index} | {row.severity} | {issue} | {_code(row.location)} | {_md(row.fix)} |"
            )
        remaining = report["risk_count"] - sum(
            1 + row.more for row in report["top_risks"]
        )
        if remaining > 0:
            lines.extend(
                [
                    "",
                    f"{remaining} more risk {_plural(remaining, 'finding', 'findings')} in the full scan output.",
                ]
            )
    else:
        lines.append("No risk findings.")
    lines.extend(
        [
            "",
            "## Issues by category",
            "",
            "| Category | Issues |",
            "|----------|--------|",
        ]
    )
    for label, text in report["categories"]:
        lines.append(f"| {_md(label)} | {_md(text)} |")
    lines.append(f"| **Total** | **{report['summary']['total']}** |")
    lines.extend(["", "## Gate", "", _md(_gate_line(report))])
    lines.extend(["", "## Suppressed and dismissed", ""])
    lines.extend(f"- {line}" for line in _held_back_lines(report["summary"]))
    lines.extend(["", "## Not covered by this scan", ""])
    lines.extend(f"- {_md(gap)}" for gap in report["coverage_gaps"])
    lines.extend(
        [
            "",
            "---",
            "Generated by `skylos report`. Rule details: https://docs.skylos.dev/rules-reference",
            "",
        ]
    )
    return "\n".join(lines)


_CSS = """
:root{--fg:#1d2327;--muted:#5b6670;--line:#d9dee2;--bg:#ffffff;--panel:#f5f7f8;
--bad:#b42318;--warn:#a15c07;--good:#1a7f37;--accent:#0f766e}
@media (prefers-color-scheme: dark){:root{--fg:#e6e9eb;--muted:#a3adb5;--line:#3a4248;
--bg:#15191c;--panel:#1d2226;--bad:#f97066;--warn:#fdb022;--good:#47cd89;--accent:#2dd4bf}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:17px;margin:28px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}
.meta{color:var(--muted);font-size:13px;margin:0 0 16px}
.verdict{padding:14px 16px;border:1px solid var(--line);border-left:6px solid var(--muted);
background:var(--panel);margin:16px 0}
.verdict strong{font-size:18px;display:block}
.verdict.not_ready{border-left-color:var(--bad)}.verdict.not_ready strong{color:var(--bad)}
.verdict.incomplete,.verdict.review{border-left-color:var(--warn)}
.verdict.ready{border-left-color:var(--good)}.verdict.ready strong{color:var(--good)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td.num{white-space:nowrap}
code{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
.sev{font-weight:600;white-space:nowrap}
.sev.CRITICAL,.sev.HIGH{color:var(--bad)}.sev.MEDIUM,.sev.WARN{color:var(--warn)}
.tag{display:inline-block;font-size:12px;color:var(--muted);margin-left:4px}
.tag.block{color:var(--bad);font-weight:600}
a{color:var(--accent)}
ul{padding-left:20px;margin:6px 0}
footer{margin-top:32px;color:var(--muted);font-size:12px}
@media (max-width:640px){th:nth-child(4),td:nth-child(4){display:none}}
@media print{:root{--fg:#000;--muted:#444;--line:#bbb;--bg:#fff;--panel:#f3f3f3}
main{max-width:none;padding:0}body{font-size:11pt}a{color:#000;text-decoration:none}
tr,li,.verdict{break-inside:avoid}h2{break-after:avoid}}
"""


def _h(text) -> str:
    return html.escape(str(text), quote=True)


def _html_tag(tag) -> str:
    css = "tag"
    if tag == "blocks the gate":
        css = "tag block"
    return f'<span class="{css}">{_h(tag)}</span>'


def render_html(report) -> str:
    verdict = report["verdict"]
    meta = report["meta"]
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Skylos report: {_h(meta['project'])}</title>",
        f"<style>{_CSS}</style></head><body><main>",
        f"<h1>Skylos report: {_h(meta['project'])}</h1>",
        f'<p class="meta">{_h(_meta_line(report))}</p>',
        f'<div class="verdict {_h(verdict["status"])}"><strong>{_h(verdict["text"])}</strong>'
        f"{_h(_total_line(report))}</div>",
        "<h2>Top risks</h2>",
    ]
    if report["top_risks"]:
        parts.append(
            "<table><thead><tr><th>#</th><th>Severity</th><th>Issue and fix</th>"
            "<th>Location</th></tr></thead><tbody>"
        )
        for index, row in enumerate(report["top_risks"], 1):
            tags = "".join(_html_tag(tag) for tag in _risk_tags(row))
            parts.append(
                f'<tr><td class="num">{index}</td>'
                f'<td><span class="sev {_h(row.severity)}">{_h(row.severity)}</span></td>'
                f'<td><a href="{_h(row.docs_url)}">{_h(row.title)}</a> '
                f"<code>{_h(row.rule_id)}</code>{tags}<br>Fix: {_h(row.fix)}</td>"
                f"<td><code>{_h(row.location)}</code></td></tr>"
            )
        parts.append("</tbody></table>")
        remaining = report["risk_count"] - sum(
            1 + row.more for row in report["top_risks"]
        )
        if remaining > 0:
            parts.append(
                f'<p class="meta">{remaining} more risk '
                f"{_plural(remaining, 'finding', 'findings')} in the full scan output.</p>"
            )
    else:
        parts.append("<p>No risk findings.</p>")
    parts.append(
        "<h2>Issues by category</h2><table><thead><tr><th>Category</th>"
        "<th>Issues</th></tr></thead><tbody>"
    )
    for label, text in report["categories"]:
        parts.append(f"<tr><td>{_h(label)}</td><td>{_h(text)}</td></tr>")
    parts.append(
        f"<tr><td><strong>Total</strong></td><td><strong>{report['summary']['total']}"
        "</strong></td></tr></tbody></table>"
    )
    parts.append(f"<h2>Gate</h2><p>{_h(_gate_line(report))}</p>")
    parts.append("<h2>Suppressed and dismissed</h2><ul>")
    parts.extend(
        f"<li>{_h(line).replace('`', '')}</li>"
        for line in _held_back_lines(report["summary"])
    )
    parts.append("</ul><h2>Not covered by this scan</h2><ul>")
    parts.extend(f"<li>{_h(gap)}</li>" for gap in report["coverage_gaps"])
    parts.append(
        "</ul><footer>Generated by skylos report. Rule details: "
        '<a href="https://docs.skylos.dev/rules-reference">docs.skylos.dev/rules-reference</a>'
        "</footer></main></body></html>"
    )
    return "\n".join(parts) + "\n"


def render_report(
    result, report_format, *, project_root=None, config=None, now=None
) -> str:
    report = build_report(result, project_root=project_root, config=config, now=now)
    if report_format == "html":
        return render_html(report)
    return render_markdown(report)
