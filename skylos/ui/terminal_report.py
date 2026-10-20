from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from skylos.api._snippets import _resolve_snippet_path
from skylos.deadcode.confidence import confidence_detail
from skylos.reporting.advice_display import (
    ADVICE_PRIORITY_NOTE,
    advice_display_counts,
    advice_priority,
    combine_complexity_advice,
    complexity_display,
    group_advice_for_display,
)
from skylos.reporting.advice_policy import prepare_advice_view
from skylos.reporting.assessment_display import (
    assessment_coverage_text,
    assessment_rows,
    dependency_coverage_lines,
    maintainability_rows,
)
from skylos.reporting.finding_types import (
    get_finding_type,
    iter_result_findings,
)
from skylos.reporting.rollups import FINDING_SECTIONS
from skylos.reporting.typing_coverage import typing_coverage_text
from skylos.ui.dead_code_evidence import (
    compact_dead_code_evidence,
    dead_code_candidate_counts,
    dead_code_uncertainty_summary,
    dead_code_uncertainty_text,
)
from skylos.ui.quality_advice import pytest_signature_advice, pytest_signature_title
from skylos.ui.scope_notes import scope_note_lines
from skylos.ui.security_evidence import security_evidence_details

CATEGORY_SPECS = (
    ("analysis_errors", "Analysis", "File analysis failed"),
    ("ai_defects", "AI Defect", "AI defect"),
    ("danger", "Security", "security issue"),
    ("reliability", "Reliability", "reliability issue"),
    ("secrets", "Secret", "secret detected"),
    ("quality", "Quality", "quality issue"),
    ("circular_dependencies", "Architecture", "circular dependency"),
    ("custom_rules", "Custom", "custom rule"),
    ("dependency_vulnerabilities", "Dependency", "dependency vulnerability"),
    ("publisher_change_findings", "Publisher review", "npm publisher change"),
    ("unused_functions", "Dead Code", "unused function"),
    ("unused_imports", "Dead Code", "unused import"),
    ("unused_classes", "Dead Code", "unused class"),
    ("unused_variables", "Dead Code", "unused variable"),
    ("unused_parameters", "Dead Code", "unused parameter"),
    ("unused_files", "Dead Code", "unused file"),
    ("unused_fixtures", "Dead Code", "unused fixture"),
    ("unused_exports", "Dead Code", "unused export"),
)

DEAD_CODE_TYPES = {
    "unused_functions": "function",
    "unused_imports": "import",
    "unused_classes": "class",
    "unused_variables": "variable",
    "unused_parameters": "parameter",
    "unused_files": "file",
    "unused_fixtures": "fixture",
    "unused_exports": "export",
}

SEVERITY_STYLES = {
    "CRITICAL": "bold white on magenta",
    "HIGH": "bold white on red",
    "MEDIUM": "bold black on yellow",
    "LOW": "bold white on blue",
    "WARN": "bold black on yellow",
    "INFO": "dim",
}

SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "WARN": 2,
    "INFO": 4,
}

SUMMARY_CATEGORIES = (
    "analysis_errors",
    "unused_functions",
    "unused_imports",
    "unused_parameters",
    "unused_variables",
    "unused_classes",
    "unused_files",
    "ai_defects",
    "quality",
    "circular_dependencies",
    "custom_rules",
    "danger",
    "reliability",
    "secrets",
    "dependency_vulnerabilities",
    "publisher_change_findings",
)

_TERMINAL_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


@dataclass(frozen=True)
class PrettyFinding:
    category: str
    category_label: str
    fallback_label: str
    file: str
    line: int
    severity: str
    rule: str
    title: str
    snippet: str
    fix: str
    why: str = ""
    finding_type: str = "review"
    details: tuple[str, ...] = ()


def render_pretty_results(
    console: Console,
    result: dict,
    *,
    root_path=None,
    limit: int | None = None,
    expand_advice: bool = False,
    all_advice: bool = False,
) -> None:
    result, visibility = prepare_advice_view(
        result, project_root=root_path, all_advice=all_advice
    )
    from skylos.reporting.sca_summary import group_advisories, is_advisory

    # Advisories print as one row per package; JSON keeps every advisory.
    advisory_groups = group_advisories(result.get("dependency_vulnerabilities") or [])
    display = result
    if advisory_groups:
        display = dict(result)
        display["dependency_vulnerabilities"] = [
            item
            for item in result.get("dependency_vulnerabilities") or []
            if not is_advisory(item)
        ]
    findings = collect_pretty_findings(display, root_path=root_path, limit=limit)
    total_files = (result.get("analysis_summary") or {}).get("total_files", "?")

    header = Text.assemble(
        ("Skylos", "bold cyan"),
        (" static analysis", "bold"),
        (f"  {_finding_type_headline(result)}", "dim"),
        (f"  {total_files} file{'s' if total_files != 1 else ''} analyzed", "dim"),
    )
    console.print(header)
    annotation_summary = typing_coverage_text(result.get("analysis_summary"))
    if annotation_summary:
        console.print(Text(annotation_summary, style="dim"))

    summary = _summary_line(result)
    if summary.plain:
        console.print(summary)
    if visibility.message:
        console.print(Text(_sanitize_terminal_text(visibility.message), style="dim"))
    if advice_display_counts(result)["advice"]:
        console.print(Text(ADVICE_PRIORITY_NOTE, style="dim"))
    uncertainty = dead_code_uncertainty_text(dead_code_uncertainty_summary(result))
    if uncertainty:
        console.print(Text(_sanitize_terminal_text(uncertainty), style="yellow"))
    _print_architecture_advisory_status(console, result)
    _print_publisher_review_status(console, result)
    _print_assessment(console, result)
    if not isinstance(result.get("assessment"), dict) or not result["assessment"]:
        for detail in dependency_coverage_lines(result.get("analysis_summary")):
            console.print(Text("  " + _sanitize_terminal_text(detail), style="dim"))
    summary = result.get("analysis_summary") or {}
    if summary.get("assessment_includes_filtered_findings") or summary.get(
        "grade_includes_filtered_findings"
    ):
        label = "Assessment" if result.get("assessment") else "Grade"
        console.print(
            Text(
                f"  {label} includes all analyzed findings, including those outside this display.",
                style="dim",
            )
        )
    for note in scope_note_lines(result):
        console.print(Text(f"  {_sanitize_terminal_text(note)}", style="dim"))
    _print_directory_rollups(console, result)
    console.print()

    if not findings and not advisory_groups:
        console.print(Text("  No findings to display.", style="bold green"))
        return

    _print_sca_packages(console, advisory_groups, root_path=root_path, limit=limit)
    for finding_type in ("defect", "review", "advice"):
        if finding_type == "advice" and not expand_advice:
            _print_advice_groups(console, result, root_path=root_path, limit=limit)
            continue
        selected = [
            finding for finding in findings if finding.finding_type == finding_type
        ]
        if not selected:
            continue
        label = "Defects" if finding_type == "defect" else finding_type.title()
        console.print(Text(f"  {label}", style="bold"))
        by_file: dict[str, list[PrettyFinding]] = {}
        for finding in selected:
            by_file.setdefault(finding.file, []).append(finding)
        for file_path in sorted(by_file):
            file_findings = sorted(
                by_file[file_path],
                key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.line, f.rule),
            )
            short_path = _sanitize_terminal_text(_shorten_path(file_path, root_path))
            console.print(
                Text.assemble(
                    ("  ", ""),
                    (short_path, "bold"),
                    (" · ", "dim"),
                    (_finding_count_label(file_findings), "dim"),
                )
            )
            console.print()
            for finding in file_findings:
                _print_finding(console, finding, short_path)
            console.print()

    _print_footer(console, findings)


def _print_sca_packages(console: Console, groups, *, root_path=None, limit=None):
    from skylos.reporting.sca_summary import summary_footer

    if not groups:
        return
    console.print(Text("  Dependency vulnerabilities, by package", style="bold"))
    shown = groups if limit is None else groups[:limit]
    for group in shown:
        location = _sanitize_terminal_text(
            f"{_shorten_path(group.file, root_path)}:{group.line}"
        )
        console.print(
            Text.assemble(
                ("  ", ""),
                (
                    _severity_badge(group.worst_severity),
                    _severity_rail_style(group.worst_severity),
                ),
                (" ", ""),
                (_sanitize_terminal_text(f"{group.name}@{group.version}"), "bold"),
                (_sanitize_terminal_text(f"  upgrade to {group.fix_text()}"), ""),
                (
                    _sanitize_terminal_text(f"  {group.count}: {group.ids_text()}"),
                    "dim",
                ),
                (f"  {location}", "dim"),
            )
        )
    if len(shown) < len(groups):
        console.print(
            Text(f"  ... and {len(groups) - len(shown)} more packages", style="dim")
        )
    console.print(Text("  " + summary_footer(groups), style="dim"))
    console.print()


def _print_assessment(console: Console, result: dict) -> None:
    assessment = result.get("assessment")
    if not isinstance(assessment, dict) or not assessment:
        return
    for label, detail in assessment_rows(
        assessment, gate=result.get("gate") or result.get("quality_gate")
    ):
        console.print(
            Text.assemble(
                (f"  {label}: ", "bold"), (_sanitize_terminal_text(detail), "")
            )
        )
    console.print(
        Text(
            "  " + _sanitize_terminal_text(assessment_coverage_text(assessment)),
            style="dim",
        )
    )
    for detail in dependency_coverage_lines(result.get("analysis_summary")):
        console.print(Text("  " + _sanitize_terminal_text(detail), style="dim"))
    for label, spread, magnitude in maintainability_rows(assessment):
        console.print(
            Text(
                "    " + _sanitize_terminal_text(f"{label}: {spread}; {magnitude}"),
                style="dim",
            )
        )


def _print_architecture_advisory_status(console: Console, result: dict) -> None:
    metrics = result.get("architecture_metrics")
    if not isinstance(metrics, dict):
        return
    count = metrics.get("advisory_count")
    if not isinstance(count, int) or count <= 0:
        return
    signals = metrics.get("advisory_signal_count")
    signal_label = f" ({signals} signals)" if isinstance(signals, int) else ""
    console.print(
        Text(
            f"  Architecture: {count} advisory module{'s' if count != 1 else ''}"
            f"{signal_label}; maintainability advice; gates use configured limits; "
            "see architecture_metrics.advisories in JSON",
            style="dim",
        )
    )


def _print_publisher_review_status(console: Console, result: dict) -> None:
    receipt = (result.get("analysis_summary") or {}).get("publisher_change_scan")
    if not isinstance(receipt, dict):
        return
    status = receipt.get("status")
    if status == "no_inputs":
        console.print(
            Text("  npm publisher review: no supported package lockfile", style="dim")
        )
    elif status not in {"complete", "disabled"}:
        warnings = receipt.get("warnings")
        detail = warnings[0] if isinstance(warnings, list) and warnings else status
        message = _sanitize_terminal_text(str(detail or "check incomplete"))
        console.print(
            Text(
                f"  npm publisher review incomplete: {_truncate(message, 160)}",
                style="yellow",
            )
        )


def _finding_count_label(findings: list[PrettyFinding]) -> str:
    counts = Counter(finding.finding_type for finding in findings)
    return (
        " · ".join(
            f"{counts[kind]} {('defect' if counts[kind] == 1 else 'defects') if kind == 'defect' else kind}"
            for kind in ("defect", "review", "advice")
            if counts[kind]
        )
        or "0 defects"
    )


def _finding_type_headline(result):
    counts = advice_display_counts(result)
    defect_label = "defect" if counts["defect"] == 1 else "defects"
    group_label = "group" if counts["advice_groups"] == 1 else "groups"
    advice = f"{counts['advice']} advice"
    if counts["raw_advice"] != counts["advice"]:
        entry_label = "entry" if counts["advice"] == 1 else "entries"
        advice += f" {entry_label} ({counts['raw_advice']} findings)"
    return (
        f"{counts['defect']} {defect_label} · {counts['review']} review · "
        f"{advice} in {counts['advice_groups']} {group_label}"
    )


def _print_advice_groups(console, result, *, root_path=None, limit=None):
    groups = group_advice_for_display(result)
    if not groups:
        return
    console.print(Text("  Advice", style="bold"))
    table = Table(box=None, padding=(0, 1), expand=True)
    table.add_column("Type", width=6)
    table.add_column("Advice priority", width=15, overflow="fold")
    table.add_column("Rule", width=20, overflow="fold")
    table.add_column("Count", width=5, justify="right")
    table.add_column("Top files", overflow="fold")
    visible = groups if limit is None else groups[:limit]
    for group in visible:
        severities = ", ".join(
            sorted(
                {
                    advice_priority(finding, "quality")
                    for finding in group["findings"]
                }
            )
        )
        files = Counter(
            str(finding.get("file") or finding.get("file_path") or "?")
            for finding in group["findings"]
        )
        top = sorted(files, key=lambda file: (-files[file], file))[:3]
        names = [f"{_shorten_path(file, root_path)} ({files[file]})" for file in top]
        if len(files) > len(top):
            names.append(f"+{len(files) - len(top)} more files")
        table.add_row(
            "Advice",
            _sanitize_terminal_text(severities),
            Text(
                _sanitize_terminal_text(str(group["name"]))
                + "\n"
                + _sanitize_terminal_text(str(group["rule_id"]))
            ),
            str(group["count"]),
            Text("\n".join(_sanitize_terminal_text(name) for name in names)),
        )
    console.print(table)
    if len(visible) < len(groups):
        console.print(
            Text(
                f"  ... and {len(groups) - len(visible)} more advice groups (use --limit to adjust)",
                style="dim",
            )
        )
    console.print(
        Text(
            "  Use --expand-advice for every location and message, or --format json for full records.",
            style="dim",
        )
    )
    console.print()


def collect_pretty_findings(
    result: dict,
    *,
    root_path=None,
    limit: int | None = None,
) -> list[PrettyFinding]:
    source_cache: dict[str, list[str] | None] = {}
    findings: list[PrettyFinding] = []
    source_sections = {}
    for section in [
        *(section for section, _ in FINDING_SECTIONS),
        "circular_dependencies",
        "publisher_change_findings",
    ]:
        for item in result.get(section, []) or []:
            source_sections.setdefault((id(item), section == "custom_rules"), section)
    by_category = {"analysis_errors": result.get("analysis_errors", []) or []}
    for category, item in combine_complexity_advice(iter_result_findings(result)):
        section = source_sections.get((id(item), category == "custom_rules"), "quality")
        by_category.setdefault(section, []).append(item)

    for category, category_label, fallback_label in CATEGORY_SPECS:
        items = by_category.get(category, [])
        if limit is not None:
            items = items[:limit]
        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append(
                _make_pretty_finding(
                    category,
                    category_label,
                    fallback_label,
                    item,
                    root_path=root_path,
                    source_cache=source_cache,
                )
            )

    return findings


def _make_pretty_finding(
    category: str,
    category_label: str,
    fallback_label: str,
    item: dict,
    *,
    root_path=None,
    source_cache: dict[str, list[str] | None],
) -> PrettyFinding:
    file_path = _sanitize_terminal_text(
        str(item.get("file") or item.get("file_path") or "?")
    )
    line = _line_number(item)
    severity = _severity(item, category)
    complexity = complexity_display(item)
    rule = _sanitize_terminal_text(
        complexity.rule_label if complexity is not None else _rule_id(item, category)
    )
    title = _sanitize_terminal_text(
        f"{complexity.name}: {item.get('name') or item.get('simple_name')}"
        if complexity is not None
        else _title(item, category, fallback_label)
    )
    snippet = _sanitize_terminal_text(
        _snippet(item, category, root_path=root_path, source_cache=source_cache)
    )
    fix = _sanitize_terminal_text(_fix(item, category))
    why = _sanitize_terminal_text(
        _dead_code_why(item) if category in DEAD_CODE_TYPES else ""
    )
    details = _context_details(item)
    if complexity is not None:
        details = [*complexity.message.splitlines(), *details]
    return PrettyFinding(
        category=category,
        category_label=category_label,
        fallback_label=fallback_label,
        file=file_path,
        line=line,
        severity=severity,
        rule=rule,
        title=title,
        snippet=snippet,
        fix=fix,
        why=why,
        finding_type=get_finding_type(item, category),
        details=tuple(_sanitize_terminal_text(detail) for detail in details),
    )


def _context_details(item):
    details = security_evidence_details(item)
    test_advice = pytest_signature_advice(item)
    if test_advice:
        details.append(test_advice)
    confidence = confidence_detail(item)
    if confidence:
        details.append(confidence)
    symbol = item.get("symbol")
    if symbol and symbol != "<module>":
        details.append(f"Symbol: {symbol}")
    if item.get("ai_authored"):
        details.append(f"AI: {item.get('ai_agent') or 'ai'}")
    verification = item.get("verification")
    if isinstance(verification, dict) and verification.get("verdict"):
        details.append(f"Verified: {verification['verdict']}")
        evidence = verification.get("evidence")
        chain = evidence.get("chain") if isinstance(evidence, dict) else None
        if isinstance(chain, list) and chain:
            names = [
                str(part.get("fn") or "?") if isinstance(part, dict) else "?"
                for part in chain[:6]
            ]
            details.append("Proof: " + " -> ".join(names))
    return details


def _print_finding(console: Console, finding: PrettyFinding, short_path: str) -> None:
    priority_label = "Advice priority" if finding.finding_type == "advice" else "Severity"
    first = Text.assemble(
        ("    ", ""),
        ("█", _severity_rail_style(finding.severity)),
        (" ", ""),
        (f"Type: {finding.finding_type.title()}  {priority_label}: ", "dim"),
        (
            _severity_badge(finding.severity),
            SEVERITY_STYLES.get(finding.severity, "dim"),
        ),
        (" ", ""),
        (finding.rule, "cyan"),
        ("  ", ""),
        (finding.title, ""),
    )
    console.print(first)

    meta = Text.assemble(
        ("      ", ""),
        (finding.category_label, "dim"),
        ("  ", "dim"),
        (f"{short_path}:{finding.line}", "dim"),
    )
    console.print(meta)

    if finding.why:
        console.print(
            Text.assemble(
                ("      evidence: ", "dim"),
                (finding.why, "dim"),
            )
        )

    if finding.snippet:
        console.print(
            Text.assemble(
                ("      ", ""),
                (finding.snippet.strip(), "dim"),
            )
        )

    for detail in finding.details:
        console.print(Text.assemble(("      ", "dim"), (detail, "dim")))

    if finding.fix:
        label = (
            "Review: " if finding.category == "publisher_change_findings" else "Fix: "
        )
        console.print(
            Text.assemble((f"      {label}", "bold green"), (finding.fix, ""))
        )

    console.print()


def _print_footer(console: Console, findings: list[PrettyFinding]) -> None:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    console.print(Text("  " + "─" * 52, style="dim"))
    parts: list[Text] = [
        Text(
            f"  {_finding_count_label(findings)}",
            style="bold",
        )
    ]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "WARN", "LOW", "INFO"):
        count = counts.get(severity, 0)
        if not count:
            continue
        parts.append(Text("  "))
        parts.append(_summary_badge(severity, count))

    line = Text()
    for part in parts:
        line.append(part)
    console.print(line)


def _summary_line(result: dict) -> Text:
    parts: list[Text] = []
    for category in SUMMARY_CATEGORIES:
        count = len(result.get(category, []) or [])
        if not count:
            continue
        label = category.replace("unused_", "unused ").replace("_", " ")
        if parts:
            parts.append(Text("  "))
        parts.append(Text(f"{label}: {count}", style="dim"))

    evidence_counts = dead_code_candidate_counts(result)
    for key, label in (("rescued", "rescued"), ("abstained", "abstained")):
        count = evidence_counts.get(key, 0)
        if not count:
            continue
        if parts:
            parts.append(Text("  "))
        parts.append(Text(f"dead-code {label}: {count}", style="dim"))

    if not parts:
        return Text()

    line = Text("  ")
    for part in parts:
        line.append(part)
    return line


def _print_directory_rollups(console: Console, result: dict) -> None:
    rollups = (result.get("analysis_summary") or {}).get("by_directory") or []
    if not isinstance(rollups, list):
        return

    visible = [item for item in rollups if isinstance(item, dict)][:5]
    if not visible:
        return

    console.print(Text("  Hot directories", style="bold"))
    for item in visible:
        path = _sanitize_terminal_text(str(item.get("path") or "."))
        total = _safe_int(item.get("total"))
        files = _safe_int(item.get("files"))
        detail = _directory_rollup_detail(item, total)

        segments = [
            (_truncate(path, 64), "bold"),
            (_plural_count(total, "issue"), "dim"),
            (_plural_count(files, "file"), "dim"),
            (detail, "dim"),
        ]
        line = Text("    ")
        for index, segment in enumerate(segments):
            if index:
                line.append(" · ", style="dim")
            text, style = segment
            line.append(text, style=style)
        console.print(line)


def _directory_rollup_detail(item: dict, total: int) -> str:
    parts = []
    categories = (
        ("dead_code", "dead"),
        ("quality", "quality"),
        ("reliability", "reliability"),
        ("security", "security"),
        ("secrets", "secrets"),
        ("dependencies", "deps"),
    )
    for key, label in categories:
        count = _safe_int(item.get(key))
        if count:
            parts.append(f"{label}: {count}")
    if parts:
        return ", ".join(parts)
    return _plural_count(total, "issue")


def _plural_count(count: int, noun: str) -> str:
    if count == 1:
        return f"{count} {noun}"
    return f"{count} {noun}s"


def _safe_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _summary_badge(severity: str, count: int) -> Text:
    style = SEVERITY_STYLES.get(severity, "dim")
    return Text(f" {count} {severity.lower()} ", style=style)


def _severity_badge(severity: str) -> str:
    label = severity.upper()
    if label == "CRITICAL":
        return " CRITICAL "
    if label == "HIGH":
        return " HIGH "
    if label == "MEDIUM":
        return " MEDIUM "
    if label in {"WARN", "WARNING"}:
        return " WARN "
    if label == "LOW":
        return " LOW "
    return " INFO "


def _severity_rail_style(severity: str) -> str:
    label = severity.upper()
    if label == "CRITICAL":
        return "magenta"
    if label == "HIGH":
        return "red"
    if label == "MEDIUM":
        return "yellow"
    if label in {"WARN", "WARNING"}:
        return "yellow"
    if label == "LOW":
        return "blue"
    return "dim"


def _shorten_path(path: str, root_path=None) -> str:
    if not path or path == "?":
        return "?"

    raw = Path(path)
    root = Path(root_path) if root_path is not None else Path.cwd()

    try:
        if raw.is_absolute():
            return str(raw.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        pass

    return str(path)


def _line_number(item: dict) -> int:
    raw = item.get("line") or item.get("line_number") or item.get("lineno") or 1
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return 1


def _severity(item: dict, category: str) -> str:
    if get_finding_type(item, category) == "advice":
        return advice_priority(item, category)
    raw = item.get("severity")
    if raw:
        label = str(raw).strip().upper()
        if label:
            return label
    if category in {"danger", "secrets", "dependency_vulnerabilities"}:
        return "HIGH"
    if category in {"quality", "custom_rules", "reliability"}:
        return "MEDIUM"
    return "LOW"


def _rule_id(item: dict, category: str) -> str:
    rule = item.get("rule_id") or item.get("rule") or item.get("code") or item.get("id")
    if rule:
        return str(rule)
    if category in DEAD_CODE_TYPES:
        return f"dead-code/{DEAD_CODE_TYPES[category]}"
    return category.replace("_", "-")


def _title(item: dict, category: str, fallback_label: str) -> str:
    if category == "quality" and pytest_signature_advice(item):
        return pytest_signature_title(item)
    if category in DEAD_CODE_TYPES:
        name = item.get("name") or item.get("simple_name") or item.get("symbol")
        if name:
            title = f"Unused {DEAD_CODE_TYPES[category]}: {name}"
            message = item.get("message")
            return f"{title}\n{message}" if message and str(message) != title else title

    if category == "dependency_vulnerabilities":
        meta = item.get("metadata") or {}
        pkg = meta.get("package_name")
        version = meta.get("package_version")
        vuln = meta.get("display_id") or meta.get("vuln_id") or item.get("rule_id")
        if pkg:
            package = f"{pkg}@{version}" if version else str(pkg)
            suffix = f" ({vuln})" if vuln else ""
            title = f"Vulnerable dependency: {package}{suffix}"
            message = item.get("message")
            return f"{title}\n{message}" if message and str(message) != title else title

    for key in ("message", "msg", "detail", "description", "reason"):
        value = item.get(key)
        if value:
            return str(value)

    return fallback_label


def _snippet(
    item: dict,
    category: str,
    *,
    root_path=None,
    source_cache: dict[str, list[str] | None],
) -> str:
    if category == "secrets":
        preview = item.get("preview")
        return str(preview) if preview else ""

    for key in ("snippet", "line_text", "source_line"):
        value = item.get(key)
        if value:
            return str(value).splitlines()[0]

    return _read_source_line(item, root_path=root_path, source_cache=source_cache)


def _fix(item: dict, category: str) -> str:
    for key in ("suggestion", "fix", "remediation", "recommendation"):
        value = item.get(key)
        if value:
            return str(value)

    if category == "dependency_vulnerabilities":
        meta = item.get("metadata") or {}
        fixed = meta.get("fixed_version")
        if fixed:
            return f"Upgrade to {fixed}"

    if category in DEAD_CODE_TYPES:
        return f"Remove the unused {DEAD_CODE_TYPES[category]} if it is not public API."

    return ""


def _dead_code_why(item: dict) -> str:
    return compact_dead_code_evidence(item)


def _read_source_line(
    item: dict,
    *,
    root_path=None,
    source_cache: dict[str, list[str] | None],
) -> str:
    file_path = item.get("file") or item.get("file_path")
    if not file_path:
        return ""

    raw_path = Path(str(file_path))
    lookup_path = raw_path
    if not raw_path.is_absolute() and root_path is not None:
        lookup_path = Path(root_path) / raw_path

    path = _resolve_snippet_path(str(lookup_path), repo_root=root_path)
    if path is None:
        return ""

    cache_key = str(path)
    if cache_key not in source_cache:
        try:
            source_cache[cache_key] = path.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines()
        except OSError:
            source_cache[cache_key] = None

    lines = source_cache[cache_key]
    if not lines:
        return ""

    line = _line_number(item)
    if line > len(lines):
        return ""
    return lines[line - 1].strip()


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def _sanitize_terminal_text(text: str) -> str:
    return _TERMINAL_CONTROL_RE.sub(
        lambda match: f"\\x{ord(match.group()):02x}",
        str(text),
    )
