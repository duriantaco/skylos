import logging
import math
from collections import Counter, defaultdict
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from skylos.deadcode.confidence import confidence_detail
from skylos.reporting.advice_display import (
    ADVICE_PRIORITY_NOTE,
    advice_display_counts,
    advice_priority,
    combine_complexity_advice,
    complexity_display,
    default_display_severity,
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
from skylos.ui.dead_code_evidence import (
    compact_dead_code_evidence,
    dead_code_candidate_counts,
    dead_code_uncertainty_summary,
    dead_code_uncertainty_text,
)
from skylos.ui.quality_advice import pytest_signature_advice, pytest_signature_title
from skylos.ui.scope_notes import scope_note_lines
from skylos.ui.security_evidence import security_evidence_details

logger = logging.getLogger(__name__)

_RESULTS_SUPPRESS_HINT = "[muted]Suppress a line: # skylos: ignore (Python) or // skylos: ignore (JS/TS); add [SKY-XXX] for one rule or -start/-end for a block[/muted]\n"
_RESULTS_DOCS_LINK = (
    _RESULTS_SUPPRESS_HINT
    + "[muted]Full guide: https://docs.skylos.dev/guides/understanding-output[/muted]\n"
)

_FINDING_TITLES = (
    ("danger", "Security"),
    ("reliability", "Reliability"),
    ("ai_defects", "AI Code"),
    ("secrets", "Secrets"),
    ("quality", "Quality"),
    ("circular_dependencies", "Circular Dependencies"),
    ("custom_rules", "Custom Rules"),
    ("dependency_vulnerabilities", "Dependency Vulnerabilities (SCA)"),
    ("publisher_change_findings", "npm Publisher Changes (review only)"),
    ("unused_functions", "Unused Functions"),
    ("unused_imports", "Unused Imports"),
    ("unused_parameters", "Unused Parameters"),
    ("unused_variables", "Unused Variables"),
    ("unused_classes", "Unused Classes"),
    ("unused_files", "Unused Files"),
    ("unused_fixtures", "Unused Fixtures"),
    ("unused_exports", "Unused Exports"),
)


def _shorten_path(path, root_path=None, keep_parts=3):
    """Use the scan root for locations, retaining context for external paths."""
    if not path:
        return "?"

    try:
        input_path = Path(path)
        p = input_path.resolve()
        if root_path is not None and input_path.is_absolute():
            try:
                rel = p.relative_to(Path(root_path).resolve())
            except (OSError, RuntimeError, TypeError, ValueError):
                pass
            else:
                # A file scan can supply the source itself as its root.
                return str(rel) if rel.parts else p.name or str(p)
        cwd = Path.cwd().resolve()

        rel = p.relative_to(cwd)
        return str(rel)

    except ValueError:
        return str(p)
    except Exception:
        return str(path)


def _results_pill(label, n, ok_style="good", bad_style="bad"):
    if n == 0:
        style = ok_style
    else:
        style = bad_style
    return f"[{style}]{label}: {n}[/{style}]"


def _architecture_advisory_pill(result):
    metrics = result.get("architecture_metrics")
    count = metrics.get("advisory_count") if isinstance(metrics, dict) else None
    if not isinstance(count, int) or count <= 0:
        return None
    return _results_pill(
        "Architecture advisories", count, ok_style="muted", bad_style="muted"
    )


def _grep_verify_pill(summary):
    grep_verify = summary.get("grep_verify")
    if not isinstance(grep_verify, dict):
        return None
    if not grep_verify.get("enabled"):
        return "[muted]Grep verify: off[/muted]"
    if grep_verify.get("complete") is False:
        candidate_count = int(grep_verify.get("candidate_count") or 0)
        return (
            "[warn]Grep verify: incomplete[/warn] "
            f"[muted]({candidate_count} candidates affected)[/muted]"
        )
    rescued_count = int(grep_verify.get("rescued_count") or 0)
    return f"[brand]Grep verify: on[/brand] [muted](rescued {rescued_count})[/muted]"


def _dead_code_evidence_pill(result):
    counts = dead_code_candidate_counts(result)
    rescued = counts.get("rescued", 0)
    abstained = counts.get("abstained", 0)
    uncertainty = dead_code_uncertainty_text(dead_code_uncertainty_summary(result))
    if not rescued and not abstained and not uncertainty:
        return None
    parts = []
    if rescued or abstained:
        parts.append(
            f"[good]Evidence rescued: {rescued}[/good] [warn]abstained: {abstained}[/warn]"
        )
    if uncertainty:
        parts.append(f"[warn]{escape(uncertainty)}[/warn]")
    return " ".join(parts)


def _display_cap(items, limit):
    cap = limit or len(items)
    return items[:cap], max(0, len(items) - cap)


# A message column narrower than this wraps to a word or two per line, so
# less useful columns fold into the message cell instead.
_MIN_MESSAGE_WIDTH = 30
# Longer locations wrap inside their column rather than crowd the message.
_MAX_LOCATION_WIDTH = 48
# Custom rule IDs may be arbitrarily long; fold them without consuming the report.
_MAX_RULE_WIDTH = 24


def _text_width(values, *, floor=1, cap=None):
    width = max([len(value) for value in values] + [floor])
    return min(width, cap) if cap else width


def _message_room(console, side_widths):
    """Width left for the message column beside ``side_widths``.

    Each Rich column also takes two padding spaces and one border. None when
    the console has no known width (a test double).
    """
    width = getattr(console, "width", None)
    if not isinstance(width, int):
        return None
    return width - sum(side_widths) - 3 * (len(side_widths) + 1) - 1


def _fit_side_columns(console, fixed_widths, optional):
    """Return the optional columns that leave the message column readable.

    ``fixed_widths`` are the columns that always show, ``optional`` is
    ``[(key, width)]`` from most to least useful. Callers fold the columns
    left out into the message cell. A console without a known width keeps
    every column.
    """
    shown = list(optional)
    while shown:
        widths = [*fixed_widths, *(column_width for _, column_width in shown)]
        room = _message_room(console, widths)
        if room is None or room >= _MIN_MESSAGE_WIDTH:
            break
        shown.pop()
    return {key for key, _ in shown}


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


def _finding_view(result, finding_type):
    """A display-only view; the caller's complete results remain untouched."""
    source_sections = {}
    for section in [
        *(section for section, _ in FINDING_SECTIONS),
        "circular_dependencies",
        "publisher_change_findings",
    ]:
        for finding in result.get(section, []) or []:
            source_sections.setdefault(
                (id(finding), section == "custom_rules"), section
            )
    view = defaultdict(list)
    rows = iter_result_findings(result)
    if finding_type == "advice":
        rows = combine_complexity_advice(rows)
    for category, finding in rows:
        if get_finding_type(finding, category) == finding_type:
            section = source_sections.get(
                (id(finding), category == "custom_rules"), "quality"
            )
            view[section].append(finding)
    return view


def _finding_severity(item, category):
    if get_finding_type(item, category) == "advice":
        return advice_priority(item, category)
    return str(item.get("severity") or default_display_severity(category)).upper()


def _finding_table_cells(item, category, root_path=None):
    """Keep category-specific evidence in a consistent finding table."""
    complexity = complexity_display(item)
    rule = (
        complexity.rule_label
        if complexity is not None
        else str(item.get("rule_id") or item.get("rule") or "")
    )
    name = str(item.get("name") or item.get("simple_name") or "")
    details = []
    if category.startswith("unused_"):
        kind = {
            "unused_classes": "class",
            "unused_fixtures": "fixture",
        }.get(category, category.removeprefix("unused_").rstrip("s"))
        rule = rule or {
            "function": "SKY-U001",
            "import": "SKY-U002",
            "variable": "SKY-U003",
            "class": "SKY-U004",
            "parameter": "SKY-U006",
            "file": "SKY-E002",
        }.get(kind, "SKY-U001")
        details.append(str(item.get("message") or f"Unused {kind}: {name or '<?>'}"))
        if name and name not in details[0]:
            details.append(name)
        confidence = confidence_detail(item)
        if confidence:
            details.append(confidence)
        why = compact_dead_code_evidence(item)
        if why:
            details.append(f"Evidence: {why}")
    elif category == "quality":
        kind, name, detail = _quality_detail(item)
        test_advice = pytest_signature_advice(item)
        details.append(pytest_signature_title(item) if test_advice else str(detail))
        if test_advice:
            details.append(test_advice)
        elif item.get("message") and str(item["message"]) != str(detail):
            details.append(str(item["message"]))
        if name and name != "<?>":
            details.append(f"Name: {name}")
        rule = rule or kind
    else:
        details.append(str(item.get("message") or item.get("error_type") or "Finding"))
        if name:
            details.append(f"Name: {name}")
    if category == "secrets":
        rule = rule or "SKY-S101"
        details.extend(
            [
                f"Provider: {item.get('provider') or 'generic'}",
                f"Preview: {item.get('preview') or '****'}",
            ]
        )
    if category == "circular_dependencies":
        rule = rule or "SKY-CIRC"
        cycle = item.get("cycle") or []
        if cycle:
            details.append(
                "Cycle: " + " → ".join(str(part) for part in [*cycle, cycle[0]])
            )
        details.append(f"Length: {item.get('cycle_length', len(cycle))}")
        if item.get("suggested_break"):
            details.append(f"Suggested break: {item['suggested_break']}")
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    details.extend(security_evidence_details(item))
    if category in {"dependency_vulnerabilities", "publisher_change_findings"}:
        details.append(
            f"Package: {metadata.get('package_name', '?')}@{metadata.get('package_version', '?')}"
        )
    if category == "dependency_vulnerabilities":
        vuln = metadata.get("display_id") or metadata.get("vuln_id")
        if vuln:
            details.append(f"Vulnerability: {vuln}")
        details.append(f"Fix: {metadata.get('fixed_version') or '-'}")
        if metadata.get("reachability_verdict"):
            details.append(f"Reachability: {metadata['reachability_verdict']}")
    if category == "publisher_change_findings":
        details.append(
            f"Publisher: {metadata.get('previous_publisher') or '?'} → "
            f"{metadata.get('new_publisher') or '?'}"
        )
        if metadata.get("dormancy_days") is not None:
            details.append(f"Release gap: {metadata['dormancy_days']} days")
    symbol = item.get("symbol")
    if symbol and symbol != "<module>" and symbol != name:
        details.append(f"Symbol: {symbol}")
    if item.get("ai_authored"):
        details.append(f"AI: {item.get('ai_agent') or 'ai'}")
    verification = item.get("verification")
    if isinstance(verification, dict) and verification.get("verdict"):
        details.append(f"Verified: {verification['verdict']}")
        proof = _verification_proof(item)
        if proof:
            details.append(f"Proof: {proof}")
    file_path = item.get("file") or item.get("file_path") or item.get("basename")
    line = item.get("line") or item.get("line_number") or item.get("lineno") or 1
    location = f"{_shorten_path(file_path, root_path)}:{line}"
    rule_name = (
        complexity.name
        if complexity is not None
        else _display_rule_name(
            rule, default=str(item.get("kind") or "Finding").replace("_", " ").title()
        )
    )
    return rule, rule_name, "\n".join(details), location


def _render_finding_table(console, root_path, limit, title, items, category):
    items = [item for item in (items or []) if isinstance(item, dict)]
    if not items:
        return
    console.rule(f"[bold]{escape(title)}")
    show, overflow = _display_cap(items, limit)
    cells = [_finding_table_cells(item, category, root_path) for item in show]
    rule_width = _text_width([cell[0] for cell in cells], floor=18, cap=_MAX_RULE_WIDTH)
    location_width = _text_width([cell[3] for cell in cells], cap=_MAX_LOCATION_WIDTH)
    columns = _fit_side_columns(
        console, [6, rule_width], [("severity", 9), ("location", location_width)]
    )
    table = Table(expand=True)
    table.add_column("Type", width=6, overflow="fold")
    advice_only = all(get_finding_type(item, category) == "advice" for item in show)
    priority_label = "Advice priority" if advice_only else "Severity"
    if "severity" in columns:
        table.add_column(priority_label, width=9, overflow="fold")
    table.add_column("Rule", width=rule_width, overflow="fold")
    table.add_column("Message", overflow="fold")
    if "location" in columns:
        table.add_column("Location", width=location_width, overflow="fold")
    for item, (rule, name, detail, location) in zip(show, cells):
        severity = _finding_severity(item, category)
        row = [get_finding_type(item, category).title()]
        if "severity" in columns:
            row.append(escape(severity))
        else:
            detail += f"\n{priority_label}: {severity}"
        row.extend([escape(f"{name}\n{rule}"), escape(detail)])
        if "location" in columns:
            row.append(escape(location))
        else:
            row[-1] += f"\n[muted]{escape(location)}[/muted]"
        table.add_row(*row)
    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print()


def _render_advice_groups(console, result, *, root_path=None, limit=None):
    groups = group_advice_for_display(result)
    if not groups:
        return
    console.rule("[bold]Advice")
    table = Table(expand=True)
    table.add_column("Type", width=6)
    table.add_column("Advice priority", width=15, overflow="fold")
    table.add_column("Rule", width=20, overflow="fold")
    table.add_column("Count", width=5, justify="right")
    table.add_column("Top files", overflow="fold")
    show, overflow = _display_cap(groups, limit)
    for group in show:
        counts = Counter(
            advice_priority(finding, "quality")
            for finding in group["findings"]
        )
        severities = ", ".join(sorted(counts))
        files = Counter(
            str(finding.get("file") or finding.get("file_path") or "?")
            for finding in group["findings"]
        )
        top = sorted(files, key=lambda file: (-files[file], file))[:3]
        file_labels = [
            f"{_shorten_path(file, root_path)} ({files[file]})" for file in top
        ]
        if len(files) > len(top):
            file_labels.append(f"+{len(files) - len(top)} more files")
        table.add_row(
            "Advice",
            escape(severities),
            escape(f"{group['name']}\n{group['rule_id']}"),
            str(group["count"]),
            escape("\n".join(file_labels)),
        )
    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more advice groups (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Use --expand-advice for every location and message, or --format json for full records.[/muted]"
    )
    console.print()


def _analysis_error_affected_file_count(error):
    count = error.get("affected_file_count")
    if isinstance(count, int) and not isinstance(count, bool) and count > 0:
        return count
    return 1


def _analysis_error_runtime(error):
    kind = str(error.get("kind") or error.get("error_type") or "")
    if kind == "language_engine_unavailable":
        language = str(error.get("language") or "").strip()
        return f"{language.title()} engine" if language else "Language engine"

    runtime = str(error.get("python_version") or "?")
    return f"Python {runtime}"


def _render_analysis_errors(
    console: Console,
    result,
    *,
    root_path=None,
    limit=None,
):
    errors = [
        error
        for error in (result.get("analysis_errors") or [])
        if isinstance(error, dict)
    ]
    if not errors:
        return

    error_count = len(errors)
    affected_file_count = sum(
        _analysis_error_affected_file_count(error) for error in errors
    )
    affected_label = "file" if affected_file_count == 1 else "files"
    error_label = "error" if error_count == 1 else "errors"
    coverage = (result.get("analysis_summary") or {}).get("analysis_coverage")
    blocking = (
        not isinstance(coverage, dict) or coverage.get("exit_blocking") is not False
    )
    if blocking:
        console.print(
            Panel.fit(
                f"[bad]Analysis incomplete: {affected_file_count} affected "
                f"{affected_label} across {error_count} analysis {error_label}.[/bad]\n"
                "[muted]Analysis is incomplete; known findings remain visible. Skylos exits with code 2.[/muted]",
                border_style="bad",
            )
        )
        title = "Analysis Errors"
    else:
        console.print(
            Panel.fit(
                f"[warn]Incomplete coverage: {_coverage_subject(coverage, affected_file_count, affected_label)}.[/warn]\n"
                "[muted]Everything else was analysed and its findings are shown; the exit "
                "code is decided on them. --strict exits 2 instead.[/muted]",
                border_style="warn",
            )
        )
        title = "Not Analysed"

    rows = []
    for error in errors:
        kind = str(error.get("kind") or error.get("error_type") or "analysis error")
        message = str(error.get("message") or "File analysis failed")
        affected_count = _analysis_error_affected_file_count(error)
        affected = "1 file" if affected_count == 1 else f"{affected_count} files"
        rows.append(
            {
                **error,
                "rule_id": error.get("rule_id") or "SKY-ANALYSIS-INCOMPLETE",
                "message": f"{kind.replace('_', ' ')}: {message}\nAffected: {affected}\nRuntime: {_analysis_error_runtime(error)}",
            }
        )
    _render_finding_table(console, root_path, limit, title, rows, "analysis_errors")
    # e.g. how to install a missing language engine; shown once per distinct fix.
    for suggestion in dict.fromkeys(
        str(error.get("suggestion") or "").strip() for error in errors
    ):
        if suggestion:
            console.print(f"  [bold]How to fix:[/bold] {escape(suggestion)}")
    console.print()


def _coverage_subject(coverage, affected_file_count, affected_label):
    unchecked = coverage.get("unchecked_file_count")
    total = coverage.get("source_file_count")
    unverified = coverage.get("unverified_dead_code_candidates")
    parts = []
    if isinstance(unchecked, int) and unchecked > 0:
        has_total = isinstance(total, int) and total > 0
        noun = "file" if (total if has_total else unchecked) == 1 else "files"
        verb = "was" if unchecked == 1 else "were"
        of_total = f" of {total}" if has_total else ""
        parts.append(f"{unchecked}{of_total} {noun} {verb} not analysed")
    if isinstance(unverified, int) and unverified > 0:
        noun = "candidate" if unverified == 1 else "candidates"
        parts.append(f"{unverified} dead-code {noun} not verified")
    if not parts:
        parts.append(f"{affected_file_count} {affected_label} not fully analysed")
    return "; ".join(parts)


def _render_analysis_warnings(console: Console, result, *, root_path=None, limit=None):
    warnings = [
        w for w in (result.get("analysis_warnings") or []) if isinstance(w, dict)
    ]
    if not warnings:
        return
    visible, overflow = _display_cap(warnings, limit)
    if all(w.get("generated_file") for w in warnings):
        subject = f"{len(warnings)} generated or vendored file(s)"
    elif any(w.get("generated_file") for w in warnings):
        subject = f"{len(warnings)} file(s) outside the diff or generated/vendored"
    else:
        subject = f"{len(warnings)} file(s) outside the diff"
    console.print(
        f"[warn]Analysis warnings: {subject} could not be analyzed "
        "(not blocking):[/warn]"
    )
    for warning in visible:
        path = escape(_shorten_path(warning.get("file"), root_path))
        kind = str(warning.get("kind") or "analysis error").replace("_", " ")
        message = escape(str(warning.get("message") or ""))
        console.print(
            f"  [muted]{path}:{warning.get('line') or 1} {kind}: {message}[/muted]"
        )
    if overflow:
        console.print(f"  [muted]... and {overflow} more[/muted]")
    console.print()


def _render_publisher_review_status(console: Console, result):
    receipt = (result.get("analysis_summary") or {}).get("publisher_change_scan")
    if not isinstance(receipt, dict):
        return
    status = receipt.get("status")
    if status == "no_inputs":
        console.print(
            "[muted]npm publisher review: no supported package lockfile.[/muted]"
        )
    elif status not in {"complete", "disabled"}:
        warnings = receipt.get("warnings")
        detail = warnings[0] if isinstance(warnings, list) and warnings else status
        safe_detail = escape(str(detail or "check incomplete")[:200])
        console.print(f"[warn]npm publisher review incomplete: {safe_detail}[/warn]")


def _score_style(score):
    if score >= 90:
        return "good"
    if score >= 80:
        return "brand"
    if score >= 70:
        return "yellow"
    return "bad"


def _render_grade(console: Console, grade_data, *, copy_badge: bool = True):
    overall = grade_data["overall"]
    cats = grade_data["categories"]
    o_score = overall["score"]
    g_style = _score_style(o_score)

    console.print(
        Panel.fit(
            f"[{g_style}]Legacy score: {overall['letter']} ({o_score}/100)[/{g_style}]",
            border_style=g_style,
        )
    )

    grade_table = Table(title="Legacy score breakdown", expand=True)
    grade_table.add_column("Category", style="bold", width=16)
    grade_table.add_column("Score", justify="right", width=8)
    grade_table.add_column("Grade", width=6)
    grade_table.add_column("Weight", style="muted", width=8)
    grade_table.add_column("Key Issue", overflow="fold")

    default_category_order = (
        "security",
        "quality",
        "dead_code",
        "dependencies",
        "secrets",
    )
    category_order = grade_data.get("scanned_categories") or default_category_order

    for cat_name in category_order:
        if cat_name not in cats:
            continue
        cat = cats[cat_name]
        display_name = cat_name.replace("_", " ").title()
        s_val = cat["score"]
        l_val = cat["letter"]
        w_pct = f"{int(cat['weight'] * 100)}%"
        issue = cat.get("key_issue") or "-"
        if len(issue) > 60:
            issue = issue[:57] + "..."

        s_style = _score_style(s_val)
        s_str = f"[{s_style}]{s_val}[/{s_style}]"
        l_str = f"[{s_style}]{l_val}[/{s_style}]"

        grade_table.add_row(display_name, s_str, l_str, w_pct, escape(issue))

    console.print(grade_table)
    console.print(
        "[muted]Historical result; this score is not a current risk assessment.[/muted]"
    )
    console.print()


def _render_assessment(
    console: Console, assessment, *, gate=None, analysis_summary=None
):
    table = Table(title="Scan assessment", expand=True)
    table.add_column("Area", style="bold", width=16)
    table.add_column("Result", overflow="fold")
    for label, detail in assessment_rows(assessment, gate=gate):
        table.add_row(label, escape(detail))
    console.print(table)
    console.print(escape(assessment_coverage_text(assessment)), style="muted")
    for detail in dependency_coverage_lines(analysis_summary):
        console.print(escape(detail), style="muted")
    checks = maintainability_rows(assessment)
    if checks:
        maintenance = Table(title="Maintainability measurements", expand=True)
        maintenance.add_column("Rule", width=12)
        maintenance.add_column("Spread", overflow="fold")
        maintenance.add_column("Magnitude", overflow="fold")
        for row in checks:
            maintenance.add_row(*(escape(value) for value in row))
        console.print(maintenance)
    console.print(
        "[muted]Risk includes Defect and Review findings; review evidence before acting.[/muted]"
    )
    console.print()


def _format_confidence(conf):
    if isinstance(conf, int):
        if conf >= 90:
            return f"[red]{conf}%[/red]"
        if conf >= 75:
            return f"[yellow]{conf}%[/yellow]"
        return f"[dim]{conf}%[/dim]"
    return str(conf)


def _dead_code_why(item: dict) -> str:
    return escape(compact_dead_code_evidence(item))


def _render_unused(console: Console, root_path, limit, title, items, name_key="name"):
    category = "unused_" + title.removeprefix("Unused ").lower().replace(" ", "_")
    _render_finding_table(console, root_path, limit, title, items, category)


def _render_unused_simple(
    console: Console, root_path, limit, title, items, name_key="name"
):
    _render_finding_table(console, root_path, limit, title, items, "unused_fixtures")


def _render_unused_files(console: Console, root_path, limit, items):
    _render_finding_table(
        console, root_path, limit, "Unused Files", items, "unused_files"
    )


_CLONE_KINDS = {
    "type1": "exact copy",
    "type2": "same structure",
    "type3": "near copy",
    "type4": "same logic",
}


def _clone_detail(value):
    """``"type2 1.00"`` -> ``"same structure, 100% similar"``."""
    clone_type, _, similarity = str(value or "").partition(" ")
    words = _CLONE_KINDS.get(clone_type, "similar code")
    try:
        score = float(similarity)
        if math.isfinite(score) and 0 <= score <= 1:
            return f"{words}, {round(score * 100)}% similar"
    except ValueError:
        pass
    return words


def _structure_detail(quality, value, limit):
    rule_id = quality.get("rule_id")
    if rule_id == "SKY-C303":
        message = str(quality.get("message") or "")
        noun = "parameters" if "total parameters" in message else "arguments"
        return f"{value} {noun}{limit}"
    if rule_id == "SKY-C304":
        return f"{value} lines{limit}"
    if rule_id == "SKY-L028":
        return f"{value} return statements{limit}"
    return str(quality.get("message") or f"{value}{limit}")


def _quality_detail(quality):
    complexity = complexity_display(quality)
    if complexity is not None:
        return (
            complexity.name,
            quality.get("name") or quality.get("simple_name") or "<?>",
            complexity.message,
        )
    raw_kind = quality.get("kind") or quality.get("metric") or "quality"
    func = quality.get("name") or quality.get("simple_name") or "<?>"
    value = quality.get("value")
    if value is None:
        value = quality.get("complexity")
    thr = quality.get("threshold")
    length = quality.get("length")
    qtype = quality.get("type", "")
    limit = f" (limit {thr})" if thr is not None else ""

    if value is None:
        detail = str(quality.get("message") or "Measurement unavailable")
    elif qtype == "string":
        detail = f"repeated {value}×{limit}"
        func = f'"{func}"'
    elif qtype == "dependency":
        detail = "declared but never imported" if value == "unused" else str(value)
    elif raw_kind in {
        "typing",
        "framework",
        "framework_security",
        "repo_policy",
    }:
        detail = quality.get("message") or str(value)
    elif raw_kind == "clone":
        detail = _clone_detail(value)
    elif quality.get("rule_id") == "SKY-L029":
        detail = "true/false positional parameter; make it keyword-only"
    elif raw_kind == "nesting":
        detail = f"Nesting depth {value}{limit}"
    elif raw_kind == "structure":
        detail = _structure_detail(quality, value, limit)
    elif raw_kind == "complexity":
        detail = f"Complexity: {value}{limit}"
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        detail = f"{value}{limit}"
    else:
        # Rules that report a label ("disabled", "bare", a parameter name)
        # rather than a measurement say what they found in the message.
        detail = quality.get("message") or str(value)
    if length is not None:
        detail += f", {length} lines"

    return raw_kind.replace("_", " ").title(), func, detail


def _render_quality(console: Console, limit, items):
    _render_finding_table(console, None, limit, "Quality", items, "quality")


def _render_circular_deps(console: Console, limit, items):
    _render_finding_table(
        console, None, limit, "Circular Dependencies", items, "circular_dependencies"
    )


def _render_custom_rules(console: Console, root_path, limit, items):
    _render_finding_table(
        console, root_path, limit, "Custom Rules", items, "custom_rules"
    )


def _render_secrets(console: Console, root_path, limit, items):
    _render_finding_table(console, root_path, limit, "Secrets", items, "secrets")


def _render_result_tree(console: Console, result, root_path=None):
    by_file = defaultdict(list)
    for category, _title in _FINDING_TITLES:
        for finding in result.get(category, []) or []:
            if not isinstance(finding, dict):
                continue
            rule, name, detail, location = _finding_table_cells(
                finding, category, root_path
            )
            file = str(finding.get("file") or finding.get("file_path") or "?")
            line = finding.get("line") or finding.get("lineno") or 1
            severity = _finding_severity(finding, category)
            finding_type = get_finding_type(finding, category)
            priority_label = "Advice priority" if finding_type == "advice" else "Severity"
            msg = (
                f"Type: {finding_type.title()}  {priority_label}: {severity}\n"
                f"{rule} · {name}\n{detail}\n{location}"
            )
            by_file[file].append((line, severity.lower(), escape(msg)))

    if not by_file:
        console.print("[good]No findings to display.[/good]")
        return

    root_label = str(root_path) if root_path is not None else "Skylos results"
    tree = Tree(f"[brand]{escape(root_label)}[/brand]")

    for file in sorted(by_file.keys()):
        short = _shorten_path(file, root_path)
        file_node = tree.add(f"[bold]{escape(short)}[/bold]")

        for line, sev, msg in sorted(by_file[file], key=lambda t: t[0]):
            if sev == "high" or sev == "critical":
                style = "bad"
            elif sev in {"medium", "warn", "warning"}:
                style = "warn"
            else:
                style = "muted"
            file_node.add(f"[{style}]L{escape(str(line))}[/{style}] {msg}")

    console.print(tree)


def _display_rule_name(rule_id, default="Security issue"):
    from skylos.rules.catalog import get_rule_name

    return get_rule_name(rule_id, default)


def _verification_proof(danger_finding):
    verification = danger_finding.get("verification")
    if verification is None:
        verification = {}

    evidence = verification.get("evidence")
    if evidence is None:
        evidence = {}

    chain = evidence.get("chain")
    if isinstance(chain, list) and len(chain) > 0:
        names = []
        for x in chain[:6]:
            fn = None
            if isinstance(x, dict):
                fn = x.get("fn")
            if not fn:
                fn = "?"
            names.append(fn)
        return " -> ".join(names)

    entrypoints = evidence.get("entrypoints")
    if entrypoints:
        return str(len(entrypoints)) + " entrypoints scanned"

    ver = verification.get("verdict")
    if ver:
        return "No evidence attached"
    return ""


def _verification_label(verdict):
    if verdict == "VERIFIED":
        return "[good]VERIFIED[/good]"
    if verdict == "REFUTED":
        return "[muted]REFUTED[/muted]"
    if verdict == "UNKNOWN":
        return "[warn]UNKNOWN[/warn]"
    return "-"


def _render_ai_defects(console: Console, root_path, limit, items):
    _render_finding_table(console, root_path, limit, "AI Code", items, "ai_defects")


def _render_danger(
    console: Console, root_path, limit, items, *, title="Security", reliability=False
):
    category = "reliability" if reliability else "danger"
    _render_finding_table(console, root_path, limit, title, items, category)


def _render_reliability(console: Console, root_path, limit, items):
    _render_danger(
        console,
        root_path,
        limit,
        items,
        title="Reliability Issues",
        reliability=True,
    )


def _render_sca(console: Console, limit, items, root_path=None):
    """Advisories as one row per package; licences and other SCA findings as rows."""
    from skylos.reporting.sca_summary import is_advisory, is_license_finding

    items = [item for item in (items or []) if isinstance(item, dict)]
    _render_sca_packages(
        console, root_path, limit, [item for item in items if is_advisory(item)]
    )
    _render_finding_table(
        console,
        root_path,
        limit,
        "Dependency Licenses",
        [item for item in items if is_license_finding(item)],
        "dependency_vulnerabilities",
    )
    _render_finding_table(
        console,
        root_path,
        limit,
        "Dependency Vulnerabilities (SCA)",
        [
            item
            for item in items
            if not is_advisory(item) and not is_license_finding(item)
        ],
        "dependency_vulnerabilities",
    )


def _render_sca_packages(console: Console, root_path, limit, advisories):
    from skylos.reporting.sca_summary import group_advisories, summary_footer

    groups = group_advisories(advisories)
    if not groups:
        return
    console.rule("[bold]Dependency Vulnerabilities (SCA), by package")
    show, overflow = _display_cap(groups, limit)
    table = Table(expand=True)
    table.add_column("Severity", width=9, overflow="fold")
    table.add_column("Package", overflow="fold")
    table.add_column("Installed", overflow="fold")
    table.add_column("Upgrade to", overflow="fold")
    table.add_column("Advisories", overflow="fold")
    table.add_column("Location", overflow="fold")
    for group in show:
        table.add_row(
            escape(group.worst_severity),
            escape(group.name),
            escape(group.version),
            escape(group.fix_text()),
            escape(f"{group.count}: {group.ids_text()}"),
            escape(f"{_shorten_path(group.file, root_path)}:{group.line}"),
        )
    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more packages (use --limit to adjust)[/muted]"
        )
    console.print(f"[muted]{escape(summary_footer(groups))}[/muted]")
    console.print()


def _render_publisher_changes(console: Console, limit, items):
    if not items:
        return
    _render_finding_table(
        console,
        None,
        limit,
        "npm Publisher Changes (review only)",
        items,
        "publisher_change_findings",
    )
    console.print(
        "[muted]Review the publisher and release provenance. This signal does not establish compromise or a known vulnerability and does not fail the quality gate.[/muted]\n"
    )


def render_results(
    console: Console,
    result,
    tree=False,
    root_path=None,
    limit=None,
    *,
    copy_badge: bool = True,
    expand_advice: bool = False,
    all_advice: bool = False,
):
    result, visibility = prepare_advice_view(
        result, project_root=root_path, all_advice=all_advice
    )
    summ = result.get("analysis_summary", {})
    console.print(
        Panel.fit(
            f"[brand]Static Analysis Results[/brand]\n{_finding_type_headline(result)}\n[muted]Analyzed {summ.get('total_files', '?')} file(s)[/muted]",
            border_style="brand",
        )
    )

    console.print(
        " ".join(
            part
            for part in [
                _results_pill(
                    "Unused functions", len(result.get("unused_functions", []))
                ),
                _results_pill("Unused imports", len(result.get("unused_imports", []))),
                _results_pill(
                    "Unused params", len(result.get("unused_parameters", []))
                ),
                _results_pill("Unused vars", len(result.get("unused_variables", []))),
                _results_pill("Unused classes", len(result.get("unused_classes", []))),
                _results_pill("Unused files", len(result.get("unused_files", []))),
                _results_pill("AI defects", len(result.get("ai_defects", []) or [])),
                _results_pill(
                    "Quality", len(result.get("quality", []) or []), bad_style="warn"
                ),
                _architecture_advisory_pill(result),
                _results_pill(
                    "Reliability",
                    len(result.get("reliability", []) or []),
                    bad_style="warn",
                ),
                _results_pill(
                    "Custom",
                    len(result.get("custom_rules", []) or []),
                    bad_style="warn",
                ),
                (
                    _results_pill(
                        "Publisher review",
                        len(result.get("publisher_change_findings") or []),
                        bad_style="warn",
                    )
                    if result.get("publisher_change_findings")
                    else None
                ),
                _results_pill(
                    "Suppressed",
                    len(result.get("suppressed", []) or []),
                    ok_style="muted",
                    bad_style="muted",
                ),
                _grep_verify_pill(summ),
                _dead_code_evidence_pill(result),
            ]
            if part
        )
    )
    if _architecture_advisory_pill(result):
        console.print(
            "[muted]Architecture advice describes maintainability; gate decisions use "
            "your configured limits. To list signals, add --format concise.[/muted]"
        )
    from skylos.reporting.typing_coverage import typing_coverage_text

    annotation_summary = typing_coverage_text(summ)
    if annotation_summary:
        console.print(escape(annotation_summary), style="muted")
    if result.get("quality"):
        console.print(
            "[muted]Quality thresholds: tune in "
            + escape(
                "[tool.skylos] (complexity, nesting, max_args, max_lines, duplicate_strings)"
            )
            + "[/muted]"
        )
    if visibility.message:
        console.print(escape(visibility.message), style="muted")
    if advice_display_counts(result)["advice"]:
        console.print(ADVICE_PRIORITY_NOTE, style="muted")
    for note in scope_note_lines(result):
        console.print(f"[muted]{escape(note)}[/muted]")
    console.print()

    _render_analysis_warnings(console, result, root_path=root_path, limit=limit)
    _render_publisher_review_status(console, result)

    if not isinstance(result.get("assessment"), dict) or not result["assessment"]:
        for detail in dependency_coverage_lines(summ):
            console.print(escape(detail), style="muted")

    assessment = result.get("assessment")
    grade_data = result.get("grade")
    if isinstance(assessment, dict) and assessment:
        _render_assessment(
            console,
            assessment,
            gate=result.get("gate") or result.get("quality_gate"),
            analysis_summary=summ,
        )
    elif grade_data:
        _render_grade(console, grade_data, copy_badge=copy_badge)
    if summ.get("assessment_includes_filtered_findings") or summ.get(
        "grade_includes_filtered_findings"
    ):
        label = "Assessment" if assessment else "Grade"
        console.print(
            f"[muted]{label} includes all analyzed findings, including those outside this display.[/muted]"
        )

    _render_analysis_errors(console, result, root_path=root_path, limit=limit)

    for finding_type in ("defect", "review", "advice"):
        if finding_type == "advice" and not expand_advice:
            _render_advice_groups(console, result, root_path=root_path, limit=limit)
            continue
        view = _finding_view(result, finding_type)
        if not any(view.values()):
            continue
        label = "Defects" if finding_type == "defect" else finding_type.title()
        console.rule(f"[bold]{label}")
        if tree:
            _render_result_tree(console, view, root_path=root_path)
            continue
        for category, title in _FINDING_TITLES:
            if category == "dependency_vulnerabilities":
                _render_sca(console, limit, view.get(category), root_path)
                continue
            _render_finding_table(
                console, root_path, limit, title, view.get(category), category
            )
        if view.get("publisher_change_findings"):
            console.print(
                "[muted]Review publisher and release provenance; this signal does not establish compromise or fail the quality gate.[/muted]"
            )
