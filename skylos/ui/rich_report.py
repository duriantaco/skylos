import logging
import math
from collections import defaultdict
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from skylos.ui.dead_code_evidence import (
    compact_dead_code_evidence,
    dead_code_candidate_counts,
    dead_code_uncertainty_summary,
    dead_code_uncertainty_text,
)


logger = logging.getLogger(__name__)

_RESULTS_SUPPRESS_HINT = "[muted]Suppress a line: # skylos: ignore (Python) or // skylos: ignore (JS/TS); add [SKY-XXX] for one rule or -start/-end for a block[/muted]\n"
_RESULTS_DOCS_LINK = (
    _RESULTS_SUPPRESS_HINT
    + "[muted]Full guide: https://docs.skylos.dev/guides/understanding-output[/muted]\n"
)


def _shorten_path(path, root_path=None, keep_parts=3):
    if not path:
        return "?"

    try:
        p = Path(path).resolve()
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
    console.print(
        Panel.fit(
            f"[bad]Analysis incomplete: {affected_file_count} affected "
            f"{affected_label} across {error_count} analysis {error_label}.[/bad]\n"
            "[muted]No grade or clean result was produced; Skylos exits with code 2.[/muted]",
            border_style="bad",
        )
    )

    table = Table(title="Analysis Errors", expand=True)
    table.add_column("File", style="bold", overflow="fold")
    table.add_column("Line", justify="right", width=6)
    table.add_column("Error", overflow="fold")
    table.add_column("Affected", justify="right", width=10)
    table.add_column("Runtime", style="muted", width=14)

    visible, overflow = _display_cap(errors, limit)
    for error in visible:
        path = escape(_shorten_path(error.get("file"), root_path))
        line = str(error.get("line") or 1)
        kind = str(error.get("kind") or error.get("error_type") or "analysis error")
        message = str(error.get("message") or "File analysis failed")
        affected_count = _analysis_error_affected_file_count(error)
        affected = "1 file" if affected_count == 1 else f"{affected_count} files"
        table.add_row(
            path,
            line,
            escape(f"{kind.replace('_', ' ')}: {message}"),
            affected,
            escape(_analysis_error_runtime(error)),
        )

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    # e.g. how to install a missing language engine; shown once per distinct fix.
    for suggestion in dict.fromkeys(
        str(error.get("suggestion") or "").strip() for error in errors
    ):
        if suggestion:
            console.print(f"  [bold]How to fix:[/bold] {escape(suggestion)}")
    console.print()


def _render_analysis_warnings(console: Console, result, *, root_path=None, limit=None):
    warnings = [
        w for w in (result.get("analysis_warnings") or []) if isinstance(w, dict)
    ]
    if not warnings:
        return
    visible, overflow = _display_cap(warnings, limit)
    console.print(
        f"[warn]Analysis warnings: {len(warnings)} file(s) outside the diff could "
        "not be analyzed (not blocking):[/warn]"
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
    from skylos.reporting.grader import generate_badge_url

    overall = grade_data["overall"]
    cats = grade_data["categories"]
    o_score = overall["score"]
    g_style = _score_style(o_score)

    console.print(
        Panel.fit(
            f"[{g_style}]Codebase Grade: {overall['letter']} ({o_score}/100)[/{g_style}]",
            border_style=g_style,
        )
    )

    grade_table = Table(title="Grade Breakdown", expand=True)
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
    badge_url = generate_badge_url(overall["letter"], o_score)
    badge_markdown = (
        f"[![Skylos Grade]({badge_url})](https://github.com/duriantaco/skylos)"
    )

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]Score Badge for your README.md:[/bold cyan]\n\n"
            f"[yellow]{badge_markdown}[/yellow]",
            title="[cyan]Score Badge[/cyan]",
            border_style="cyan",
        )
    )

    if copy_badge:
        from skylos.ui.clipboard import copy_to_clipboard

        status = copy_to_clipboard(badge_markdown, console)
        if status == "copied":
            console.print("[good]Copied to clipboard![/good]")
        elif status == "missing":
            console.print(
                "[muted]Install pyperclip for auto-copy: pip install pyperclip[/muted]"
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
    if not items:
        return

    console.rule(f"[bold]{title}")

    has_why = any(_dead_code_why(item) for item in items if isinstance(item, dict))
    show, overflow = _display_cap(items, limit)
    locations = [
        f"{_shorten_path(item.get('file'), root_path)}:{item.get('line', '?')}"
        for item in show
    ]
    location_width = _text_width(locations, cap=_MAX_LOCATION_WIDTH)
    optional = [("location", location_width)]
    if has_why:
        optional.append(("evidence", 42))
    columns = _fit_side_columns(console, [3, 6], optional)

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Name", overflow="fold")
    if "location" in columns:
        table.add_column(
            "Location", style="muted", width=location_width, overflow="fold"
        )
    table.add_column("Conf", style="yellow", width=6, justify="right")
    if "evidence" in columns:
        table.add_column("Evidence", style="muted", width=42, overflow="fold")

    for i, (item, location) in enumerate(zip(show, locations), 1):
        nm = escape(str(item.get(name_key) or item.get("simple_name") or "<?>"))
        name_cell = f"[bold]{nm}[/bold]"
        why = _dead_code_why(item)
        if "location" not in columns:
            name_cell += f"\n[muted]{escape(location)}[/muted]"
        if why and has_why and "evidence" not in columns:
            name_cell += f"\n[muted]{why}[/muted]"
        row = [str(i), name_cell]
        if "location" in columns:
            row.append(escape(location))
        row.append(_format_confidence(item.get("confidence", "?")))
        if "evidence" in columns:
            row.append(why or "-")
        table.add_row(*row)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Name — the unused function, import, class, or variable.[/muted]\n"
        "[muted]Conf — how confident Skylos is that this code is truly unused (higher = safer to remove).[/muted]\n"
        + (
            "[muted]Evidence — classification and analyzer evidence behind the dead-code decision.[/muted]\n"
            if has_why
            else ""
        )
        + _RESULTS_DOCS_LINK
    )


def _render_unused_simple(
    console: Console, root_path, limit, title, items, name_key="name"
):
    if not items:
        return

    console.rule(f"[bold]{title}")

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Name", style="bold")
    table.add_column("Location", style="muted", overflow="fold")

    show, overflow = _display_cap(items, limit)
    for i, item in enumerate(show, 1):
        nm = escape(str(item.get(name_key) or item.get("simple_name") or "<?>"))
        short = _shorten_path(item.get("file"), root_path)
        loc = escape(f"{short}:{item.get('line', '?')}")
        table.add_row(str(i), nm, loc)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print()


def _render_unused_files(console: Console, root_path, limit, items):
    if not items:
        return

    console.rule("[bold]Unused Files")

    show, overflow = _display_cap(items, limit)
    rules = [str(item.get("rule_id") or "SKY-E002") for item in show]
    locations = [
        f"{_shorten_path(item.get('file'), root_path)}:{item.get('line', 1)}"
        for item in show
    ]
    rule_width = _text_width(rules, floor=10, cap=_MAX_RULE_WIDTH)
    location_width = _text_width(locations, cap=_MAX_LOCATION_WIDTH)
    columns = _fit_side_columns(
        console, [3, rule_width], [("location", location_width)]
    )

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Rule", style="bold", width=rule_width, overflow="fold")
    table.add_column("Message", overflow="fold")
    if "location" in columns:
        table.add_column(
            "Location", style="muted", width=location_width, overflow="fold"
        )

    for index, (item, rule, location) in enumerate(zip(show, rules, locations), 1):
        message = escape(str(item.get("message") or "Unused file"))
        if "location" in columns:
            table.add_row(str(index), escape(rule), message, escape(location))
        else:
            message += f"\n[muted]{escape(location)}[/muted]"
            table.add_row(str(index), escape(rule), message)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(_RESULTS_DOCS_LINK)


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
    if not items:
        return

    console.rule("[bold red]Quality Issues")

    show, overflow = _display_cap(items, limit)
    locations = []
    for quality in show:
        file_path = quality.get("file")
        short = _shorten_path(file_path) if file_path else quality.get("basename")
        locations.append(f"{short or '?'}:{quality.get('line', '?')}")
    rule_ids = [str(quality.get("rule_id") or "") for quality in show]
    names = [_quality_detail(quality)[1] for quality in show]
    rule_width = _text_width(rule_ids, floor=18, cap=_MAX_RULE_WIDTH)
    location_width = _text_width(locations, cap=_MAX_LOCATION_WIDTH)
    name_width = _text_width(names, floor=8, cap=30)
    columns = _fit_side_columns(
        console,
        [3, rule_width],
        [("location", location_width), ("name", name_width)],
    )
    if "name" in columns:
        # Long test names read better whole; give them what the detail spares.
        room = _message_room(console, [3, rule_width, location_width, name_width])
        if room is not None:
            spare = max(0, room - _MIN_MESSAGE_WIDTH)
            name_width = min(_text_width(names), name_width + spare)

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Rule", style="yellow", width=rule_width, overflow="fold")
    if "name" in columns:
        table.add_column("Name", style="bold", width=name_width, overflow="fold")
    table.add_column("Detail", overflow="fold")
    if "location" in columns:
        table.add_column(
            "Location", style="muted", width=location_width, overflow="fold"
        )

    for i, (quality, rule_id, location) in enumerate(zip(show, rule_ids, locations), 1):
        kind, func, detail = _quality_detail(quality)
        rule_cell = escape(_display_rule_name(rule_id, default=kind))
        if rule_id:
            rule_cell += f"\n[dim]{escape(rule_id)}[/dim]"
        detail_cell = escape(detail)
        if "name" not in columns:
            detail_cell = f"[bold]{escape(func)}[/bold]\n{detail_cell}"
        row = [str(i), rule_cell]
        if "name" in columns:
            row.append(escape(func))
        if "location" in columns:
            row.extend([detail_cell, escape(location)])
        else:
            row.append(f"{detail_cell}\n[muted]{escape(location)}[/muted]")
        table.add_row(*row)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Reading the table:[/muted]\n"
        "[muted]  • Rule — what was checked, with its rule ID[/muted]\n"
        "[muted]  • Detail — what Skylos found; for clones, an exact copy, the same structure with different names, or a near copy of another class or function[/muted]\n"
        '[muted]  • "(limit N)" — the configured threshold; tune in \\[tool.skylos] (complexity, nesting, max_args, max_lines, duplicate_strings)[/muted]\n'
        + _RESULTS_DOCS_LINK
    )


def _render_circular_deps(console: Console, limit, items):
    if not items:
        return

    console.rule("[bold yellow]Circular Dependencies")
    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Cycle", style="bold")
    table.add_column("Length", width=6)
    table.add_column("Severity", width=8)
    table.add_column("Suggested Break", style="cyan")

    show, overflow = _display_cap(items, limit)
    for i, cd in enumerate(show, 1):
        cycle = cd.get("cycle", [])
        cycle_str = " → ".join(cycle) + f" → {cycle[0]}" if cycle else "?"
        length = str(cd.get("cycle_length", len(cycle)))
        sev = cd.get("severity", "MEDIUM")
        suggested = cd.get("suggested_break", "?")
        table.add_row(
            str(i),
            escape(cycle_str),
            escape(length),
            escape(str(sev)),
            escape(str(suggested)),
        )

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Cycle — the chain of modules that import each other in a loop.[/muted]\n"
        "[muted]Length — how many modules are in the cycle.[/muted]\n"
        "[muted]Suggested Break — the module to refactor to break the dependency loop.[/muted]\n"
        + _RESULTS_DOCS_LINK
    )


def _render_custom_rules(console: Console, root_path, limit, items):
    custom = [
        i for i in (items or []) if str(i.get("rule_id", "")).startswith("CUSTOM-")
    ]
    if not custom:
        return

    console.rule("[bold magenta]Custom Rules")
    show, overflow = _display_cap(custom, limit)
    rules = [str(d.get("rule_id") or "CUSTOM") for d in show]
    locations = [
        f"{_shorten_path(d.get('file'), root_path)}:{d.get('line', '?')}" for d in show
    ]
    rule_width = _text_width(rules, floor=18, cap=_MAX_RULE_WIDTH)
    location_width = _text_width(locations, cap=_MAX_LOCATION_WIDTH)
    columns = _fit_side_columns(
        console,
        [3, rule_width],
        [("location", location_width), ("severity", 10)],
    )

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Rule", style="magenta", width=rule_width, overflow="fold")
    if "severity" in columns:
        table.add_column("Severity", width=10)
    table.add_column("Message", overflow="fold")
    if "location" in columns:
        table.add_column(
            "Location", style="muted", width=location_width, overflow="fold"
        )

    for i, (d, rule, loc) in enumerate(zip(show, rules, locations), 1):
        sev = str(d.get("severity") or "MEDIUM")
        msg = escape(str(d.get("message") or "Custom rule violation"))
        rule_cell = escape(rule)
        row = [str(i)]
        if "severity" in columns:
            row.extend([rule_cell, escape(sev)])
        else:
            row.append(f"{rule_cell}\n[dim]{escape(sev)}[/dim]")
        if "location" in columns:
            row.extend([msg, escape(loc)])
        else:
            row.append(f"{msg}\n[muted]{escape(loc)}[/muted]")
        table.add_row(*row)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print()


def _render_secrets(console: Console, root_path, limit, items):
    if not items:
        return

    console.rule("[bold red]Secrets")
    has_provenance = any(s.get("ai_authored") for s in (items or []))

    show, overflow = _display_cap(items, limit)
    locations = [
        f"{_shorten_path(s.get('file'), root_path)}:{s.get('line', '?')}" for s in show
    ]
    location_width = _text_width(locations, cap=_MAX_LOCATION_WIDTH)
    optional = [("location", location_width), ("preview", 18)]
    if has_provenance:
        optional.append(("ai", 12))
    columns = _fit_side_columns(console, [3, 14], optional)

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Provider", style="yellow", width=14)
    table.add_column("Message", overflow="fold")
    if "preview" in columns:
        table.add_column("Preview", style="muted", width=18)
    if "location" in columns:
        table.add_column(
            "Location", style="muted", width=location_width, overflow="fold"
        )
    if "ai" in columns:
        table.add_column("AI", width=12)

    for i, (s, loc) in enumerate(zip(show, locations), 1):
        prov = s.get("provider") or "generic"
        msg = s.get("message") or "Secret detected"
        prev = s.get("preview") or "****"
        if s.get("ai_authored"):
            agent = f"[red]{escape(str(s.get('ai_agent') or 'ai'))}[/red]"
        else:
            agent = "[muted]-[/muted]"
        message_cell = escape(str(msg))
        folded = [] if "location" in columns else [escape(loc)]
        if "preview" not in columns:
            folded.append(escape(str(prev)))
        if folded:
            message_cell += f"\n[muted]{' · '.join(folded)}[/muted]"
        if "ai" not in columns and has_provenance and s.get("ai_authored"):
            message_cell += f"\nAI: {agent}"
        row = [str(i), escape(str(prov)), message_cell]
        if "preview" in columns:
            row.append(escape(str(prev)))
        if "location" in columns:
            row.append(escape(loc))
        if "ai" in columns:
            row.append(agent)

        table.add_row(*row)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        '[muted]Provider — the service the secret belongs to (e.g. AWS, Stripe, GitHub) or "generic" for high-entropy strings.[/muted]\n'
        "[muted]Preview — a masked snippet of the detected secret.[/muted]\n"
        + _RESULTS_DOCS_LINK
    )


def _render_result_tree(console: Console, result, root_path=None):
    by_file = defaultdict(list)

    def _add_unused(items, kind):
        for u in items or []:
            file = u.get("file")
            if not file:
                continue
            line = u.get("line") or u.get("lineno") or 1
            name = u.get("name") or u.get("simple_name") or "<?>"
            msg = f"Unused {kind}: {escape(str(name))}"
            by_file[file].append((line, "info", msg))

    def _add_findings(items, kind, default_sev="medium"):
        for f in items or []:
            file = f.get("file")
            if not file:
                continue
            line = f.get("line") or 1
            sev = (f.get("severity") or default_sev).lower()
            rule = f.get("rule_id")
            msg = escape(str(f.get("message") or kind))
            if rule:
                msg = f"{escape(f'[{rule}]')} {msg}"
            by_file[file].append((line, sev, msg))

    _add_unused(result.get("unused_functions"), "function")
    _add_unused(result.get("unused_imports"), "import")
    _add_unused(result.get("unused_classes"), "class")
    _add_unused(result.get("unused_variables"), "variable")
    _add_unused(result.get("unused_parameters"), "parameter")
    _add_findings(result.get("unused_files"), "unused file", default_sev="low")

    _add_findings(result.get("danger"), "security", default_sev="high")
    _add_findings(result.get("reliability"), "reliability", default_sev="medium")
    _add_findings(result.get("ai_defects"), "AI defect", default_sev="medium")
    _add_findings(result.get("secrets"), "secret", default_sev="high")
    _add_findings(result.get("quality"), "quality", default_sev="medium")
    _add_findings(
        result.get("dependency_vulnerabilities"),
        "vulnerability",
        default_sev="high",
    )
    _add_findings(
        result.get("publisher_change_findings"),
        "npm publisher review",
        default_sev="warn",
    )

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
    if not items:
        return

    console.rule("[bold magenta]AI Defects")

    show, overflow = _display_cap(items, limit)
    rule_ids = [str(defect.get("rule_id") or "UNKNOWN") for defect in show]
    locations = [
        f"{_shorten_path(defect.get('file'), root_path)}:{defect.get('line', '?')}"
        for defect in show
    ]
    defect_width = _text_width(rule_ids, floor=18, cap=_MAX_RULE_WIDTH)
    location_width = _text_width(locations, cap=_MAX_LOCATION_WIDTH)
    columns = _fit_side_columns(
        console,
        [3, defect_width],
        [("location", location_width), ("severity", 8)],
    )

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Defect", style="yellow", width=defect_width, overflow="fold")
    if "severity" in columns:
        table.add_column("Severity", width=8)
    table.add_column("Message", overflow="fold")
    if "location" in columns:
        table.add_column(
            "Location", style="muted", width=location_width, overflow="fold"
        )

    for i, (defect, rule_id, location) in enumerate(zip(show, rule_ids, locations), 1):
        defect_name = str(_display_rule_name(rule_id))
        severity = str(defect.get("severity") or "UNKNOWN").title()
        rule_line = escape(rule_id)
        if "severity" not in columns:
            rule_line += f" · {escape(severity)}"
        defect_cell = f"{escape(defect_name)}\n[dim]{rule_line}[/dim]"
        message = str(defect.get("message") or "AI defect detected")
        symbol = (
            defect.get("symbol")
            or defect.get("name")
            or defect.get("simple_name")
            or "<module>"
        )
        message_cell = escape(message)
        if symbol != "<module>":
            message_cell += f"\n[muted]Symbol: {escape(str(symbol))}[/muted]"
        if "location" not in columns:
            message_cell += f"\n[muted]{escape(location)}[/muted]"
        row = [str(i), defect_cell]
        if "severity" in columns:
            row.append(escape(severity))
        row.append(message_cell)
        if "location" in columns:
            row.append(escape(location))
        table.add_row(*row)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Defect — the evidence-backed AI-code failure mode and rule ID.[/muted]\n"
        "[muted]Severity — impact level: Critical > High > Medium > Low.[/muted]\n"
        "[muted]Message — the defect evidence and affected symbol, when available.[/muted]\n"
        + _RESULTS_DOCS_LINK
    )


def _render_danger(
    console: Console,
    root_path,
    limit,
    items,
    *,
    title="Security Issues",
    reliability=False,
):
    if not items:
        return

    console.rule(f"[bold {'yellow' if reliability else 'red'}]{title}")

    has_verification = not reliability and any(
        isinstance(d.get("verification"), dict) and d["verification"].get("verdict")
        for d in (items or [])
    )
    # A column of "-" says nothing; show it once something was AI-written.
    has_provenance = any(d.get("ai_authored") for d in (items or []))

    show, overflow = _display_cap(items, limit)
    rule_ids = [str(d.get("rule_id") or "UNKNOWN") for d in show]
    locations = [
        f"{_shorten_path(d.get('file'), root_path)}:{d.get('line', '?')}" for d in show
    ]
    symbols = [str(d.get("symbol") or "<module>") for d in show]
    issue_width = _text_width(rule_ids, floor=20, cap=_MAX_RULE_WIDTH)
    location_width = _text_width(locations, cap=_MAX_LOCATION_WIDTH)
    symbol_width = _text_width(symbols, floor=8, cap=20)
    optional = [("location", location_width), ("severity", 9)]
    if has_verification:
        optional.append(("verified", 9))
    if has_provenance:
        optional.append(("ai", 12))
    optional.append(("symbol", symbol_width))
    if has_verification:
        optional.append(("proof", 30))
    columns = _fit_side_columns(console, [3, issue_width], optional)

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Issue", style="yellow", width=issue_width, overflow="fold")
    if "severity" in columns:
        table.add_column("Severity", width=9)
    table.add_column("Message", overflow="fold")
    if "location" in columns:
        table.add_column(
            "Location", style="muted", width=location_width, overflow="fold"
        )
    if "symbol" in columns:
        table.add_column("Symbol", style="muted", width=symbol_width, overflow="fold")
    if "ai" in columns:
        table.add_column("AI", width=12)
    if "verified" in columns:
        table.add_column("Verified", width=9)
    if "proof" in columns:
        table.add_column("Proof", width=30, overflow="fold")

    for i, (d, rule_id, loc, symbol) in enumerate(
        zip(show, rule_ids, locations, symbols), 1
    ):
        issue_name = _display_rule_name(rule_id)
        sev = (d.get("severity") or "UNKNOWN").title()
        rule_line = escape(rule_id)
        if "severity" not in columns:
            rule_line += f" · {escape(sev)}"
        issue_cell = f"{escape(str(issue_name))}\n[dim]{rule_line}[/dim]"
        msg = d.get("message") or "Issue detected"
        if d.get("ai_authored"):
            agent = f"[red]{escape(str(d.get('ai_agent') or 'ai'))}[/red]"
        else:
            agent = "[muted]-[/muted]"
        ver = (d.get("verification") or {}).get("verdict")

        # Columns that did not fit keep their facts, one muted line each.
        message_cell = escape(str(msg))
        where = [] if "location" in columns else [escape(loc)]
        if "symbol" not in columns and symbol != "<module>":
            where.append(f"in {escape(symbol)}")
        if where:
            message_cell += f"\n[muted]{' '.join(where)}[/muted]"
        if "ai" not in columns and d.get("ai_authored"):
            message_cell += f"\nAI: {agent}"
        if has_verification and "verified" not in columns:
            message_cell += f"\nVerified: {_verification_label(ver)}"
        if has_verification and "proof" not in columns and _verification_proof(d):
            message_cell += f"\n[muted]{escape(_verification_proof(d))}[/muted]"

        row = [str(i), issue_cell]
        if "severity" in columns:
            row.append(escape(sev))
        row.append(message_cell)
        if "location" in columns:
            row.append(escape(loc))
        if "symbol" in columns:
            row.append(escape(symbol))
        if "ai" in columns:
            row.append(agent)
        if "verified" in columns:
            row.append(_verification_label(ver))
        if "proof" in columns:
            row.append(escape(_verification_proof(d)))

        table.add_row(*row)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    if reliability:
        issue_help = (
            "[muted]Issue — a deployment or runtime compatibility risk.[/muted]\n"
        )
    else:
        issue_help = "[muted]Issue — the type of vulnerability (e.g. SQL injection, command injection, eval).[/muted]\n"
    console.print(
        issue_help
        + "[muted]Severity — impact level: Critical > High > Medium > Low.[/muted]\n"
        "[muted]Symbol — the function or scope where the issue was found.[/muted]\n"
        + _RESULTS_DOCS_LINK
    )


def _render_reliability(console: Console, root_path, limit, items):
    _render_danger(
        console,
        root_path,
        limit,
        items,
        title="Reliability Issues",
        reliability=True,
    )


def _render_sca(console: Console, limit, items):
    if not items:
        return

    console.rule("[bold red]Dependency Vulnerabilities (SCA)")
    columns = _fit_side_columns(
        console,
        [3, 22, 18],
        [("fix", 14), ("severity", 9), ("reachability", 14)],
    )
    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Package", style="yellow", width=22, overflow="fold")
    table.add_column("Vuln ID", width=18, overflow="fold")
    if "severity" in columns:
        table.add_column("Severity", width=9)
    if "reachability" in columns:
        table.add_column("Reachability", width=14)
    table.add_column("Message", overflow="fold")
    if "fix" in columns:
        table.add_column("Fix", style="good", width=14, overflow="fold")

    show, overflow = _display_cap(items, limit)
    for i, v in enumerate(show, 1):
        meta = v.get("metadata") or {}
        pkg = f"{meta.get('package_name', '?')}@{meta.get('package_version', '?')}"
        vuln_id = meta.get("display_id") or meta.get("vuln_id") or v.get("rule_id", "")
        sev = (v.get("severity") or "MEDIUM").title()
        msg = v.get("message") or "Known vulnerability"
        fix = meta.get("fixed_version") or "-"
        rv = meta.get("reachability_verdict", "")
        if rv == "reachable":
            reach = "[red]Reachable[/red]"
        elif rv.startswith("unreachable"):
            reach = "[green]Unreachable[/green]"
        elif rv == "inconclusive":
            reach = "[yellow]Inconclusive[/yellow]"
        else:
            reach = "[dim]-[/dim]"
        message_cell = escape(str(msg))
        if "severity" not in columns:
            message_cell += f"\n[muted]Severity: {escape(sev)}[/muted]"
        if "reachability" not in columns and rv:
            message_cell += f"\nReachability: {reach}"
        if "fix" not in columns:
            message_cell += f"\n[good]Fix: {escape(str(fix))}[/good]"
        row = [str(i), escape(pkg), escape(str(vuln_id))]
        if "severity" in columns:
            row.append(escape(sev))
        if "reachability" in columns:
            row.append(reach)
        row.append(message_cell)
        if "fix" in columns:
            row.append(escape(str(fix)))
        table.add_row(*row)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Package — the dependency and its installed version.[/muted]\n"
        "[muted]Reachability — whether your code actually calls the vulnerable code path.[/muted]\n"
        "[muted]Fix — the version that patches the vulnerability (upgrade to this).[/muted]\n"
        + _RESULTS_DOCS_LINK
    )


def _render_publisher_changes(console: Console, limit, items):
    if not items:
        return

    console.rule("[bold yellow]npm Publisher Changes (review only)")
    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Package", style="yellow", width=22)
    table.add_column("Publisher", width=24, overflow="fold")
    table.add_column("Release gap", width=12)
    table.add_column("Location", overflow="fold")

    show, overflow = _display_cap(items, limit)
    for i, finding in enumerate(show, 1):
        meta = finding.get("metadata")
        if not isinstance(meta, dict):
            meta = {}
        name = str(meta.get("package_name") or "?")
        version = str(meta.get("package_version") or "?")
        publisher = (
            f"{meta.get('previous_publisher') or '?'} → "
            f"{meta.get('new_publisher') or '?'}"
        )
        days = meta.get("dormancy_days")
        gap = f"{days} days" if isinstance(days, int) and days >= 0 else "?"
        file_path = _shorten_path(finding.get("file") or finding.get("file_path"))
        line = finding.get("line") or finding.get("line_number") or 1
        location = f"{file_path}:{line}"
        table.add_row(
            str(i),
            escape(f"{name}@{version}"),
            escape(publisher),
            gap,
            escape(location),
        )

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Review the publisher and release provenance. This signal does "
        "not establish compromise or a known vulnerability and does not fail "
        "the quality gate.[/muted]\n"
    )


def render_results(
    console: Console,
    result,
    tree=False,
    root_path=None,
    limit=None,
    *,
    copy_badge: bool = True,
):
    summ = result.get("analysis_summary", {})
    console.print(
        Panel.fit(
            f"[brand]Python Static Analysis Results[/brand]\n[muted]Analyzed {summ.get('total_files', '?')} file(s)[/muted]",
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
            "[muted]Architecture advisories are advice only: they don't change "
            "the grade or the gate. To list them, add --format concise.[/muted]"
        )
    console.print()

    _render_analysis_errors(
        console,
        result,
        root_path=root_path,
        limit=limit,
    )
    _render_analysis_warnings(console, result, root_path=root_path, limit=limit)
    _render_publisher_review_status(console, result)

    grade_data = result.get("grade")
    if grade_data:
        _render_grade(console, grade_data, copy_badge=copy_badge)

    if tree:
        _render_result_tree(console, result, root_path=root_path)
    else:
        _render_unused(
            console,
            root_path,
            limit,
            "Unused Functions",
            result.get("unused_functions", []),
            name_key="name",
        )
        _render_unused(
            console,
            root_path,
            limit,
            "Unused Imports",
            result.get("unused_imports", []),
            name_key="name",
        )
        _render_unused(
            console,
            root_path,
            limit,
            "Unused Parameters",
            result.get("unused_parameters", []),
            name_key="name",
        )
        _render_unused(
            console,
            root_path,
            limit,
            "Unused Variables",
            result.get("unused_variables", []),
            name_key="name",
        )
        _render_unused(
            console,
            root_path,
            limit,
            "Unused Classes",
            result.get("unused_classes", []),
            name_key="name",
        )
        _render_unused_files(
            console,
            root_path,
            limit,
            result.get("unused_files", []),
        )
        _render_unused_simple(
            console,
            root_path,
            limit,
            "Unused Fixtures",
            result.get("unused_fixtures", []),
            name_key="name",
        )
        _render_secrets(console, root_path, limit, result.get("secrets", []) or [])
        _render_danger(console, root_path, limit, result.get("danger", []) or [])
        _render_reliability(
            console, root_path, limit, result.get("reliability", []) or []
        )
        _render_ai_defects(
            console, root_path, limit, result.get("ai_defects", []) or []
        )
        _render_quality(console, limit, result.get("quality", []) or [])
        _render_circular_deps(
            console, limit, result.get("circular_dependencies", []) or []
        )
        _render_custom_rules(
            console, root_path, limit, result.get("custom_rules", []) or []
        )
        _render_sca(console, limit, result.get("dependency_vulnerabilities", []) or [])
        _render_publisher_changes(
            console, limit, result.get("publisher_change_findings", []) or []
        )
