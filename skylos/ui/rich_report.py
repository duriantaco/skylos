import logging
from collections import defaultdict
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree


logger = logging.getLogger(__name__)

_RESULTS_SUPPRESS_HINT = '[muted]Suppress: # skylos: ignore (line), ignore = ["SKY-XXX"] (rule), or # skylos: ignore-start/end (block)[/muted]\n'
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


def _grep_verify_pill(summary):
    grep_verify = summary.get("grep_verify")
    if not isinstance(grep_verify, dict):
        return None
    if not grep_verify.get("enabled"):
        return "[muted]Grep verify: off[/muted]"
    rescued_count = int(grep_verify.get("rescued_count") or 0)
    return f"[brand]Grep verify: on[/brand] [muted](rescued {rescued_count})[/muted]"


def _display_cap(items, limit):
    cap = limit or len(items)
    return items[:cap], max(0, len(items) - cap)


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

        grade_table.add_row(display_name, s_str, l_str, w_pct, issue)

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
        try:
            import pyperclip

            pyperclip.copy(badge_markdown)
            console.print("[good]Copied to clipboard![/good]")
        except ImportError:
            console.print(
                "[muted]Install pyperclip for auto-copy: pip install pyperclip[/muted]"
            )
        except (pyperclip.PyperclipException, OSError) as exc:
            logger.debug("Failed to copy badge markdown to clipboard: %s", exc)

    console.print()


def _format_confidence(conf):
    if isinstance(conf, int):
        if conf >= 90:
            return f"[red]{conf}%[/red]"
        if conf >= 75:
            return f"[yellow]{conf}%[/yellow]"
        return f"[dim]{conf}%[/dim]"
    return str(conf)


_DEAD_CODE_REASON_LABELS = {
    "no_refs": "no refs",
    "not_exported": "not exported",
    "no_entrypoint": "no entrypoint",
    "static_reference": "has refs",
    "reachable_from_root": "root reachable",
    "top_level_execution": "import-time call",
    "framework_root": "framework entry",
    "package_entrypoint": "package entry",
    "test_entrypoint": "test entry",
    "dynamic_pattern": "dynamic ref",
    "coverage_hit": "coverage hit",
    "trace_hit": "trace hit",
    "grep_rescue": "grep usage",
    "uncertainty": "uncertain",
    "validated_dead": "validated dead",
    "validation_failed": "live use found",
    "no_liveness_evidence": "no live evidence",
}


def _dead_code_why(item: dict) -> str:
    decision = item.get("dead_code_decision") or {}
    tags = item.get("dead_code_reason_tags")
    if tags is None and isinstance(decision, dict):
        tags = decision.get("reason_tags")

    if isinstance(tags, (list, tuple)):
        visible = []
        for raw_tag in tags:
            tag = str(raw_tag)
            if tag == "confidence_ge_threshold":
                continue
            label = _DEAD_CODE_REASON_LABELS.get(tag)
            if label:
                visible.append(label)
        if visible:
            shown = visible[:3]
            suffix = ""
            if len(visible) > len(shown):
                suffix = f" · +{len(visible) - len(shown)}"
            return " · ".join(shown) + suffix

    reason = item.get("dead_code_reason")
    if reason is None and isinstance(decision, dict):
        reason = decision.get("primary_reason")
    if not reason:
        return ""
    return escape(str(reason))


def _render_unused(console: Console, root_path, limit, title, items, name_key="name"):
    if not items:
        return

    console.rule(f"[bold]{title}")

    has_why = any(_dead_code_why(item) for item in items if isinstance(item, dict))
    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Name", style="bold")
    table.add_column("Location", style="muted", overflow="fold")
    table.add_column("Conf", style="yellow", width=6, justify="right")
    if has_why:
        table.add_column("Why", style="muted", width=30, overflow="fold")

    show, overflow = _display_cap(items, limit)
    for i, item in enumerate(show, 1):
        nm = item.get(name_key) or item.get("simple_name") or "<?>"
        short = _shorten_path(item.get("file"), root_path)
        loc = f"{short}:{item.get('line', '?')}"
        conf_str = _format_confidence(item.get("confidence", "?"))
        row = [str(i), nm, loc, conf_str]
        if has_why:
            row.append(_dead_code_why(item) or "-")
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
            "[muted]Why — compact evidence behind the dead-code decision.[/muted]\n"
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
        nm = item.get(name_key) or item.get("simple_name") or "<?>"
        short = _shorten_path(item.get("file"), root_path)
        loc = f"{short}:{item.get('line', '?')}"
        table.add_row(str(i), nm, loc)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print()


def _quality_detail(quality):
    raw_kind = quality.get("kind") or quality.get("metric") or "quality"
    func = quality.get("name") or quality.get("simple_name") or "<?>"
    value = quality.get("value") or quality.get("complexity")
    thr = quality.get("threshold")
    length = quality.get("length")
    qtype = quality.get("type", "")

    if qtype == "string":
        detail = f"repeated {value}×"
        if thr is not None:
            detail += f" (max {thr})"
        func = f'"{func}"'
    elif qtype == "dependency":
        detail = str(value)
    elif raw_kind in {
        "typing",
        "framework",
        "framework_security",
        "repo_policy",
    }:
        detail = quality.get("message") or str(value)
    elif raw_kind == "nesting":
        detail = f"Deep nesting: depth {value}"
    elif raw_kind == "structure":
        detail = f"Line count: {value}"
    elif raw_kind == "complexity":
        detail = f"Complexity: {value}"
        if thr is not None:
            detail += f" (max {thr})"
    else:
        detail = f"{value}"
        if thr is not None:
            detail += f" (max {thr})"
    if length is not None:
        detail += f", {length} lines"

    return raw_kind.replace("_", " ").title(), func, detail


def _render_quality(console: Console, limit, items):
    if not items:
        return

    console.rule("[bold red]Quality Issues")
    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Type", style="yellow", width=12)
    table.add_column("Name", style="bold")
    table.add_column("Detail")
    table.add_column("Location", style="muted", width=36)

    show, overflow = _display_cap(items, limit)
    for i, quality in enumerate(show, 1):
        kind, func, detail = _quality_detail(quality)
        loc = f"{quality.get('basename', '?')}:{quality.get('line', '?')}"
        table.add_row(str(i), escape(kind), escape(func), escape(detail), escape(loc))

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Reading the table:[/muted]\n"
        "[muted]  • Complexity — number of branches/loops in a function (lower = easier to test)[/muted]\n"
        "[muted]  • Nesting — how deeply indented the code is (depth count)[/muted]\n"
        "[muted]  • Structure — line count of a function or argument count[/muted]\n"
        "[muted]  • Duplicate strings — how many times a literal appears[/muted]\n"
        '[muted]  • "max N" / "(max N)" — the configured threshold; tune in [tool.skylos] (complexity, nesting, max_args, max_lines, duplicate_strings)[/muted]\n'
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
        table.add_row(str(i), cycle_str, length, sev, suggested)

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
    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Rule", style="magenta", width=18)
    table.add_column("Severity", width=10)
    table.add_column("Message", overflow="fold")
    table.add_column("Location", style="muted", width=36)

    show, overflow = _display_cap(custom, limit)
    for i, d in enumerate(show, 1):
        rule = d.get("rule_id") or "CUSTOM"
        sev = d.get("severity") or "MEDIUM"
        msg = d.get("message") or "Custom rule violation"
        short = _shorten_path(d.get("file"), root_path)
        loc = f"{short}:{d.get('line', '?')}"
        table.add_row(str(i), rule, sev, msg, loc)

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
    has_provenance = any(s.get("ai_authored") is not None for s in (items or []))

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Provider", style="yellow", width=14)
    table.add_column("Message")
    table.add_column("Preview", style="muted", width=18)
    table.add_column("Location", style="muted", overflow="fold")

    if has_provenance:
        table.add_column("AI", width=12)

    show, overflow = _display_cap(items, limit)
    for i, s in enumerate(show, 1):
        prov = s.get("provider") or "generic"
        msg = s.get("message") or "Secret detected"
        prev = s.get("preview") or "****"
        short = _shorten_path(s.get("file"), root_path)
        loc = f"{short}:{s.get('line', '?')}"
        row = [str(i), prov, msg, prev, loc]

        if has_provenance:
            if s.get("ai_authored"):
                agent = s.get("ai_agent") or "ai"
                row.append(f"[red]{agent}[/red]")
            else:
                row.append("[muted]-[/muted]")

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
            msg = f"Unused {kind}: {name}"
            by_file[file].append((line, "info", msg))

    def _add_findings(items, kind, default_sev="medium"):
        for f in items or []:
            file = f.get("file")
            if not file:
                continue
            line = f.get("line") or 1
            sev = (f.get("severity") or default_sev).lower()
            rule = f.get("rule_id")
            msg = f.get("message") or kind
            if rule:
                msg = f"[{rule}] {msg}"
            by_file[file].append((line, sev, msg))

    _add_unused(result.get("unused_functions"), "function")
    _add_unused(result.get("unused_imports"), "import")
    _add_unused(result.get("unused_classes"), "class")
    _add_unused(result.get("unused_variables"), "variable")
    _add_unused(result.get("unused_parameters"), "parameter")

    _add_findings(result.get("danger"), "security", default_sev="high")
    _add_findings(result.get("secrets"), "secret", default_sev="high")
    _add_findings(result.get("quality"), "quality", default_sev="medium")
    _add_findings(
        result.get("dependency_vulnerabilities"),
        "vulnerability",
        default_sev="high",
    )

    if not by_file:
        console.print("[good]No findings to display.[/good]")
        return

    root_label = str(root_path) if root_path is not None else "Skylos results"
    tree = Tree(f"[brand]{root_label}[/brand]")

    for file in sorted(by_file.keys()):
        short = _shorten_path(file, root_path)
        file_node = tree.add(f"[bold]{short}[/bold]")

        for line, sev, msg in sorted(by_file[file], key=lambda t: t[0]):
            if sev == "high" or sev == "critical":
                style = "bad"
            elif sev == "medium":
                style = "warn"
            else:
                style = "muted"
            file_node.add(f"[{style}]L{line}[/{style}] {msg}")

    console.print(tree)


def _display_rule_name(rule_id):
    from skylos.rules.catalog import get_rule_name

    return get_rule_name(rule_id)


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


def _render_danger(console: Console, root_path, limit, items):
    if not items:
        return

    console.rule("[bold red]Security Issues")

    has_verification = any(
        isinstance(d.get("verification"), dict) and d["verification"].get("verdict")
        for d in (items or [])
    )
    has_provenance = any(d.get("ai_authored") is not None for d in (items or []))

    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Issue", style="yellow", width=20)
    table.add_column("Severity", width=9)
    table.add_column("Message", overflow="fold")
    table.add_column("Location", style="muted", width=20, overflow="fold")
    table.add_column("Symbol", style="muted", width=10, overflow="fold")

    if has_provenance:
        table.add_column("AI", width=12)

    if has_verification:
        table.add_column("Verified", width=9)
        table.add_column("Proof", overflow="fold")

    show, overflow = _display_cap(items, limit)
    for i, d in enumerate(show, 1):
        rule_id = d.get("rule_id") or "UNKNOWN"
        issue_name = _display_rule_name(rule_id)
        issue_cell = f"{issue_name}\n[dim]{rule_id}[/dim]"
        sev = (d.get("severity") or "UNKNOWN").title()
        msg = d.get("message") or "Issue detected"
        short = _shorten_path(d.get("file"), root_path)
        loc = f"{short}:{d.get('line', '?')}"
        symbol = d.get("symbol") or "<module>"
        row = [str(i), issue_cell, sev, msg, loc, symbol]

        if has_provenance:
            if d.get("ai_authored"):
                agent = d.get("ai_agent") or "ai"
                row.append(f"[red]{agent}[/red]")
            else:
                row.append("[muted]-[/muted]")

        if has_verification:
            ver = (d.get("verification") or {}).get("verdict")
            row.extend([_verification_label(ver), _verification_proof(d)])

        table.add_row(*row)

    console.print(table)
    if overflow:
        console.print(
            f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
        )
    console.print(
        "[muted]Issue — the type of vulnerability (e.g. SQL injection, command injection, eval).[/muted]\n"
        "[muted]Severity — risk level: Critical > High > Medium > Low.[/muted]\n"
        "[muted]Symbol — the function or scope where the issue was found.[/muted]\n"
        + _RESULTS_DOCS_LINK
    )


def _render_sca(console: Console, limit, items):
    if not items:
        return

    console.rule("[bold red]Dependency Vulnerabilities (SCA)")
    table = Table(expand=True)
    table.add_column("#", style="muted", width=3)
    table.add_column("Package", style="yellow", width=22)
    table.add_column("Vuln ID", width=18)
    table.add_column("Severity", width=9)
    table.add_column("Reachability", width=14)
    table.add_column("Message", overflow="fold")
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
        table.add_row(str(i), pkg, vuln_id, sev, reach, msg, fix)

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
                _results_pill(
                    "Quality", len(result.get("quality", []) or []), bad_style="warn"
                ),
                _results_pill(
                    "Custom",
                    len(result.get("custom_rules", []) or []),
                    bad_style="warn",
                ),
                _results_pill(
                    "Suppressed",
                    len(result.get("suppressed", []) or []),
                    ok_style="muted",
                    bad_style="muted",
                ),
                _grep_verify_pill(summ),
            ]
            if part
        )
    )
    console.print()

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
        _render_quality(console, limit, result.get("quality", []) or [])
        _render_circular_deps(
            console, limit, result.get("circular_dependencies", []) or []
        )
        _render_custom_rules(
            console, root_path, limit, result.get("custom_rules", []) or []
        )
        _render_sca(console, limit, result.get("dependency_vulnerabilities", []) or [])
