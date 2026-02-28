"""Skylos interactive TUI dashboard powered by Textual."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
)
from rich.text import Text

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "red bold",
    "HIGH": "#ff8800",
    "MEDIUM": "yellow",
    "LOW": "dim",
}

CATEGORIES = [
    ("overview", "Overview"),
    ("dead_code", "Dead Code"),
    ("security", "Security"),
    ("secrets", "Secrets"),
    ("quality", "Quality"),
    ("dependencies", "Dependencies"),
    ("suppressed", "Suppressed"),
]

DEAD_CODE_KEYS = [
    ("unused_functions", "Function"),
    ("unused_imports", "Import"),
    ("unused_classes", "Class"),
    ("unused_variables", "Variable"),
    ("unused_parameters", "Parameter"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _shorten(path, root_path=None):
    if not path:
        return "?"
    try:
        p = Path(path).resolve()
        root = Path(root_path).resolve() if root_path else Path.cwd().resolve()
        return str(p.relative_to(root))
    except (ValueError, Exception):
        return str(path)


def _loc(item, root_path=None):
    return f"{_shorten(item.get('file'), root_path)}:{item.get('line', '?')}"


# ---------------------------------------------------------------------------
# Data preparation  (pure, runs once)
# ---------------------------------------------------------------------------


def prepare_category_data(result: dict, root_path=None) -> dict:
    data = {}

    # -- Dead Code --
    dc_cols = ["Type", "Name", "File:Line", "Confidence"]
    dc_rows, dc_raw = [], []
    for key, type_label in DEAD_CODE_KEYS:
        for item in result.get(key) or []:
            name = item.get("name") or item.get("simple_name") or "?"
            conf = item.get("confidence", "?")
            conf_str = f"{conf}%" if isinstance(conf, (int, float)) else str(conf)
            dc_rows.append((type_label, name, _loc(item, root_path), conf_str))
            dc_raw.append({**item, "_type_label": type_label})
    data["dead_code"] = (dc_cols, dc_rows, dc_raw)

    # -- Security --
    sec_cols = ["Rule", "Severity", "Message", "File:Line", "Symbol"]
    sec_rows, sec_raw = [], []
    for item in result.get("danger") or []:
        sec_rows.append(
            (
                item.get("rule_id", "?"),
                (item.get("severity") or "?").upper(),
                item.get("message") or "",
                _loc(item, root_path),
                item.get("symbol") or "<module>",
            )
        )
        sec_raw.append(item)
    data["security"] = (sec_cols, sec_rows, sec_raw)

    # -- Secrets --
    secret_cols = ["Provider", "Message", "File:Line"]
    secret_rows, secret_raw = [], []
    for item in result.get("secrets") or []:
        secret_rows.append(
            (
                item.get("provider") or "generic",
                item.get("message") or "Secret detected",
                _loc(item, root_path),
            )
        )
        secret_raw.append(item)
    data["secrets"] = (secret_cols, secret_rows, secret_raw)

    # -- Quality (+ circular deps + custom rules) --
    q_cols = ["Type", "Function", "Detail", "File:Line"]
    q_rows, q_raw = [], []
    for item in result.get("quality") or []:
        kind = (item.get("kind") or "quality").title()
        name = item.get("name") or "?"
        value = item.get("value") or item.get("complexity")
        thr = item.get("threshold")
        detail = str(value) if value is not None else ""
        if thr is not None:
            detail += f" (limit {thr})"
        q_rows.append((kind, name, detail, _loc(item, root_path)))
        q_raw.append(item)
    for item in result.get("circular_dependencies") or []:
        cycle = item.get("cycle", [])
        q_rows.append(
            (
                "Circular Dep",
                " → ".join(cycle),
                f"Break: {item.get('suggested_break', '?')}",
                item.get("severity", "MEDIUM"),
            )
        )
        q_raw.append(item)
    for item in result.get("custom_rules") or []:
        q_rows.append(
            (
                "Custom",
                item.get("rule_id") or item.get("rule") or "CUSTOM",
                item.get("message") or "",
                _loc(item, root_path),
            )
        )
        q_raw.append(item)
    data["quality"] = (q_cols, q_rows, q_raw)

    # -- Dependencies (SCA) --
    dep_cols = ["Package", "Vuln ID", "Severity", "Message", "Fix"]
    dep_rows, dep_raw = [], []
    for item in result.get("dependency_vulnerabilities") or []:
        meta = item.get("metadata") or {}
        pkg_name = meta.get("package_name") or "?"
        pkg_ver = meta.get("package_version") or "?"
        vuln_id = (
            meta.get("display_id") or meta.get("vuln_id") or item.get("rule_id", "")
        )
        dep_rows.append(
            (
                f"{pkg_name}@{pkg_ver}",
                vuln_id,
                (item.get("severity") or "MEDIUM").upper(),
                item.get("message") or "",
                meta.get("fixed_version") or "-",
            )
        )
        dep_raw.append(item)
    data["dependencies"] = (dep_cols, dep_rows, dep_raw)

    sup_cols = ["Category", "Name / Rule", "Reason", "File:Line"]
    sup_rows, sup_raw = [], []
    for item in result.get("suppressed") or []:
        cat = (item.get("category") or "dead_code").replace("_", " ").title()
        name = item.get("name") or item.get("rule_id") or item.get("message") or "?"
        reason = item.get("reason") or "suppressed"
        sup_rows.append((cat, name, reason, _loc(item, root_path)))
        sup_raw.append(item)
    data["suppressed"] = (sup_cols, sup_rows, sup_raw)

    return data


class CategoryItem(ListItem):
    def __init__(self, cat_key: str, label: str, count: int) -> None:
        super().__init__()
        self.cat_key = cat_key
        self._label = label
        self._count = count

    def compose(self) -> ComposeResult:
        style = "bold red" if self._count > 0 else "dim"
        yield Label(f" {self._label}  [{style}]{self._count}[/{style}]")


class OverviewPanel(VerticalScroll):
    def __init__(self, result: dict, category_data: dict, **kw) -> None:
        super().__init__(**kw)
        self.result = result
        self.category_data = category_data

    def compose(self) -> ComposeResult:
        summ = self.result.get("analysis_summary") or {}
        total_files = summ.get("total_files", "?")

        yield Static(
            f"[bold cyan]  Skylos Analysis Summary[/bold cyan]\n\n"
            f"  Files analyzed: [bold]{total_files}[/bold]\n"
        )

        # Per-category counts
        lines = []
        for cat_key, label in CATEGORIES[1:]:
            _, rows, _ = self.category_data.get(cat_key, ([], [], []))
            n = len(rows)
            style = "bold red" if n > 0 else "dim"
            lines.append(f"  [{style}]{label:15s} {n}[/{style}]")
        yield Static("\n".join(lines) + "\n")

        sev_counts: dict[str, int] = {}
        for cat in ("security", "dependencies"):
            _, _, raw = self.category_data.get(cat, ([], [], []))
            for item in raw:
                sev = (item.get("severity") or "").upper()
                if sev:
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if sev_counts:
            total = sum(sev_counts.values())
            bar_width = 30
            sev_lines = ["  [bold]Severity Distribution[/bold]"]
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                c = sev_counts.get(s, 0)
                if c == 0:
                    continue
                color = SEVERITY_COLORS.get(s, "white")
                filled = max(1, round(c / total * bar_width)) if total else 0
                pct = round(c / total * 100) if total else 0
                bar = "█" * filled + "░" * (bar_width - filled)
                sev_lines.append(f"    [{color}]{s:10s} {bar} {c} ({pct}%)[/{color}]")
            yield Static("\n".join(sev_lines) + "\n")

        languages = summ.get("languages") or {}
        if languages:
            lang_lines = ["  [bold]Languages Detected[/bold]"]
            for lang, count in sorted(languages.items(), key=lambda x: -x[1]):
                lang_lines.append(
                    f"    {lang:15s} {count} file{'s' if count != 1 else ''}"
                )
            yield Static("\n".join(lang_lines) + "\n")

        file_counts: dict[str, int] = {}
        for cat_key in ("dead_code", "security", "secrets", "quality", "dependencies"):
            _, _, raw = self.category_data.get(cat_key, ([], [], []))
            for item in raw:
                f = item.get("file")
                if f:
                    file_counts[f] = file_counts.get(f, 0) + 1
        if file_counts:
            top = sorted(file_counts.items(), key=lambda x: -x[1])[:8]
            lines = ["  [bold]Top Affected Files[/bold]"]
            for path, n in top:
                short = _shorten(path)
                lines.append(f"    {short}: {n}")
            yield Static("\n".join(lines))


class DetailPanel(Static):
    def show_detail(self, category: str, item: dict, root_path=None) -> None:
        lines: list[str] = []
        file_path = item.get("file", "?")
        line_no = item.get("line", "?")
        lines.append(f"  [bold]File:[/bold]  {file_path}:{line_no}")

        if category == "dead_code":
            conf = item.get("confidence", "?")
            lines.append(f"  [bold]Type:[/bold]  {item.get('_type_label', '?')}")
            lines.append(f"  [bold]Confidence:[/bold]  {conf}%")
            if isinstance(conf, (int, float)):
                bar_len = int(conf) // 5
                color = "red" if conf >= 90 else "yellow" if conf >= 75 else "dim"
                lines.append(
                    f"  [{color}]{'█' * bar_len}{'░' * (20 - bar_len)}[/{color}]"
                )

        elif category == "security":
            lines.append(f"  [bold]Rule:[/bold]  {item.get('rule_id', '?')}")
            sev = item.get("severity", "?")
            color = (
                SEVERITY_COLORS.get(sev.upper(), "white")
                if isinstance(sev, str)
                else "white"
            )
            lines.append(f"  [bold]Severity:[/bold]  [{color}]{sev}[/{color}]")
            lines.append(f"  [bold]Message:[/bold]  {item.get('message', '')}")
            ver = item.get("verification") or {}
            if ver.get("verdict"):
                lines.append(f"  [bold]Verification:[/bold]  {ver['verdict']}")
                evidence = ver.get("evidence") or {}
                chain = evidence.get("chain")
                if isinstance(chain, list) and chain:
                    names = [
                        x.get("fn", "?") if isinstance(x, dict) else "?"
                        for x in chain[:6]
                    ]
                    lines.append(f"  [bold]Chain:[/bold]  {' → '.join(names)}")

        elif category == "secrets":
            lines.append(f"  [bold]Provider:[/bold]  {item.get('provider', '?')}")
            lines.append(f"  [bold]Preview:[/bold]  {item.get('preview', '****')}")

        elif category == "dependencies":
            meta = item.get("metadata") or {}
            lines.append(
                f"  [bold]Package:[/bold]  "
                f"{meta.get('package_name', '?')}@{meta.get('package_version', '?')}"
            )
            lines.append(f"  [bold]Vuln ID:[/bold]  {meta.get('vuln_id', '?')}")
            lines.append(f"  [bold]Fixed:[/bold]  {meta.get('fixed_version', '-')}")
            refs = meta.get("references") or []
            if refs:
                lines.append(f"  [bold]Refs:[/bold]  {', '.join(refs[:3])}")

        elif category == "quality":
            kind = item.get("kind") or item.get("_type_label") or "?"
            lines.append(f"  [bold]Kind:[/bold]  {kind}")
            value = item.get("value") or item.get("complexity")
            if value is not None:
                lines.append(f"  [bold]Value:[/bold]  {value}")
            thr = item.get("threshold")
            if thr is not None:
                lines.append(f"  [bold]Limit:[/bold]  {thr}")

        elif category == "suppressed":
            cat = item.get("category", "?")
            lines.append(f"  [bold]Category:[/bold]  {cat}")
            lines.append(f"  [bold]Reason:[/bold]  {item.get('reason', '?')}")
            name = item.get("name") or item.get("rule_id")
            if name:
                lines.append(f"  [bold]Name/Rule:[/bold]  {name}")
            msg = item.get("message")
            if msg:
                lines.append(f"  [bold]Message:[/bold]  {msg}")
            sev = item.get("severity")
            if sev:
                color = SEVERITY_COLORS.get(str(sev).upper(), "white")
                lines.append(f"  [bold]Severity:[/bold]  [{color}]{sev}[/{color}]")

        self.update("\n".join(lines))


class SkylosApp(App):
    TITLE = "Skylos"

    CSS = """
    #sidebar {
        width: 26;
        dock: left;
        background: $surface;
        border-right: solid $primary-background;
    }
    #sidebar ListView {
        height: 1fr;
    }
    #sidebar ListItem {
        padding: 0 0;
        height: 2;
    }
    #main-area {
        height: 1fr;
    }
    #overview-panel {
        height: 1fr;
        padding: 1 2;
    }
    #findings-table {
        height: 1fr;
    }
    #detail-panel {
        height: auto;
        max-height: 14;
        background: $surface;
        border-top: solid $primary-background;
        padding: 1 0;
        display: none;
    }
    #detail-panel.visible {
        display: block;
    }
    #search-input {
        dock: bottom;
        display: none;
    }
    #search-input.visible {
        display: block;
    }
    #status-bar {
        dock: bottom;
        height: 1;
        background: $primary-background;
        color: $text;
        padding: 0 2;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("slash", "toggle_search", "Search", key_display="/", priority=True),
        Binding("f", "cycle_severity", "Severity Filter", priority=True),
        Binding("tab", "next_category", "Next Tab", priority=True),
        Binding("shift+tab", "prev_category", "Prev Tab", priority=True),
        Binding("enter", "show_detail", "Detail", show=False, priority=True),
        Binding("o", "open_editor", "Open in $EDITOR", priority=True),
        Binding("escape", "dismiss", "Dismiss", show=False, priority=True),
        Binding("1", "go_category('overview')", "Overview", show=False, priority=True),
        Binding(
            "2", "go_category('dead_code')", "Dead Code", show=False, priority=True
        ),
        Binding("3", "go_category('security')", "Security", show=False, priority=True),
        Binding("4", "go_category('secrets')", "Secrets", show=False, priority=True),
        Binding("5", "go_category('quality')", "Quality", show=False, priority=True),
        Binding("6", "go_category('dependencies')", "Deps", show=False, priority=True),
        Binding(
            "7", "go_category('suppressed')", "Suppressed", show=False, priority=True
        ),
    ]

    active_category: reactive[str] = reactive("overview")
    severity_filter: reactive[str | None] = reactive(None)
    search_query: reactive[str] = reactive("")

    def __init__(self, result: dict, root_path=None) -> None:
        super().__init__()
        self.result = result
        self.root_path = str(root_path) if root_path else None
        self.category_data = prepare_category_data(result, self.root_path)
        self.category_counts: dict[str, int] = {}
        for cat_key, _ in CATEGORIES:
            if cat_key == "overview":
                self.category_counts[cat_key] = sum(
                    len(self.category_data.get(c, ([], [], []))[1])
                    for c, _ in CATEGORIES[1:]
                )
            else:
                _, rows, _ = self.category_data.get(cat_key, ([], [], []))
                self.category_counts[cat_key] = len(rows)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield ListView(
                    *[
                        CategoryItem(k, label, self.category_counts.get(k, 0))
                        for k, label in CATEGORIES
                    ],
                    id="category-list",
                )
            with Vertical(id="main-area"):
                yield OverviewPanel(
                    self.result, self.category_data, id="overview-panel"
                )
                yield DataTable(id="findings-table")
                yield DetailPanel("", id="detail-panel")
        yield Input(placeholder="Type to search...", id="search-input")
        yield Static("", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.display = False
        table.cursor_type = "row"
        self._update_status()
        self.query_one("#category-list", ListView).focus()

    # ── Category switching ──────────────────────────────────────────────

    def _show_category(self, cat_key: str) -> None:
        self.active_category = cat_key
        overview = self.query_one("#overview-panel", OverviewPanel)
        table = self.query_one("#findings-table", DataTable)
        detail = self.query_one("#detail-panel", DetailPanel)
        detail.remove_class("visible")

        if cat_key == "overview":
            overview.display = True
            table.display = False
        else:
            overview.display = False
            table.display = True
            self._populate_table(cat_key)
            table.focus()

        self._update_status()

    def _populate_table(self, cat_key: str) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear(columns=True)

        cols, rows, raw = self.category_data.get(cat_key, ([], [], []))
        if not cols:
            return

        for col in cols:
            table.add_column(col, key=col)

        filtered = self._filtered_rows(cat_key)
        for i, (row, _) in enumerate(filtered):
            styled = self._style_row(row)
            table.add_row(*styled, key=str(i))

    def _filtered_rows(self, cat_key: str) -> list[tuple[tuple, dict]]:
        _, rows, raw = self.category_data.get(cat_key, ([], [], []))
        result = []
        for row, item in zip(rows, raw):
            if self.severity_filter:
                sev = (item.get("severity") or "").upper()
                if sev and sev != self.severity_filter:
                    continue
            if self.search_query:
                q = self.search_query.lower()
                if not any(q in str(cell).lower() for cell in row):
                    continue
            result.append((row, item))
        return result

    def _style_row(self, row: tuple) -> list[Text]:
        cells = []
        for cell in row:
            t = Text(str(cell))
            upper = str(cell).strip().upper()
            if upper in SEVERITY_COLORS:
                t.stylize(SEVERITY_COLORS[upper])
            cells.append(t)
        return cells

    def _search_active(self) -> bool:
        return self.query_one("#search-input", Input).has_class("visible")

    def action_next_category(self) -> None:
        keys = [k for k, _ in CATEGORIES]
        idx = keys.index(self.active_category)
        nxt = (idx + 1) % len(keys)
        self._show_category(keys[nxt])
        self.query_one("#category-list", ListView).index = nxt

    def action_prev_category(self) -> None:
        keys = [k for k, _ in CATEGORIES]
        idx = keys.index(self.active_category)
        prev = (idx - 1) % len(keys)
        self._show_category(keys[prev])
        self.query_one("#category-list", ListView).index = prev

    def action_go_category(self, cat_key: str) -> None:
        if self._search_active():
            return
        keys = [k for k, _ in CATEGORIES]
        if cat_key in keys:
            self._show_category(cat_key)
            self.query_one("#category-list", ListView).index = keys.index(cat_key)

    def action_toggle_search(self) -> None:
        inp = self.query_one("#search-input", Input)
        inp.toggle_class("visible")
        if inp.has_class("visible"):
            inp.focus()
        else:
            self.search_query = ""
            inp.value = ""
            self._focus_main()
            if self.active_category != "overview":
                self._populate_table(self.active_category)

    def action_cycle_severity(self) -> None:
        if self._search_active():
            return
        cycle = [None, "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        idx = cycle.index(self.severity_filter) if self.severity_filter in cycle else 0
        self.severity_filter = cycle[(idx + 1) % len(cycle)]
        self._update_status()
        if self.active_category != "overview":
            self._populate_table(self.active_category)

    def action_show_detail(self) -> None:
        if self.active_category == "overview":
            return
        table = self.query_one("#findings-table", DataTable)
        cursor = table.cursor_row
        filtered = self._filtered_rows(self.active_category)
        if 0 <= cursor < len(filtered):
            _, item = filtered[cursor]
            detail = self.query_one("#detail-panel", DetailPanel)
            detail.show_detail(self.active_category, item, self.root_path)
            detail.add_class("visible")

    def action_open_editor(self) -> None:
        if self._search_active() or self.active_category == "overview":
            return
        table = self.query_one("#findings-table", DataTable)
        cursor = table.cursor_row
        filtered = self._filtered_rows(self.active_category)
        if 0 <= cursor < len(filtered):
            _, item = filtered[cursor]
            file_path = item.get("file")
            line = item.get("line", 1)
            editor = os.environ.get("EDITOR", "vi")
            if file_path:
                with self.suspend():
                    subprocess.call([editor, f"+{line}", file_path])

    def action_dismiss(self) -> None:
        self.query_one("#detail-panel", DetailPanel).remove_class("visible")
        inp = self.query_one("#search-input", Input)
        if inp.has_class("visible"):
            inp.remove_class("visible")
            self.search_query = ""
            inp.value = ""
            if self.active_category != "overview":
                self._populate_table(self.active_category)
        self._focus_main()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        item = event.item
        if isinstance(item, CategoryItem):
            self._show_category(item.cat_key)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, CategoryItem):
            self._show_category(item.cat_key)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self.search_query = event.value
            if self.active_category != "overview":
                self._populate_table(self.active_category)

    # ── Helpers ─────────────────────────────────────────────────────────

    def _focus_main(self) -> None:
        if self.active_category == "overview":
            self.query_one("#category-list", ListView).focus()
        else:
            self.query_one("#findings-table", DataTable).focus()

    def _update_status(self) -> None:
        total = sum(
            len(self.category_data.get(c, ([], [], []))[1]) for c, _ in CATEGORIES[1:]
        )
        sev = self.severity_filter or "ALL"
        cat = self.active_category.replace("_", " ").title()
        bar = self.query_one("#status-bar", Static)
        bar.update(f" Findings: {total}  │  Severity: {sev}  │  {cat}")


def run_tui(result: dict, root_path=None) -> None:
    app = SkylosApp(result, root_path=root_path)
    app.run()
