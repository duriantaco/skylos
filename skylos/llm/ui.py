from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
        TimeElapsedColumn,
    )
    from rich.live import Live
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.rule import Rule

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .schemas import Severity, Confidence


THEME_CRITICAL = "bold red"
THEME_HIGH = "red"
THEME_MEDIUM = "yellow"
THEME_LOW = "cyan"
THEME_INFO = "dim"

THEME_SUCCESS = "bold green"
THEME_WARNING = "bold yellow"
THEME_ERROR = "bold red"
THEME_MUTED = "dim"

THEME_BRAND = "bold cyan"
THEME_ACCENT = "magenta"


SEVERITY_STYLE_MAP = {
    Severity.CRITICAL: THEME_CRITICAL,
    Severity.HIGH: THEME_HIGH,
    Severity.MEDIUM: THEME_MEDIUM,
    Severity.LOW: THEME_LOW,
    Severity.INFO: THEME_INFO,
}

CONFIDENCE_STYLE_MAP = {
    Confidence.HIGH: "green",
    Confidence.MEDIUM: "yellow",
    Confidence.LOW: "dim yellow",
    Confidence.UNCERTAIN: "dim red",
}

SEVERITY_ICON_MAP = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def severity_style(severity):
    if severity in SEVERITY_STYLE_MAP:
        return SEVERITY_STYLE_MAP[severity]
    return THEME_MUTED


def confidence_style(confidence):
    if confidence in CONFIDENCE_STYLE_MAP:
        return CONFIDENCE_STYLE_MAP[confidence]
    return "dim"


def severity_icon(severity):
    if severity in SEVERITY_ICON_MAP:
        return SEVERITY_ICON_MAP[severity]
    return "⚪"


def _finding_line_key(finding):
    loc = getattr(finding, "location", None)
    if loc is None:
        return 0
    line = getattr(loc, "line", 0)
    try:
        return int(line)
    except Exception:
        return 0


class SkylosUI:
    def _make_console(self):
        if not RICH_AVAILABLE:
            return None
        return Console()

    def __init__(self, quiet=False):
        self.quiet = quiet
        self.console = self._make_console()

    def print(self, message, style=None):
        if self.quiet:
            return
        if self.console:
            self.console.print(message, style=style)
        else:
            print(message)

    def print_banner(self):
        if self.quiet:
            return

        banner = """
╔═══════════════════════════════════════════╗
║     Skylos AI Analyzer                    ║
║  Intelligent Code Analysis                ║
╚═══════════════════════════════════════════╝
"""
        self.print(banner, style=THEME_BRAND)

    def print_section(self, title, icon=""):
        if self.quiet:
            return

        if self.console:
            text = icon + " " + title
            self.console.print(Rule(text, style=THEME_BRAND))
        else:
            print("\n=== " + icon + " " + title + " ===\n")

    def create_progress(self):
        if not RICH_AVAILABLE:
            return DummyProgress()

        return Progress(
            SpinnerColumn(style=THEME_BRAND),
            TextColumn("[bold cyan]Skylos[/bold cyan] {task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )

    def stream_output(self, generator, prefix=""):
        if self.quiet:
            full_text = ""
            for chunk in generator:
                full_text += chunk
            return full_text

        full_text = ""

        if self.console:
            with Live(console=self.console, refresh_per_second=10) as live:
                for chunk in generator:
                    full_text += chunk

                    preview = full_text
                    if len(preview) > 500:
                        preview = preview[-500:]

                    live.update(Panel(preview, title=prefix, border_style=THEME_MUTED))
        else:
            for chunk in generator:
                full_text += chunk
                print(chunk, end="", flush=True)
            print()

        return full_text

    def print_findings_table(self, findings, title="Findings"):
        if self.quiet or not findings:
            return

        if not self.console:
            self._print_findings_plain(findings)
            return

        table = Table(title=title, expand=True)
        table.add_column("#", style="dim", width=3)
        table.add_column("Severity", width=10)
        table.add_column("Rule", style="yellow", width=12)
        table.add_column("Message", overflow="fold")
        table.add_column("Location", style="dim", width=30)
        table.add_column("Conf", width=6)

        i = 1
        for f in findings:
            sev_style = severity_style(f.severity)
            conf_style = confidence_style(f.confidence)

            icon = severity_icon(f.severity)

            filename = ""
            if f.location and f.location.file:
                filename = Path(f.location.file).name

            loc = filename + ":" + str(f.location.line)

            sev_text = (
                "["
                + sev_style
                + "]"
                + icon
                + " "
                + f.severity.value
                + "[/"
                + sev_style
                + "]"
            )
            conf_text = (
                "["
                + conf_style
                + "]"
                + f.confidence.value[:1].upper()
                + "[/"
                + conf_style
                + "]"
            )

            table.add_row(
                str(i),
                sev_text,
                f.rule_id,
                f.message,
                loc,
                conf_text,
            )
            i += 1

        self.console.print(table)

    def _print_findings_plain(self, findings):
        i = 1
        for f in findings:
            print(
                str(i) + ". [" + f.severity.value + "] " + f.rule_id + ": " + f.message
            )
            print("   Location: " + str(f.location.file) + ":" + str(f.location.line))
            if f.suggestion:
                print("   Suggestion: " + str(f.suggestion))
            print()
            i += 1

    def print_findings_tree(self, findings, root_path=None):
        if self.quiet or not findings:
            return

        if not self.console:
            self._print_findings_plain(findings)
            return

        by_file = {}
        for f in findings:
            file_path = f.location.file
            if file_path not in by_file:
                by_file[file_path] = []
            by_file[file_path].append(f)

        root_label = root_path
        if not root_label:
            root_label = "Skylos AI Analysis"

        tree = Tree("[" + THEME_BRAND + "]🔍 " + root_label + "[/" + THEME_BRAND + "]")

        for file_path in sorted(by_file.keys()):
            file_findings = by_file[file_path]
            short_path = Path(file_path).name
            file_node = tree.add("[bold]" + short_path + "[/bold]")

            file_findings.sort(key=_finding_line_key)

            for f in file_findings:
                sev_style = severity_style(f.severity)
                icon = severity_icon(f.severity)
                msg = (
                    "["
                    + sev_style
                    + "]"
                    + "L"
                    + str(f.location.line)
                    + "[/"
                    + sev_style
                    + "] "
                    + icon
                    + " "
                    + f.message
                )
                file_node.add(msg)

        self.console.print(tree)

    def print_summary(self, result):
        if self.quiet:
            return

        counts = {}
        for s in Severity:
            counts[s] = 0

        for f in result.findings:
            counts[f.severity] += 1

        if self.console:
            self.console.print()
            self.console.print(Rule("Summary", style=THEME_BRAND))

            stats_lines = []
            stats_lines.append("Files analyzed: " + str(result.files_analyzed))
            stats_lines.append("Total findings: " + str(len(result.findings)))
            stats_lines.append("Analysis time: " + str(result.analysis_time_ms) + "ms")

            if result.tokens_used:
                stats_lines.append("Tokens used: " + str(result.tokens_used))

            self.console.print(
                Panel("\n".join(stats_lines), title="Stats", border_style=THEME_MUTED)
            )

            breakdown = []

            ordered = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            for sev in ordered:
                if counts[sev] > 0:
                    style = severity_style(sev)
                    icon = severity_icon(sev)
                    breakdown.append(
                        "["
                        + style
                        + "]"
                        + icon
                        + " "
                        + sev.value
                        + ": "
                        + str(counts[sev])
                        + "[/"
                        + style
                        + "]"
                    )

            if breakdown:
                self.console.print(" | ".join(breakdown))
            else:
                self.console.print(
                    "[" + THEME_SUCCESS + "]✨ No issues found![/" + THEME_SUCCESS + "]"
                )

        else:
            print(
                "\nSummary: "
                + str(len(result.findings))
                + " findings in "
                + str(result.files_analyzed)
                + " files"
            )

    def print_fix(self, fix):
        if self.quiet:
            return

        if self.console:
            panel_text = "[bold]Problem:[/bold] " + str(fix.description)
            self.console.print(
                Panel(
                    panel_text,
                    title="Fix Proposed",
                    border_style=THEME_ACCENT,
                )
            )

            self.console.print("[red]- Original:[/red]")
            self.console.print(
                Syntax(fix.original_code, "python", theme="monokai", line_numbers=True)
            )

            self.console.print("[green]+ Fixed:[/green]")

            if not (fix.fixed_code or "").strip():
                self.console.print("[yellow]No fixed code returned by model.[/yellow]")
                return

            issue_line = getattr(fix.finding.location, "line", 1) or 1
            fixed_lines = fix.fixed_code.splitlines()

            if len(fixed_lines) > 80:
                start = max(0, issue_line - 6)
                end = min(len(fixed_lines), issue_line + 6)
                fixed_snip = "\n".join(fixed_lines[start:end])
            else:
                fixed_snip = fix.fixed_code

            self.console.print(
                Syntax(fixed_snip, "python", theme="monokai", line_numbers=True)
            )

            conf_style = confidence_style(fix.confidence)
            self.console.print(
                "\nConfidence: ["
                + conf_style
                + "]"
                + fix.confidence.value
                + "[/"
                + conf_style
                + "]"
            )

        else:
            print("\n=== Fix Proposed ===")
            print("Problem: " + str(fix.description))
            print("\nOriginal:\n" + str(fix.original_code))
            print("\nFixed:\n" + str(fix.fixed_code))

    def confirm(self, message, default=False):
        if not self.console:
            response = input(str(message) + " [y/N]: ").lower()
            return response in ("y", "yes")

        try:
            import inquirer

            return inquirer.confirm(message, default=default)
        except ImportError:
            prompt = (
                "["
                + THEME_WARNING
                + "]"
                + str(message)
                + "[/"
                + THEME_WARNING
                + "] [y/N]: "
            )
            response = self.console.input(prompt)
            return response.lower() in ("y", "yes")

    def status(self, message):
        if self.quiet or not self.console:
            return DummyContext()

        text = "[" + THEME_BRAND + "]" + str(message) + "[/" + THEME_BRAND + "]"
        return self.console.status(text, spinner="dots")


class DummyProgress:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def add_task(self, description):
        print("Starting: " + str(description))
        return 0

    def update(self, **kwargs):
        if "description" in kwargs:
            print("  " + str(kwargs["description"]))


class DummyContext:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def format_finding_for_display(finding):
    sev = finding.severity.value.upper()[:4]
    text = "[" + sev + "] " + finding.rule_id + ": " + finding.message
    text += " (" + str(finding.location.file) + ":" + str(finding.location.line) + ")"
    return text


def estimate_cost(files, model="gpt-4.1"):
    total_chars = 0

    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            total_chars += len(content)
        except Exception:
            pass

    est_tokens = total_chars / 4

    model_l = str(model).lower()

    cost_per_1k = 0.002
    if "gpt-4" in model_l:
        cost_per_1k = 0.03
    elif "claude" in model_l:
        cost_per_1k = 0.015

    est_cost = (est_tokens / 1000) * cost_per_1k * 2

    return int(est_tokens), round(est_cost, 4)
