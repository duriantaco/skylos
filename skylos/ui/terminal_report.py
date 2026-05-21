from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from rich.console import Console
from rich.text import Text

from skylos.api._snippets import _resolve_snippet_path


CATEGORY_SPECS = (
    ("danger", "Security", "security issue"),
    ("secrets", "Secret", "secret detected"),
    ("quality", "Quality", "quality issue"),
    ("custom_rules", "Custom", "custom rule"),
    ("dependency_vulnerabilities", "Dependency", "dependency vulnerability"),
    ("unused_functions", "Dead Code", "unused function"),
    ("unused_imports", "Dead Code", "unused import"),
    ("unused_classes", "Dead Code", "unused class"),
    ("unused_variables", "Dead Code", "unused variable"),
    ("unused_parameters", "Dead Code", "unused parameter"),
    ("unused_files", "Dead Code", "unused file"),
    ("unused_fixtures", "Dead Code", "unused fixture"),
)

DEAD_CODE_TYPES = {
    "unused_functions": "function",
    "unused_imports": "import",
    "unused_classes": "class",
    "unused_variables": "variable",
    "unused_parameters": "parameter",
    "unused_files": "file",
    "unused_fixtures": "fixture",
}

SEVERITY_STYLES = {
    "CRITICAL": "bold white on magenta",
    "HIGH": "bold white on red",
    "MEDIUM": "bold black on yellow",
    "LOW": "bold white on blue",
    "INFO": "dim",
}

SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

SUMMARY_CATEGORIES = (
    "unused_functions",
    "unused_imports",
    "unused_parameters",
    "unused_variables",
    "unused_classes",
    "quality",
    "custom_rules",
    "danger",
    "secrets",
    "dependency_vulnerabilities",
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


def render_pretty_results(
    console: Console,
    result: dict,
    *,
    root_path=None,
    limit: int | None = None,
) -> None:
    findings = collect_pretty_findings(result, root_path=root_path, limit=limit)
    total_files = (result.get("analysis_summary") or {}).get("total_files", "?")

    header = Text.assemble(
        ("Skylos", "bold cyan"),
        (" static analysis", "bold"),
        (f"  {len(findings)} issue{'s' if len(findings) != 1 else ''}", "dim"),
        (f"  {total_files} file{'s' if total_files != 1 else ''} analyzed", "dim"),
    )
    console.print(header)

    summary = _summary_line(result)
    if summary.plain:
        console.print(summary)
    console.print()

    if not findings:
        console.print(Text("  No findings to display.", style="bold green"))
        return

    by_file: dict[str, list[PrettyFinding]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)

    for file_path in sorted(by_file):
        file_findings = sorted(
            by_file[file_path],
            key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.line, f.rule),
        )
        short_path = _sanitize_terminal_text(_shorten_path(file_path, root_path))
        count = len(file_findings)
        console.print(
            Text.assemble(
                ("  ", ""),
                (short_path, "bold"),
                (" · ", "dim"),
                (f"{count} issue{'s' if count != 1 else ''}", "dim"),
            )
        )
        console.print()

        for finding in file_findings:
            _print_finding(console, finding, short_path)
        console.print()

    _print_footer(console, findings)


def collect_pretty_findings(
    result: dict,
    *,
    root_path=None,
    limit: int | None = None,
) -> list[PrettyFinding]:
    source_cache: dict[str, list[str] | None] = {}
    findings: list[PrettyFinding] = []

    for category, category_label, fallback_label in CATEGORY_SPECS:
        items = list(result.get(category, []) or [])
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
    rule = _sanitize_terminal_text(_rule_id(item, category))
    title = _sanitize_terminal_text(_title(item, category, fallback_label))
    snippet = _sanitize_terminal_text(
        _snippet(item, category, root_path=root_path, source_cache=source_cache)
    )
    fix = _sanitize_terminal_text(_fix(item, category))
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
    )


def _print_finding(console: Console, finding: PrettyFinding, short_path: str) -> None:
    first = Text.assemble(
        ("    ", ""),
        ("█", _severity_rail_style(finding.severity)),
        (" ", ""),
        (
            _severity_badge(finding.severity),
            SEVERITY_STYLES.get(finding.severity, "dim"),
        ),
        (" ", ""),
        (finding.rule, "cyan"),
        ("  ", ""),
        (_truncate(finding.title, 140), ""),
    )
    console.print(first)

    meta = Text.assemble(
        ("      ", ""),
        (finding.category_label, "dim"),
        ("  ", "dim"),
        (f"{short_path}:{finding.line}", "dim"),
    )
    console.print(meta)

    if finding.snippet:
        console.print(
            Text.assemble(
                ("      ", ""),
                (_truncate(finding.snippet.strip(), 140), "dim"),
            )
        )

    if finding.fix:
        console.print(Text.assemble(("      Fix: ", "bold green"), (finding.fix, "")))

    console.print()


def _print_footer(console: Console, findings: list[PrettyFinding]) -> None:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    console.print(Text("  " + "─" * 52, style="dim"))
    parts: list[Text] = [
        Text(
            f"  {len(findings)} issue{'s' if len(findings) != 1 else ''}",
            style="bold",
        )
    ]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
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

    if not parts:
        return Text()

    line = Text("  ")
    for part in parts:
        line.append(part)
    return line


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

    text = str(path)
    parts = text.replace("\\", "/").split("/")
    if raw.is_absolute() and len(parts) > 4:
        return ".../" + "/".join(parts[-3:])
    return text


def _line_number(item: dict) -> int:
    raw = item.get("line") or item.get("line_number") or item.get("lineno") or 1
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return 1


def _severity(item: dict, category: str) -> str:
    raw = item.get("severity")
    if raw:
        label = str(raw).strip().upper()
        if label:
            return label
    if category in {"danger", "secrets", "dependency_vulnerabilities"}:
        return "HIGH"
    if category in {"quality", "custom_rules"}:
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
    if category in DEAD_CODE_TYPES:
        name = item.get("name") or item.get("simple_name") or item.get("symbol")
        if name:
            return f"Unused {DEAD_CODE_TYPES[category]}: {name}"

    if category == "dependency_vulnerabilities":
        meta = item.get("metadata") or {}
        pkg = meta.get("package_name")
        version = meta.get("package_version")
        vuln = meta.get("display_id") or meta.get("vuln_id") or item.get("rule_id")
        if pkg:
            package = f"{pkg}@{version}" if version else str(pkg)
            suffix = f" ({vuln})" if vuln else ""
            return f"Vulnerable dependency: {package}{suffix}"

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
