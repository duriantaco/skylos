import argparse
import json
import sys
import re
import logging
import os
from skylos.constants import parse_exclude_folders, DEFAULT_EXCLUDE_FOLDERS
from skylos.fixer import Fixer
from skylos.analyzer import analyze as run_analyze
from skylos.codemods import (
    remove_unused_import_cst,
    remove_unused_function_cst,
    comment_out_unused_import_cst,
    comment_out_unused_function_cst,
)
from skylos.llm.runtime import resolve_llm_runtime
from skylos.config import load_config
from skylos.gatekeeper import run_gate_interaction
from skylos.api import upload_report
from skylos.sarif_exporter import SarifExporter
from skylos.pipeline import run_pipeline

from pathlib import Path
import pathlib
import skylos
from collections import defaultdict
import subprocess
import textwrap

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.theme import Theme
from rich.logging import RichHandler
from rich.rule import Rule
from rich.tree import Tree

try:
    import inquirer

    INTERACTIVE_AVAILABLE = True
except ImportError:
    INTERACTIVE_AVAILABLE = False


try:
    from skylos.llm.analyzer import SkylosLLM, AnalyzerConfig
    from skylos.llm.ui import estimate_cost as llm_estimate_cost

    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False


class CleanFormatter(logging.Formatter):
    def format(self, record):
        return record.getMessage()


def setup_logger(output_file=None):
    theme = Theme(
        {
            "good": "bold green",
            "warn": "bold yellow",
            "bad": "bold red",
            "muted": "dim",
            "brand": "bold cyan",
        }
    )
    console = Console(theme=theme)

    logger = logging.getLogger("skylos")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    rich_handler = RichHandler(
        console=console, show_time=False, show_path=False, markup=True
    )
    rich_handler.setFormatter(CleanFormatter())
    logger.addHandler(rich_handler)

    if output_file:
        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler = logging.FileHandler(output_file)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    logger.propagate = False
    logger.console = console
    return logger


def remove_unused_import(file_path, import_name, line_number):
    path = pathlib.Path(file_path)

    try:
        src = path.read_text(encoding="utf-8")
        new_code, changed = remove_unused_import_cst(src, import_name, line_number)
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True

    except Exception as e:
        logging.error(f"Failed to remove import {import_name} from {file_path}: {e}")
        return False


def remove_unused_function(file_path, function_name, line_number):
    path = pathlib.Path(file_path)

    try:
        src = path.read_text(encoding="utf-8")
        new_code, changed = remove_unused_function_cst(src, function_name, line_number)
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True

    except Exception as e:
        logging.error(
            f"Failed to remove function {function_name} from {file_path}: {e}"
        )
        return False


def comment_out_unused_import(
    file_path, import_name, line_number, marker="SKYLOS DEADCODE"
):
    path = pathlib.Path(file_path)

    try:
        src = path.read_text(encoding="utf-8")
        new_code, changed = comment_out_unused_import_cst(
            src, import_name, line_number, marker=marker
        )
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True

    except Exception as e:
        logging.error(
            f"Failed to comment out import {import_name} from {file_path}: {e}"
        )
        return False


def comment_out_unused_function(
    file_path, function_name, line_number, marker="SKYLOS DEADCODE"
):
    path = pathlib.Path(file_path)

    try:
        src = path.read_text(encoding="utf-8")
        new_code, changed = comment_out_unused_function_cst(
            src, function_name, line_number, marker=marker
        )
        if not changed:
            return False
        path.write_text(new_code, encoding="utf-8")
        return True

    except Exception as e:
        logging.error(
            f"Failed to comment out function {function_name} from {file_path}: {e}"
        )
        return False


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


def find_project_root(path):
    try:
        p = Path(path).resolve()
    except Exception:
        return Path.cwd().resolve()

    if p.is_file():
        cur = p.parent
    else:
        cur = p

    while True:
        if (cur / "pyproject.toml").exists():
            return cur
        if (cur / ".git").exists():
            return cur

        parent = cur.parent
        if parent == cur:
            break
        cur = parent

    return Path.cwd().resolve()


def _rel_to_project_root(file_path: str, project_root: Path) -> str:
    if not file_path:
        return "?"
    try:
        p = Path(file_path).resolve()
        root = Path(project_root).resolve()
        return str(p.relative_to(root)).replace("\\", "/")
    except Exception:
        return str(file_path).replace("\\", "/")


def _normalize_agent_findings(payload, project_root: Path):
    if isinstance(payload, dict):
        items = payload.get("findings") or payload.get("merged_findings") or []
        payload = dict(payload)
        payload["findings"] = _normalize_agent_findings(items, project_root)
        return payload

    out = []
    for f in payload or []:
        if not isinstance(f, dict):
            continue
        ff = dict(f)
        ff["file"] = _rel_to_project_root(ff.get("file", ""), project_root)
        try:
            ff["line"] = int(ff.get("line") or 1)
        except Exception:
            ff["line"] = 1
        out.append(ff)
    return out


def _agent_findings_to_result_json(findings):
    result = {
        "danger": [],
        "quality": [],
        "secrets": [],
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
    }

    category_map = {
        "security": "danger",
        "danger": "danger",
        "quality": "quality",
        "secret": "secrets",
        "secrets": "secrets",
    }

    dead_code_map = {
        "SKY-U001": "unused_functions",
        "SKY-U002": "unused_imports",
        "SKY-U003": "unused_variables",
        "SKY-U004": "unused_classes",
    }

    for f in findings or []:
        item = dict(f)
        item.setdefault("file_path", item.get("file", ""))
        item.setdefault("line_number", item.get("line", 1))

        cat = str(item.get("_category") or item.get("category") or "").lower()
        rule_id = str(item.get("rule_id") or item.get("rule") or "")

        if cat == "dead_code" or rule_id.startswith("SKY-U"):
            bucket = dead_code_map.get(rule_id, "unused_functions")
            result[bucket].append(item)
        elif cat in category_map:
            result[category_map[cat]].append(item)
        else:
            result["quality"].append(item)

    return result


def _is_tty():
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def _has_high_intent_findings(result: dict) -> bool:
    secrets = result.get("secrets") or []
    if len(secrets) > 0:
        return True

    def _is_highish(item: dict) -> bool:
        sev = str(item.get("severity", "")).strip().lower()
        return sev in ("high", "critical")

    for item in result.get("danger") or []:
        if _is_highish(item):
            return True

    for item in result.get("custom_rules") or []:
        if _is_highish(item):
            return True

    return False


def _set_no_upload_prompt(project_root: Path, value: bool) -> bool:
    pyproject = project_root / "pyproject.toml"
    if not pyproject.exists():
        return False

    content = pyproject.read_text(encoding="utf-8", errors="ignore")

    key_line = f"no_upload_prompt = {'true' if value else 'false'}"

    if "[tool.skylos]" not in content:
        content = content.rstrip() + "\n\n[tool.skylos]\n" + key_line + "\n"
        pyproject.write_text(content, encoding="utf-8")
        return True

    if re.search(r"(?m)^\s*no_upload_prompt\s*=\s*(true|false)\s*$", content):
        content = re.sub(
            r"(?m)^\s*no_upload_prompt\s*=\s*(true|false)\s*$",
            key_line,
            content,
        )
        pyproject.write_text(content, encoding="utf-8")
        return True

    content = re.sub(
        r"(?m)^\[tool\.skylos\]\s*$",
        "[tool.skylos]\n" + key_line,
        content,
        count=1,
    )
    pyproject.write_text(content, encoding="utf-8")
    return True


def _detect_link_file(project_root: Path) -> Path | None:
    p = project_root / ".skylos" / "link.json"

    if p.exists():
        return p
    else:
        return None


def _print_upload_destination(console: Console, project_root: Path):
    using_env = bool(os.getenv("SKYLOS_TOKEN"))
    link_path = _detect_link_file(project_root)
    has_link = link_path is not None

    if using_env:
        console.print("[brand]Upload destination:[/brand] SKYLOS_TOKEN override")
    elif has_link:
        console.print(
            f"[brand]Upload destination:[/brand] linked project ([muted]{link_path}[/muted])"
        )
    else:
        console.print(
            "[warn]Upload destination:[/warn] default token (no repo link found)"
        )

    return has_link, using_env


def _is_ci():
    return any(
        os.getenv(v)
        for v in (
            "CI",
            "GITHUB_ACTIONS",
            "JENKINS_URL",
            "BUILD_NUMBER",
            "CIRCLECI",
            "GITLAB_CI",
            "BITBUCKET_PIPELINE_UUID",
            "AZURE_PIPELINES",
            "TF_BUILD",
        )
    )


def _print_upload_cta(console: Console, project_root: Path):
    if _is_ci():
        return

    has_link = _detect_link_file(project_root) is not None
    has_env = bool(os.getenv("SKYLOS_TOKEN"))
    connected = has_link or has_env

    console.print()
    if connected:
        console.print(
            Panel(
                "\n".join(
                    [
                        "[bold]Upload to Skylos Cloud for trend tracking and PR blocking[/bold]",
                        "",
                        "  [bold cyan]skylos . --upload[/bold cyan]",
                        "",
                        "  [dim]Dashboard:[/dim] https://skylos.dev/dashboard",
                    ]
                ),
                title="[bold]☁️  Skylos Cloud[/bold]",
                border_style="blue",
                padding=(1, 2),
            )
        )
    else:
        console.print(
            Panel(
                "\n".join(
                    [
                        "[bold]Upload to Skylos Cloud in one command[/bold]",
                        "",
                        "  [bold cyan]skylos . --upload[/bold cyan]",
                        "",
                        "  [dim]Browser opens → pick project → done![/dim]",
                        "  [dim]Dashboard:[/dim] https://skylos.dev",
                    ]
                ),
                title="[bold]☁️  Skylos Cloud[/bold]",
                border_style="blue",
                padding=(1, 2),
            )
        )


def interactive_selection(
    console: Console, unused_functions, unused_imports, root_path=None
):
    if not INTERACTIVE_AVAILABLE:
        console.print(
            "[bad]Interactive mode requires 'inquirer'. Install with: pip install inquirer[/bad]"
        )
        return [], []

    selected_functions = []
    selected_imports = []

    if unused_functions:
        console.print(
            "\n[brand][bold]Select unused functions to remove (space to select):[/bold][/brand]"
        )

        function_choices = []
        for item in unused_functions:
            short = _shorten_path(item.get("file"), root_path)
            choice_text = f"{item['name']} ({short}:{item['line']})"
            function_choices.append((choice_text, item))

        questions = [
            inquirer.Checkbox(
                "functions",
                message="Select functions to remove",
                choices=function_choices,
            )
        ]
        answers = inquirer.prompt(questions)
        if answers:
            selected_functions = answers["functions"]

    if unused_imports:
        console.print(
            "\n[brand][bold]Select unused imports to act on (space to select):[/bold][/brand]"
        )

        import_choices = []
        for item in unused_imports:
            short = _shorten_path(item.get("file"), root_path)
            choice_text = f"{item['name']} ({short}:{item['line']})"
            import_choices.append((choice_text, item))

        questions = [
            inquirer.Checkbox(
                "imports", message="Select imports to remove", choices=import_choices
            )
        ]
        answers = inquirer.prompt(questions)
        if answers:
            selected_imports = answers["imports"]

    return selected_functions, selected_imports


def print_badge(
    dead_code_count,
    logger,
    *,
    danger_enabled=False,
    danger_count=0,
    quality_enabled=False,
    quality_count=0,
):
    console: Console = logger.console
    console.print(Rule(style="muted"))

    has_dead_code = dead_code_count > 0
    has_danger = danger_enabled and danger_count > 0
    has_quality = quality_enabled and quality_count > 0

    if not has_dead_code and not has_danger and not has_quality:
        console.print(
            Panel.fit(
                "[good]Your code is 100% dead-code free![/good]\nAdd this badge to your README:",
                border_style="good",
            )
        )
        console.print("```markdown")
        console.print(
            "![Dead Code Free](https://img.shields.io/badge/Dead_Code-Free-brightgreen?logo=moleculer&logoColor=white)"
        )
        console.print("```")
        return

    headline = f"Found {dead_code_count} dead-code items"
    if danger_enabled:
        headline += f" and {danger_count} security issues"
    if quality_enabled:
        headline += f" and {quality_count} quality issues"
    headline += ". Add this badge to your README:"

    console.print(Panel.fit(headline, border_style="warn"))
    console.print("```markdown")
    console.print(
        f"![Dead Code: {dead_code_count}](https://img.shields.io/badge/Dead_Code-{dead_code_count}_detected-orange?logo=codacy&logoColor=red)"
    )
    console.print("```")


def _emit_github_annotations(result, *, max_annotations=50, severity_filter=None):
    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "notice",
    }
    severity_priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    severity_thresholds = {
        "critical": {"CRITICAL"},
        "high": {"CRITICAL", "HIGH"},
        "medium": {"CRITICAL", "HIGH", "MEDIUM"},
        "low": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
    }

    grade_data = result.get("grade")
    if grade_data:
        overall = grade_data["overall"]
        print(
            f"::notice title=Skylos Grade::{overall['letter']} ({overall['score']}/100)"
        )

    annotations = []

    for category in ("danger", "quality", "secrets", "custom_rules"):
        for finding in result.get(category, []) or []:
            file = finding.get("file") or finding.get("file_path") or ""
            line = finding.get("line") or finding.get("line_number") or 1
            msg = (
                finding.get("message")
                or finding.get("msg")
                or finding.get("detail")
                or "Issue detected"
            )
            rule_id = finding.get("rule_id") or ""
            severity = finding.get("severity", "MEDIUM").upper()
            title = f"Skylos {rule_id}" if rule_id else "Skylos"
            annotations.append(
                {
                    "file": file,
                    "line": line,
                    "msg": msg,
                    "title": title,
                    "severity": severity,
                }
            )

    for category, label in (
        ("unused_functions", "Unused function"),
        ("unused_imports", "Unused import"),
        ("unused_classes", "Unused class"),
        ("unused_variables", "Unused variable"),
        ("unused_parameters", "Unused parameter"),
    ):
        for item in result.get(category, []) or []:
            name = item.get("name", "") if isinstance(item, dict) else str(item)
            file = item.get("file", "") if isinstance(item, dict) else ""
            line = item.get("line", 1) if isinstance(item, dict) else 1
            annotations.append(
                {
                    "file": file,
                    "line": line,
                    "msg": f"{label}: {name}",
                    "title": "Skylos Dead Code",
                    "severity": "MEDIUM",
                }
            )

    if severity_filter:
        allowed = severity_thresholds.get(severity_filter, set())
        annotations = [a for a in annotations if a["severity"] in allowed]

    annotations.sort(key=lambda a: severity_priority.get(a["severity"], 99))
    annotations = annotations[:max_annotations]

    for ann in annotations:
        level = severity_map.get(ann["severity"], "warning")
        print(
            f"::{level} file={ann['file']},line={ann['line']},title={ann['title']}::{ann['msg']}"
        )


def _apply_display_filters(result, severity=None, category=None, file_filter=None):
    import copy

    SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if severity:
        min_rank = SEVERITY_RANK.get(str(severity).lower(), 0)
    else:
        min_rank = 0

    allowed_cats = None
    if category:
        allowed_cats = {c.strip().lower() for c in category.split(",")}

    CATEGORY_MAP = {
        "unused_functions": "dead_code",
        "unused_imports": "dead_code",
        "unused_parameters": "dead_code",
        "unused_variables": "dead_code",
        "unused_classes": "dead_code",
        "unused_fixtures": "dead_code",
        "danger": "security",
        "secrets": "secret",
        "quality": "quality",
        "circular_dependencies": "quality",
        "custom_rules": "quality",
        "dependency_vulnerabilities": "dependency",
    }

    filtered = copy.copy(result)

    for key, cat in CATEGORY_MAP.items():
        items = result.get(key, []) or []
        if not items:
            continue

        if allowed_cats and cat not in allowed_cats:
            filtered[key] = []
            continue

        kept = items
        if file_filter:
            kept = [
                item
                for item in kept
                if file_filter in (item.get("file") or item.get("file_path") or "")
            ]

        if min_rank > 0:

            def _passes_severity(item):
                sev = (item.get("severity") or "").lower()
                return SEVERITY_RANK.get(sev, 0) >= min_rank

            if kept:
                has_severity = False
                for item in kept:
                    if "severity" in item:
                        has_severity = True
                        break

                if has_severity:
                    filtered = []
                    for item in kept:
                        if _passes_severity(item):
                            filtered.append(item)
                    kept = filtered

        filtered[key] = kept

    return filtered


def render_results(console: Console, result, tree=False, root_path=None, limit=None):
    summ = result.get("analysis_summary", {})
    console.print(
        Panel.fit(
            f"[brand]Python Static Analysis Results[/brand]\n[muted]Analyzed {summ.get('total_files', '?')} file(s)[/muted]",
            border_style="brand",
        )
    )

    def _pill(label, n, ok_style="good", bad_style="bad"):
        if n == 0:
            style = ok_style
        else:
            style = bad_style
        return f"[{style}]{label}: {n}[/{style}]"

    console.print(
        " ".join(
            [
                _pill("Unused functions", len(result.get("unused_functions", []))),
                _pill("Unused imports", len(result.get("unused_imports", []))),
                _pill("Unused params", len(result.get("unused_parameters", []))),
                _pill("Unused vars", len(result.get("unused_variables", []))),
                _pill("Unused classes", len(result.get("unused_classes", []))),
                _pill(
                    "Quality", len(result.get("quality", []) or []), bad_style="warn"
                ),
                _pill(
                    "Custom",
                    len(result.get("custom_rules", []) or []),
                    bad_style="warn",
                ),
                _pill(
                    "Suppressed",
                    len(result.get("suppressed", []) or []),
                    ok_style="muted",
                    bad_style="muted",
                ),
            ]
        )
    )
    console.print()

    grade_data = result.get("grade")
    if grade_data:
        from skylos.grader import generate_badge_url

        overall = grade_data["overall"]
        cats = grade_data["categories"]
        o_score = overall["score"]

        if o_score >= 90:
            g_style = "good"
        elif o_score >= 80:
            g_style = "brand"
        elif o_score >= 70:
            g_style = "yellow"
        else:
            g_style = "bad"

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

        for cat_name in ("security", "quality", "dead_code", "dependencies", "secrets"):
            cat = cats[cat_name]
            display_name = cat_name.replace("_", " ").title()
            s_val = cat["score"]
            l_val = cat["letter"]
            w_pct = f"{int(cat['weight'] * 100)}%"
            issue = cat.get("key_issue") or "-"
            if len(issue) > 60:
                issue = issue[:57] + "..."

            if s_val >= 90:
                s_str = f"[good]{s_val}[/good]"
                l_str = f"[good]{l_val}[/good]"
            elif s_val >= 80:
                s_str = f"[brand]{s_val}[/brand]"
                l_str = f"[brand]{l_val}[/brand]"
            elif s_val >= 70:
                s_str = f"[yellow]{s_val}[/yellow]"
                l_str = f"[yellow]{l_val}[/yellow]"
            else:
                s_str = f"[bad]{s_val}[/bad]"
                l_str = f"[bad]{l_val}[/bad]"

            grade_table.add_row(display_name, s_str, l_str, w_pct, issue)

        console.print(grade_table)
        badge_url = generate_badge_url(overall["letter"], o_score)
        console.print(f"[muted]Badge: ![Skylos Grade]({badge_url})[/muted]")
        console.print()

    def _display_cap(items):
        cap = limit or len(items)
        return items[:cap], max(0, len(items) - cap)

    def _render_unused(title, items, name_key="name"):
        if not items:
            return

        console.rule(f"[bold]{title}")

        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Name", style="bold")
        table.add_column("Location", style="muted", overflow="fold")
        table.add_column("Conf", style="yellow", width=6, justify="right")

        show, overflow = _display_cap(items)
        for i, item in enumerate(show, 1):
            nm = item.get(name_key) or item.get("simple_name") or "<?>"
            short = _shorten_path(item.get("file"), root_path)
            loc = f"{short}:{item.get('line', '?')}"
            conf = item.get("confidence", "?")

            if isinstance(conf, int):
                if conf >= 90:
                    conf_str = f"[red]{conf}%[/red]"
                elif conf >= 75:
                    conf_str = f"[yellow]{conf}%[/yellow]"
                else:
                    conf_str = f"[dim]{conf}%[/dim]"
            else:
                conf_str = str(conf)

            table.add_row(str(i), nm, loc, conf_str)

        console.print(table)
        if overflow:
            console.print(
                f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
            )
        console.print()

    def _render_unused_simple(title, items, name_key="name"):
        if not items:
            return

        console.rule(f"[bold]{title}")

        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Name", style="bold")
        table.add_column("Location", style="muted", overflow="fold")

        show, overflow = _display_cap(items)
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

    def _render_quality(items):
        if not items:
            return

        console.rule("[bold red]Quality Issues")
        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Type", style="yellow", width=12)
        table.add_column("Function", style="bold")
        table.add_column("Detail")
        table.add_column("Location", style="muted", width=36)

        show, overflow = _display_cap(items)
        for i, quality in enumerate(show, 1):
            kind = (quality.get("kind") or quality.get("metric") or "quality").title()
            func = quality.get("name") or quality.get("simple_name") or "<?>"
            loc = f"{quality.get('basename', '?')}:{quality.get('line', '?')}"
            value = quality.get("value") or quality.get("complexity")
            thr = quality.get("threshold")
            length = quality.get("length")

            if quality.get("kind") == "nesting":
                detail = f"Deep nesting: depth {value}"
            elif quality.get("kind") == "structure":
                detail = f"Line count: {value}"
            else:
                detail = f"{value}"
            if thr is not None:
                detail += f" (target ≤ {thr})"
            if length is not None:
                detail += f", {length} lines"
            table.add_row(str(i), kind, func, detail, loc)

        console.print(table)
        if overflow:
            console.print(
                f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
            )
        console.print(
            "[muted]Tip: split helpers, add early returns, flatten branches.[/muted]\n"
        )

    def _render_circular_deps(items):
        if not items:
            return

        console.rule("[bold yellow]Circular Dependencies")
        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Cycle", style="bold")
        table.add_column("Length", width=6)
        table.add_column("Severity", width=8)
        table.add_column("Suggested Break", style="cyan")

        show, overflow = _display_cap(items)
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
            "[muted]Tip: Break the cycle by refactoring the suggested module.[/muted]\n"
        )

    def _render_custom_rules(items):
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

        show, overflow = _display_cap(custom)
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

    def _render_secrets(items):
        if not items:
            return

        console.rule("[bold red]Secrets")
        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Provider", style="yellow", width=14)
        table.add_column("Message")
        table.add_column("Preview", style="muted", width=18)
        table.add_column("Location", style="muted", overflow="fold")

        show, overflow = _display_cap(items)
        for i, s in enumerate(show, 1):
            prov = s.get("provider") or "generic"
            msg = s.get("message") or "Secret detected"
            prev = s.get("preview") or "****"
            short = _shorten_path(s.get("file"), root_path)
            loc = f"{short}:{s.get('line', '?')}"
            table.add_row(str(i), prov, msg, prev, loc)

        console.print(table)
        if overflow:
            console.print(
                f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
            )
        console.print()

    def render_tree(console: Console, result, root_path=None):
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
        RULE_TITLES = {
            "SKY-D201": "Dynamic code execution (eval)",
            "SKY-D202": "Dynamic code execution (exec)",
            "SKY-D203": "OS command execution (os.system)",
            "SKY-D204": "Unsafe deserialization (pickle.load)",
            "SKY-D205": "Unsafe deserialization (pickle.loads)",
            "SKY-D206": "Unsafe YAML load (no SafeLoader)",
            "SKY-D207": "Weak hash (MD5)",
            "SKY-D208": "Weak hash (SHA1)",
            "SKY-D209": "Shell execution (subprocess shell=True)",
            "SKY-D210": "TLS verification disabled (requests verify=False)",
            "SKY-D211": "SQL injection (cursor)",
            "SKY-D212": "Possible command injection (os.system): tainted input",
            "SKY-D222": "Dependency hallucination",
            "SKY-D223": "Undeclared third-party dependency",
        }
        return RULE_TITLES.get(rule_id, "Security issue")

    def _render_danger(items):
        if not items:
            return

        console.rule("[bold red]Security Issues")

        has_verification = any(
            isinstance(d.get("verification"), dict) and d["verification"].get("verdict")
            for d in (items or [])
        )

        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Issue", style="yellow", width=20)
        table.add_column("Severity", width=9)
        table.add_column("Message", overflow="fold")
        table.add_column("Location", style="muted", width=20, overflow="fold")
        table.add_column("Symbol", style="muted", width=10, overflow="fold")

        if has_verification:
            table.add_column("Verified", width=9)
            table.add_column("Proof", overflow="fold")

        show, overflow = _display_cap(items)
        for i, d in enumerate(show, 1):
            rule_id = d.get("rule_id") or "UNKNOWN"

            issue_name = _display_rule_name(rule_id)
            issue_cell = f"{issue_name}\n[dim]{rule_id}[/dim]"

            sev = (d.get("severity") or "UNKNOWN").title()
            msg = d.get("message") or "Issue detected"

            short = _shorten_path(d.get("file"), root_path)
            loc = f"{short}:{d.get('line', '?')}"

            symbol = d.get("symbol") or "<module>"

            if has_verification:
                ver = (d.get("verification") or {}).get("verdict")
                if ver == "VERIFIED":
                    ver_str = "[good]VERIFIED[/good]"
                elif ver == "REFUTED":
                    ver_str = "[muted]REFUTED[/muted]"
                elif ver == "UNKNOWN":
                    ver_str = "[warn]UNKNOWN[/warn]"
                else:
                    ver_str = "-"

                proof = ""
                verification = d.get("verification")
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

                    proof = " -> ".join(names)

                else:
                    entrypoints = evidence.get("entrypoints")

                    if entrypoints:
                        proof = str(len(entrypoints)) + " entrypoints scanned"
                    else:
                        if ver:
                            proof = "No evidence attached"

                table.add_row(str(i), issue_cell, sev, msg, loc, symbol, ver_str, proof)
            else:
                table.add_row(str(i), issue_cell, sev, msg, loc, symbol)

        console.print(table)
        if overflow:
            console.print(
                f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
            )
        console.print()

    def _render_sca(items):
        if not items:
            return

        console.rule("[bold red]Dependency Vulnerabilities (SCA)")
        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Package", style="yellow", width=22)
        table.add_column("Vuln ID", width=18)
        table.add_column("Severity", width=9)
        table.add_column("Message", overflow="fold")
        table.add_column("Fix", style="good", width=14, overflow="fold")

        show, overflow = _display_cap(items)
        for i, v in enumerate(show, 1):
            meta = v.get("metadata") or {}
            pkg = f"{meta.get('package_name', '?')}@{meta.get('package_version', '?')}"
            vuln_id = (
                meta.get("display_id") or meta.get("vuln_id") or v.get("rule_id", "")
            )
            sev = (v.get("severity") or "MEDIUM").title()
            msg = v.get("message") or "Known vulnerability"
            fix = meta.get("fixed_version") or "-"
            table.add_row(str(i), pkg, vuln_id, sev, msg, fix)

        console.print(table)
        if overflow:
            console.print(
                f"  [muted]... and {overflow} more (use --limit to adjust)[/muted]"
            )
        console.print()

    if tree:
        render_tree(console, result, root_path=root_path)
    else:
        _render_unused(
            "Unused Functions", result.get("unused_functions", []), name_key="name"
        )
        _render_unused(
            "Unused Imports", result.get("unused_imports", []), name_key="name"
        )
        _render_unused(
            "Unused Parameters", result.get("unused_parameters", []), name_key="name"
        )
        _render_unused(
            "Unused Variables", result.get("unused_variables", []), name_key="name"
        )
        _render_unused(
            "Unused Classes", result.get("unused_classes", []), name_key="name"
        )
        _render_unused_simple(
            "Unused Fixtures", result.get("unused_fixtures", []), name_key="name"
        )
        _render_secrets(result.get("secrets", []) or [])
        _render_danger(result.get("danger", []) or [])
        _render_quality(result.get("quality", []) or [])
        _render_circular_deps(result.get("circular_dependencies", []) or [])
        _render_custom_rules(result.get("custom_rules", []) or [])
        _render_sca(result.get("dependency_vulnerabilities", []) or [])


def run_init():
    console = Console()
    path = pathlib.Path("pyproject.toml")

    template = """
[tool.skylos]
complexity = 10
nesting = 3
max_args = 5
max_lines = 50
model = "gpt-4.1"
exclude = []
ignore = []

[tool.skylos.masking]
names = []
decorators = []
bases = []

[tool.skylos.whitelist]
names = []

[tool.skylos.whitelist.documented]

[tool.skylos.whitelist.temporary]

[tool.skylos.gate]
fail_on_critical = true
max_critical = 0 
max_high = 5
max_security = 0
max_quality = 10
strict = false
"""

    if path.exists():
        content = path.read_text(encoding="utf-8")
        if "[tool.skylos" in content:
            import re

            content = re.sub(r"\[tool\.skylos[^\]]*\](?:\n(?!\[).*)*\n*", "", content)
            content = content.rstrip() + "\n"
            path.write_text(content, encoding="utf-8")
            console.print("[brand]Resetting Skylos configuration...[/brand]")

        with open(path, "a", encoding="utf-8") as f:
            f.write("\n" + template.strip() + "\n")
    else:
        path.write_text(template.strip(), encoding="utf-8")

    console.print("[good]✓ Configuration initialized![/good]")


def run_whitelist(pattern=None, reason=None, show=False):
    console = Console()
    path = pathlib.Path("pyproject.toml")

    if not path.exists():
        console.print("[bad]No pyproject.toml found. Run 'skylos init' first.[/bad]")
        return

    cfg = load_config(path)

    if show:
        console.print("[bold]Current whitelist:[/bold]\n")

        names = cfg.get("whitelist", [])
        if names:
            console.print("[dim]names:[/dim]")
            for name in names:
                console.print(f"  • {name}")

        documented = cfg.get("whitelist_documented", {})
        if documented:
            console.print("\n[dim]documented:[/dim]")
            for name, r in documented.items():
                console.print(f"  • {name} → {r}")

        temporary = cfg.get("whitelist_temporary", {})
        if temporary:
            console.print("\n[dim]temporary:[/dim]")
            for name, conf in temporary.items():
                r = conf.get("reason", "")
                e = conf.get("expires", "")
                console.print(f"  • {name} → {r} (expires: {e})")

        if not any([names, documented, temporary]):
            console.print("[muted]No whitelist entries yet.[/muted]")
        return

    if not pattern:
        console.print("[warn]Usage: skylos whitelist <pattern> [--reason 'why'][/warn]")
        console.print("\nExamples:")
        console.print("  skylos whitelist 'handle_*'")
        console.print("  skylos whitelist dark_logic --reason 'Called via globals()'")
        console.print("  skylos whitelist --show")
        return

    content = path.read_text(encoding="utf-8")

    if reason:
        if "[tool.skylos.whitelist.documented]" in content:
            import re

            content = re.sub(
                r"(\[tool\.skylos\.whitelist\.documented\])",
                f'\\1\n"{pattern}" = "{reason}"',
                content,
            )
        else:
            content += (
                f'\n[tool.skylos.whitelist.documented]\n"{pattern}" = "{reason}"\n'
            )
        console.print(f"[good]✓ Added '{pattern}' to whitelist.documented[/good]")
    else:
        import re

        match = re.search(
            r"(\[tool\.skylos\.whitelist\][^\[]*?)(names\s*=\s*\[)", content, re.DOTALL
        )
        if match:
            start = match.start(2)
            end = match.end(2)
            content = content[:end] + f'\n    "{pattern}",' + content[end:]
        elif "[tool.skylos.whitelist]" in content:
            content = re.sub(
                r"(\[tool\.skylos\.whitelist\])",
                f'\\1\nnames = [\n    "{pattern}",\n]',
                content,
            )
        else:
            content += f'\n[tool.skylos.whitelist]\nnames = [\n    "{pattern}",\n]\n'
        console.print(f"[good]✓ Added '{pattern}' to whitelist.names[/good]")

    path.write_text(content, encoding="utf-8")
    console.print("[muted]Run 'skylos whitelist --show' to see all entries[/muted]")


def get_git_changed_files(root_path):
    try:
        subprocess.check_output(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=root_path,
            stderr=subprocess.DEVNULL,
        )
        cmd = ["git", "diff", "--name-only", "HEAD"]
        output = subprocess.check_output(cmd, cwd=root_path).decode("utf-8")
        files = []
        for line in output.splitlines():
            if line.endswith(".py"):
                full_path = pathlib.Path(root_path) / line
                if full_path.exists():
                    files.append(full_path)
        return files
    except Exception:
        return []


def estimate_cost(files):
    total_chars = 0
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            total_chars += len(content)
        except Exception:
            pass
    est_tokens = total_chars / 4
    est_cost_usd = (est_tokens / 1_000_000) * 2.50
    return est_tokens, est_cost_usd


def _run_clean_command():
    console = Console()
    path = sys.argv[2] if len(sys.argv) > 2 else "."

    console.print(
        Panel(
            "[bold]Skylos Clean[/bold] — Interactive Dead Code Removal",
            border_style="blue",
        )
    )
    console.print(f"Scanning [bold]{path}[/bold]...\n")

    result = json.loads(run_analyze(path))

    findings = []
    for fn in result.get("unused_functions", []):
        findings.append(
            {
                "type": "function",
                "name": fn.get("name", ""),
                "file": fn.get("file", ""),
                "line": fn.get("line", 0),
                "confidence": fn.get("confidence", 100),
            }
        )
    for imp in result.get("unused_imports", []):
        findings.append(
            {
                "type": "import",
                "name": imp.get("name", ""),
                "file": imp.get("file", ""),
                "line": imp.get("line", 0),
                "confidence": imp.get("confidence", 100),
            }
        )
    for var in result.get("unused_variables", []):
        findings.append(
            {
                "type": "variable",
                "name": var.get("name", ""),
                "file": var.get("file", ""),
                "line": var.get("line", 0),
                "confidence": var.get("confidence", 100),
            }
        )
    for cls in result.get("unused_classes", []):
        findings.append(
            {
                "type": "class",
                "name": cls.get("name", ""),
                "file": cls.get("file", ""),
                "line": cls.get("line", 0),
                "confidence": cls.get("confidence", 100),
            }
        )

    findings.sort(key=lambda f: -f["confidence"])

    if not findings:
        console.print("[green]No dead code found. Your codebase is clean![/green]")
        return

    console.print(f"Found [bold]{len(findings)}[/bold] potential dead code items.\n")

    to_remove = []
    to_comment = []
    skipped = 0

    for i, f in enumerate(findings, 1):
        console.print(Rule(style="dim"))
        console.print(
            f"[bold][{i}/{len(findings)}][/bold] Unused {f['type']} "
            f"[bold cyan]{f['name']}[/bold cyan] at {f['file']}:{f['line']}"
        )
        console.print(f"         Confidence: [bold]{f['confidence']}%[/bold]")

        try:
            choice = (
                input("\n  [R]emove  [C]omment-out  [S]kip  [Q]uit > ").strip().lower()
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Interrupted.[/dim]")
            break

        if choice in ("r", "remove"):
            to_remove.append(f)
            console.print("  [green]Marked for removal[/green]")
        elif choice in ("c", "comment", "comment-out"):
            to_comment.append(f)
            console.print("  [yellow]Marked for comment-out[/yellow]")
        elif choice in ("q", "quit"):
            console.print("[dim]Stopping early.[/dim]")
            break
        else:
            skipped += 1
            console.print("  [dim]Skipped[/dim]")

    if not to_remove and not to_comment:
        console.print("\n[dim]No changes to apply.[/dim]")
        return

    console.print(Rule(style="blue"))
    console.print(
        f"\n[bold]Summary:[/bold] {len(to_remove)} to remove, "
        f"{len(to_comment)} to comment out, {skipped} skipped\n"
    )

    try:
        confirm = input("Apply changes? (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled.[/dim]")
        return

    if confirm not in ("y", "yes"):
        console.print("[dim]No changes applied.[/dim]")
        return

    applied = 0

    for f in to_remove:
        try:
            if f["type"] == "import":
                remove_unused_import_cst(f["file"], f["name"])
                applied += 1
            elif f["type"] == "function":
                remove_unused_function_cst(f["file"], f["name"])
                applied += 1
        except Exception as e:
            console.print(f"  [red]Failed to remove {f['name']}: {e}[/red]")

    for f in to_comment:
        try:
            if f["type"] == "import":
                comment_out_unused_import_cst(f["file"], f["name"])
                applied += 1
            elif f["type"] == "function":
                comment_out_unused_function_cst(f["file"], f["name"])
                applied += 1
        except Exception as e:
            console.print(f"  [red]Failed to comment out {f['name']}: {e}[/red]")

    console.print(
        f"\n[green]Done![/green] Applied {applied} changes "
        f"({len(to_remove)} removed, {len(to_comment)} commented out)."
    )


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "key":
        from skylos.commands.key_cmd import run_key_command

        args = sys.argv[2:]

        if len(args) == 0:
            sys.exit(run_key_command(["menu"]))

        sys.exit(run_key_command(args))

    if len(sys.argv) > 1 and sys.argv[1] == "baseline":
        from skylos.baseline import save_baseline
        from skylos import analyze as _baseline_analyze

        if len(sys.argv) > 2:
            path = sys.argv[2]
        else:
            path = "."

        console = Console()
        console.print(f"[bold]Creating baseline for {path}...[/bold]")
        result = json.loads(_baseline_analyze(path))
        bp = save_baseline(path, result)
        total = sum(
            len(result.get(k, []))
            for k in [
                "unused_functions",
                "unused_imports",
                "unused_classes",
                "unused_variables",
                "danger",
                "quality",
                "secrets",
            ]
        )
        console.print(
            f"[good]Baseline saved to {bp} ({total} existing findings captured)[/good]"
        )
        console.print(
            "[muted]Future runs with --baseline will only report new findings[/muted]"
        )
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "init":
        run_init()
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "badge":
        console = Console()

        badge_markdown = "[![Analyzed with Skylos](https://img.shields.io/badge/Analyzed%20with-Skylos-2f80ed?style=flat&logo=python&logoColor=white)](https://github.com/duriantaco/skylos)"

        console.print()
        console.print(
            Panel.fit(
                "[bold cyan]Add this badge to your README.md:[/bold cyan]\n\n"
                f"[yellow]{badge_markdown}[/yellow]\n\n"
                "[dim]Shows others you maintain clean, secure code with Skylos![/dim]\n\n"
                "[bold]Preview:[/bold]\n"
                "[![Analyzed with Skylos](2f80ed badge)](github.com/duriantaco/skylos)",
                title="[cyan]📛 Skylos Badge[/cyan]",
                border_style="cyan",
            )
        )
        console.print()
        console.print(
            "[dim]💡 Tip: Add this near your other badges at the top of README.md[/dim]"
        )
        console.print(
            "[dim]📢 Share your project: https://github.com/duriantaco/skylos#projects-using-skylos[/dim]"
        )
        console.print()

        try:
            import pyperclip

            pyperclip.copy(badge_markdown)
            console.print("[good]✅ Badge markdown copied to clipboard![/good]")
        except ImportError:
            console.print(
                "[muted]💡 Install pyperclip for auto-copy: pip install pyperclip[/muted]"
            )

        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "whitelist":
        pattern = None
        reason = None
        show = False
        i = 2
        while i < len(sys.argv):
            arg = sys.argv[i]
            if arg in ("--show", "-s"):
                show = True
            elif arg in ("--reason", "-r") and i + 1 < len(sys.argv):
                reason = sys.argv[i + 1]
                i += 1
            elif not arg.startswith("-"):
                pattern = arg
            i += 1
        run_whitelist(pattern=pattern, reason=reason, show=show)
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        _run_clean_command()
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "login":
        from skylos.login import run_login

        console = Console()
        result = run_login(console=console)
        if result:
            sys.exit(0)
        else:
            sys.exit(1)

    if len(sys.argv) > 1 and sys.argv[1] == "sync":
        from skylos.sync import main as sync_main

        sync_main(sys.argv[2:])
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "cicd":
        import argparse as cicd_argparse

        cicd_parser = cicd_argparse.ArgumentParser(
            prog="skylos cicd", description="CI/CD integration for Skylos"
        )
        cicd_sub = cicd_parser.add_subparsers(dest="cicd_cmd")

        p_ci_init = cicd_sub.add_parser("init", help="Generate GitHub Actions workflow")
        p_ci_init.add_argument("--python-version", default="3.12")
        p_ci_init.add_argument(
            "--triggers",
            nargs="+",
            default=["pull_request", "push"],
            help="GitHub Actions triggers",
        )
        p_ci_init.add_argument(
            "--analysis",
            nargs="+",
            default=["dead-code", "security", "quality", "secrets"],
            help="Analysis types to run",
        )
        p_ci_init.add_argument("--no-baseline", action="store_true")
        p_ci_init.add_argument(
            "--llm", action="store_true", help="Include LLM-enhanced analysis"
        )
        p_ci_init.add_argument("--model", default=None, help="LLM model for agent mode")
        p_ci_init.add_argument(
            "--output", "-o", default=".github/workflows/skylos.yml", help="Output path"
        )

        p_ci_gate = cicd_sub.add_parser(
            "gate", help="Check quality gate (CI exit code)"
        )
        p_ci_gate.add_argument("path", nargs="?", default=".")
        p_ci_gate.add_argument(
            "--input", "-i", dest="input_file", help="Read results from JSON file"
        )
        p_ci_gate.add_argument("--strict", action="store_true")
        p_ci_gate.add_argument(
            "--summary",
            action="store_true",
            help="Write markdown to $GITHUB_STEP_SUMMARY",
        )

        p_ci_ann = cicd_sub.add_parser(
            "annotate", help="Emit GitHub Actions annotations"
        )
        p_ci_ann.add_argument("path", nargs="?", default=".")
        p_ci_ann.add_argument(
            "--input", "-i", dest="input_file", help="Read results from JSON file"
        )
        p_ci_ann.add_argument("--max", type=int, default=50, dest="max_annotations")
        p_ci_ann.add_argument(
            "--severity",
            choices=["critical", "high", "medium", "low"],
            help="Minimum severity filter",
        )

        p_ci_rev = cicd_sub.add_parser(
            "review", help="Post PR review comments via gh CLI"
        )
        p_ci_rev.add_argument("path", nargs="?", default=".")
        p_ci_rev.add_argument(
            "--input", "-i", dest="input_file", help="Read results from JSON file"
        )
        p_ci_rev.add_argument("--pr", type=int, help="PR number (auto-detect in CI)")
        p_ci_rev.add_argument("--repo", help="owner/repo (auto-detect in CI)")
        p_ci_rev.add_argument("--summary-only", action="store_true")
        p_ci_rev.add_argument("--max-comments", type=int, default=25)
        p_ci_rev.add_argument("--diff-base", default="origin/main")

        cicd_argv = sys.argv[2:]
        if not cicd_argv:
            cicd_parser.print_help()
            sys.exit(0)

        cicd_args = cicd_parser.parse_args(cicd_argv)

        def _cicd_load_results(a):
            if getattr(a, "input_file", None):
                try:
                    with open(a.input_file) as f:
                        return json.load(f)
                except (FileNotFoundError, json.JSONDecodeError) as e:
                    Console().print(
                        f"[bold red]Error reading {a.input_file}: {e}[/bold red]"
                    )
                    sys.exit(1)
            p = getattr(a, "path", ".")
            try:
                from skylos import analyze

                return json.loads(analyze(p))
            except Exception as e:
                Console().print(f"[bold red]Analysis failed: {e}[/bold red]")
                sys.exit(1)

        if cicd_args.cicd_cmd == "init":
            from skylos.cicd.workflow import generate_workflow, write_workflow

            yaml_content = generate_workflow(
                triggers=cicd_args.triggers,
                analysis_types=cicd_args.analysis,
                python_version=cicd_args.python_version,
                use_baseline=not cicd_args.no_baseline,
                use_llm=cicd_args.llm,
                model=cicd_args.model,
            )
            write_workflow(yaml_content, cicd_args.output)

        elif cicd_args.cicd_cmd == "gate":
            results = _cicd_load_results(cicd_args)
            config = load_config(results.get("project_root", "."))
            exit_code = run_gate_interaction(
                result=results,
                config=config,
                strict=cicd_args.strict,
                summary=cicd_args.summary,
            )
            sys.exit(exit_code)

        elif cicd_args.cicd_cmd == "annotate":
            results = _cicd_load_results(cicd_args)
            _emit_github_annotations(
                results,
                max_annotations=cicd_args.max_annotations,
                severity_filter=cicd_args.severity,
            )

        elif cicd_args.cicd_cmd == "review":
            from skylos.cicd.review import run_pr_review

            results = _cicd_load_results(cicd_args)
            run_pr_review(
                results,
                pr_number=cicd_args.pr,
                repo=cicd_args.repo,
                summary_only=cicd_args.summary_only,
                max_comments=cicd_args.max_comments,
                diff_base=cicd_args.diff_base,
            )

        else:
            cicd_parser.print_help()

        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "agent":
        if not LLM_AVAILABLE:
            Console().print("[bold red]Agent module not available[/bold red]")
            sys.exit(1)

        import argparse as agent_argparse
        # from skylos.llm.merger import merge_findings

        agent_parser = agent_argparse.ArgumentParser(prog="skylos agent")
        agent_sub = agent_parser.add_subparsers(dest="agent_cmd", required=True)

        p_analyze = agent_sub.add_parser(
            "analyze", help="Hybrid analysis (static + LLM)"
        )
        p_analyze.add_argument("path", help="File or directory to analyze")
        p_analyze.add_argument("--model", default="gpt-4.1")
        p_analyze.add_argument(
            "--format", choices=["table", "tree", "json", "sarif"], default="table"
        )
        p_analyze.add_argument("--output", "-o", help="Output file")
        p_analyze.add_argument(
            "--min-confidence", choices=["high", "medium", "low"], default="low"
        )
        p_analyze.add_argument(
            "--llm-only", action="store_true", help="Skip static, run LLM only"
        )
        p_analyze.add_argument(
            "--fix", action="store_true", help="Generate fix proposals for findings"
        )
        p_analyze.add_argument(
            "--apply", action="store_true", help="Apply approved fixes to files"
        )
        p_analyze.add_argument(
            "--yes", action="store_true", help="Auto-approve prompts (use with --apply)"
        )
        p_analyze.add_argument("--quiet", "-q", action="store_true")
        p_analyze.add_argument(
            "--provider",
            choices=[
                "openai",
                "anthropic",
                "google",
                "mistral",
                "groq",
                "xai",
                "together",
                "deepseek",
                "ollama",
            ],
            default=None,
            help="Force LLM provider",
        )
        p_analyze.add_argument(
            "--base-url",
            default=None,
            help="OpenAI-compatible base URL (Ollama/LM Studio/vLLM)",
        )
        p_analyze.add_argument(
            "--upload",
            action="store_true",
            help="Upload results to skylos.dev dashboard",
        )
        p_analyze.add_argument(
            "--force",
            action="store_true",
            help="Force upload even if quality gate fails",
        )
        p_analyze.add_argument(
            "--strict",
            action="store_true",
            help="Exit with error code if quality gate fails",
        )

        p_sec_audit = agent_sub.add_parser(
            "security-audit", help="Security audit with LLM"
        )
        p_sec_audit.add_argument("path", help="File or directory")
        p_sec_audit.add_argument("--model", default="gpt-4.1")
        p_sec_audit.add_argument(
            "--format", choices=["table", "tree", "json", "sarif"], default="tree"
        )
        p_sec_audit.add_argument("--output", "-o")
        p_sec_audit.add_argument("--quiet", "-q", action="store_true")
        p_sec_audit.add_argument("--interactive", "-i", action="store_true")
        p_sec_audit.add_argument(
            "--provider",
            choices=[
                "openai",
                "anthropic",
                "google",
                "mistral",
                "groq",
                "xai",
                "together",
                "deepseek",
                "ollama",
            ],
            default=None,
            help="Force LLM provider",
        )
        p_sec_audit.add_argument(
            "--base-url",
            default=None,
            help="OpenAI-compatible base URL (Ollama/LM Studio/vLLM)",
        )

        p_fix = agent_sub.add_parser("fix", help="Generate fix for issue")
        p_fix.add_argument("path", help="File path")
        p_fix.add_argument("--line", "-l", type=int, required=False)
        p_fix.add_argument("--message", "-m", required=False)
        p_fix.add_argument("--model", default="gpt-4.1")
        p_fix.add_argument(
            "--provider",
            choices=[
                "openai",
                "anthropic",
                "google",
                "mistral",
                "groq",
                "xai",
                "together",
                "deepseek",
                "ollama",
            ],
            default=None,
            help="Force LLM provider",
        )
        p_fix.add_argument(
            "--base-url",
            default=None,
            help="OpenAI-compatible base URL (Ollama/LM Studio/vLLM)",
        )

        p_review = agent_sub.add_parser("review", help="Review git-changed files")
        p_review.add_argument("path", nargs="?", default=".")
        p_review.add_argument("--model", default="gpt-4.1")
        p_review.add_argument(
            "--format", choices=["table", "tree", "json", "sarif"], default="table"
        )
        p_review.add_argument("--output", "-o")
        p_review.add_argument("--quiet", "-q", action="store_true")
        p_review.add_argument(
            "--provider",
            choices=[
                "openai",
                "anthropic",
                "google",
                "mistral",
                "groq",
                "xai",
                "together",
                "deepseek",
                "ollama",
            ],
            default=None,
            help="Force LLM provider",
        )
        p_review.add_argument(
            "--base-url",
            default=None,
            help="OpenAI-compatible base URL (Ollama/LM Studio/vLLM)",
        )

        p_remediate = agent_sub.add_parser(
            "remediate",
            help="Scan, fix, test, and create PR for security/quality issues",
        )
        p_remediate.add_argument("path", nargs="?", default=".")
        p_remediate.add_argument("--model", default="gpt-4.1")
        p_remediate.add_argument(
            "--max-fixes",
            type=int,
            default=10,
            help="Maximum number of findings to fix (default: 10)",
        )
        p_remediate.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be fixed without applying changes",
        )
        p_remediate.add_argument(
            "--auto-pr",
            action="store_true",
            help="Automatically create a PR with fixes",
        )
        p_remediate.add_argument(
            "--branch-prefix", default="skylos/fix", help="Git branch prefix"
        )
        p_remediate.add_argument(
            "--test-cmd",
            default=None,
            help="Custom test command (default: auto-detect)",
        )
        p_remediate.add_argument(
            "--severity",
            choices=["critical", "high", "medium", "low"],
            default=None,
            help="Only fix findings at or above this severity",
        )
        p_remediate.add_argument("--quiet", "-q", action="store_true")
        p_remediate.add_argument(
            "--provider",
            choices=[
                "openai",
                "anthropic",
                "google",
                "mistral",
                "groq",
                "xai",
                "together",
                "deepseek",
                "ollama",
            ],
            default=None,
            help="Force LLM provider",
        )
        p_remediate.add_argument(
            "--base-url",
            default=None,
            help="OpenAI-compatible base URL (Ollama/LM Studio/vLLM)",
        )

        agent_args = agent_parser.parse_args(sys.argv[2:])
        console = Console()

        model = agent_args.model

        provider, api_key, base_url, _is_local = resolve_llm_runtime(
            model=model,
            provider_override=getattr(agent_args, "provider", None),
            base_url_override=getattr(agent_args, "base_url", None),
            console=console,
            allow_prompt=True,
        )

        if base_url:
            os.environ["OPENAI_BASE_URL"] = base_url
            os.environ["SKYLOS_LLM_BASE_URL"] = base_url

        if api_key is None:
            sys.exit(1)

        if api_key is None or api_key == "":
            if not _is_local:
                console.print("[bad]No API key provided.[/bad]")
                sys.exit(1)

        cmd = agent_args.agent_cmd
        agent_exclude_folders = list(parse_exclude_folders(use_defaults=True))

        if cmd == "analyze":
            path = pathlib.Path(agent_args.path)
            if not path.exists():
                console.print(f"[bad]Path not found: {path}[/bad]")
                sys.exit(1)

            project_root = find_project_root(path)

            merged_findings = run_pipeline(
                path=str(path),
                model=model,
                api_key=api_key,
                agent_args=agent_args,
                console=console,
                exclude_folders=agent_exclude_folders,
            )

            merged_findings = _normalize_agent_findings(merged_findings, project_root)

            static_only = 0
            llm_only = 0
            both = 0

            for f in merged_findings:
                source = f.get("_source")
                if source == "static":
                    static_only += 1
                elif source == "llm":
                    llm_only += 1
                elif source == "static+llm":
                    both += 1

            console.print(f"\n[brand]Results:[/brand]")
            console.print(f"  Total findings: {len(merged_findings)}")
            console.print(f"  [green]HIGH confidence (both agree):[/green] {both}")
            console.print(f"  [yellow]MEDIUM (static only):[/yellow] {static_only}")
            console.print(
                f"  [yellow]MEDIUM (LLM only, needs review):[/yellow] {llm_only}"
            )

            if agent_args.format == "json":
                output = json.dumps(merged_findings, indent=2, default=str)
                if agent_args.output:
                    pathlib.Path(agent_args.output).write_text(output)
                else:
                    print(output)
            else:
                if merged_findings:
                    table = Table(title="Hybrid Analysis Results", expand=True)
                    table.add_column("#", style="dim", width=3)
                    table.add_column("Conf", width=6)
                    table.add_column("Source", width=10)
                    table.add_column("Category", width=10)
                    table.add_column("Message", overflow="fold")
                    table.add_column("Location", style="dim", width=30)

                    for i, f in enumerate(merged_findings[:100], 1):
                        conf = f.get("_confidence", "?")
                        if conf == "high":
                            conf_style = "[green]HIGH[/green]"
                        else:
                            conf_style = "[yellow]MED[/yellow]"

                        source = f.get("_source", "?")
                        cat = f.get("_category", "?")
                        msg = f.get("message", "?")[:120]
                        file_rel = f.get("file", "?")
                        loc = f"{file_rel}:{f.get('line', '?')}"

                        table.add_row(str(i), conf_style, source, cat, msg, loc)

                    console.print(table)
                else:
                    console.print("[good]No issues found![/good]")

            if getattr(agent_args, "upload", False) and merged_findings:
                result_for_upload = _agent_findings_to_result_json(merged_findings)
                upload_report(
                    result_for_upload,
                    is_forced=getattr(agent_args, "force", False),
                    strict=getattr(agent_args, "strict", False),
                    analysis_mode="hybrid",
                )

            if merged_findings:
                sys.exit(1)
            else:
                sys.exit(0)

        elif cmd == "security-audit":
            path = pathlib.Path(agent_args.path)
            if not path.exists():
                console.print(f"[bad]Path not found: {path}[/bad]")
                sys.exit(1)

            if path.is_file():
                files = [path]
            else:
                files = [
                    f
                    for f in path.rglob("*.py")
                    if not any(ex in f.parts for ex in agent_exclude_folders)
                ]

            if not files:
                console.print("[warn]No Python files found[/warn]")
                sys.exit(0)

            if (
                INTERACTIVE_AVAILABLE
                and getattr(agent_args, "interactive", False)
                and len(files) > 1
            ):
                choices = [
                    (f"{f.name} ({f.stat().st_size / 1024:.1f}KB)", f) for f in files
                ]
                questions = [
                    inquirer.Checkbox("files", message="Select files", choices=choices)
                ]
                answers = inquirer.prompt(questions)
                if not answers or not answers["files"]:
                    sys.exit(0)
                files = answers["files"]

            tokens, cost = llm_estimate_cost(files, model)
            console.print(
                f"\n[brand]Audit:[/brand] {len(files)} files, ~{tokens:,} tokens, ~${cost:.4f}"
            )

            if INTERACTIVE_AVAILABLE and not inquirer.confirm("Proceed?", default=True):
                sys.exit(0)

            config = AnalyzerConfig(
                model=model,
                api_key=api_key,
                quiet=getattr(agent_args, "quiet", False),
            )
            analyzer = SkylosLLM(config)
            llm_result = analyzer.analyze_files(files, issue_types=["security_audit"])
            analyzer.print_results(
                llm_result, format=agent_args.format, output_file=agent_args.output
            )
            sys.exit(1 if llm_result.has_blockers else 0)

        elif cmd == "fix":
            path = pathlib.Path(agent_args.path)
            if not path.exists():
                console.print(f"[bad]File not found: {path}[/bad]")
                sys.exit(1)

            config = AnalyzerConfig(model=model, api_key=api_key, quiet=False)
            analyzer = SkylosLLM(config)
            if agent_args.line and agent_args.message:
                fix_result = analyzer.fix_issue(
                    path, agent_args.line, agent_args.message
                )
                if fix_result:
                    analyzer.ui.print_fix(fix_result)
                    sys.exit(0)
                console.print("[bad]Could not generate fix[/bad]")
                sys.exit(1)

            llm_result = analyzer.analyze_files(
                [path], issue_types=["security", "quality", "dead_code"]
            )

            if not llm_result or not llm_result.findings:
                console.print("[good]No issues found to fix.[/good]")
                sys.exit(0)

            analyzer.fix_all(llm_result.findings)
            sys.exit(0)

        elif cmd == "review":
            path = pathlib.Path(agent_args.path)
            console.print("[brand]Finding git-changed files...[/brand]")
            files = get_git_changed_files(path)

            if not files:
                console.print("[dim]No changed Python files[/dim]")
                sys.exit(0)

            console.print(f"Found {len(files)} changed files")
            if INTERACTIVE_AVAILABLE and not inquirer.confirm(
                "Run hybrid review (static + LLM)?", default=True
            ):
                sys.exit(0)

            project_root = find_project_root(path)

            merged_findings = run_pipeline(
                path=str(path),
                model=model,
                api_key=api_key,
                agent_args=agent_args,
                console=console,
                changed_files=files,
                exclude_folders=agent_exclude_folders,
            )

            merged_findings = _normalize_agent_findings(merged_findings, project_root)

            if agent_args.format == "json":
                output = json.dumps(merged_findings, indent=2, default=str)
                if agent_args.output:
                    pathlib.Path(agent_args.output).write_text(output)
                else:
                    print(output)
                if merged_findings:
                    sys.exit(1)
                else:
                    sys.exit(0)

            if merged_findings:
                table = Table(
                    title="Hybrid Review Results (Changed Files)", expand=True
                )
                table.add_column("#", style="dim", width=3)
                table.add_column("Conf", width=6)
                table.add_column("Source", width=10)
                table.add_column("Category", width=10)
                table.add_column("Message", overflow="fold")
                table.add_column("Location", style="dim", width=30)

                for i, f in enumerate(merged_findings[:100], 1):
                    conf = f.get("_confidence", "?")
                    if conf == "high":
                        conf_style = "[green]HIGH[/green]"
                    else:
                        conf_style = "[yellow]MED[/yellow]"

                    source = f.get("_source", "?")
                    cat = f.get("_category", "?")
                    msg = (f.get("message", "?") or "?")[:120]
                    file_rel = f.get("file", "?")
                    loc = f"{file_rel}:{f.get('line', '?')}"

                    table.add_row(str(i), conf_style, source, cat, msg, loc)

                console.print(table)
                sys.exit(1)

            console.print("[good]No issues found in changed files![/good]")
            sys.exit(0)

        if cmd == "remediate":
            from skylos.llm.orchestrator import RemediationAgent

            agent = RemediationAgent(
                model=model,
                api_key=api_key,
                test_cmd=getattr(agent_args, "test_cmd", None),
                severity_filter=getattr(agent_args, "severity", None),
                provider=provider,
                base_url=base_url,
            )

            summary = agent.run(
                agent_args.path,
                dry_run=getattr(agent_args, "dry_run", False),
                max_fixes=getattr(agent_args, "max_fixes", 10),
                auto_pr=getattr(agent_args, "auto_pr", False),
                branch_prefix=getattr(agent_args, "branch_prefix", "skylos/fix"),
                quiet=getattr(agent_args, "quiet", False),
            )

            if getattr(agent_args, "quiet", False):
                import json as _json_mod

                print(_json_mod.dumps(summary, indent=2))

            sys.exit(
                0
                if summary.get("fixed", 0) > 0 or summary.get("total_findings", 0) == 0
                else 1
            )

    if len(sys.argv) > 1 and sys.argv[1] == "run":
        try:
            from skylos.server import start_server
        except ImportError:
            Console().print("[bold red]Error: Flask is required[/bold red]")
            Console().print(
                "[bold yellow]Install with: pip install flask flask-cors[/bold yellow]"
            )
            sys.exit(1)

        run_exclude_folders = []
        run_include_folders = []
        no_defaults = False

        i = 2
        while i < len(sys.argv):
            if sys.argv[i] == "--exclude-folder" and i + 1 < len(sys.argv):
                run_exclude_folders.append(sys.argv[i + 1])
                i += 2
            elif sys.argv[i] == "--include-folder" and i + 1 < len(sys.argv):
                run_include_folders.append(sys.argv[i + 1])
                i += 2
            elif sys.argv[i] == "--no-default-excludes":
                no_defaults = True
                i += 1
            else:
                i += 1

        exclude_folders = parse_exclude_folders(
            user_exclude_folders=run_exclude_folders or None,
            use_defaults=not no_defaults,
            include_folders=run_include_folders or None,
        )

        try:
            start_server(exclude_folders=list(exclude_folders))
            return
        except ImportError:
            Console().print("[bold red]Error: Flask is required[/bold red]")
            Console().print(
                "[bold yellow]Install with: pip install flask flask-cors[/bold yellow]"
            )
            sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Detect unused functions and unused imports in a Python project",
        epilog="""
Additional commands:
  skylos cicd init       Generate GitHub Actions workflow (30-second setup)
  skylos cicd gate       Quality gate for CI/CD pipelines
  skylos cicd annotate   Emit GitHub Annotations on PRs
  skylos cicd review     Post inline PR review comments
  skylos agent analyze   AI-powered hybrid analysis with LLM
  skylos agent review    AI code review for git-changed files
  skylos badge           Get badge markdown for your README

Run 'skylos <command> --help' for more information on each command.
        """,
    )
    parser.add_argument("path", help="Path to the Python project")
    parser.add_argument(
        "--gate",
        action="store_true",
        help="Run as a quality gate (block deployment on failure)",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload results to skylos.dev dashboard",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="(PRO) Verify findings with neuro-symbolic prover. Requires paid plan.",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Run tests with call tracing to capture dynamic dispatch (e.g., visitor patterns)",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Run tests with coverage before analysis",
    )
    parser.add_argument(
        "--pytest-fixtures",
        action="store_true",
        help="Run pytest runtime fixture tracker and report unused fixtures",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Bypass the quality gate (exit 0 even if issues found)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Strict gate: fail if ANY issue is found",
    )
    parser.add_argument(
        "--fix", action="store_true", help="Attempt to auto-fix issues using AI"
    )
    parser.add_argument(
        "--table",
        action="store_true",
        help="Show findings in Rich table format instead of TUI",
    )
    parser.add_argument(
        "--tree", action="store_true", help="Show findings in tree format"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="LLM model. Examples: gpt-4o-mini, claude-sonnet-4-20250514, groq/llama3-70b-8192. Full list: https://docs.litellm.ai/docs/providers",
    )
    parser.add_argument(
        "--api-base",
        type=str,
        default=None,
        help="Custom API URL for self-hosted models",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"skylos {skylos.__version__}",
        help="Show version and exit",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument(
        "--comment-out",
        action="store_true",
        help="Comment out selected dead code instead of deleting item",
    )
    parser.add_argument("--output", "-o", type=str, help="Write output to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose")
    parser.add_argument(
        "--confidence",
        "-c",
        type=int,
        default=60,
        help="Confidence threshold (0-100). Lower = include more. Default: 60",
    )
    parser.add_argument(
        "--interactive", "-i", action="store_true", help="Select items to remove"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be removed"
    )

    parser.add_argument(
        "--exclude-folder",
        action="append",
        dest="exclude_folders",
        help=(
            "Exclude a folder from analysis (can be used multiple times). By default, common folders like __pycache__, "
            ".git, venv are excluded. Use --no-default-excludes to disable default exclusions."
        ),
    )
    parser.add_argument(
        "--include-folder",
        action="append",
        dest="include_folders",
        help=(
            "Force include a folder that would otherwise be excluded (overrides both default and custom exclusions). "
            "Example: --include-folder venv"
        ),
    )
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="Do not exclude default folders (__pycache__, .git, venv, etc.). Only exclude folders with --exclude-folder.",
    )
    parser.add_argument(
        "--list-default-excludes",
        action="store_true",
        help="List the default excluded folders and exit.",
    )
    parser.add_argument(
        "--secrets", action="store_true", help="Scan for API keys. Off by default."
    )
    parser.add_argument(
        "--danger",
        action="store_true",
        help="Scan for security issues. Off by default.",
    )
    parser.add_argument(
        "--quality",
        action="store_true",
        help="Run code quality checks. Off by default.",
    )
    parser.add_argument(
        "--sca",
        action="store_true",
        help="Scan dependencies for known vulnerabilities (CVEs) via OSV.dev.",
    )

    parser.add_argument(
        "--sarif",
        nargs="?",
        const="skylos.sarif.json",
        default=None,
        help="Write SARIF (2.1.0). Optional path. Example: --sarif or --sarif results.sarif.json",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Only report findings not in the baseline. Run 'skylos baseline .' first.",
    )
    parser.add_argument(
        "--diff-base",
        type=str,
        default=None,
        metavar="REF",
        help="Only report findings in files changed since REF (e.g. origin/main). "
        "Unchanged files are still parsed for cross-file dead code accuracy, "
        "but quality/danger/secrets rules are skipped on them.",
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help="Output GitHub Actions annotations (::warning / ::error) for inline PR comments.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Write markdown summary to $GITHUB_STEP_SUMMARY (use with --gate)",
    )

    parser.add_argument(
        "--severity",
        type=str,
        default=None,
        metavar="LEVEL",
        help="Filter findings by minimum severity: critical, high, medium, low. "
        "Example: --severity high shows only CRITICAL and HIGH.",
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        metavar="CAT",
        help="Show only specific category: security, secret, quality, dead_code, dependency. "
        "Comma-separated for multiple. Example: --category security,secret",
    )
    parser.add_argument(
        "--file-filter",
        type=str,
        default=None,
        metavar="PATTERN",
        help="Only show findings in files matching this substring. "
        "Example: --file-filter auth/ or --file-filter models.py",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Max findings to display per category. Remaining shown as summary. "
        "Example: --limit 20",
    )

    parser.add_argument("command", nargs="*", help="Command to run if gate passes")

    args = parser.parse_args()
    project_root = pathlib.Path(args.path).resolve()
    if project_root.is_file():
        project_root = project_root.parent

    logger = setup_logger(args.output)
    console = logger.console

    if args.list_default_excludes:
        console.print("[brand]Default excluded folders:[/brand]")
        for folder in sorted(DEFAULT_EXCLUDE_FOLDERS):
            console.print(f" {folder}")
        console.print(f"\n[muted]Total: {len(DEFAULT_EXCLUDE_FOLDERS)} folders[/muted]")
        console.print("\nUse --no-default-excludes to disable these exclusions")
        console.print("Use --include-folder <folder> to force include specific folders")
        return

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"Analyzing path: {args.path}")
        if args.exclude_folders:
            logger.debug(f"Excluding folders: {args.exclude_folders}")

    use_defaults = not args.no_default_excludes
    final_exclude_folders = parse_exclude_folders(
        user_exclude_folders=args.exclude_folders,
        use_defaults=use_defaults,
        include_folders=args.include_folders,
    )

    if not args.json:
        if final_exclude_folders:
            console.print(
                f"[warn] Excluding:[/warn] {', '.join(sorted(final_exclude_folders))}"
            )
        else:
            console.print("[good] No folders excluded[/good]")

    if args.coverage:
        if not args.json:
            console.print("[brand]Running tests with coverage...[/brand]")

        cmd = ["coverage", "run", "-m", "pytest", "-q"]
        env = os.environ.copy()

        if args.pytest_fixtures:
            env["SKYLOS_UNUSED_FIXTURES_OUT"] = str(
                project_root / ".skylos_unused_fixtures.json"
            )
            cmd += ["-p", "skylos.pytest_unused_fixtures"]

        pytest_result = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True,
            env=env,
        )

        if pytest_result.returncode != 0:
            if not args.json:
                console.print("[warn]pytest failed, trying unittest...[/warn]")
            subprocess.run(
                ["coverage", "run", "-m", "unittest", "discover"],
                cwd=project_root,
                capture_output=True,
            )

        if not args.json:
            console.print("[good]Coverage data collected[/good]")

    if args.trace:
        if not args.json:
            console.print("[brand]Running tests with call tracing...[/brand]")

        trace_script = textwrap.dedent(f"""\
import os
import sys
sys.path.insert(0, {str(project_root)!r})
from skylos.tracer import CallTracer

tracer = CallTracer(exclude_patterns=["site-packages", "venv", ".venv", "pytest", "_pytest"])
tracer.start()

ret = 0
try:
    import pytest

    pytest_args = ["-q"]
    if {bool(args.pytest_fixtures)!r}:
        os.environ["SKYLOS_UNUSED_FIXTURES_OUT"] = {str(project_root / ".skylos_unused_fixtures.json")!r}
        pytest_args += ["-p", "skylos.pytest_unused_fixtures"]

    ret = pytest.main(pytest_args)

finally:
    tracer.stop()
    tracer.save({str(project_root / ".skylos_trace")!r})

sys.exit(ret)

""")

        r = subprocess.run(
            [sys.executable, "-c", trace_script],
            cwd=project_root,
            capture_output=not args.json,
            text=True,
        )

        trace_file = project_root / ".skylos_trace"

        if r.returncode != 0 and not args.json:
            if trace_file.exists() and trace_file.stat().st_size > 0:
                console.print(
                    "[warn]Tests had failures, but trace data was collected.[/warn]"
                )
            else:
                console.print(
                    "[warn]Trace run failed; continuing without trace.[/warn]"
                )
                if r.stderr:
                    console.print(r.stderr)
        elif not args.json:
            console.print("[good]Trace data collected[/good]")

    pytest_fixtures_ok = None

    if args.pytest_fixtures and (not args.coverage) and (not args.trace):
        if not args.json:
            console.print(
                "[brand]Running tests to detect unused pytest fixtures...[/brand]"
            )

        env = os.environ.copy()
        env["SKYLOS_UNUSED_FIXTURES_OUT"] = str(
            project_root / ".skylos_unused_fixtures.json"
        )

        pytest_targets = []
        p = pathlib.Path(args.path).resolve()
        if p.is_file():
            pytest_targets = [str(p)]

        r = subprocess.run(
            ["pytest", "-q", *pytest_targets, "-p", "skylos.pytest_unused_fixtures"],
            cwd=project_root,
            capture_output=not args.json,
            text=True,
            env=env,
        )

        pytest_fixtures_ok = r.returncode == 0

        if not args.json:
            if pytest_fixtures_ok:
                console.print("[good]Unused fixture report collected[/good]")
            else:
                console.print(
                    "[warn]pytest had failures; unused fixture report may be partial[/warn]"
                )

    custom_rules_data = None
    if not args.json:
        try:
            from skylos.sync import get_custom_rules, get_token

            token = get_token()
            if token:
                custom_rules_data = get_custom_rules()
                if custom_rules_data:
                    console.print(
                        f"[brand]Loaded {len(custom_rules_data)} custom rules from cloud[/brand]"
                    )
        except Exception as e:
            if args.verbose:
                console.print(f"[warn]Could not load custom rules: {e}[/warn]")

    changed_files = None
    if getattr(args, "diff_base", None):
        try:
            diff_result = subprocess.run(
                ["git", "diff", "--name-only", f"{args.diff_base}...HEAD"],
                cwd=project_root,
                capture_output=True,
                text=True,
            )
            if diff_result.returncode == 0:
                changed_files = set()
                for line in diff_result.stdout.strip().splitlines():
                    changed_files.add(str((project_root / line).resolve()))
                if not args.json:
                    console.print(
                        f"[brand]--diff-base:[/brand] {len(changed_files)} changed files "
                        f"(full scan on changed, defs/refs-only on rest)"
                    )
            else:
                if not args.json:
                    console.print(
                        f"[warn]git diff failed: {diff_result.stderr.strip()}. "
                        f"Running full analysis.[/warn]"
                    )
        except FileNotFoundError:
            if not args.json:
                console.print("[warn]git not found. Running full analysis.[/warn]")

    try:
        with Progress(
            SpinnerColumn(style="brand"),
            TextColumn("[brand]Skylos[/brand] {task.description}"),
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("analyzing..", total=None)

            def update_progress(current, total, file):
                progress.update(task, description=f"[{current}/{total}] {file.name}")

            result_json = run_analyze(
                args.path,
                conf=args.confidence,
                enable_secrets=bool(args.secrets),
                enable_danger=bool(args.danger),
                enable_quality=bool(args.quality),
                exclude_folders=list(final_exclude_folders),
                progress_callback=update_progress,
                custom_rules_data=custom_rules_data,
                changed_files=changed_files,
            )

        result = json.loads(result_json)

        if getattr(args, "sca", False) and "dependency_vulnerabilities" not in result:
            try:
                from skylos.rules.sca.vulnerability_scanner import scan_dependencies

                sca_findings = scan_dependencies(project_root)
                if sca_findings:
                    result["dependency_vulnerabilities"] = sca_findings
                    result.setdefault("analysis_summary", {})["sca_count"] = len(
                        sca_findings
                    )
            except Exception as e:
                if args.verbose:
                    console.print(f"[warn]SCA scan error: {e}[/warn]")

        if args.baseline:
            from skylos.baseline import load_baseline, filter_new_findings

            baseline = load_baseline(project_root)
            if baseline is None:
                console.print(
                    "[warn]No baseline found. Run 'skylos baseline .' first.[/warn]"
                )
            else:
                result = filter_new_findings(result, baseline)
                result_json = json.dumps(result)

        if changed_files is not None:
            for category in [
                "unused_functions",
                "unused_imports",
                "unused_classes",
                "unused_variables",
                "unused_parameters",
                "unused_files",
                "danger",
                "quality",
                "secrets",
                "custom_rules",
            ]:
                items = result.get(category, [])
                if items:
                    result[category] = [
                        item
                        for item in items
                        if str((project_root / item.get("file", "")).resolve())
                        in changed_files
                    ]

        if args.pytest_fixtures:
            report_path = project_root / ".skylos_unused_fixtures.json"

            if pytest_fixtures_ok is False:
                result["unused_fixtures"] = []
                result["unused_fixtures_counts"] = {}
            elif report_path.exists():
                try:
                    data = json.loads(report_path.read_text(encoding="utf-8"))
                    fixtures = data.get("unused_fixtures", []) or []
                    counts = data.get("counts", {}) or {}

                    p = pathlib.Path(args.path).resolve()
                    if p.is_file():
                        allowed = {str(p)}
                        allowed.add(str(p.parent / "conftest.py"))
                        fixtures = [
                            f for f in fixtures if str(f.get("file")) in allowed
                        ]

                    for f in fixtures:
                        f.setdefault("confidence", 100)

                    result["unused_fixtures"] = fixtures
                    result["unused_fixtures_counts"] = counts

                except Exception as e:
                    result["unused_fixtures"] = []
                    result["unused_fixtures_counts"] = {}
                    if args.verbose and not args.json:
                        console.print(
                            f"[warn]Could not read unused fixture report: {e}[/warn]"
                        )
            else:
                result["unused_fixtures"] = []
                result["unused_fixtures_counts"] = {}

        if args.verify and (not args.json):
            try:
                from skylos.api import verify_report

                vresp = verify_report(result, quiet=False)
                if vresp.get("success"):
                    console.print(
                        "[good]✓ Verified evidence attached (Skylos Pro)[/good]"
                    )
                else:
                    msg = vresp.get("error") or "Verification unavailable."
                    console.print(f"[warn]{msg}[/warn]")
            except Exception as e:
                console.print(f"[warn]Verification failed: {e}[/warn]")

        if args.sarif:
            all_findings = []

            def _add(items, category, default_rule_id):
                for item in items or []:
                    f = dict(item)
                    rid = (
                        f.get("rule_id")
                        or f.get("rule")
                        or f.get("code")
                        or f.get("id")
                        or default_rule_id
                        or "SKYLOS-UNKNOWN"
                    )
                    f["rule_id"] = str(rid)
                    f["category"] = category
                    f["file_path"] = f.get("file_path") or f.get("file") or "unknown"

                    line_raw = f.get("line_number") or f.get("line") or 1
                    try:
                        line = int(line_raw)
                    except Exception:
                        line = 1

                    f["line_number"] = max(1, line)

                    f["file"] = f.get("file") or f.get("file_path") or "unknown"
                    f["line"] = f.get("line") or f.get("line_number") or 1

                    if not f.get("message"):
                        name = (
                            f.get("name") or f.get("symbol") or f.get("function") or ""
                        )
                        if category == "DEAD_CODE" and name:
                            f["message"] = f"Dead code: {name}"
                        else:
                            f["message"] = f.get("detail") or f.get("msg") or "Issue"
                    if not f.get("severity"):
                        f["severity"] = "LOW"
                    all_findings.append(f)

            _add(result.get("danger", []), "SECURITY", None)
            _add(result.get("quality", []), "QUALITY", None)
            _add(result.get("secrets", []), "SECRET", None)
            _add(result.get("custom_rules", []), "CUSTOM", None)

            _add(
                result.get("unused_functions", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_FUNCTION",
            )
            _add(
                result.get("unused_imports", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_IMPORT",
            )
            _add(
                result.get("unused_variables", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_VARIABLE",
            )
            _add(
                result.get("unused_classes", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_CLASS",
            )
            _add(
                result.get("unused_parameters", []),
                "DEAD_CODE",
                "SKYLOS-DEADCODE-UNUSED_PARAMETER",
            )

            exporter = SarifExporter(all_findings, tool_name="Skylos")
            sarif_data = exporter.generate()
            grade_data = result.get("grade")
            if grade_data:
                sarif_data["runs"][0].setdefault("properties", {})["grade"] = grade_data
            import json as _json

            with open(args.sarif, "w", encoding="utf-8") as _sf:
                _json.dump(sarif_data, _sf, indent=2)

        if args.json:
            print(result_json)
            return

        if args.github:
            _emit_github_annotations(result)
            return

    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        sys.exit(1)

    config = load_config(project_root)

    if args.gate:
        if not args.json:
            _print_upload_destination(console, project_root)

        upload_report(result, is_forced=args.force, strict=args.strict)

        exit_code = run_gate_interaction(
            result=result,
            config=config,
            strict=bool(args.strict),
            force=bool(args.force),
            summary=bool(getattr(args, "summary", False)),
        )
        sys.exit(exit_code)

    if args.fix:
        console.print("[brand]Auto-Fix Mode Enabled (GPT-5)[/brand]")

        provider, api_key, base_url, _is_local = resolve_llm_runtime(
            model=args.model or "gpt-4.1",
            provider_override=None,
            base_url_override=getattr(args, "api_base", None),
            console=console,
            allow_prompt=True,
        )

        if base_url:
            os.environ["OPENAI_BASE_URL"] = base_url
            os.environ["SKYLOS_LLM_BASE_URL"] = base_url

        if api_key is None or (api_key == "" and not _is_local):
            console.print("[bad]No API key provided. Exiting.[/bad]")
            sys.exit(1)

        fixer_model = args.model or "gpt-4.1"
        fixer = Fixer(api_key=api_key, model=fixer_model)

        defs_map = result.get("definitions", {})

        all_findings = []
        if result.get("danger"):
            all_findings.extend(result["danger"])

        if result.get("quality"):
            all_findings.extend(result["quality"])

        for k in [
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
        ]:
            for item in result.get(k, []):
                name = item.get("name") or item.get("simple_name")
                item_type = item.get("type", "item")
                all_findings.append(
                    {
                        "file": item["file"],
                        "line": item["line"],
                        "message": f"Unused {item_type} '{name}' detected. Remove it safely.",
                        "severity": "MEDIUM",
                    }
                )

        if not all_findings:
            console.print("[good]No security issues found to fix.[/good]")
        else:
            for finding in all_findings:
                f_path = finding["file"]
                f_line = finding["line"]
                f_msg = finding["message"]

                console.print(
                    f"\n[warn]Attempting to fix:[/warn] {f_msg} in {f_path}:{f_line}"
                )

                try:
                    p = pathlib.Path(f_path)
                    src = p.read_text(encoding="utf-8")

                    with console.status(
                        f"[bold cyan]Fixing script {f_path} now...[/bold cyan]",
                        spinner="dots",
                    ):
                        fixed_code = fixer.fix_bug(src, f_line, f_msg, defs_map)

                    if "Error" in fixed_code:
                        console.print(f"[bad]{fixed_code}[/bad]")
                    else:
                        problem = fixed_code.get("problem", "Issue detected")
                        change = fixed_code.get("change", "Applied fix")
                        fixed_code = fixed_code.get("code", "")

                        console.print(f"\n[bold]File:[/bold] {f_path}:{f_line}")
                        console.print(f"[bold red]Problem:[/bold red] {problem}")
                        console.print(f"[bold green]Change:[/bold green]  {change}")
                        console.print(
                            Panel(
                                fixed_code,
                                title="[brand]Proposed Code[/brand]",
                                border_style="cyan",
                            )
                        )

                except Exception as e:
                    console.print(f"[bad]Failed to fix: {e}[/bad]")

    if args.interactive:
        unused_functions = result.get("unused_functions", [])
        unused_imports = result.get("unused_imports", [])

        if not (unused_functions or unused_imports):
            console.print("[good]No unused functions/imports to process.[/good]")
        else:
            selected_functions, selected_imports = interactive_selection(
                console, unused_functions, unused_imports, root_path=project_root
            )

            if selected_functions or selected_imports:
                if not args.dry_run:
                    if args.comment_out:
                        action_func_fn = comment_out_unused_function
                        action_func_imp = comment_out_unused_import
                        action_past = "Commented out"
                        action_verb = "comment out"
                    else:
                        action_func_fn = remove_unused_function
                        action_func_imp = remove_unused_import
                        action_past = "Removed"
                        action_verb = "remove"

                    if INTERACTIVE_AVAILABLE:
                        confirm_q = [
                            inquirer.Confirm(
                                "confirm",
                                message="Proceed with changes?",
                                default=False,
                            )
                        ]
                        answers = inquirer.prompt(confirm_q)
                        proceed = answers and answers.get("confirm")
                    else:
                        proceed = True

                    if proceed:
                        console.print(f"[warn]Applying changes…[/warn]")
                        for func in selected_functions:
                            ok = action_func_fn(
                                func["file"], func["name"], func["line"]
                            )
                            if ok:
                                console.print(
                                    f"[good] ✓ {action_past} function:[/good] {func['name']}"
                                )
                            else:
                                console.print(
                                    f"[bad] x Failed to {action_verb} function:[/bad] {func['name']}"
                                )

                        for imp in selected_imports:
                            ok = action_func_imp(imp["file"], imp["name"], imp["line"])
                            if ok:
                                console.print(
                                    f"[good] ✓ {action_past} import:[/good] {imp['name']}"
                                )
                            else:
                                console.print(
                                    f"[bad] x Failed to {action_verb} import:[/bad] {imp['name']}"
                                )
                        console.print(f"[good]Cleanup complete![/good]")
                    else:
                        console.print(f"[warn]Operation cancelled.[/warn]")
                else:
                    console.print(f"[warn]Dry run — no files modified.[/warn]")
            else:
                console.print("[muted]No items selected.[/muted]")

    if args.tree or args.table:
        display_result = result
        _cli_severity = getattr(args, "severity", None)
        _cli_category = getattr(args, "category", None)
        _cli_file_filter = getattr(args, "file_filter", None)
        _cli_limit = getattr(args, "limit", None)
        if _cli_severity or _cli_category or _cli_file_filter:
            display_result = _apply_display_filters(
                result,
                severity=_cli_severity,
                category=_cli_category,
                file_filter=_cli_file_filter,
            )
        render_results(
            console,
            display_result,
            tree=args.tree,
            root_path=project_root,
            limit=_cli_limit,
        )
    else:
        from skylos.tui import run_tui

        run_tui(result, root_path=project_root)

    unused_total = sum(
        len(result.get(k, []))
        for k in (
            "unused_functions",
            "unused_imports",
            "unused_variables",
            "unused_classes",
            "unused_parameters",
        )
    )
    danger_count = len(result.get("danger", []) or [])
    quality_count = len(result.get("quality", []) or [])
    print_badge(
        unused_total,
        logging.getLogger("skylos"),
        danger_enabled=bool(danger_count),
        danger_count=danger_count,
        quality_enabled=bool(quality_count),
        quality_count=quality_count,
    )

    if (not args.json) and _is_tty() and (not args.upload):
        total_findings = 0
        for k in (
            "unused_functions",
            "unused_imports",
            "unused_variables",
            "unused_classes",
            "unused_parameters",
            "danger",
            "quality",
            "secrets",
            "custom_rules",
            "dependency_vulnerabilities",
        ):
            total_findings += len(result.get(k, []) or [])

        if total_findings > 0:
            workflow_path = project_root / ".github" / "workflows" / "skylos.yml"
            if not workflow_path.exists():
                console.print()
                console.print(
                    Panel.fit(
                        "[bold cyan]💡 Tip:[/bold cyan] Catch these issues automatically on every PR\n\n"
                        "[dim]Run:[/dim] [bold]skylos cicd init[/bold]\n"
                        "[dim]Then:[/dim] [bold]git add .github/workflows/skylos.yml && git push[/bold]\n\n"
                        "[muted]30-second setup for automated code analysis in CI/CD[/muted]",
                        title="[cyan]Set up CI/CD[/cyan]",
                        border_style="cyan",
                    )
                )

            _print_upload_cta(console, project_root)
        else:
            console.print()
            console.print(
                "[good]✨ Clean codebase! No issues found.[/good]\n"
                "[dim]💡 Show others you maintain quality code: [/dim][bold cyan]skylos badge[/bold cyan]"
            )

            no_prompt = bool(config.get("no_upload_prompt"))
            if (not no_prompt) and _has_high_intent_findings(result) and _is_tty():
                try:
                    ans = (
                        input("  Upload this scan to Skylos Cloud? [Y/n/never] ")
                        .strip()
                        .lower()
                    )
                except (KeyboardInterrupt, EOFError):
                    ans = "n"

                if ans in ("", "y", "yes"):
                    args.upload = True
                elif ans == "never":
                    ok = _set_no_upload_prompt(project_root, True)
                    if ok:
                        console.print(
                            "[muted]Okay. Run 'skylos . --upload' anytime to upload manually.[/muted]"
                        )
                    else:
                        console.print(
                            "[warn]Could not persist preference (no pyproject.toml).[/warn]"
                        )

    forgotten = result.get("forgotten", [])
    if forgotten:
        console.print(
            "\n[bold red]Forgotten / Dead Functions (Last 30 Days)[/bold red]"
        )
        console.print("=====================================================")
        for item in forgotten:
            status = item["status"]

            if "EXPIRED" in status:
                style = "dim"
            else:
                style = "bold red"

            console.print(f" [{style}]{status}[/{style}] {item['name']}")
            console.print(f"    └─ {item['file']}:{item['line']}")

    if args.upload and not args.json:
        has_link, using_env = _print_upload_destination(console, project_root)

        if (not has_link) and (not using_env):
            if _is_tty() and not _is_ci():
                console.print(
                    "\n[bold yellow]No Skylos token found.[/bold yellow] "
                    "Let's connect to Skylos Cloud.\n"
                )
                from skylos.login import run_login

                login_result = run_login(console=console)
                if login_result is None:
                    console.print("[dim]Upload cancelled.[/dim]")
                    raise SystemExit(0)
                has_link, using_env = _print_upload_destination(console, project_root)
            elif _is_ci():
                console.print(
                    "[warn]No SKYLOS_TOKEN set. To upload from CI, add SKYLOS_TOKEN to your environment.[/warn]"
                )
                console.print("  See: https://docs.skylos.dev/ci-setup")
                raise SystemExit(1)
            else:
                from skylos.login import manual_token_fallback

                login_result = manual_token_fallback(console=console)
                if login_result is None:
                    raise SystemExit(1)

        upload_resp = upload_report(result, is_forced=args.force, strict=args.strict)

        if not upload_resp.get("success"):
            err = upload_resp.get("error")
            if (
                err
                and err
                != "No token found. Run 'skylos sync connect' or set SKYLOS_TOKEN."
            ):
                console.print(f"[warn]Upload failed: {err}[/warn]")
        else:
            passed = upload_resp.get("quality_gate_passed")
            if passed is None:
                passed = (upload_resp.get("quality_gate") or {}).get("passed", True)

            if passed is False and not args.force:
                raise SystemExit(1)

    if args.command and not args.gate:
        cmd_list = args.command
        if cmd_list[0] == "--":
            cmd_list = cmd_list[1:]

        console.print(Rule(style="brand"))
        console.print(f"[brand]Executing Deployment:[/brand] {' '.join(cmd_list)}")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("[cyan]Initializing deployment...", total=None)

                process = subprocess.Popen(
                    cmd_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                for line in process.stdout:
                    line = line.strip()
                    if line:
                        progress.update(task, description=f"[cyan]{line}")
                        console.print(f"[dim]{line}[/dim]")

                process.wait()

            if process.returncode == 0:
                console.print(f"[bold green]✓ Deployment Successful[/bold green]")
                sys.exit(0)
            else:
                console.print(
                    f"[bold red]x Deployment Failed (Exit Code {process.returncode})[/bold red]"
                )
                sys.exit(process.returncode)

        except Exception as e:
            console.print(f"[bad]Failed to execute command: {e}[/bad]")
            sys.exit(1)


if __name__ == "__main__":
    main()
