import argparse
import json
import sys
import re
import logging
import os
import secrets
from skylos.constants import parse_exclude_folders, DEFAULT_EXCLUDE_FOLDERS
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
from skylos.file_discovery import discover_source_files

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
        console.print("[brand]Auto-uploading:[/brand] SKYLOS_TOKEN")
    elif has_link:
        console.print(
            f"[brand]Auto-uploading:[/brand] linked project ([muted]{link_path}[/muted])"
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


def _print_feature_hints(console: Console, args):
    """Print contextual hints about features the user hasn't used yet."""
    if _is_ci():
        return

    hints = []

    ran_all = getattr(args, "all_checks", False)
    ran_danger = getattr(args, "danger", False)
    ran_secrets = getattr(args, "secrets", False)
    ran_quality = getattr(args, "quality", False)

    if not ran_all and not (ran_danger and ran_secrets and ran_quality):
        extras = []
        if not ran_danger:
            extras.append("security")
        if not ran_secrets:
            extras.append("secrets")
        if not ran_quality:
            extras.append("quality")
        hints.append(
            f"[dim]Add {' + '.join(extras)} scanning:[/dim] [bold]skylos . -a[/bold]"
        )

    hint_file = Path.home() / ".skylos" / ".hint_index"
    try:
        idx = int(hint_file.read_text().strip()) if hint_file.exists() else 0
    except (ValueError, OSError):
        idx = 0

    rotating_hints = [
        "[dim]Scan for AI/LLM guardrails:[/dim] [bold]skylos defend .[/bold]",
        "[dim]Map LLM integrations:[/dim] [bold]skylos discover .[/bold]",
        "[dim]LLM-verified dead code (100% accuracy):[/dim] [bold]skylos agent verify .[/bold]",
        "[dim]Visualize codebase topology:[/dim] [bold]skylos city .[/bold]",
        "[dim]Auto-fix dead code interactively:[/dim] [bold]skylos . -i[/bold]",
    ]

    hints.append(rotating_hints[idx % len(rotating_hints)])

    try:
        hint_file.parent.mkdir(parents=True, exist_ok=True)
        hint_file.write_text(str(idx + 1))
    except OSError:
        pass

    if hints:
        console.print()
        for hint in hints:
            console.print(f"  {hint}")


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


def _generate_llm_report(result: dict, project_root: pathlib.Path) -> str:
    sections = []
    finding_num = 0

    all_findings = []
    for category, label in [
        ("danger", "Security"),
        ("secrets", "Secrets"),
        ("quality", "Quality"),
        ("custom_rules", "Custom Rules"),
    ]:
        for f in result.get(category, []):
            all_findings.append((f, label))

    _dead_code_meta = {
        "unused_functions": ("SKY-DC001", "MEDIUM", "Unused function"),
        "unused_imports": ("SKY-DC002", "LOW", "Unused import"),
        "unused_classes": ("SKY-DC003", "MEDIUM", "Unused class"),
        "unused_variables": ("SKY-DC004", "LOW", "Unused variable"),
        "unused_parameters": ("SKY-DC005", "LOW", "Unused parameter"),
        "unused_files": ("SKY-DC006", "LOW", "Empty file"),
    }
    for category in _dead_code_meta:
        rule_id, sev, human_label = _dead_code_meta[category]
        for f in result.get(category, []):
            if not f.get("message"):
                name = f.get("name") or f.get("simple_name") or ""
                why = f.get("why_unused")
                if why:
                    f["message"] = f"{human_label} '{name}' is never used ({', '.join(why)})"
                else:
                    f["message"] = f"{human_label} '{name}' is never used"
            if not f.get("rule_id"):
                f["rule_id"] = rule_id
            if not f.get("severity"):
                f["severity"] = sev
            all_findings.append((f, "Dead Code"))

    if not all_findings:
        return "# Skylos Report\n\nNo findings.\n"

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda x: severity_order.get(x[0].get("severity", "LOW"), 4))

    header = (
        f"# Skylos Report — {len(all_findings)} findings\n\n"
        f"Fix each finding below. The code context shows the problematic lines.\n\n---\n"
    )
    sections.append(header)

    _file_cache = {}

    for finding, label in all_findings:
        finding_num += 1
        rule_id = finding.get("rule_id", "")
        severity = finding.get("severity", "INFO")
        name = finding.get("name") or finding.get("simple_name", "")
        file_path = finding.get("file", "")
        line = finding.get("line", 0)
        message = finding.get("message", "")

        code_block = ""
        try:
            abs_path = pathlib.Path(file_path)
            if not abs_path.is_absolute():
                abs_path = project_root / file_path
            cache_key = str(abs_path)
            if cache_key not in _file_cache:
                if abs_path.is_file():
                    _file_cache[cache_key] = abs_path.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                else:
                    _file_cache[cache_key] = None
            src_lines = _file_cache[cache_key]
            if src_lines is not None:
                start = max(0, line - 3)
                end = min(len(src_lines), line + 4)
                context_lines = []
                for i in range(start, end):
                    marker = ">>>" if i == line - 1 else "   "
                    context_lines.append(f"{marker} {i + 1:4d} | {src_lines[i]}")
                if context_lines:
                    code_block = "\n```\n" + "\n".join(context_lines) + "\n```\n"
        except Exception:
            pass

        section = (
            f"\n## {finding_num}. {rule_id} | {severity} | {label}\n"
            f"File: {file_path}:{line}\n"
            f"Name: {name}\n"
            f"{code_block}\n"
            f"Problem: {message}\n"
            f"\n---\n"
        )
        sections.append(section)

    return "".join(sections)


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

        try:
            import pyperclip

            pyperclip.copy(badge_markdown)
            console.print("[good]Copied to clipboard![/good]")
        except ImportError:
            console.print(
                "[muted]Install pyperclip for auto-copy: pip install pyperclip[/muted]"
            )
        except Exception:
            pass

        console.print()

    _SUPPRESS_HINT = "[muted]Suppress: # skylos: ignore (line), ignore = [\"SKY-XXX\"] (rule), or # skylos: ignore-start/end (block)[/muted]\n"
    _DOCS_LINK = _SUPPRESS_HINT + "[muted]Full guide: https://docs.skylos.dev/guides/understanding-output[/muted]\n"

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
        console.print(
            "[muted]Name — the unused function, import, class, or variable.[/muted]\n"
            "[muted]Conf — how confident Skylos is that this code is truly unused (higher = safer to remove).[/muted]\n"
            + _DOCS_LINK
        )

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
        table.add_column("Name", style="bold")
        table.add_column("Detail")
        table.add_column("Location", style="muted", width=36)

        show, overflow = _display_cap(items)
        for i, quality in enumerate(show, 1):
            raw_kind = quality.get("kind") or quality.get("metric") or "quality"
            kind = raw_kind.title()
            func = quality.get("name") or quality.get("simple_name") or "<?>"
            loc = f"{quality.get('basename', '?')}:{quality.get('line', '?')}"
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
            table.add_row(str(i), kind, func, detail, loc)

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
            "[muted]  • \"max N\" / \"(max N)\" — the configured threshold; tune in [tool.skylos] (complexity, nesting, max_args, max_lines, duplicate_strings)[/muted]\n"
            + _DOCS_LINK
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
            "[muted]Cycle — the chain of modules that import each other in a loop.[/muted]\n"
            "[muted]Length — how many modules are in the cycle.[/muted]\n"
            "[muted]Suggested Break — the module to refactor to break the dependency loop.[/muted]\n"
            + _DOCS_LINK
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

        has_provenance = any(
            s.get("ai_authored") is not None for s in (items or [])
        )

        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Provider", style="yellow", width=14)
        table.add_column("Message")
        table.add_column("Preview", style="muted", width=18)
        table.add_column("Location", style="muted", overflow="fold")

        if has_provenance:
            table.add_column("AI", width=12)

        show, overflow = _display_cap(items)
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
            "[muted]Provider — the service the secret belongs to (e.g. AWS, Stripe, GitHub) or \"generic\" for high-entropy strings.[/muted]\n"
            "[muted]Preview — a masked snippet of the detected secret.[/muted]\n"
            + _DOCS_LINK
        )

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

        has_provenance = any(
            d.get("ai_authored") is not None for d in (items or [])
        )

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

            row = [str(i), issue_cell, sev, msg, loc, symbol]

            if has_provenance:
                if d.get("ai_authored"):
                    agent = d.get("ai_agent") or "ai"
                    row.append(f"[red]{agent}[/red]")
                else:
                    row.append("[muted]-[/muted]")

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

                row.extend([ver_str, proof])

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
            + _DOCS_LINK
        )

    def _render_sca(items):
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
            + _DOCS_LINK
        )

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
    from skylos.commands.init_cmd import run_init_command

    return run_init_command()


def run_whitelist(pattern=None, reason=None, show=False):
    from skylos.commands.whitelist_cmd import run_whitelist as run_whitelist_impl

    return run_whitelist_impl(pattern=pattern, reason=reason, show=show)


def get_git_changed_files(root_path):
    from skylos.cli_shared import get_git_changed_files as get_git_changed_files_impl

    return get_git_changed_files_impl(root_path)


def estimate_cost(files):
    from skylos.cli_shared import estimate_cost as estimate_cost_impl

    return estimate_cost_impl(files)


def _run_clean_command():
    from skylos.commands.clean_cmd import run_clean_command

    return run_clean_command(sys.argv[2:])


def run_debt_command(argv):
    from skylos.commands.debt_cmd import run_debt_command as run_debt_command_impl

    return run_debt_command_impl(
        argv,
        console_factory=Console,
        get_git_changed_files_func=get_git_changed_files,
        resolve_llm_runtime_func=resolve_llm_runtime,
        parse_exclude_folders_func=parse_exclude_folders,
        load_config_func=load_config,
    )


def run_defend_command(argv):
    from skylos.commands.defend_cmd import run_defend_command as run_defend_command_impl

    return run_defend_command_impl(
        argv,
        console_factory=Console,
        progress_factory=Progress,
    )


def run_ingest_command(argv):
    from skylos.commands.ingest_cmd import run_ingest_command as run_ingest_command_impl

    return run_ingest_command_impl(
        argv,
        console_factory=Console,
    )


def run_provenance_command(argv):
    from skylos.api import get_git_root
    from skylos.commands.provenance_cmd import (
        run_provenance_command as run_provenance_command_impl,
    )

    return run_provenance_command_impl(
        argv,
        console_factory=Console,
        progress_factory=Progress,
        get_git_root_func=get_git_root,
    )


def run_cicd_command(argv):
    from skylos.commands.cicd_cmd import run_cicd_command as run_cicd_command_impl

    return run_cicd_command_impl(
        argv,
        console_factory=Console,
        load_config_func=load_config,
        run_gate_interaction_func=run_gate_interaction,
        emit_github_annotations_func=_emit_github_annotations,
    )


def _load_addopts():
    from skylos.cli_shared import load_addopts

    return load_addopts()


def _handle_rules_command():
    from skylos.commands.rules_cmd import run_rules_command

    sys.exit(run_rules_command(sys.argv[2:], console_factory=Console))


def _rules_install(console, rules_dir, pack_or_url):
    from skylos.commands.rules_cmd import install_rules

    return install_rules(console, rules_dir, pack_or_url)


def _rules_list(console, rules_dir):
    from skylos.commands.rules_cmd import list_rules

    return list_rules(console, rules_dir)


def _rules_remove(console, rules_dir, name):
    from skylos.commands.rules_cmd import remove_rules

    return remove_rules(console, rules_dir, name)


def _rules_validate(console, path_str):
    from skylos.commands.rules_cmd import validate_rules

    return validate_rules(console, path_str)


def main() -> None:
    if len(sys.argv) == 1:
        from skylos.help import print_command_overview

        print_command_overview(Console())
        sys.exit(0)

    if sys.argv[1] == "commands":
        from skylos.help import print_flat_commands

        print_flat_commands(Console())
        sys.exit(0)

    if sys.argv[1] == "tour":
        from skylos.tour import run_tour

        run_tour(Console())
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "key":
        from skylos.commands.key_cmd import run_key_command

        args = sys.argv[2:]

        if len(args) == 0:
            sys.exit(run_key_command(["menu"]))

        sys.exit(run_key_command(args))

    if len(sys.argv) > 1 and sys.argv[1] == "credits":
        from skylos.commands.credits_cmd import run_credits_command

        sys.exit(run_credits_command())

    if len(sys.argv) > 1 and sys.argv[1] == "baseline":
        from skylos.commands.baseline_cmd import run_baseline_command

        sys.exit(run_baseline_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "init":
        from skylos.commands.init_cmd import run_init_command

        sys.exit(run_init_command())

    if len(sys.argv) > 1 and sys.argv[1] == "badge":
        from skylos.commands.badge_cmd import run_badge_command

        sys.exit(run_badge_command())

    if len(sys.argv) > 1 and sys.argv[1] == "whitelist":
        from skylos.commands.whitelist_cmd import run_whitelist_command

        sys.exit(run_whitelist_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        sys.exit(_run_clean_command())

    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        from skylos.commands.doctor_cmd import run_doctor_command

        sys.exit(run_doctor_command())

    if len(sys.argv) > 1 and sys.argv[1] == "whoami":
        from skylos.commands.whoami_cmd import run_whoami_command

        sys.exit(run_whoami_command())

    if len(sys.argv) > 1 and sys.argv[1] == "login":
        from skylos.commands.login_cmd import run_login_command

        sys.exit(run_login_command())

    if len(sys.argv) > 1 and sys.argv[1] == "sync":
        from skylos.commands.sync_cmd import run_sync_command

        sys.exit(run_sync_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "city":
        from skylos.commands.city_cmd import run_city_command

        sys.exit(run_city_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "discover":
        from skylos.commands.discover_cmd import run_discover_command

        sys.exit(run_discover_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "defend":
        sys.exit(run_defend_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "debt":
        sys.exit(run_debt_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "ingest":
        sys.exit(run_ingest_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "provenance":
        sys.exit(run_provenance_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "rules":
        _handle_rules_command()

    if len(sys.argv) > 1 and sys.argv[1] == "cicd":
        sys.exit(run_cicd_command(sys.argv[2:]))

    if len(sys.argv) > 1 and sys.argv[1] == "agent":
        import argparse as agent_argparse
        # from skylos.llm.merger import merge_findings

        agent_parser = agent_argparse.ArgumentParser(prog="skylos agent")
        agent_sub = agent_parser.add_subparsers(dest="agent_cmd", required=True)

        p_scan = agent_sub.add_parser("scan", help="Hybrid analysis (static + LLM)")
        p_scan.add_argument(
            "path", nargs="?", default=".", help="File or directory to analyze"
        )
        p_scan.add_argument("--model", default="gpt-4.1")
        p_scan.add_argument(
            "--format", choices=["table", "tree", "json", "sarif"], default="table"
        )
        p_scan.add_argument("--output", "-o", help="Output file")
        p_scan.add_argument(
            "--min-confidence", choices=["high", "medium", "low"], default="low"
        )
        p_scan.add_argument(
            "--llm-only", action="store_true", help="Skip static, run LLM only"
        )
        p_scan.add_argument("--quiet", "-q", action="store_true")
        p_scan.add_argument(
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
        p_scan.add_argument(
            "--base-url",
            default=None,
            help="OpenAI-compatible base URL (Ollama/LM Studio/vLLM)",
        )
        p_scan.add_argument(
            "--upload",
            action="store_true",
            help="Upload results to skylos.dev dashboard",
        )
        p_scan.add_argument(
            "--force",
            action="store_true",
            help="Force upload even if quality gate fails",
        )
        p_scan.add_argument(
            "--strict",
            action="store_true",
            help="Exit with error code if findings are reported",
        )
        p_scan.add_argument(
            "--verification-mode",
            choices=["judge_all", "production"],
            default="production",
            help="Dead-code verifier mode: judge_all sends nearly every refs==0 candidate to the LLM",
        )
        p_scan.add_argument(
            "--with-fixes",
            action="store_true",
            help="Generate fix suggestions for findings (slower)",
        )
        p_scan.add_argument(
            "--no-fixes",
            action="store_true",
            help="Disable fix suggestions (compatibility alias; fixes are off by default)",
        )
        p_scan.add_argument(
            "--changed",
            action="store_true",
            help="Analyze only git-changed files",
        )
        p_scan.add_argument(
            "--security",
            action="store_true",
            help="Security-only LLM audit mode",
        )
        p_scan.add_argument(
            "--interactive",
            "-i",
            action="store_true",
            help="Interactive file selection (with --security)",
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
        p_remediate.add_argument(
            "--standards",
            nargs="?",
            const="__builtin__",
            default=None,
            help="Enable LLM-guided cleanup mode (optional: path to custom standards .md file)",
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

        p_verify = agent_sub.add_parser(
            "verify",
            help="LLM-verify dead code findings (reduce false positives, catch more dead code)",
        )
        p_verify.add_argument("path", help="File or directory to analyze")
        p_verify.add_argument("--model", default="gpt-4.1")
        p_verify.add_argument(
            "--conf", type=int, default=60, help="Static analysis confidence threshold"
        )
        p_verify.add_argument(
            "--max-verify",
            type=int,
            default=50,
            help="Max findings to verify with LLM (default: 50)",
        )
        p_verify.add_argument(
            "--max-challenge",
            type=int,
            default=20,
            help="Max survivors to challenge with LLM (default: 20)",
        )
        p_verify.add_argument(
            "--no-entry-discovery",
            action="store_true",
            help="Skip entry point discovery pass",
        )
        p_verify.add_argument(
            "--no-survivor-challenge",
            action="store_true",
            help="Skip survivor challenge pass",
        )
        p_verify.add_argument(
            "--verification-mode",
            choices=["judge_all", "production"],
            default="judge_all",
            help="Dead-code verifier mode: judge_all sends nearly every refs==0 candidate to the LLM",
        )
        p_verify.add_argument(
            "--format",
            choices=["table", "json"],
            default="table",
        )
        p_verify.add_argument("--output", "-o", help="Output file")
        p_verify.add_argument("--quiet", "-q", action="store_true")
        p_verify.add_argument(
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
        p_verify.add_argument(
            "--base-url",
            default=None,
            help="OpenAI-compatible base URL (Ollama/LM Studio/vLLM)",
        )
        p_verify.add_argument(
            "--grep-workers",
            type=int,
            default=4,
            help="Number of parallel grep workers (default: 4)",
        )
        p_verify.add_argument(
            "--parallel-grep",
            action="store_true",
            help="Enable parallel grep execution for faster verification",
        )
        p_verify.add_argument(
            "--fix",
            action="store_true",
            help="Generate removal patches for confirmed dead code",
        )
        p_verify.add_argument(
            "--fix-mode",
            choices=["delete", "comment"],
            default="delete",
            help="Fix mode: delete removes code, comment comments it out (default: delete)",
        )
        p_verify.add_argument(
            "--apply",
            action="store_true",
            help="Apply generated patches (use with --fix)",
        )
        p_verify.add_argument(
            "--pr",
            action="store_true",
            help="Create a branch, apply patches, and commit (use with --fix)",
        )

        p_watch = agent_sub.add_parser(
            "watch",
            help="Continuously maintain active-agent state for a repository",
        )
        p_watch.add_argument("path", nargs="?", default=".")
        p_watch.add_argument("--interval", type=float, default=5.0)
        p_watch.add_argument(
            "--cycles",
            type=int,
            default=0,
            help="Number of refresh cycles to run (0 means keep watching)",
        )
        p_watch.add_argument("--once", action="store_true")
        p_watch.add_argument("--conf", type=int, default=80)
        p_watch.add_argument("--no-baseline", action="store_true")
        p_watch.add_argument("--state-file", default=None)
        p_watch.add_argument(
            "--format",
            choices=["table", "json"],
            default="table",
        )
        p_watch.add_argument("--limit", type=int, default=10)
        p_watch.add_argument(
            "--learn", action="store_true", help="Enable triage pattern learning"
        )

        p_precommit = agent_sub.add_parser(
            "pre-commit",
            help="Analyze staged files only (git hook mode)",
        )
        p_precommit.add_argument("path", nargs="?", default=".")
        p_precommit.add_argument("--conf", type=int, default=80)
        p_precommit.add_argument("--state-file", default=None)
        p_precommit.add_argument(
            "--format",
            choices=["table", "json"],
            default="table",
        )

        p_triage = agent_sub.add_parser(
            "triage",
            help="Manage finding triage (suggest, dismiss, snooze, restore)",
        )
        triage_sub = p_triage.add_subparsers(dest="triage_cmd", required=True)

        t_suggest = triage_sub.add_parser(
            "suggest",
            help="Show auto-triage candidates based on learned patterns",
        )
        t_suggest.add_argument("path", nargs="?", default=".")
        t_suggest.add_argument("--state-file", default=None)
        t_suggest.add_argument(
            "--format",
            choices=["table", "json"],
            default="table",
        )

        t_dismiss = triage_sub.add_parser(
            "dismiss",
            help="Dismiss a ranked action",
        )
        t_dismiss.add_argument("path", nargs="?", default=".")
        t_dismiss.add_argument("action_id")
        t_dismiss.add_argument("--state-file", default=None)
        t_dismiss.add_argument(
            "--format",
            choices=["table", "json"],
            default="table",
        )
        t_dismiss.add_argument("--limit", type=int, default=10)

        t_snooze = triage_sub.add_parser(
            "snooze",
            help="Temporarily snooze a ranked action",
        )
        t_snooze.add_argument("path", nargs="?", default=".")
        t_snooze.add_argument("action_id")
        t_snooze.add_argument("--hours", type=float, default=24.0)
        t_snooze.add_argument("--state-file", default=None)
        t_snooze.add_argument(
            "--format",
            choices=["table", "json"],
            default="table",
        )
        t_snooze.add_argument("--limit", type=int, default=10)

        t_restore = triage_sub.add_parser(
            "restore",
            help="Restore a dismissed or snoozed action",
        )
        t_restore.add_argument("path", nargs="?", default=".")
        t_restore.add_argument("action_id")
        t_restore.add_argument("--state-file", default=None)
        t_restore.add_argument(
            "--format",
            choices=["table", "json"],
            default="table",
        )
        t_restore.add_argument("--limit", type=int, default=10)

        p_status = agent_sub.add_parser(
            "status",
            help="Show the latest active-agent summary",
        )
        p_status.add_argument("path", nargs="?", default=".")
        p_status.add_argument("--state-file", default=None)
        p_status.add_argument("--refresh", action="store_true")
        p_status.add_argument("--conf", type=int, default=80)
        p_status.add_argument("--no-baseline", action="store_true")
        p_status.add_argument(
            "--format",
            choices=["table", "json", "feed"],
            default="table",
        )
        p_status.add_argument("--limit", type=int, default=10)

        p_serve = agent_sub.add_parser(
            "serve",
            help="Run a local cross-platform HTTP API for the active-agent state",
        )
        p_serve.add_argument("path", nargs="?", default=".")
        p_serve.add_argument("--host", default="127.0.0.1")
        p_serve.add_argument("--port", type=int, default=5089)
        p_serve.add_argument("--token", default=None)
        p_serve.add_argument("--state-file", default=None)
        p_serve.add_argument("--conf", type=int, default=80)
        p_serve.add_argument("--no-baseline", action="store_true")
        p_serve.add_argument("--limit", type=int, default=10)
        p_serve.add_argument("--refresh-on-start", action="store_true")

        agent_args = agent_parser.parse_args(sys.argv[2:])
        console = Console()
        cmd = agent_args.agent_cmd

        if cmd in {"watch", "pre-commit", "triage", "status", "serve"}:
            from skylos.agent_center import (
                clear_action_triage,
                command_center_payload,
                load_agent_state,
                refresh_agent_state,
                render_status_table,
                update_action_triage,
                watch_project,
            )

            def _print_agent_table(state, limit):
                rendered = render_status_table(state, limit=limit)
                console.print(f"[bold]{rendered['headline']}[/bold]")
                if rendered["subtitle"]:
                    console.print(f"[dim]{rendered['subtitle']}[/dim]")

                actions = rendered["actions"]
                if not actions:
                    console.print("[green]No ranked actions.[/green]")
                    return

                table = Table(title="Active Agent Queue", expand=True)
                table.add_column("#", style="dim", width=3)
                table.add_column("Severity", width=9)
                table.add_column("Category", width=10)
                table.add_column("Action")
                table.add_column("Location", style="dim", width=28)
                table.add_column("Reason", overflow="fold")

                for idx, action in enumerate(actions[:limit], 1):
                    table.add_row(
                        str(idx),
                        str(action.get("severity", "")),
                        str(action.get("category", "")),
                        str(action.get("title", "")),
                        f"{action.get('file', '?')}:{action.get('line', '?')}",
                        str(action.get("reason", "")),
                    )
                console.print(table)

            def _resolve_state(refresh=False):
                state = (
                    None
                    if refresh
                    else load_agent_state(
                        agent_args.path,
                        state_file=getattr(agent_args, "state_file", None),
                    )
                )
                if state is None:
                    state, _ = refresh_agent_state(
                        agent_args.path,
                        conf=getattr(agent_args, "conf", 80),
                        use_baseline=not getattr(agent_args, "no_baseline", False),
                        state_file=getattr(agent_args, "state_file", None),
                        force=True,
                    )
                return state

            if cmd == "watch":
                state = watch_project(
                    agent_args.path,
                    interval=agent_args.interval,
                    cycles=None if agent_args.cycles == 0 else agent_args.cycles,
                    once=agent_args.once,
                    conf=agent_args.conf,
                    use_baseline=not agent_args.no_baseline,
                    state_file=agent_args.state_file,
                )
                if agent_args.format == "json":
                    print(json.dumps(state, indent=2, default=str))
                else:
                    _print_agent_table(state, agent_args.limit)
                sys.exit(0)

            if cmd == "pre-commit":
                import subprocess as _sp

                staged_result = _sp.run(
                    ["git", "diff", "--cached", "--name-only"],
                    capture_output=True,
                    text=True,
                    cwd=agent_args.path,
                )
                staged_files = [
                    f.strip()
                    for f in staged_result.stdout.strip().splitlines()
                    if f.strip()
                ]
                if not staged_files:
                    console.print("[good]No staged files to analyze[/good]")
                    sys.exit(0)

                state, _ = refresh_agent_state(
                    agent_args.path,
                    conf=agent_args.conf,
                    state_file=agent_args.state_file,
                    force=True,
                )
                staged_set = set(staged_files)
                staged_findings = [
                    f
                    for f in state.get("findings", [])
                    if f.get("file", "") in staged_set
                ]
                if staged_findings:
                    if agent_args.format == "json":
                        print(json.dumps(staged_findings, indent=2, default=str))
                    else:
                        console.print(
                            f"[warn]{len(staged_findings)} finding(s) in staged files:[/warn]"
                        )
                        for f in staged_findings[:20]:
                            sev = f.get("severity", "INFO")
                            console.print(
                                f"  [{sev.lower()}]{sev}[/{sev.lower()}] {f['file']}:{f['line']} {f['message']}"
                            )
                    sys.exit(1)
                console.print("[good]No issues in staged files[/good]")
                sys.exit(0)

            if cmd == "triage":
                tcmd = agent_args.triage_cmd

                if tcmd == "suggest":
                    from skylos.triage_learner import TriageLearner

                    project_root = find_project_root(agent_args.path)
                    learner = TriageLearner()
                    learner.load(str(project_root))

                    state = load_agent_state(
                        project_root, state_file=agent_args.state_file
                    )
                    if not state:
                        console.print(
                            "[dim]No agent state found. Run 'skylos agent watch --once' first.[/dim]"
                        )
                        sys.exit(1)

                    findings = state.get("findings", [])
                    candidates = learner.get_auto_triage_candidates(findings)

                    if not candidates:
                        console.print(
                            "[dim]No auto-triage candidates (need more observations)[/dim]"
                        )
                        sys.exit(0)

                    if agent_args.format == "json":
                        out = [
                            {"finding": f, "action": a, "confidence": c}
                            for f, a, c in candidates
                        ]
                        print(json.dumps(out, indent=2, default=str))
                    else:
                        console.print(
                            f"[brand]Auto-triage candidates ({len(candidates)}):[/brand]"
                        )
                        for finding, action, confidence in candidates:
                            console.print(
                                f"  {action.upper()} ({confidence:.0%}) "
                                f"{finding.get('file', '?')}:{finding.get('line', '?')} "
                                f"{finding.get('message', '?')}"
                            )
                    sys.exit(0)

                if tcmd == "dismiss":
                    state = update_action_triage(
                        agent_args.path,
                        agent_args.action_id,
                        status="dismissed",
                        state_file=agent_args.state_file,
                    )
                elif tcmd == "snooze":
                    state = update_action_triage(
                        agent_args.path,
                        agent_args.action_id,
                        status="snoozed",
                        state_file=agent_args.state_file,
                        snooze_hours=agent_args.hours,
                    )
                elif tcmd == "restore":
                    state = clear_action_triage(
                        agent_args.path,
                        agent_args.action_id,
                        state_file=agent_args.state_file,
                    )

                if agent_args.format == "json":
                    print(json.dumps(state, indent=2, default=str))
                else:
                    _print_agent_table(state, agent_args.limit)
                sys.exit(0)

            if cmd == "status":
                state = _resolve_state(refresh=agent_args.refresh)
                if agent_args.format == "feed":
                    print(
                        json.dumps(
                            command_center_payload(state, limit=agent_args.limit),
                            indent=2,
                            default=str,
                        )
                    )
                elif agent_args.format == "json":
                    print(json.dumps(state, indent=2, default=str))
                else:
                    _print_agent_table(state, agent_args.limit)
                sys.exit(0)

            if cmd == "serve":
                from skylos.agent_service import create_agent_service

                token = agent_args.token or secrets.token_urlsafe(24)
                server = create_agent_service(
                    agent_args.path,
                    host=agent_args.host,
                    port=agent_args.port,
                    token=token,
                    state_file=agent_args.state_file,
                    conf=agent_args.conf,
                    use_baseline=not agent_args.no_baseline,
                    default_limit=agent_args.limit,
                    refresh_on_start=agent_args.refresh_on_start,
                )
                address = server.server_address
                console.print(
                    f"[bold]Skylos Agent API[/bold] listening on http://{address[0]}:{address[1]}"
                )
                console.print(f"[dim]Repo:[/dim] {agent_args.path}")
                console.print("[dim]Auth header:[/dim] X-Skylos-Agent-Token")
                console.print(f"[dim]Session token:[/dim] {token}")
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    console.print("\n[dim]Stopping Skylos Agent API[/dim]")
                finally:
                    server.server_close()
                sys.exit(0)

        if not LLM_AVAILABLE:
            Console().print("[bold red]Agent module not available[/bold red]")
            sys.exit(1)

        model = agent_args.model

        _provider_override = getattr(agent_args, "provider", None)
        if _provider_override and model == "gpt-4.1":
            _provider_default_models = {
                "anthropic": "claude-sonnet-4-20250514",
                "google": "gemini/gemini-2.0-flash",
                "mistral": "mistral/mistral-large-latest",
                "groq": "groq/llama3-70b-8192",
                "deepseek": "deepseek/deepseek-chat",
                "xai": "xai/grok-2",
                "together": "together/meta-llama/Meta-Llama-3-70B-Instruct-Turbo",
                "ollama": "ollama/llama3",
            }
            if _provider_override in _provider_default_models:
                model = _provider_default_models[_provider_override]

        provider, api_key, base_url, _is_local = resolve_llm_runtime(
            model=model,
            provider_override=_provider_override,
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

        agent_exclude_folders = list(
            parse_exclude_folders(
                use_defaults=True,
                config_exclude_folders=load_config(
                    getattr(agent_args, "path", Path.cwd())
                ).get("exclude"),
            )
        )

        if cmd == "scan":
            if getattr(agent_args, "security", False):
                path = pathlib.Path(agent_args.path)
                if not path.exists():
                    console.print(f"[bad]Path not found: {path}[/bad]")
                    sys.exit(1)

                if path.is_file():
                    files = [path]
                else:
                    files = discover_source_files(
                        path,
                        [".py"],
                        exclude_folders=agent_exclude_folders,
                    )

                if not files:
                    console.print("[warn]No Python files found[/warn]")
                    sys.exit(0)

                if (
                    INTERACTIVE_AVAILABLE
                    and getattr(agent_args, "interactive", False)
                    and len(files) > 1
                ):
                    choices = [
                        (f"{f.name} ({f.stat().st_size / 1024:.1f}KB)", f)
                        for f in files
                    ]
                    questions = [
                        inquirer.Checkbox(
                            "files", message="Select files", choices=choices
                        )
                    ]
                    answers = inquirer.prompt(questions)
                    if not answers or not answers["files"]:
                        sys.exit(0)
                    files = answers["files"]

                tokens, cost = llm_estimate_cost(files, model)
                console.print(
                    f"\n[brand]Security audit:[/brand] {len(files)} files, ~{tokens:,} tokens, ~${cost:.4f}"
                )

                if (
                    INTERACTIVE_AVAILABLE
                    and _is_tty()
                    and not inquirer.confirm("Proceed?", default=True)
                ):
                    sys.exit(0)

                config = AnalyzerConfig(
                    model=model,
                    api_key=api_key,
                    quiet=getattr(agent_args, "quiet", False),
                )
                analyzer = SkylosLLM(config)
                llm_result = analyzer.analyze_files(
                    files, issue_types=["security_audit"]
                )
                analyzer.print_results(
                    llm_result, format=agent_args.format, output_file=agent_args.output
                )
                sys.exit(1 if llm_result.has_blockers else 0)

            changed_files = None
            if getattr(agent_args, "changed", False):
                path = pathlib.Path(agent_args.path)
                console.print("[brand]Finding git-changed files...[/brand]")
                changed_files = get_git_changed_files(path)

                if not changed_files:
                    console.print("[dim]No changed files[/dim]")
                    sys.exit(0)

                console.print(f"Found {len(changed_files)} changed files")

            agent_args.with_fixes = bool(getattr(agent_args, "with_fixes", False))
            if getattr(agent_args, "no_fixes", False):
                agent_args.with_fixes = False

            path = pathlib.Path(agent_args.path)
            if not path.exists():
                console.print(f"[bad]Path not found: {path}[/bad]")
                sys.exit(1)

            project_root = find_project_root(path)

            import time as _time

            _scan_start = _time.time()
            pipeline_stats = {}
            merged_findings = run_pipeline(
                path=str(path),
                model=model,
                api_key=api_key,
                agent_args=agent_args,
                console=console,
                changed_files=changed_files,
                exclude_folders=agent_exclude_folders,
                stats_out=pipeline_stats,
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
            if pipeline_stats:
                console.print("[dim]Timings:[/dim]")
                console.print(
                    f"  static={pipeline_stats.get('phase_1_seconds', 0):.1f}s "
                    f"verify={pipeline_stats.get('phase_2a_seconds', 0):.1f}s "
                    f"audit={pipeline_stats.get('phase_2b_seconds', 0):.1f}s "
                    f"fixes={pipeline_stats.get('phase_3_seconds', 0):.1f}s "
                    f"total={pipeline_stats.get('elapsed_seconds', 0):.1f}s"
                )

            if agent_args.format == "json":
                output = json.dumps(merged_findings, indent=2, default=str)
                if agent_args.output:
                    pathlib.Path(agent_args.output).write_text(output)
                else:
                    print(output)
            else:
                title = (
                    "Hybrid Review Results (Changed Files)"
                    if changed_files
                    else "Hybrid Analysis Results"
                )
                if merged_findings:
                    table = Table(title=title, expand=True)
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

            try:
                from skylos.api import upload_agent_run

                upload_agent_run(
                    "scan",
                    {
                        "total": len(merged_findings),
                        "static_only": static_only,
                        "llm_only": llm_only,
                        "both": both,
                    },
                    model=model,
                    provider=provider,
                    duration_seconds=round(_time.time() - _scan_start, 1),
                )
            except Exception:
                pass

            if merged_findings and getattr(agent_args, "strict", False):
                sys.exit(1)
            sys.exit(0)

        if cmd == "verify":
            path = pathlib.Path(agent_args.path)
            if not path.exists():
                console.print(f"[bad]Path not found: {path}[/bad]")
                sys.exit(1)

            console.print("[brand]Step 1/2: Running static analysis...[/brand]")

            from skylos.analyzer import analyze as run_static

            raw = run_static(
                str(path),
                conf=agent_args.conf,
                enable_danger=False,
                enable_quality=False,
                enable_secrets=False,
                exclude_folders=agent_exclude_folders,
            )
            static_result = json.loads(raw) if isinstance(raw, str) else raw

            from skylos.dead_code import collect_dead_code_findings

            all_findings = collect_dead_code_findings(static_result)

            defs_map = static_result.get("definitions", {})

            if not all_findings:
                console.print("[good]No dead code findings to verify![/good]")
                sys.exit(0)

            console.print(f"  Found {len(all_findings)} dead code findings")

            console.print("\n[brand]Step 2/2: LLM verification (4-pass)...[/brand]")

            from skylos.llm.verify_orchestrator import run_verification

            result = run_verification(
                findings=all_findings,
                defs_map=defs_map,
                project_root=str(path if path.is_dir() else path.parent),
                model=model,
                api_key=api_key,
                provider=provider,
                base_url=base_url,
                max_verify=agent_args.max_verify,
                max_challenge=agent_args.max_challenge,
                enable_entry_discovery=not agent_args.no_entry_discovery,
                enable_survivor_challenge=not agent_args.no_survivor_challenge,
                quiet=getattr(agent_args, "quiet", False),
                verification_mode=getattr(agent_args, "verification_mode", "judge_all"),
                grep_workers=getattr(agent_args, "grep_workers", 4),
                parallel_grep=getattr(agent_args, "parallel_grep", False)
                or getattr(agent_args, "fix", False),
            )

            stats = result["stats"]
            verified = result["verified_findings"]
            new_dead = result["new_dead_code"]

            if agent_args.format == "json":
                output = json.dumps(result, indent=2, default=str)
                if agent_args.output:
                    pathlib.Path(agent_args.output).write_text(output)
                    console.print(f"[dim]Written to {agent_args.output}[/dim]")
                else:
                    print(output)
            else:
                console.print("\n[brand]Verification Summary[/brand]")
                summary_table = Table(expand=False)
                summary_table.add_column("Metric", style="cyan")
                summary_table.add_column("Value", style="bold")
                summary_table.add_row("Total findings", str(stats["total_findings"]))
                summary_table.add_row(
                    "Confirmed dead (TRUE_POSITIVE)",
                    f"[red]{stats['verified_true_positive']}[/red]",
                )
                summary_table.add_row(
                    "False positives removed",
                    f"[green]{stats['verified_false_positive']}[/green]",
                )
                summary_table.add_row("Uncertain", str(stats["uncertain"]))
                summary_table.add_row(
                    "Entry points discovered", str(stats["entry_points_discovered"])
                )
                summary_table.add_row(
                    "Survivors challenged", str(stats["survivors_challenged"])
                )
                summary_table.add_row(
                    "New dead code found",
                    f"[red]{stats['survivors_reclassified_dead']}[/red]",
                )
                summary_table.add_row("LLM calls", str(stats["llm_calls"]))
                summary_table.add_row("Time", f"{stats['elapsed_seconds']}s")
                console.print(summary_table)

                fps = [f for f in verified if f.get("_llm_verdict") == "FALSE_POSITIVE"]
                if fps:
                    console.print(
                        f"\n[green]False positives removed ({len(fps)}):[/green]"
                    )
                    fp_table = Table(expand=True)
                    fp_table.add_column("Name", style="green")
                    fp_table.add_column("File", style="dim")
                    fp_table.add_column("Rationale", overflow="fold")
                    for f in fps[:30]:
                        fp_table.add_row(
                            f.get("name", "?"),
                            f"{f.get('file', '?')}:{f.get('line', '?')}",
                            f.get("_llm_rationale", "")[:100],
                        )
                    console.print(fp_table)

                if new_dead:
                    console.print(
                        f"\n[red]New dead code discovered ({len(new_dead)}):[/red]"
                    )
                    nd_table = Table(expand=True)
                    nd_table.add_column("Name", style="red")
                    nd_table.add_column("File", style="dim")
                    nd_table.add_column("Rationale", overflow="fold")
                    for d in new_dead[:30]:
                        nd_table.add_row(
                            d.get("full_name", d.get("name", "?")),
                            f"{d.get('file', '?')}:{d.get('line', '?')}",
                            d.get("_llm_rationale", "")[:100],
                        )
                    console.print(nd_table)

                eps = result.get("entry_points", [])
                if eps:
                    console.print(
                        f"\n[cyan]Entry points discovered ({len(eps)}):[/cyan]"
                    )
                    for ep in eps:
                        console.print(f"  - {ep['name']} (from {ep['source']})")

            total_removed = stats["verified_false_positive"]
            total_added = stats["survivors_reclassified_dead"]
            net = stats["total_findings"] - total_removed + total_added

            console.print(
                f"\n[brand]Net result:[/brand] {stats['total_findings']} findings "
                f"→ [green]-{total_removed} FP[/green] "
                f"[red]+{total_added} new[/red] "
                f"= {net} verified findings"
            )

            if getattr(agent_args, "fix", False):
                from skylos.fixgen import (
                    generate_removal_plan,
                    generate_unified_diff,
                    apply_patches,
                    validate_patches,
                    generate_fix_summary,
                )

                dead_findings = [
                    f for f in verified if f.get("_llm_verdict") == "TRUE_POSITIVE"
                ] + (new_dead or [])

                if dead_findings:
                    fix_mode = getattr(agent_args, "fix_mode", "delete")
                    project_root_str = str(path if path.is_dir() else path.parent)
                    patches = generate_removal_plan(
                        dead_findings,
                        defs_map,
                        project_root_str,
                        mode=fix_mode,
                    )

                    if patches:
                        errors = validate_patches(patches, project_root_str)
                        if errors:
                            console.print("\n[warn]Patch validation warnings:[/warn]")
                            for err in errors:
                                console.print(f"  [yellow]! {err}[/yellow]")

                        summary = generate_fix_summary(patches)
                        console.print(f"\n[brand]Fix Plan:[/brand]")
                        console.print(f"  Patches: {summary['total_patches']}")
                        console.print(f"  Files affected: {summary['files_affected']}")
                        console.print(
                            f"  Lines to remove: {summary['total_lines_removed']}"
                        )
                        console.print(f"  Avg safety: {summary['avg_safety_score']}")

                        diff = generate_unified_diff(patches, project_root_str)
                        if diff:
                            console.print("\n[brand]Unified Diff:[/brand]")
                            print(diff)

                        if getattr(agent_args, "pr", False) and not errors:
                            import time as _time

                            branch_name = f"skylos/fix-deadcode-{int(_time.time())}"
                            try:
                                subprocess.run(
                                    ["git", "checkout", "-b", branch_name],
                                    cwd=project_root_str,
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                )
                                apply_patches(patches, project_root_str, dry_run=False)
                                subprocess.run(
                                    ["git", "add", "-A"],
                                    cwd=project_root_str,
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                )
                                commit_msg = (
                                    f"fix: remove {summary['total_patches']} dead code items "
                                    f"({summary['total_lines_removed']} lines)"
                                )
                                subprocess.run(
                                    ["git", "commit", "-m", commit_msg],
                                    cwd=project_root_str,
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                )
                                console.print(
                                    f"\n[good]Branch created: {branch_name}[/good]"
                                )
                                console.print(f"[good]Committed: {commit_msg}[/good]")
                                if shutil.which("gh"):
                                    console.print(
                                        f"\n[brand]Create PR with:[/brand]\n"
                                        f'  gh pr create --title "{commit_msg}" '
                                        f'--body "Automated dead code removal by Skylos"'
                                    )
                                else:
                                    console.print(
                                        f"\n[dim]Push and create PR:[/dim]\n"
                                        f"  git push -u origin {branch_name}\n"
                                        f"  # then open PR on GitHub"
                                    )
                            except subprocess.CalledProcessError as e:
                                console.print(
                                    f"\n[warn]Git operation failed: {e.stderr or e}[/warn]"
                                )
                        elif getattr(agent_args, "apply", False) and not errors:
                            apply_patches(patches, project_root_str, dry_run=False)
                            console.print(
                                "\n[good]Patches applied successfully![/good]"
                            )
                        elif (
                            getattr(agent_args, "apply", False)
                            or getattr(agent_args, "pr", False)
                        ) and errors:
                            console.print(
                                "\n[warn]Skipping apply due to validation errors[/warn]"
                            )
                    else:
                        console.print("\n[dim]No patches generated[/dim]")
                else:
                    console.print("\n[dim]No confirmed dead code to fix[/dim]")

            try:
                from skylos.api import upload_agent_run

                upload_agent_run(
                    "verify",
                    {
                        "total_findings": stats["total_findings"],
                        "verified_true_positive": stats["verified_true_positive"],
                        "verified_false_positive": stats["verified_false_positive"],
                        "entry_points_discovered": stats["entry_points_discovered"],
                        "llm_calls": stats["llm_calls"],
                        "elapsed_seconds": stats["elapsed_seconds"],
                    },
                    model=model,
                    provider=provider,
                    duration_seconds=stats.get("elapsed_seconds"),
                )
            except Exception:
                pass

            sys.exit(0)

        if cmd == "remediate":
            standards_raw = getattr(agent_args, "standards", None)

            if standards_raw:
                standards_path = (
                    None if standards_raw == "__builtin__" else standards_raw
                )

                from skylos.llm.cleanup_orchestrator import CleanupOrchestrator

                orchestrator = CleanupOrchestrator(
                    model=model,
                    api_key=api_key,
                    provider=provider,
                    base_url=base_url,
                    test_cmd=getattr(agent_args, "test_cmd", None),
                    standards_path=standards_path,
                )

                summary = orchestrator.run(
                    agent_args.path,
                    max_fixes=getattr(agent_args, "max_fixes", 20),
                    dry_run=getattr(agent_args, "dry_run", False),
                    quiet=getattr(agent_args, "quiet", False),
                )

                if getattr(agent_args, "quiet", False):
                    import json as _json_mod

                    print(_json_mod.dumps(summary, indent=2))

                try:
                    from skylos.api import upload_agent_run

                    upload_agent_run(
                        "cleanup",
                        {
                            "total_items": summary.get("total_items", 0),
                            "applied": summary.get("applied", 0),
                            "reverted": summary.get("reverted", 0),
                            "skipped": summary.get("skipped", 0),
                            "total_analyzed_files": summary.get(
                                "total_analyzed_files", 0
                            ),
                        },
                        model=model,
                        provider=provider,
                        duration_seconds=summary.get("elapsed_seconds"),
                    )
                except Exception:
                    pass

                sys.exit(
                    0
                    if summary.get("applied", 0) > 0
                    or summary.get("total_items", 0) == 0
                    else 1
                )
            else:
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

                try:
                    from skylos.api import upload_agent_run

                    upload_agent_run(
                        "remediate",
                        {
                            "total_findings": summary.get("total_findings", 0),
                            "fixed": summary.get("fixed", 0),
                            "failed": summary.get("failed", 0),
                            "skipped": summary.get("skipped", 0),
                            "pr_url": summary.get("pr_url"),
                        },
                        model=model,
                        provider=provider,
                        duration_seconds=summary.get("elapsed_seconds"),
                    )
                except Exception:
                    pass

                sys.exit(
                    0
                    if summary.get("fixed", 0) > 0
                    or summary.get("total_findings", 0) == 0
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
            config_exclude_folders=load_config(Path.cwd()).get("exclude"),
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
        description="Find dead code, secrets, and risky flows in Python, TypeScript, and Go",
        epilog="""
Run 'skylos commands' for a full list of all available commands.
Run 'skylos tour' for a guided walkthrough of capabilities.
        """,
    )
    parser.add_argument("path", nargs="+", help="Path(s) to the project")
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
        "--no-upload",
        action="store_true",
        help="Skip automatic upload even if connected to Skylos Cloud",
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
        "--tui",
        action="store_true",
        help="Launch interactive TUI dashboard",
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
        "--llm",
        action="store_true",
        help="Output LLM-optimized report (structured findings with code context for AI agents to fix)",
    )
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
        "-a",
        "--all",
        action="store_true",
        dest="all_checks",
        help="Enable all checks: --danger --secrets --quality --sca",
    )
    parser.add_argument(
        "--no-grep-verify",
        action="store_true",
        help="Disable grep-based verification pass (reduces false positives by default).",
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
        "--diff",
        type=str,
        default=None,
        nargs="?",
        const="auto",
        metavar="BASE_REF",
        help="Only report findings in lines changed since BASE_REF (e.g. --diff origin/main). "
        "Use --diff without a value to auto-detect (GITHUB_BASE_REF or origin/main).",
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

    parser.add_argument(
        "--provenance",
        action="store_true",
        help="(Deprecated — provenance is now automatic in git repos.) "
        "Kept for backwards compatibility; has no effect.",
    )
    parser.add_argument(
        "--no-provenance",
        action="store_true",
        help="Disable automatic AI provenance detection.",
    )
    parser.add_argument(
        "--provenance-base",
        type=str,
        default=None,
        metavar="REF",
        help="Base ref for provenance detection (default: auto-detect).",
    )

    parser.add_argument("command", nargs="*", help="Command to run if gate passes")

    _argv = sys.argv[1:]

    _addopts = _load_addopts()
    if _addopts:
        _argv = _addopts + _argv

    if "--" in _argv:
        _split = _argv.index("--")
        _main_argv = _argv[:_split]
        _cmd_argv = _argv[_split + 1 :]
    else:
        _main_argv = _argv
        _cmd_argv = []
    if _cmd_argv:
        args, _extra = parser.parse_known_args(_main_argv)
        args.command = _cmd_argv + (_extra or [])
    else:
        args = parser.parse_args(_main_argv)
        args.command = []

    if getattr(args, "all_checks", False):
        args.danger = True
        args.secrets = True
        args.quality = True
        args.sca = True

    project_root = pathlib.Path(args.path[0]).resolve()
    if project_root.is_file():
        project_root = project_root.parent
    if len(args.path) > 1:
        all_resolved = [pathlib.Path(p).resolve() for p in args.path]
        project_root = pathlib.Path(os.path.commonpath(all_resolved))

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
        logger.debug(f"Analyzing path(s): {args.path}")
        if args.exclude_folders:
            logger.debug(f"Excluding folders: {args.exclude_folders}")

    use_defaults = not args.no_default_excludes
    project_cfg = load_config(project_root)
    final_exclude_folders = parse_exclude_folders(
        user_exclude_folders=args.exclude_folders,
        config_exclude_folders=project_cfg.get("exclude"),
        use_defaults=use_defaults,
        include_folders=args.include_folders,
    )

    if not args.json:
        banner = (
            "[bold cyan]"
            " ███████ ██   ██ ██    ██ ██       ██████  ███████\n"
            " ██      ██  ██   ██  ██  ██      ██    ██ ██     \n"
            " ███████ █████     ████   ██      ██    ██ ███████\n"
            "      ██ ██  ██     ██    ██      ██    ██      ██\n"
            " ███████ ██   ██    ██    ███████  ██████  ███████\n"
            "[/bold cyan]\n"
            "  [bold white]v" + skylos.__version__ + "[/bold white]"
            "  [dim]│[/dim]  [blue]github.com/duriantaco/skylos[/blue]"
        )
        console.print(Panel(banner, border_style="cyan", padding=(1, 2)))
        console.print()

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
            capture_output=True,
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
        if len(args.path) == 1:
            p = pathlib.Path(args.path[0]).resolve()
            if p.is_file():
                pytest_targets = [str(p)]

        r = subprocess.run(
            ["pytest", "-q", *pytest_targets, "-p", "skylos.pytest_unused_fixtures"],
            cwd=project_root,
            capture_output=True,
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
                args.path if len(args.path) > 1 else args.path[0],
                conf=args.confidence,
                enable_secrets=bool(args.secrets),
                enable_danger=bool(args.danger),
                enable_quality=bool(args.quality),
                exclude_folders=list(final_exclude_folders),
                progress_callback=update_progress,
                custom_rules_data=custom_rules_data,
                changed_files=changed_files,
                grep_verify=not getattr(args, "no_grep_verify", False),
            )

        result = json.loads(result_json)

        if getattr(args, "sca", False) and "dependency_vulnerabilities" not in result:
            try:
                from skylos.rules.sca.vulnerability_scanner import scan_dependencies

                sca_findings = scan_dependencies(project_root)
                if sca_findings:
                    try:
                        from skylos.rules.sca.reachability import (
                            enrich_with_reachability,
                        )

                        sca_findings = enrich_with_reachability(
                            sca_findings, project_root
                        )
                    except Exception:
                        pass
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

        if getattr(args, "diff", None):
            from skylos.cicd.review import (
                get_changed_line_ranges,
                filter_findings_to_diff,
            )

            base_ref = args.diff
            if base_ref == "auto":
                base_ref = os.environ.get("GITHUB_BASE_REF", "origin/main")
                if base_ref and not base_ref.startswith("origin/"):
                    base_ref = f"origin/{base_ref}"

            changed_ranges = get_changed_line_ranges(base_ref)
            if changed_ranges:
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
                        result[category] = filter_findings_to_diff(
                            items, changed_ranges
                        )
                result_json = json.dumps(result)
                if not args.json:
                    console.print(
                        f"[brand]--diff:[/brand] filtered to {len(changed_ranges)} changed line ranges "
                        f"from {base_ref}"
                    )
            elif not args.json:
                console.print(
                    f"[warn]--diff: no changed lines found vs {base_ref}[/warn]"
                )

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

                    p = pathlib.Path(args.path[0]).resolve()
                    if len(args.path) == 1 and p.is_file():
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

        prov_report = None
        _skip_provenance = getattr(args, "no_provenance", False)
        if not _skip_provenance:
            try:
                from skylos.provenance import (
                    analyze_provenance,
                    annotate_findings_with_provenance,
                    compute_ai_security_stats,
                )
                from skylos.api import get_git_root

                git_root = get_git_root()
                if not git_root:
                    raise RuntimeError("not a git repository")
                prov_base = getattr(args, "provenance_base", None)

                with Progress(
                    SpinnerColumn(style="brand"),
                    TextColumn("[brand]Skylos[/brand] {task.description}"),
                    transient=True,
                    console=console,
                ) as progress:
                    progress.add_task("detecting AI provenance...", total=None)
                    prov_report = analyze_provenance(git_root, base_ref=prov_base)

                _finding_categories = [
                    "danger", "quality", "secrets", "custom_rules",
                    "unused_functions", "unused_imports", "unused_classes",
                    "unused_variables", "unused_parameters",
                    "dependency_vulnerabilities",
                ]
                all_annotatable = []
                for cat in _finding_categories:
                    items = result.get(cat)
                    if items:
                        for item in items:
                            item.setdefault("category", cat)
                        all_annotatable.extend(items)

                annotate_findings_with_provenance(all_annotatable, prov_report)

                ai_stats = compute_ai_security_stats(all_annotatable)
                result["ai_security_stats"] = ai_stats
                result["provenance_summary"] = prov_report.summary

                result_json = json.dumps(result)

                if not args.json:
                    ai_count = ai_stats["ai_authored_findings"]
                    ai_pct = ai_stats["ai_authored_pct"]
                    if ai_count > 0:
                        console.print(
                            f"[brand]Provenance:[/brand] [red]{ai_count}[/red] of "
                            f"{ai_stats['total_findings']} findings ({ai_pct}%) are AI-authored"
                        )
                        agents = ai_stats.get("by_agent", {})
                        if agents:
                            agent_parts = [f"{name}: {cnt}" for name, cnt in sorted(agents.items())]
                            console.print(
                                f"  [muted]Agents: {', '.join(agent_parts)}[/muted]"
                            )
            except Exception as e:
                if args.verbose:
                    console.print(f"[warn]Provenance annotation failed: {e}[/warn]")

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
            if args.output:
                pathlib.Path(args.output).write_text(result_json)
            else:
                print(result_json)
            return

        if args.llm:
            llm_report = _generate_llm_report(result, project_root)
            if args.output:
                pathlib.Path(args.output).write_text(llm_report, encoding="utf-8")
                if not args.json:
                    console.print(f"[good]LLM report written to {args.output}[/good]")
            else:
                print(llm_report)
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

    if args.tui:
        from skylos.tui import run_tui

        run_tui(result, root_path=project_root)
    elif not args.upload:
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

            from skylos.nudge import pick_nudge

            nudge = pick_nudge(result, args, project_root)
            if nudge:
                console.print(f"\n  {nudge}")
            _print_upload_cta(console, project_root)
        else:
            console.print()
            console.print(
                "[good]✨ Clean codebase! No issues found.[/good]\n"
                "[dim]💡 Show others you maintain quality code: [/dim][bold cyan]skylos badge[/bold cyan]"
            )
            from skylos.nudge import pick_nudge

            nudge = pick_nudge(result, args, project_root)
            if nudge:
                console.print(f"\n  {nudge}")

    if not args.upload and not getattr(args, "no_upload", False) and not args.json:
        is_linked = _detect_link_file(project_root) is not None
        has_env_token = bool(os.getenv("SKYLOS_TOKEN"))
        if is_linked or has_env_token:
            args.upload = True

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
        from skylos.api import get_project_token as _check_token

        has_link, using_env = _print_upload_destination(console, project_root)

        if (not has_link) and (not using_env) and (not _check_token()):
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

        from skylos.api import (
            get_credit_balance,
            get_project_token as _get_token,
            BASE_URL,
        )

        _token = _get_token()

        if _token:
            _balance_data = get_credit_balance(_token)
        else:
            _balance_data = None

        if _balance_data:
            _plan = _balance_data.get("plan", "free")
            _bal = _balance_data.get("balance", 0)
            if _plan != "enterprise" and _bal <= 0:
                console.print(
                    f"[bold red]0 credits remaining — upload skipped.[/bold red] "
                    f"Buy more: [link={BASE_URL}/dashboard/billing]{BASE_URL}/dashboard/billing[/link]"
                )
                console.print("[dim]Run 'skylos credits' to check your balance.[/dim]")
                return

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

            qg = upload_resp.get("quality_gate") or {}
            new_v = qg.get("new_violations", 0)
            if new_v > 0:
                console.print(
                    f"[bold red]  {new_v} new violation{'s' if new_v != 1 else ''}[/bold red]"
                )

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
