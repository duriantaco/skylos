import argparse
import json
import sys
import os
import logging
from skylos.constants import parse_exclude_folders, DEFAULT_EXCLUDE_FOLDERS
from skylos.server import start_server
from skylos.fixer import Fixer
from skylos.analyzer import analyze as run_analyze
from skylos.codemods import (
    remove_unused_import_cst,
    remove_unused_function_cst,
    comment_out_unused_import_cst,
    comment_out_unused_function_cst,
)
from skylos.config import load_config
from skylos.gatekeeper import run_gate_interaction
from skylos.credentials import get_key, save_key
from skylos.api import upload_report

import pathlib
import skylos
from collections import defaultdict
import subprocess

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


def _shorten_path(file_path, root_path=None):
    if not file_path:
        return "?"

    try:
        p = pathlib.Path(file_path)
    except TypeError:
        return str(file_path)

    if root_path is not None:
        try:
            root = pathlib.Path(root_path)
            if root.is_file():
                root = root.parent
            p = p.resolve()
            root = root.resolve()
            rel = p.relative_to(root)
            return str(rel)
        except Exception:
            return p.name

    return str(p)


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


def render_results(console: Console, result, tree=False, root_path=None):
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
            ]
        )
    )
    console.print()

    def _render_unused(title, items, name_key="name"):
        if not items:
            return

        console.rule(f"[bold]{title}")

        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Name", style="bold")
        table.add_column("Location", style="muted", overflow="fold")

        for i, item in enumerate(items, 1):
            nm = item.get(name_key) or item.get("simple_name") or "<?>"
            short = _shorten_path(item.get("file"), root_path)
            loc = f"{short}:{item.get('line', item.get('lineno', '?'))}"
            table.add_row(str(i), nm, loc)

        console.print(table)
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

        for i, quality in enumerate(items, 1):
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
        console.print(
            "[muted]Tip: split helpers, add early returns, flatten branches.[/muted]\n"
        )

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

        for i, s in enumerate(items[:100], 1):
            prov = s.get("provider") or "generic"
            msg = s.get("message") or "Secret detected"
            prev = s.get("preview") or "****"
            short = _shorten_path(s.get("file"), root_path)
            loc = f"{short}:{s.get('line', '?')}"
            table.add_row(str(i), prov, msg, prev, loc)

        console.print(table)
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

    def _render_danger(items):
        if not items:
            return

        console.rule("[bold red]Security Issues")
        table = Table(expand=True)
        table.add_column("#", style="muted", width=3)
        table.add_column("Rule", style="yellow", width=18)
        table.add_column("Severity", width=10)
        table.add_column("Message", overflow="fold")
        table.add_column("Location", style="muted", width=36, overflow="fold")

        for i, d in enumerate(items[:100], 1):
            rule = d.get("rule_id") or "UNKNOWN"
            sev = (d.get("severity") or "UNKNOWN").title()
            msg = d.get("message") or "Issue detected"
            short = _shorten_path(d.get("file"), root_path)
            loc = f"{short}:{d.get('line', '?')}"
            table.add_row(str(i), rule, sev, msg, loc)

        console.print(table)
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
        _render_secrets(result.get("secrets", []) or [])
        _render_danger(result.get("danger", []) or [])
        _render_quality(result.get("quality", []) or [])


def run_init():
    console = Console()
    path = pathlib.Path("pyproject.toml")

    template = """
[tool.skylos]
# 1. Global Defaults (Applies to all languages)
complexity = 10
nesting = 3
max_args = 5
max_lines = 50
ignore = [] 
model = "gpt-4.1"

# 2. Language Overrides (Optional)
[tool.skylos.languages.typescript]
complexity = 15
nesting = 4

[tool.skylos.gate]
fail_on_critical = true
max_security = 0
max_quality = 10
strict = false
"""

    if path.exists():
        content = path.read_text(encoding="utf-8")
        if "[tool.skylos]" in content:
            console.print(
                "[warn]pyproject.toml already contains [tool.skylos] configuration.[/warn]"
            )
            return

        console.print(
            "[brand]Appending Skylos configuration to existing pyproject.toml...[/brand]"
        )
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n" + template)
    else:
        console.print("[brand]Creating new pyproject.toml...[/brand]")
        path.write_text(template.strip(), encoding="utf-8")

    console.print(
        "[good] ** Configuration initialized! You can now edit pyproject.toml[/good]"
    )


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


def main():
    # if len(sys.argv) > 2 and sys.argv[1] == "track":
    #     script = sys.argv[2]
    #     args = sys.argv[3:]
    #     run_and_track(script, args)
    #     sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "init":
        run_init()
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "run":
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
        description="Detect unused functions and unused imports in a Python project"
    )
    parser.add_argument("path", help="Path to the Python project")
    parser.add_argument(
        "--gate",
        action="store_true",
        help="Run as a quality gate (block deployment on failure)",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Run tests with coverage first, then analyze"
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Bypass the quality gate (exit 0 even if issues found)",
    )
    parser.add_argument(
        "--fix", action="store_true", help="Attempt to auto-fix issues using AI"
    )
    parser.add_argument(
        "--table", action="store_true", help="(deprecated) Show findings in table"
    )
    parser.add_argument(
        "--tree", action="store_true", help="Show findings in tree format"
    )
    parser.add_argument(
        "--model", default="gpt-4.1", help="OpenAI Model to use (default: gpt-4.1)"
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
        "--audit", action="store_true", help="Deep scan logic using AI (Interactive)"
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
        
        pytest_result = subprocess.run(
            ["coverage", "run", "-m", "pytest", "-q"],
            cwd=project_root,
            capture_output=True
        )
        
        if pytest_result.returncode != 0:
            if not args.json:
                console.print("[warn]pytest failed, trying unittest...[/warn]")
            subprocess.run(
                ["coverage", "run", "-m", "unittest", "discover"],
                cwd=project_root,
                capture_output=True
            )
        
        if not args.json:
            console.print("[good]Coverage data collected[/good]")

    try:
        with Progress(
            SpinnerColumn(style="brand"),
            TextColumn("[brand]Skylos[/brand] analyzing your code…"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task("analyze", total=None)
            result_json = run_analyze(
                args.path,
                conf=args.confidence,
                enable_secrets=bool(args.secrets),
                enable_danger=bool(args.danger),
                enable_quality=bool(args.quality),
                exclude_folders=list(final_exclude_folders),
            )

        if args.json:
            print(result_json)
            return

        result = json.loads(result_json)

    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        sys.exit(1)

    config = load_config(project_root)

    if args.gate:
        exit_code = run_gate_interaction(result, config, args.command or None)
        sys.exit(exit_code)

    if args.fix:
        console.print("[brand]Auto-Fix Mode Enabled (GPT-5)[/brand]")

        if "claude" in args.model.lower():
            provider = "anthropic"
            key_name = "ANTHROPIC_API_KEY"
        else:
            provider = "openai"
            key_name = "OPENAI_API_KEY"

        api_key = get_key(provider)

        if not api_key:
            console.print(
                f"[warn]No {key_name} found in environment or keychain.[/warn]"
            )
            try:
                api_key = console.input(
                    f"[bold yellow]Please paste your {provider.title()} API Key:[/bold yellow] ",
                    password=True,
                )
                if not api_key:
                    console.print("[bad]No key provided. Exiting.[/bad]")
                    sys.exit(1)

                save_key(provider, api_key)
                console.print(f"[good]Key saved[/good]")

            except KeyboardInterrupt:
                sys.exit(0)

        fixer = Fixer(api_key=api_key, model=args.model)

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

    if args.audit:
        console.print("[brand]Audit Mode Enabled[/brand]")

        if "claude" in args.model.lower():
            provider = "anthropic"
            key_name = "ANTHROPIC_API_KEY"
        else:
            provider = "openai"
            key_name = "OPENAI_API_KEY"

        api_key = get_key(provider)

        if not api_key:
            console.print(
                f"[warn]No {key_name} found in environment or keychain.[/warn]"
            )
            try:
                api_key = console.input(
                    f"[bold yellow]Please paste your {provider.title()} API Key:[/bold yellow] ",
                    password=True,
                )
                if not api_key:
                    console.print("[bad]No key provided. Exiting.[/bad]")
                    sys.exit(1)

                save_key(provider, api_key)
                console.print(f"[good]Key saved[/good]")

            except KeyboardInterrupt:
                sys.exit(0)

        fixer = Fixer(api_key=api_key, model=args.model)
        defs_map = result.get("definitions", {})

        p_arg = pathlib.Path(args.path)
        candidates = []

        if p_arg.is_file():
            candidates.append(p_arg)
        else:
            git_files = get_git_changed_files(p_arg)
            all_files = list(p_arg.glob("**/*.py"))

            valid_files = []
            for f in all_files:
                is_excluded = False
                for ex in final_exclude_folders:
                    if ex in f.parts:
                        is_excluded = True
                        break
                if not is_excluded:
                    valid_files.append(f)

            candidates = git_files + [f for f in valid_files if f not in git_files]

        if not candidates:
            console.print("[bad]No valid Python files found to audit.[/bad]")
            sys.exit(0)

        selected_files = []
        if INTERACTIVE_AVAILABLE and len(candidates) > 1:
            choices = []
            for f in candidates:
                try:
                    size_kb = f.stat().st_size / 1024
                    label = f"{f.name} ({size_kb:.1f} KB)"
                    if f in git_files:
                        label = f"[CHANGED] {label}"
                    choices.append((label, f))
                except OSError:
                    pass

            defaults = [f for f in git_files]

            questions = [
                inquirer.Checkbox(
                    "files",
                    message="Select files to audit (Space to select)",
                    choices=choices,
                    default=defaults,
                )
            ]
            answers = inquirer.prompt(questions)
            if not answers:
                sys.exit(0)
            selected_files = answers["files"]
        else:
            selected_files = candidates

        if not selected_files:
            console.print("[muted]No files selected.[/muted]")
            sys.exit(0)

        _, cost = estimate_cost(selected_files)
        console.print(Rule(style="muted"))
        console.print(f"Files:   [bold]{len(selected_files)}[/bold]")
        console.print(f"Cost:    [bold green]~${cost:.4f}[/bold green]")

        if len(selected_files) > 10:
            console.print(
                "[bold red]WARNING: You are auditing >10 files. This will be slow and costly.[/bold red]"
            )

        if not inquirer.confirm("Proceed?", default=True):
            sys.exit(0)

        for target_file in selected_files:
            try:
                if target_file.stat().st_size > 100 * 1024:
                    console.print(
                        f"[warn]Skipping {target_file.name} (Too large: >100KB). AI works best on smaller modules.[/warn]"
                    )
                    continue

                src = target_file.read_text(encoding="utf-8")

                with console.status(
                    f"[cyan]Auditing {target_file.name}...[/cyan]", spinner="dots"
                ):
                    audit_report = fixer.audit_file(src, defs_map)

                console.print(
                    Panel(
                        audit_report,
                        title=f"Audit: {target_file.name}",
                        border_style="magenta",
                    )
                )
            except Exception as e:
                console.print(f"[bad]Error: {e}[/bad]")

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

    render_results(console, result, tree=args.tree, root_path=project_root)

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

    if not args.interactive and not args.json:
        upload_resp = upload_report(result)

        if not upload_resp.get("success"):
            if upload_resp.get("error") != "No token found":
                console.print(f"[warn]Upload failed: {upload_resp.get('error')}[/warn]")
        else:
            qg = upload_resp.get("quality_gate", {})
            scan_id = upload_resp.get("scan_id")
            passed = qg.get("passed", True)

            if passed:
                console.print(
                    f"[good]✓ Quality Gate Passed.[/good] {qg.get('message', '')}"
                )
            else:
                console.print(Rule(style="bad"))
                console.print(f"[bold red]QUALITY GATE FAILED[/bold red]")
                console.print(f"   {qg.get('message', '')}")

                if args.force:
                    console.print(
                        "\n[bold yellow]WARNING: FORCED BYPASS ENABLED[/bold yellow]"
                    )
                    console.print("[dim]Proceeding despite quality failures...[/dim]")
                else:
                    console.print(
                        f"\n[bold yellow]Action Required:[/bold yellow] Override this scan to proceed."
                    )
                    console.print(
                        f"   Link: [link]http://localhost:3000/dashboard/scans/{scan_id}[/link]"
                    )
                    console.print(Rule(style="bad"))

                    if args.gate or args.command:
                        import time
                        from skylos.api import check_scan_status

                        resolved = False
                        try:
                            with console.status(
                                "[bold yellow]Waiting for approval on Dashboard...[/bold yellow]",
                                spinner="dots",
                            ) as status:
                                while True:
                                    time.sleep(2)

                                    poll_res = check_scan_status(scan_id)
                                    if poll_res and poll_res.get("status") == "PASSED":
                                        resolved = True
                                        reason = (
                                            "Overridden"
                                            if poll_res.get("is_overridden")
                                            else "Fixed"
                                        )
                                        break
                        except KeyboardInterrupt:
                            console.print("\n[bad]Aborted by user.[/bad]")
                            sys.exit(1)

                        if resolved:
                            console.print(
                                f"\n[bold green]Approval Detected![/bold green] (Status: {reason})"
                            )
                        else:
                            sys.exit(1)
                    else:
                        sys.exit(1)

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
