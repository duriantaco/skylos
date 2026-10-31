from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Sequence

REPORT_HELP = """Usage: skylos report [PATH | REPORT.json] [--format html|md] [-o FILE] [scan flags]

Write a one-page report someone outside the code can read: the verdict, the
five risks to fix first with their fixes, issue counts by category, what was
suppressed or dismissed, what the scan could not check, and the date, commit
and Skylos version.

  PATH         scan PATH (default .) with every check (-a) on this machine;
               nothing is uploaded
  REPORT.json  build the page from a saved `skylos . -a --format json` report
  --format     html (default; one self-contained file that prints well) or md
  -o FILE      where to write it (default skylos-report.html or
               skylos-report.md); - writes to standard output

Examples:
  skylos report                       scan this repo, write skylos-report.html
  skylos report . --format md -o -    Markdown to standard output
  skylos report scan.json             reuse a saved JSON scan
"""

_FORMATS = {"html": "html", "md": "md", "markdown": "md"}
_DEFAULT_OUTPUT = {"html": "skylos-report.html", "md": "skylos-report.md"}
_CHECK_FLAGS = frozenset(
    {
        "-a",
        "--all",
        "--danger",
        "--security",
        "--secrets",
        "--quality",
        "--ai-defects",
        "--sca",
    }
)
_REFUSED = frozenset({"--json", "--llm", "--github", "--tui", "-i", "--interactive"})


class ReportArgsError(ValueError):
    pass


def parse_report_argv(argv: Sequence[str]) -> tuple[str, str, list[str]]:
    """Return (format, output, remaining scan argv)."""
    report_format = "html"
    output = None
    rest = []
    items = list(argv)
    index = 0
    while index < len(items):
        item = items[index]
        value = None
        if item in {"--format", "-o", "--output"}:
            if index + 1 >= len(items):
                raise ReportArgsError(f"{item} needs a value")
            value = items[index + 1]
            index += 2
        elif item.startswith("--format="):
            value = item.split("=", 1)[1]
            item = "--format"
            index += 1
        elif item.startswith("--output="):
            value = item.split("=", 1)[1]
            item = "--output"
            index += 1
        else:
            if item in _REFUSED:
                raise ReportArgsError(f"{item} cannot be combined with skylos report")
            rest.append(item)
            index += 1
            continue
        if item == "--format":
            if value not in _FORMATS:
                raise ReportArgsError("--format must be html or md")
            report_format = _FORMATS[value]
        else:
            output = value
    if output is None:
        output = _DEFAULT_OUTPUT[report_format]
    return report_format, output, rest


def report_scan_argv(report_format: str, output: str, rest: Sequence[str]) -> list[str]:
    scan_argv = list(rest)
    if not scan_argv or scan_argv[0].startswith("-"):
        scan_argv.insert(0, ".")
    if not _CHECK_FLAGS.intersection(scan_argv):
        scan_argv.append("-a")
    scan_argv.extend(["--format", f"report-{report_format}"])
    if output != "-":
        scan_argv.extend(["--output", output])
    return scan_argv


def _saved_report(path_text: str):
    path = Path(path_text)
    if path.suffix.lower() != ".json" or not path.is_file():
        return None
    return path


def _render_saved(path: Path, report_format: str, output: str, cli_module) -> int:
    from skylos.config import load_config
    from skylos.reporting.report_page import render_report
    from skylos.reporting.top_risks import add_report_guidance

    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"skylos report: could not read {path}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(result, dict) or "analysis_summary" not in result:
        print(
            f"skylos report: {path} is not a Skylos JSON scan "
            "(create one with: skylos . -a --format json -o scan.json)",
            file=sys.stderr,
        )
        return 2
    scope = (result.get("analysis_summary") or {}).get("comparison_scope") or {}
    root = scope.get("repository_root") or scope.get("scan_path")
    project_root = Path.cwd()
    if isinstance(root, str) and Path(root).is_dir():
        project_root = Path(root)
    config = load_config(project_root)
    add_report_guidance(result, project_root=project_root, config=config)
    text = render_report(
        result, report_format, project_root=project_root, config=config
    )
    verdict = (result.get("issue_summary") or {}).get("verdict") or {}
    if output == "-":
        sys.stdout.write(text)
        return 0
    from skylos.core.safe_cache_io import write_text_no_symlink

    if not write_text_no_symlink(output, text, encoding="utf-8"):
        print(f"skylos report: could not safely write {output}", file=sys.stderr)
        return 2
    print(f"Report written to {output}: {verdict.get('text', '')}", file=sys.stderr)
    return 0


def run_report_command(argv: Sequence[str], *, cli_module: ModuleType) -> int:
    argv = list(argv)
    if argv[:1] in (["-h"], ["--help"]):
        print(REPORT_HELP, end="")
        return 0
    try:
        report_format, output, rest = parse_report_argv(argv)
    except ReportArgsError as exc:
        print(f"skylos report: error: {exc}", file=sys.stderr)
        print("See: skylos report --help", file=sys.stderr)
        return 2
    if rest and len(rest) == 1:
        saved = _saved_report(rest[0])
        if saved is not None:
            return _render_saved(saved, report_format, output, cli_module)
    from skylos.commands.scan_cmd import run_scan_command

    run_scan_command(
        report_scan_argv(report_format, output, rest), cli_module=cli_module
    )
    return 0
