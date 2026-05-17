from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence


def build_main_parser(*, version: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find dead code, secrets, and risky flows in Python, JS/TS, Go, Java, PHP, and Rust",
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
        help="Upload this code scan to Skylos Cloud",
    )
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="Skip automatic code-scan upload even if connected to Skylos Cloud",
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
        "--cache",
        action="store_true",
        help="Cache successful --trace pytest call-tracing runs.",
    )
    parser.add_argument(
        "--refresh-cache",
        action="store_true",
        help="Rerun --trace and overwrite its cache entry.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable trace cache even when --cache is set.",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help=(
            "Use coverage data during analysis. Does not execute project tests unless "
            "--allow-coverage-execution is also set."
        ),
    )
    parser.add_argument(
        "--allow-coverage-execution",
        action="store_true",
        help=(
            "Allow --coverage to execute pytest/unittest in the target project. "
            "Only use for trusted repositories."
        ),
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
        help="Fail if ANY issue is found; with --gate, use strict gate rules",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch interactive TUI dashboard",
    )
    parser.add_argument("--tree", action="store_true", help="Show findings in tree format")
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
        version=f"skylos {version}",
        help="Show version and exit",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Output LLM-optimized report (structured findings with code context for AI agents to fix)",
    )
    parser.add_argument(
        "--format",
        choices=("rich", "json", "llm", "github", "concise"),
        default="rich",
        help="Output format. Use 'concise' for IDE-friendly file:line findings only.",
    )
    parser.set_defaults(concise=False)
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
    parser.add_argument("--dry-run", action="store_true", help="Show what would be removed")

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
    parser.add_argument("--secrets", action="store_true", help="Scan for API keys. Off by default.")
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
        help="(Deprecated - provenance is now automatic in git repos.) "
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
    return parser


def apply_main_output_format(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> argparse.Namespace:
    output_format = getattr(args, "format", "rich")
    flag_by_format = {
        "json": "json",
        "llm": "llm",
        "github": "github",
    }
    selected_flags = [
        name for name in ("json", "llm", "github") if bool(getattr(args, name, False))
    ]

    if output_format != "rich":
        matching_flag = flag_by_format.get(output_format)
        conflicts = [name for name in selected_flags if name != matching_flag]
        if conflicts:
            parser.error(
                f"--format {output_format} cannot be combined with "
                + ", ".join(f"--{name}" for name in conflicts)
            )

        if output_format in flag_by_format:
            setattr(args, flag_by_format[output_format], True)
        elif output_format == "concise":
            args.concise = True

    return args


def parse_main_cli_args(
    parser: argparse.ArgumentParser,
    argv: Sequence[str],
    *,
    addopts_loader: Callable[[], list[str]],
) -> argparse.Namespace:
    user_argv = list(argv)
    addopts = list(addopts_loader() or [])
    if "--" in addopts:
        addopts = addopts[: addopts.index("--")]

    if "--" in user_argv:
        split = user_argv.index("--")
        main_argv = addopts + user_argv[:split]
        cmd_argv = user_argv[split + 1 :]
    else:
        main_argv = addopts + user_argv
        cmd_argv = []

    if cmd_argv:
        args, extra = parser.parse_known_args(main_argv)
        args.command = cmd_argv + (extra or [])
        return apply_main_output_format(parser, args)

    args = parser.parse_args(main_argv)
    args.command = []
    return apply_main_output_format(parser, args)
