"""``skylos feedback``: open a prefilled form to report a problem.

The CLI makes no network request. It prints what it will attach, builds a URL
with the Skylos version, OS, Python version and the last failed command
(paths and secrets masked), and opens it in the browser. Loading that page gives
skylos.dev those URL fields; the user's message is sent only when they press
Send there.
``--github`` opens the public GitHub issue form instead.

Output is plain ``print``: Rich would wrap the long URL across lines.
"""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from collections.abc import Callable, Mapping, Sequence
from typing import Any, TextIO

from skylos.core.report_context import (
    DISABLE_ENV,
    KINDS,
    build_feedback_url,
    build_github_issue_url,
    describe_age,
    environment_summary,
    is_ci,
    load_last_failure,
    recording_disabled,
)

NOT_ATTACHED = (
    "Not attached: your code, file paths, repository names, environment variables."
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos feedback",
        description=(
            "Open a prefilled form to report a problem or send feedback. "
            "The page address carries the Skylos version, OS, Python version and "
            "the last failed command (masked); your message is sent only when you "
            "press Send."
        ),
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help="Open the public GitHub issue form instead of the private one.",
    )
    parser.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="Print the URL only; don't open a browser.",
    )
    parser.add_argument(
        "--type",
        dest="kind",
        choices=KINDS,
        default="bug",
        help="What you're reporting (default: bug).",
    )
    return parser


def _last_error_line(failure: Mapping[str, Any] | None, *, disabled: bool) -> str:
    if disabled:
        return f"recording off ({DISABLE_ENV}=0)"
    if not failure:
        return "none recorded"
    line = (
        f"{failure['command']}  ->  exit {failure['exit_code']}, "
        f"{describe_age(int(failure.get('age_seconds') or 0))}"
    )
    if failure.get("error_type"):
        line += f" ({failure['error_type']})"
    return line


def _is_interactive(out: TextIO, interactive: bool | None) -> bool:
    if interactive is not None:
        return interactive
    try:
        return bool(out.isatty())
    except (AttributeError, ValueError):
        return False


def _print_summary(
    out: TextIO,
    *,
    github: bool,
    summary: Mapping[str, str],
    last_error: str,
    url: str,
) -> None:
    if github:
        opening = (
            "Opening a public GitHub issue form. Anyone can read GitHub issues, "
            "so leave out company code and repository names."
        )
        alternative = "Prefer a private report? Run: skylos feedback"
    else:
        opening = (
            "Opening a private feedback form on skylos.dev. "
            "Loading it shares the details below; your message is sent only "
            "when you press Send."
        )
        alternative = "Prefer a public GitHub issue? Run: skylos feedback --github"
    lines = [
        "Skylos feedback",
        "",
        opening,
        "",
        "Attached (you can remove any of these on the form):",
        f"  Skylos      {summary['version']}",
        f"  OS          {summary['os']}",
        f"  Python      {summary['python']}",
        f"  Last error  {last_error}",
        "",
        NOT_ATTACHED,
        "",
        "If the browser doesn't open, visit:",
        f"  {url}",
        "",
        alternative,
    ]
    print("\n".join(lines), file=out)


def _open_browser(open_url: Callable[[str], bool], url: str) -> bool:
    try:
        return bool(open_url(url))
    except Exception:  # noqa: BLE001 - any browser failure falls back to the printed URL
        return False


def run_feedback_command(
    argv: Sequence[str],
    *,
    opener: Callable[[str], bool] | None = None,
    stdout: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    interactive: bool | None = None,
) -> int:
    args = _parser().parse_args(list(argv))
    out = stdout or sys.stdout
    env_vars = os.environ if environ is None else environ

    summary = environment_summary()
    disabled = recording_disabled(env_vars)
    failure = None if disabled else load_last_failure()
    builder = build_github_issue_url if args.github else build_feedback_url
    url = builder(summary, failure, kind=args.kind)

    if args.print_only or is_ci(env_vars) or not _is_interactive(out, interactive):
        print(url, file=out)
        return 0

    _print_summary(
        out,
        github=args.github,
        summary=summary,
        last_error=_last_error_line(failure, disabled=disabled),
        url=url,
    )
    if not _open_browser(opener or webbrowser.open, url):
        print("Couldn't open a browser. Open the URL above.", file=out)
    return 0
