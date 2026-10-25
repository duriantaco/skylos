"""``skylos done``: check that a change is finished and write a receipt."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.text import Text

logger = logging.getLogger(__name__)

EXIT_PASS = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

_STATUS_STYLES = {
    "PASS": "green",
    "FAIL": "bold red",
    "UNFINISHED": "bold yellow",
    "WARN": "yellow",
    "SKIP": "dim",
    "OFF": "dim",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos done",
        description=(
            "Check that a change is finished: Skylos runs the tests itself and "
            "looks for deleted or skipped tests, loosened test settings, edits "
            "to Skylos settings, added secrets and imports that do not exist. "
            "Settings come from [tool.skylos.done] at the base, never from the "
            "change. Exit 0 pass, 1 fail or unfinished, 2 could not run."
        ),
    )
    parser.add_argument(
        "path", nargs="?", default=".", help="Repository to check (default: .)"
    )
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument(
        "--base",
        metavar="REF",
        help=(
            "Compare with the merge base of REF (for a pull request: its target, "
            "e.g. origin/main). Default: HEAD, so only uncommitted changes count."
        ),
    )
    baseline.add_argument(
        "--session",
        metavar="ID",
        help="Recheck the entire working tree against this agent session's captured baseline.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--no-tests",
        action="store_true",
        help=(
            "Do not run the tests (a blocking tests check becomes unfinished; "
            "this cannot produce a passing receipt under the default policy)"
        ),
    )
    parser.add_argument(
        "--agent",
        default="unknown",
        metavar="CLIENT",
        help="Agent that made the change, e.g. claude-code, codex, cursor (default: unknown)",
    )
    parser.add_argument(
        "--map",
        action="store_true",
        help=(
            "Also print the change map (what the change touches, riskiest first) after the "
            "verdict, in text or markdown. It never changes the verdict, receipt or exit code. "
            "For JSON use `skylos done map --format json`."
        ),
    )
    return parser


def build_map_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos done map",
        description=(
            "Show what a change touches: every changed Python or TypeScript/JavaScript function "
            "with its old and new code, calls added and removed, who calls it, removed security "
            "checks, and what to read first. Computed from the code, not by a model. "
            "Exit 0 shown, 2 could not run."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository (default: .)")
    parser.add_argument(
        "--base",
        metavar="REF",
        default="HEAD",
        help="Compare with the merge base of REF, e.g. origin/main (default: HEAD, uncommitted changes only)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text)",
    )
    return parser


def build_receipt_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skylos done receipt",
        description="Print the latest receipt written by skylos done in this repository.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository (default: .)")
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text)",
    )
    return parser


def run_done_command(argv: list[str], *, console: Console | None = None) -> int:
    if argv and argv[0] == "receipt":
        return _run_receipt_command(argv[1:], console=console)
    if argv and argv[0] == "map":
        return _run_map_command(argv[1:], console=console)
    args = build_parser().parse_args(argv)
    out = console or Console(highlight=False)
    err = Console(stderr=True, highlight=False)

    from skylos.done.base import DoneError
    from skylos.done.engine import run
    from skylos.done.receipt import (
        build_receipt,
        render_markdown,
        validate_receipt,
        write_receipt,
    )

    try:
        result = run(
            args.path,
            base_ref=args.base,
            run_tests=not args.no_tests,
            session_id=args.session,
        )
        receipt = build_receipt(
            result, agent_client=args.agent, session_id=args.session
        )
        problems = validate_receipt(receipt)
        if problems:  # a bug in Skylos, never the user's change
            logger.warning(
                "done receipt does not match the upload contract: %s", problems
            )
            _invalidate_latest_receipt(result.comparison.root, err)
            err.print(
                Text(
                    "skylos done: verification is unfinished because the receipt failed validation",
                    style="red",
                )
            )
            return EXIT_ERROR
        written = write_receipt(result.comparison.root, receipt)
        if written is None:
            _invalidate_latest_receipt(result.comparison.root, err)
            err.print(
                Text(
                    "skylos done: verification is unfinished because the receipt could not be saved",
                    style="red",
                )
            )
            return EXIT_ERROR
    except DoneError as exc:
        _invalidate_latest_receipt(args.path, err)
        err.print(Text(f"skylos done: {exc}", style="red"))
        return EXIT_ERROR
    except Exception:
        logger.debug("Done verification or receipt publication failed", exc_info=True)
        _invalidate_latest_receipt(args.path, err)
        err.print(
            Text(
                "skylos done: verification could not complete; no new receipt was verified",
                style="red",
            )
        )
        return EXIT_ERROR

    if args.format == "json":
        print(json.dumps(receipt, indent=2))
    elif args.format == "markdown":
        print(render_markdown(receipt))
    else:
        _print_text(out, receipt)
        for problem in result.config.problems:
            out.print(Text(f"Setting ignored: {problem}", style="yellow"))
        if written is not None:
            out.print(
                Text(
                    f"Receipt: {_display_path(written, result.comparison.root)}",
                    style="dim",
                )
            )
        if args.map:
            _print_change_map(out, args.path, args.base, "text")
    if args.map and args.format == "markdown":
        _print_change_map(out, args.path, args.base, "markdown")

    _write_step_summary(lambda: render_markdown(receipt))
    return EXIT_PASS if receipt["verdict"] == "pass" else EXIT_BLOCKED


def _change_map_text(path: str, base: str | None, fmt: str) -> str:
    from skylos import changemap

    change_map = changemap.build_change_map(path, base or "HEAD")
    if fmt == "markdown":
        return changemap.render_markdown(change_map)
    return changemap.render_text(change_map)


def _print_change_map(out: Console, path: str, base: str | None, fmt: str) -> None:
    try:
        text = _change_map_text(path, base, fmt)
    except Exception as exc:
        logger.debug("change map failed", exc_info=True)
        out.print(Text(f"Change map unavailable: {exc}", style="yellow"))
        return
    if fmt == "markdown":
        print(text)
        return
    out.print()
    out.print(Text(text.rstrip("\n")), soft_wrap=True)


def _run_map_command(argv: list[str], *, console: Console | None) -> int:
    from skylos import changemap

    args = build_map_parser().parse_args(argv)
    out = console or Console(highlight=False)
    err = Console(stderr=True, highlight=False)
    try:
        change_map = changemap.build_change_map(args.path, args.base)
    except ValueError as exc:
        err.print(Text(f"skylos done map: {exc}", style="red"))
        return EXIT_ERROR
    except Exception:
        logger.debug("change map failed", exc_info=True)
        err.print(Text("skylos done map: the change map could not be built", style="red"))
        return EXIT_ERROR
    if args.format == "json":
        print(json.dumps(change_map, indent=2))
    elif args.format == "markdown":
        print(changemap.render_markdown(change_map))
    else:
        out.print(Text(changemap.render_text(change_map).rstrip("\n")), soft_wrap=True)
    return EXIT_PASS


def _invalidate_latest_receipt(path: str | Path, err: Console) -> None:
    """A failed invocation must not leave an earlier success usable as latest."""
    from skylos.core.git_context import GitContext
    from skylos.done.session import invalidate_latest_receipt

    try:
        root = Path(GitContext.from_path(path).root)
        if invalidate_latest_receipt(root):
            return
    except Exception:
        logger.debug("could not invalidate the latest Done receipt", exc_info=True)
    err.print(
        Text(
            "skylos done: could not invalidate the latest receipt; earlier receipts do not verify this attempt",
            style="yellow",
        )
    )


def _run_receipt_command(argv: list[str], *, console: Console | None) -> int:
    args = build_receipt_parser().parse_args(argv)
    out = console or Console(highlight=False)

    from skylos.core.git_context import GitContext
    from skylos.done.receipt import (
        LATEST_NAME,
        RECEIPTS_DIR,
        read_receipt,
        render_markdown,
    )

    root = Path(GitContext.from_path(Path(args.path).resolve()).root)
    receipt = read_receipt(root / RECEIPTS_DIR / LATEST_NAME)
    if receipt is None:
        Console(stderr=True).print(
            "No receipt yet. Run [bold]skylos done[/bold] first."
        )
        return EXIT_ERROR
    if args.format == "json":
        print(json.dumps(receipt, indent=2))
    elif args.format == "markdown":
        print(render_markdown(receipt))
    else:
        _print_text(out, receipt)
    return EXIT_PASS


def _print_text(console: Console, receipt: dict) -> None:
    from skylos.done.receipt import render_text

    for line in render_text(receipt).splitlines():
        word = line.split(" ", 1)[0]
        text = Text(line)
        if word in _STATUS_STYLES:
            text.stylize(_STATUS_STYLES[word], 0, len(word))
        elif line.startswith("Verdict:"):
            text.stylize(
                "bold green" if line.startswith("Verdict: PASS") else "bold red"
            )
        elif line.startswith("Skylos done"):
            text.stylize("bold")
        console.print(text, soft_wrap=True)


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _write_step_summary(build_markdown) -> None:
    """Append the receipt to $GITHUB_STEP_SUMMARY; never affects the exit code."""
    if not os.environ.get("GITHUB_STEP_SUMMARY"):
        return
    from skylos.commands.defend_cmd import (
        _append_github_step_summary,
        _github_step_summary_path,
    )

    path = _github_step_summary_path(os.environ["GITHUB_STEP_SUMMARY"])
    if path is None:
        return
    try:
        markdown = build_markdown()
    except Exception:
        logger.debug("could not render the done summary", exc_info=True)
        return
    _append_github_step_summary(path, markdown)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run_done_command(sys.argv[1:]))
