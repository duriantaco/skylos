"""Console-script entry point for ``skylos``.

Agent hooks (``skylos hook <event>``) run on every edit, read and shell
command, so they must not pay for importing the full CLI (argparse tree,
rich, cloud/credential helpers). This shim dispatches them directly and
hands every other invocation to :func:`skylos.cli.main` unchanged.

Every other run also remembers how it failed, for ``skylos feedback``: an
exit code of 2 or more, or a crash, is written (masked) to
``~/.skylos/last_error.json``, and a crash ends with a one-line stderr hint.
Hooks never record. See ``skylos/core/report_context.py``.
"""

from __future__ import annotations

import os
import sys
from types import TracebackType

CRASH_HINT = (
    "Skylos hit an internal error ({where}). Report it: skylos feedback "
    "(opens a prefilled form to review before sending)"
)


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "hook" and not _is_help(argv):
        from skylos.commands.hook_cmd import run_hook_command

        sys.exit(run_hook_command(argv[1:]))

    try:
        from skylos.cli import main as cli_main

        _run_recording_failures(cli_main, list(sys.argv))
    except KeyboardInterrupt:
        _exit_interrupted()


INTERRUPTED_EXIT_CODE = 130  # 128 + SIGINT, the shell convention


def _exit_interrupted() -> None:
    """Ctrl-C ends the run with one line, not a traceback."""
    try:
        sys.stdout.flush()
    except (OSError, ValueError):
        pass
    try:
        print("\nInterrupted (Ctrl-C).", file=sys.stderr)
    except (OSError, ValueError):
        pass
    raise SystemExit(INTERRUPTED_EXIT_CODE)


def _is_help(argv: list[str]) -> bool:
    # ``skylos hook --help`` keeps the CLI's rich help rendering.
    return len(argv) == 2 and argv[1] in {"-h", "--help"}


def _run_recording_failures(cli_main, argv: list[str]) -> None:
    """Run the CLI; record exit codes >= 2, and hint after a crash.

    The crash hint is printed by an excepthook so it lands after the normal
    traceback, which is unchanged, as is the exit code. Recording never
    raises (see ``record_failure``).
    """

    previous_hook = sys.excepthook

    def report_hint_hook(exc_type, exc_value, traceback) -> None:
        previous_hook(exc_type, exc_value, traceback)
        _after_crash(argv, exc_type, traceback)

    sys.excepthook = report_hint_hook
    try:
        cli_main()
    except SystemExit as exc:
        # SystemExit never reaches the excepthook; put the old one back.
        sys.excepthook = previous_hook
        code = exc.code
        if isinstance(code, int) and not isinstance(code, bool) and code >= 2:
            _record(argv, code)
        raise
    # A crash (or Ctrl+C) propagates past this point with the hook still in
    # place, so the interpreter's top-level report prints the traceback and
    # then the hint. A normal return puts the old hook back.
    sys.excepthook = previous_hook


def _record(argv: list[str], exit_code: int, **details) -> None:
    try:
        from skylos.core.report_context import record_failure
    except ImportError:
        return
    # record_failure never raises: recording can't change a run's outcome.
    record_failure(argv, exit_code, **details)


def _after_crash(
    argv: list[str], exc_type: type | None, traceback: TracebackType | None
) -> None:
    try:
        _print_crash_hint(argv, exc_type, traceback)
    except (ImportError, OSError, ValueError, TypeError, AttributeError):
        # Best effort: the traceback above is already printed.
        return


def _describe_frame(filename: str, lineno: int, function: str) -> str | None:
    """``skylos/analyzer.py:1040 in analyze`` for a file inside the installed
    ``skylos`` package, else None. Never an absolute path."""

    import skylos

    package_dir = os.path.dirname(os.path.realpath(skylos.__file__))
    real = os.path.realpath(filename)
    try:
        if os.path.commonpath([package_dir, real]) != package_dir:
            return None
    except ValueError:  # different drives on Windows
        return None
    relative = os.path.relpath(real, os.path.dirname(package_dir))
    return f"{relative.replace(os.sep, '/')}:{lineno} in {function}"[:200]


def _deepest_skylos_frame(traceback: TracebackType | None) -> str | None:
    found = None
    while traceback is not None:
        code = traceback.tb_frame.f_code
        frame = _describe_frame(code.co_filename, traceback.tb_lineno, code.co_name)
        found = frame or found
        traceback = traceback.tb_next
    return found


def _print_crash_hint(
    argv: list[str], exc_type: type | None, traceback: TracebackType | None
) -> None:
    if exc_type is None or issubclass(exc_type, (KeyboardInterrupt, BrokenPipeError)):
        return
    error_type = str(getattr(exc_type, "__name__", "Exception"))[:80]
    frame = _deepest_skylos_frame(traceback)
    # The exception message is never recorded: it can hold user paths.
    _record(argv, 1, error_type=error_type, skylos_frame=frame)
    if len(argv) > 1 and argv[1] == "feedback":
        return
    where = error_type
    if frame:
        where += " in " + frame.split(" in ", 1)[0]
    print(CRASH_HINT.format(where=where), file=sys.stderr)


if __name__ == "__main__":  # python -m skylos.entry (used by installed hooks)
    main()
