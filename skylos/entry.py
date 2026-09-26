"""Console-script entry point for ``skylos``.

Agent hooks (``skylos hook <event>``) run on every edit, read and shell
command, so they must not pay for importing the full CLI (argparse tree,
rich, cloud/credential helpers). This shim dispatches them directly and
hands every other invocation to :func:`skylos.cli.main` unchanged.
"""

from __future__ import annotations

import sys


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "hook" and not _is_help(argv):
        from skylos.commands.hook_cmd import run_hook_command

        sys.exit(run_hook_command(argv[1:]))

    from skylos.cli import main as cli_main

    cli_main()


def _is_help(argv: list[str]) -> bool:
    # ``skylos hook --help`` keeps the CLI's rich help rendering.
    return len(argv) == 2 and argv[1] in {"-h", "--help"}


if __name__ == "__main__":  # python -m skylos.entry (used by installed hooks)
    main()
