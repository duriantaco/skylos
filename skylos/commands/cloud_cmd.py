from __future__ import annotations

import os
import sys
from types import ModuleType
from typing import Sequence

CLOUD_HELP = """Usage: skylos cloud [PATH] [scan flags]

Scan PATH (default .) with every check, show the findings, upload them to
Skylos Cloud, then show the quality gate for this branch and one link to it.

  Checks: every check (-a), unless you name some, e.g. --danger --secrets.
  Sends:  findings with file paths and code snippets of up to 7 lines (none
          for secrets), the branch, the commit, the git author email of each
          flagged line, and a map of your functions and classes (names,
          files, lines, sizes, which calls which). Not your repository.
  Login:  opens your browser the first time to pick this repo's project.
  Gate:   the Skylos Cloud quality gate for this branch. Exit 0 even when it
          fails; add --gate to exit 1 when it fails (use this in CI). Your
          local [tool.skylos.gate] limits are only used by skylos . --gate.

Examples:
  skylos cloud                 scan this repo and upload
  skylos cloud --gate          same, and exit 1 when the Cloud gate fails
  skylos cloud src --exclude build

Local scans, no findings sent:  skylos .   or   skylos . -a
                                (-a looks up package names online: OSV.dev for
                                known CVEs, PyPI/npm for packages that don't exist)
Other Cloud commands:           skylos login (switch project), skylos whoami,
                                skylos upload --retry (resend unfinished uploads)
"""

NOT_CONNECTED = (
    "Not connected to Skylos Cloud. Run skylos login in a terminal, "
    "or set SKYLOS_TOKEN to a project token (create one in your project's "
    "Settings on skylos.dev)."
)
OPENING_LOGIN = (
    "Not connected to Skylos Cloud yet. Log in and pick this repo's project "
    "in the browser; nothing is scanned or uploaded until you do."
)
LOGIN_CANCELLED = "Nothing was scanned or uploaded."
NO_UPLOAD_REFUSAL = "skylos cloud always uploads; run skylos . for a local-only scan."


CHECK_FLAGS = frozenset(
    {
        "-a",
        "--all",
        "--danger",
        "--security",
        "--secrets",
        "--quality",
        "--ai-defects",
        "--sca",
        "--scan-publisher-changes",
    }
)


def cloud_scan_argv(argv: Sequence[str]) -> list[str]:
    scan_argv = [arg for arg in argv if arg != "--gate"]
    if not scan_argv or scan_argv[0].startswith("-"):
        scan_argv.insert(0, ".")
    if not CHECK_FLAGS.intersection(scan_argv):
        scan_argv.append("-a")
    if "--upload" not in scan_argv:
        scan_argv.append("--upload")
    return scan_argv


def _connected(cli_module: ModuleType, project_root) -> bool:
    from skylos.api import get_project_token

    if os.getenv("SKYLOS_TOKEN"):
        return True
    if cli_module._detect_link_file(project_root) is not None:
        return True
    return bool(get_project_token())


def _ensure_connected(cli_module: ModuleType, project_root) -> bool:
    if _connected(cli_module, project_root):
        return True
    if cli_module._is_ci():
        return True
    console = cli_module.Console(theme=cli_module._skylos_console_theme())
    if not cli_module._is_tty():
        console.print(f"[warn]{NOT_CONNECTED}[/warn]", soft_wrap=True)
        return False
    console.print(f"\n[bold yellow]{OPENING_LOGIN}[/bold yellow]", soft_wrap=True)
    from skylos.cloud.login import run_login

    if run_login(console=console) is None:
        console.print(f"[dim]{LOGIN_CANCELLED}[/dim]")
        return False
    return True


def run_cloud_command(argv: Sequence[str], *, cli_module: ModuleType) -> int:
    argv = list(argv)
    if argv[:1] in (["-h"], ["--help"]):
        print(CLOUD_HELP, end="")
        return 0
    if "--no-upload" in argv:
        print(f"skylos: error: {NO_UPLOAD_REFUSAL}", file=sys.stderr)
        return 2
    scan_argv = cloud_scan_argv(argv)
    project_root = cli_module._resolve_main_project_root([scan_argv[0]])
    if not _ensure_connected(cli_module, project_root):
        return 1
    from skylos.commands.scan_cmd import run_scan_command

    run_scan_command(
        scan_argv, cli_module=cli_module, cloud=True, cloud_gate="--gate" in argv
    )
    return 0
