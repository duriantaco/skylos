from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Sequence

from rich.console import Console

from skylos.commands.project_context import command_project_context

CLOUD_HELP = """Usage: skylos cloud [PATH] [scan flags]

Scan PATH (default .) with every check, show the findings, upload them to
Skylos Cloud, then show the quality gate for this branch and one link to it.

  Checks: every check (-a), unless you name some, e.g. --danger --secrets.
  Sends:  findings with file paths and code snippets of up to 7 lines (none
          for secrets), the branch, the commit, the git author email of each
          flagged line, and a map of your functions and classes (names,
          files, lines, sizes, which calls which). Not your repository.
  Login:  opens your browser the first time to pick this repo's project;
          your sign-in is saved. No token to find or copy for local scans.
  Trust:  browser sign-in saves developer reports. Verified quality gates and
          checks require CI authentication (follow setup on the saved scan).
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
    "Skylos Cloud sign-in required. Run skylos cloud PATH in a terminal "
    "without output-format flags to sign in in your browser, then retry. "
    "For unattended CI, use GitHub Actions/GitLab OIDC or a SKYLOS_TOKEN secret."
)
OPENING_LOGIN = (
    "Sign in to Skylos Cloud in your browser and choose this repo's project. "
    "The scan and upload will continue here; no token to copy."
)
LOGIN_CANCELLED = (
    "Sign-in was not completed. Nothing was scanned or uploaded. "
    "Run skylos cloud again to retry."
)
NO_UPLOAD_REFUSAL = "skylos cloud always uploads; run skylos . for a local-only scan."
DONE_RUNNING = "Running skylos done first; its receipt goes with the upload…"
DONE_NOT_SENT_DIRTY = (
    "Done receipt not sent: commit your changes first "
    "(the receipt must name a clean commit)"
)
DONE_NOT_SENT = "Done receipt not sent: {reason}"
DONE_COULD_NOT_RUN = "skylos done could not run (see above)"
NO_DONE_TABLE = "no Done table in this repo (skylos setup adds one)"
DONE_TABLE_UNCOMMITTED = "the Done table in {name} is not committed yet"


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
    from skylos import api

    if os.getenv("SKYLOS_TOKEN", "").strip():
        return True
    if cli_module._is_ci():
        token = api.get_project_token()
        return isinstance(token, str) and bool(token.strip())
    repo_root = api._get_repo_root_for_link()
    link = api._read_json(repo_root / api.LINK_FILE) or {}
    if not isinstance(link, dict):
        return False
    project_id = api._linked_project_id_for_current_path(link, repo_root)
    if not project_id:
        return False
    credentials = api._read_json(api.GLOBAL_CREDS_FILE) or {}
    if not isinstance(credentials, dict):
        return False
    tokens = credentials.get("tokens")
    saved = tokens.get(project_id) if isinstance(tokens, dict) else None
    token = saved.get("token") if isinstance(saved, dict) else None
    if not token and credentials.get("project_id") == project_id:
        token = credentials.get("token")
    return isinstance(token, str) and bool(token.strip())


def _ensure_connected(
    cli_module: ModuleType, project_root, *, machine_output: bool = False
) -> bool:
    if _connected(cli_module, project_root):
        return True
    if cli_module._is_ci():
        return True
    interactive = not machine_output and cli_module._is_tty()
    console = cli_module.Console(
        theme=cli_module._skylos_console_theme(), stderr=not interactive
    )
    if not interactive:
        console.print(f"[warn]{NOT_CONNECTED}[/warn]", soft_wrap=True)
        return False
    console.print(f"\n[bold yellow]{OPENING_LOGIN}[/bold yellow]", soft_wrap=True)
    from skylos.cloud.login import run_login

    if (
        run_login(
            console=console, allow_manual=False, continue_scan=True, keep_existing=False
        )
        is None
    ):
        console.print(f"[dim]{LOGIN_CANCELLED}[/dim]", soft_wrap=True)
        return False
    return True


def _machine_output(argv: Sequence[str]) -> bool:
    if {"--json", "--llm", "--github", "--concise"}.intersection(argv):
        return True
    output_format = "rich"
    for index, arg in enumerate(argv):
        if arg.startswith("--format="):
            output_format = arg.partition("=")[2]
        elif arg == "--format" and index + 1 < len(argv):
            output_format = argv[index + 1]
    return output_format in {
        "json",
        "json-ci",
        "report-md",
        "report-html",
        "llm",
        "github",
        "gitlab",
        "concise",
    }


def _caller_file_args(argv: Sequence[str], caller_root: Path) -> list[str]:
    """Keep explicit file flags relative to the caller when entering the target."""
    file_flags = {
        "--output",
        "-o",
        "--config-file",
        "--done-receipt",
        "--profile-output",
    }

    def absolute(value: str) -> str:
        # Preserve symlinks for each file reader/writer's existing safety checks.
        return value if value == "-" else str(caller_root / Path(value).expanduser())

    prepared = list(argv)
    index = 0
    while index < len(prepared) and not prepared[index].startswith("-"):
        prepared[index] = str((caller_root / prepared[index]).resolve())
        index += 1
    while index < len(prepared):
        arg = prepared[index]
        if arg == "--":
            break
        flag, equals, value = arg.partition("=")
        if flag in file_flags or flag == "--sarif":
            if equals:
                prepared[index] = f"{flag}={absolute(value)}"
            elif index + 1 < len(prepared) and (
                prepared[index + 1] == "-" or not prepared[index + 1].startswith("-")
            ):
                prepared[index + 1] = absolute(prepared[index + 1])
                index += 1
            elif flag == "--sarif":
                prepared[index] = f"--sarif={absolute('skylos.sarif.json')}"
        elif arg.startswith("-o") and len(arg) > 2:
            prepared[index] = f"-o{absolute(arg[2:])}"
        index += 1
    return prepared


def _receipt_flag_given(argv: Sequence[str]) -> bool:
    return any(
        arg == "--done-receipt" or arg.startswith("--done-receipt=") for arg in argv
    )


def _done_base(root: Path) -> str | None:
    from skylos.commands.setup_cmd import current_branch, default_base

    base = default_base(root)
    if not base or base == current_branch(root):
        return None
    return base


def _run_done(root: Path, console: Console) -> int:
    from skylos.commands.done_cmd import run_done_command

    argv = [str(root)]
    base = _done_base(root)
    if base:
        argv += ["--base", base]
    console.print(f"[dim]{DONE_RUNNING}[/dim]", soft_wrap=True)
    return run_done_command(argv, console=Console(file=io.StringIO()))


def _working_tree_table_file(root: Path) -> str | None:
    from skylos.done.config import parse_done_config, working_tree_config_file

    path = working_tree_config_file(root)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if parse_done_config(text).configured:
        return path.name
    return None


def done_receipt_argv(project_root, console: Console) -> tuple[list[str], str | None]:
    """Scan flags carrying this commit's Done receipt, and the note for the Sent line."""
    from skylos.commands.done_cmd import EXIT_ERROR
    from skylos.done.base import DoneError, open_comparison
    from skylos.done.config import base_config_text, parse_done_config
    from skylos.done.receipt import (
        LATEST_NAME,
        RECEIPTS_DIR,
        _verdict_line,
        load_receipt_for_upload,
    )

    try:
        comparison = open_comparison(project_root)
    except DoneError:
        return [], NO_DONE_TABLE
    committed = parse_done_config(base_config_text(comparison, sha=comparison.head_sha))
    if not committed.configured:
        pending = _working_tree_table_file(comparison.root)
        if pending:
            return [], DONE_TABLE_UNCOMMITTED.format(name=pending)
        return [], NO_DONE_TABLE
    receipt_path = comparison.root / RECEIPTS_DIR / LATEST_NAME
    flags = ["--done-receipt", str(receipt_path)]
    if receipt_path.is_file():
        receipt, _error = load_receipt_for_upload(receipt_path, comparison.root)
        if receipt is not None:
            return flags, None
    if comparison.head_dirty:
        console.print(f"[warn]{DONE_NOT_SENT_DIRTY}[/warn]", soft_wrap=True)
        return [], None
    if _run_done(comparison.root, console) == EXIT_ERROR:
        console.print(
            f"[warn]{DONE_NOT_SENT.format(reason=DONE_COULD_NOT_RUN)}[/warn]",
            soft_wrap=True,
        )
        return [], None
    receipt, error = load_receipt_for_upload(receipt_path, comparison.root)
    if receipt is None:
        console.print(
            f"[warn]{DONE_NOT_SENT.format(reason=error)}[/warn]", soft_wrap=True
        )
        return [], None
    console.print(_verdict_line(receipt), soft_wrap=True)
    return flags, None


def run_cloud_command(argv: Sequence[str], *, cli_module: ModuleType) -> int:
    argv = list(argv)
    if argv[:1] in (["-h"], ["--help"]):
        print(CLOUD_HELP, end="")
        return 0
    if "--no-upload" in argv:
        print(f"skylos: error: {NO_UPLOAD_REFUSAL}", file=sys.stderr)
        return 2
    scan_argv = _caller_file_args(cloud_scan_argv(argv), Path.cwd())
    paths = []
    for arg in scan_argv:
        if arg.startswith("-"):
            break
        paths.append(arg)
    project_root = cli_module._resolve_main_project_root(paths)
    if not project_root.is_dir():
        print(
            f"skylos: error: scan path does not exist: {scan_argv[0]}",
            file=sys.stderr,
        )
        return 2
    with command_project_context(project_root):
        return _run_connected_cloud_command(argv, scan_argv, project_root, cli_module)


def _run_connected_cloud_command(argv, scan_argv, project_root, cli_module) -> int:
    machine_output = _machine_output([*cli_module._load_addopts(), *scan_argv])
    if not _ensure_connected(cli_module, project_root, machine_output=machine_output):
        return 1
    from skylos.commands.scan_cmd import run_scan_command

    done_note = None
    if not _receipt_flag_given(scan_argv) and not cli_module._is_ci():
        console = cli_module.Console(
            theme=cli_module._skylos_console_theme(), stderr=machine_output
        )
        done_flags, done_note = done_receipt_argv(project_root, console)
        scan_argv = scan_argv + done_flags
    run_scan_command(
        scan_argv,
        cli_module=cli_module,
        cloud=True,
        cloud_gate="--gate" in argv,
        cloud_done_note=done_note,
    )
    return 0
