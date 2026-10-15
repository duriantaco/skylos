"""``skylos doctor``: are the agent hooks installed, and do they still answer?

For Claude Code, Codex and Cursor, at project scope (the Git root of the
current directory) and user scope (``$HOME``), the check reads the hook config
the installer writes and reports:

* whether Skylos hooks are installed there, how many, and which are missing;
* whether the Skylos each hook command calls still exists. The installer
  wraps every command with a fallback (``|| exit 0``), so a deleted venv makes
  every hook a silent no-op that looks installed;
* a self-test of the pre-bash hook: it is sent a ``ls`` payload (expect allow)
  and a ``cat .env`` payload against a throwaway ``.env`` holding a generated
  token (expect deny). The payload commands are never run, only described to
  the hook, in a temporary directory, and the configs are only read.

The self-test runs the hook executable directly (no shell) and only when the
config holds exactly the command the installer writes. A project config is
repository content, so an executable that is a tracked file of the repository
is not run either.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import string
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from skylos.commands.install_hooks_cmd import (
    CLAUDE_HOOKS,
    CODEX_HOOKS,
    CURSOR_HOOKS,
    _is_ours,
    _load_config,
    _project_root,
    config_path_for,
    hook_command,
)

CLIENTS = (
    ("claude", "Claude Code", CLAUDE_HOOKS),
    ("codex", "Codex", CODEX_HOOKS),
    ("cursor", "Cursor", CURSOR_HOOKS),
)
INSTALL_FLAGS = {"claude": "", "codex": " --codex", "cursor": " --cursor"}
SELF_TEST_TIMEOUT_SECONDS = 10
_HOOK_NAME_RE = re.compile(r"\bhook\s+([a-z-]+)\b")
_SKYLOS_EXECUTABLES = {"skylos", "skylos.exe"}
_DISABLE_ENV = "SKYLOS_HOOKS_DISABLE"

Runner = Callable[..., subprocess.CompletedProcess]


def install_command(agent: str, scope: str) -> str:
    user = " --user" if scope == "user" else ""
    return f"skylos agent install-hooks{INSTALL_FLAGS[agent]}{user}"


def _commands(config: dict[str, Any], agent: str) -> list[str]:
    """Every Skylos hook command in a loaded config, in file order."""
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        return []
    found = []
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            handlers = (
                [entry]
                if agent == "cursor"
                else entry.get("hooks", [])
                if isinstance(entry, dict)
                else []
            )
            for handler in handlers if isinstance(handlers, list) else []:
                if _is_ours(handler):
                    found.append(handler["command"])
    return found


def command_prefix(command: str, agent: str) -> list[str] | None:
    """The argv prefix of a hook command exactly as the installer writes it,
    or None for any other command (hand-edited, extra shell, other client)."""
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        return None
    if "hook" not in tokens:
        return None
    index = tokens.index("hook")
    prefix = tokens[:index]
    if len(tokens) <= index + 1 or not prefix:
        return None
    name = tokens[index + 1]
    try:
        if hook_command(prefix, name, agent) != command.strip():
            return None
    except (TypeError, ValueError):  # not a command the installer writes
        return None
    if len(prefix) == 1 and Path(prefix[0]).name.lower() in _SKYLOS_EXECUTABLES:
        return prefix
    if len(prefix) == 3 and prefix[1:] == ["-m", "skylos.entry"]:
        return prefix
    return None


def resolve_executable(executable: str) -> str | None:
    """Absolute path of an existing executable file, or None."""
    if os.sep in executable or (os.altsep and os.altsep in executable):
        path = Path(executable).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        return None
    return shutil.which(executable)


def _tracked_in(path: str, project: Path) -> bool:
    """Whether ``path`` (after symlinks) is a file Git tracks in ``project``."""
    try:
        real = Path(path).resolve()
        relative = real.relative_to(project.resolve())
    except (OSError, ValueError):
        return False
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", relative.as_posix()],
            cwd=str(project),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return True  # cannot tell: treat as repository content
    return proc.returncode == 0


def _canary_token() -> str:
    # Generated per run: no secret-shaped literal lives in Skylos's source.
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


def _payload(agent: str, command: str, cwd: str) -> str:
    if agent == "cursor":
        data = {
            "hook_event_name": "beforeShellExecution",
            "conversation_id": "skylos-doctor",
            "generation_id": "skylos-doctor",
            "command": command,
            "cwd": cwd,
            "workspace_roots": [cwd],
        }
    else:
        data = {
            "session_id": "skylos-doctor",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        if agent == "codex":
            data["turn_id"] = "skylos-doctor"
    return json.dumps(data)


def _decision(agent: str, stdout: str) -> str:
    """allow, deny or unknown, read the way the client reads the output."""
    lines = [line for line in (stdout or "").splitlines() if line.strip()]
    if not lines:
        # Claude Code and Codex: no output means the normal permission flow.
        # Cursor treats empty output from a permission hook as deny.
        return "deny" if agent == "cursor" else "allow"
    try:
        data = json.loads(lines[-1])
    except ValueError:
        return "unknown"
    if not isinstance(data, dict):
        return "unknown"
    if agent == "cursor":
        permission = data.get("permission")
        return permission if permission in ("allow", "deny", "ask") else "unknown"
    specific = data.get("hookSpecificOutput")
    if isinstance(specific, dict):
        decision = specific.get("permissionDecision")
        if decision in ("allow", "deny", "ask"):
            return decision
    return "allow"


def _disabled(env: dict[str, str]) -> bool:
    names = {
        part.strip().lower()
        for part in env.get(_DISABLE_ENV, "").split(",")
        if part.strip()
    }
    return bool(names & {"all", "1", "true", "pre-bash"})


def self_test(
    prefix: list[str],
    agent: str,
    *,
    runner: Runner = subprocess.run,
    timeout: float = SELF_TEST_TIMEOUT_SECONDS,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Ask the pre-bash hook about ``ls`` (allow) and ``cat .env`` (deny)."""
    base_env = dict(os.environ if env is None else env)
    if _disabled(base_env):
        return {
            "status": "disabled",
            "detail": f"{_DISABLE_ENV} turns pre-bash off in this environment",
        }
    with tempfile.TemporaryDirectory(prefix="skylos-doctor-") as tmp:
        root = Path(tmp)
        (root / ".git").mkdir()  # keeps hook state and its log in this directory
        (root / ".env").write_text(
            f"GITHUB_TOKEN={_canary_token()}\n", encoding="utf-8"
        )
        run_env = {**base_env, "CLAUDE_PROJECT_DIR": tmp, "CURSOR_PROJECT_DIR": tmp}
        results = {}
        for label, command, expected in (
            ("allow", "ls", "allow"),
            ("deny", "cat .env", "deny"),
        ):
            started = time.monotonic()
            try:
                proc = runner(
                    [*prefix, "hook", "pre-bash", "--client", agent],
                    input=_payload(agent, command, tmp),
                    capture_output=True,
                    text=True,
                    cwd=tmp,
                    env=run_env,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return {
                    "status": "timeout",
                    "detail": f"pre-bash did not answer within {timeout:g} s",
                }
            except OSError as exc:
                return {
                    "status": "failed",
                    "detail": f"could not run {prefix[0]}: {exc.strerror or exc}",
                }
            seconds = round(time.monotonic() - started, 2)
            decision = _decision(agent, proc.stdout)
            results[label] = {
                "command": command,
                "expected": expected,
                "decision": decision,
                "seconds": seconds,
                "exit_code": proc.returncode,
            }
    passed = all(r["decision"] == r["expected"] for r in results.values())
    if passed:
        detail = (
            f"pre-bash allowed `ls` ({results['allow']['seconds']:.1f} s) and "
            f"blocked `cat .env` of a file with a token ({results['deny']['seconds']:.1f} s)"
        )
    else:
        wrong = [
            f"`{r['command']}` got {r['decision']}, expected {r['expected']}"
            for r in results.values()
            if r["decision"] != r["expected"]
        ]
        detail = "pre-bash answered wrongly: " + "; ".join(wrong)
    return {"status": "passed" if passed else "failed", "detail": detail, **results}


def _install_report(
    agent: str,
    scope: str,
    path: Path,
    expected: tuple,
    project: Path,
    *,
    tested: dict[tuple, dict[str, Any]],
    runner: Runner,
    run_self_test: bool,
) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    config, error = _load_config(path)
    if error:
        return {
            "scope": scope,
            "path": str(path),
            "status": "broken",
            "hooks": 0,
            "problems": [f"cannot read {path}: {error}"],
        }
    commands = _commands(config, agent)
    if not commands:
        return None
    names = []
    for command in commands:
        match = _HOOK_NAME_RE.search(command)
        if match:
            names.append(match.group(1))
    wanted = [name for _event, _matcher, name, _timeout in expected]
    missing = sorted(set(wanted) - set(names))
    report: dict[str, Any] = {
        "scope": scope,
        "path": str(path),
        "hooks": len(commands),
        "expected_hooks": len(wanted),
        "missing_hooks": missing,
        "problems": [],
        "notes": [],
    }
    executables: dict[str, str | None] = {}
    custom = 0
    pre_bash_prefix = None
    for command in commands:
        prefix = command_prefix(command, agent)
        if prefix is None:
            custom += 1
            continue
        for part in prefix[:1]:
            if part not in executables:
                executables[part] = resolve_executable(part)
        if pre_bash_prefix is None and re.search(r"\bhook\s+pre-bash\b", command):
            pre_bash_prefix = prefix
    report["executables"] = [
        {"command": name, "path": resolved, "exists": resolved is not None}
        for name, resolved in executables.items()
    ]
    if custom:
        report["notes"].append(
            f"{custom} hook command(s) differ from what the installer writes; "
            "not checked"
        )
    missing_bins = [name for name, resolved in executables.items() if resolved is None]
    if missing_bins:
        report["problems"].append(
            "points at a missing Skylos executable "
            + ", ".join(missing_bins)
            + "; these hooks do nothing (they fall back to allow)"
        )
    if missing:
        report["notes"].append("missing hooks: " + ", ".join(missing))

    if not run_self_test:
        report["self_test"] = {"status": "skipped", "detail": "self-test off"}
    elif pre_bash_prefix is None:
        report["self_test"] = {
            "status": "skipped",
            "detail": "no installer-written pre-bash hook to test",
        }
    elif executables.get(pre_bash_prefix[0]) is None:
        report["self_test"] = {
            "status": "skipped",
            "detail": "the pre-bash executable is missing",
        }
    elif scope == "project" and _tracked_in(
        executables[pre_bash_prefix[0]] or "", project
    ):
        report["self_test"] = {
            "status": "skipped",
            "detail": "the hook runs a file committed to this repository; "
            "not run by doctor",
        }
    else:
        key = (tuple(pre_bash_prefix), agent)
        if key not in tested:
            tested[key] = self_test(pre_bash_prefix, agent, runner=runner)
        report["self_test"] = tested[key]
        if tested[key]["status"] in ("failed", "timeout"):
            report["problems"].append("self-test " + tested[key]["status"])

    report["status"] = "broken" if report["problems"] else "ok"
    return report


def check_agent_hooks(
    cwd: Path | None = None,
    home: Path | None = None,
    *,
    runner: Runner = subprocess.run,
    run_self_test: bool = True,
) -> dict[str, Any]:
    """Per-client hook status for doctor's text and JSON output."""
    cwd = Path.cwd() if cwd is None else cwd
    home = Path.home() if home is None else home
    project = _project_root(cwd)
    tested: dict[tuple, dict[str, Any]] = {}
    clients: dict[str, Any] = {}
    for agent, label, expected in CLIENTS:
        installs = []
        seen = set()
        for scope in ("project", "user"):
            path = config_path_for(agent, scope, cwd, home)
            try:
                key = path.resolve()
            except OSError:
                key = path
            if key in seen:
                continue
            seen.add(key)
            report = _install_report(
                agent,
                scope,
                path,
                expected,
                project,
                tested=tested,
                runner=runner,
                run_self_test=run_self_test,
            )
            if report is not None:
                report["install_command"] = install_command(agent, scope)
                installs.append(report)
        status = (
            "not_installed"
            if not installs
            else "broken"
            if any(item["status"] == "broken" for item in installs)
            else "ok"
        )
        clients[agent] = {
            "name": label,
            "status": status,
            "installs": installs,
            "install_command": install_command(agent, "project"),
        }
    statuses = {client["status"] for client in clients.values()}
    overall = (
        "degraded"
        if "broken" in statuses
        else "ok"
        if "ok" in statuses
        else "not_installed"
    )
    return {
        "status": overall,
        "project": str(project),
        "home": str(home),
        "clients": clients,
    }


def print_agent_hooks(console, report: dict[str, Any]) -> None:
    from rich.markup import escape

    console.print("  [bold]Agent hooks[/bold]")
    project = Path(report.get("project") or ".")
    home = Path(report["home"]) if report.get("home") else None
    for agent, client in report["clients"].items():
        name = client["name"]
        if client["status"] == "not_installed":
            console.print(
                f"  [yellow]--[/yellow]  {name}: not installed "
                f"[dim](optional: {escape(client['install_command'])})[/dim]"
            )
            continue
        for item in client["installs"]:
            path = Path(item["path"])
            shown = str(path)
            for base, label in ((project, ""), (home, "~/")):
                if base is None:
                    continue
                try:
                    shown = label + path.relative_to(base).as_posix()
                    break
                except ValueError:
                    continue
            where = f"{shown} ({item['scope']})"
            if item["status"] == "broken":
                console.print(
                    f"  [red]FAIL[/red] {name}: {escape(where)}: "
                    + escape("; ".join(item["problems"])),
                    soft_wrap=True,
                )
                console.print(
                    f"      [dim]Reinstall: {escape(item['install_command'])}[/dim]"
                )
            else:
                target = ", ".join(
                    entry["path"]
                    for entry in item.get("executables", [])
                    if entry["path"]
                )
                count = (
                    f"{item['hooks']} of {item.get('expected_hooks', item['hooks'])}"
                )
                console.print(
                    f"  [green]OK[/green]  {name}: {count} hooks in {escape(where)}"
                    + (f" [dim]→ {escape(target)}[/dim]" if target else ""),
                    soft_wrap=True,
                )
            test = item.get("self_test") or {}
            if test.get("detail"):
                console.print(
                    f"      [dim]Self-test ({escape(test.get('status', '?'))}): "
                    f"{escape(test.get('detail', ''))}[/dim]",
                    soft_wrap=True,
                )
            for note in item.get("notes", []):
                console.print(f"      [dim]{escape(note)}[/dim]")
