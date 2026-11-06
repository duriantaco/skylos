"""Is an agent hook command one that ``skylos agent install-hooks`` wrote?

One helper for the scanner (hooks committed on any machine) and the agent hook
(this machine). The command must be exactly
``<program> hook <event> --client <agent>`` with one of the fixed ``||``
fallbacks Skylos writes and no other shell syntax. ``<program>`` is ``skylos``
found on the user's PATH or an absolute path ending in ``/skylos`` outside the
repository (as written and after following symlinks) and outside
world-writable temp folders, so the repository cannot supply the program.
``python -m skylos.entry`` is never accepted: ``-m`` imports from the working
folder, which the repository controls. The settings file holding the hook
must be JSON whose ``env`` sets no PATH or loader variable.

With ``this_machine=True`` the command must also equal, character for
character, what ``install-hooks`` writes on this machine (the running Skylos
console script, or ``skylos`` on PATH). A name check or ``samefile`` would
accept a symlink the repository commits.

``looks_like_skylos_hook`` is the loose shape test used to notice that one of
Skylos's own hooks was removed or weakened; it never makes a command trusted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

HOOK_EVENTS = (
    "session-start",
    "pre-edit",
    "post-edit",
    "pre-read",
    "pre-bash",
    "post-bash",
    "post-failure",
    "stop",
)
FALLBACKS = (
    "exit 0",
    "echo '{}'",
    """echo '{"permission":"allow"}'""",
    """echo '{"continue":true}'""",
)
LOADER_VARIABLES = frozenset(
    {"PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONSAFEPATH",
     "VIRTUAL_ENV", "BASH_ENV", "ENV", "NODE_OPTIONS", "SHELL"}
)  # fmt: skip
LOADER_PREFIXES = ("LD_", "DYLD_")
WORLD_WRITABLE = ("/tmp/", "/private/tmp/", "/var/tmp/", "/dev/shm/")
_SAFE_PATH = r"/(?:[A-Za-z0-9_.+@~-]+/)*"
_HOOK_RE = re.compile(
    r"(?P<program>skylos|" + _SAFE_PATH + r"skylos)"
    r" hook (?P<event>" + "|".join(HOOK_EVENTS) + r")"
    r" --client (?P<agent>claude|codex|cursor)"
    r"(?: \|\| (?:" + "|".join(re.escape(item) for item in FALLBACKS) + r"))?"
)
_LOOSE_RE = re.compile(
    r"(?:^|[\s/\\'\"])skylos(?:\.exe|\.entry)?['\"]?\s+hook\s+"
    r"(?:" + "|".join(HOOK_EVENTS) + r")\b"
)


def is_skylos_hook_command(command: object, *, root: Path, settings_text: str | None,
                           this_machine: bool = False) -> bool:  # fmt: skip
    if not isinstance(command, str):
        return False
    match = _HOOK_RE.fullmatch(command.strip())
    if match is None:
        return False
    program = match.group("program")
    if program.startswith("/") and not _outside(program, root):
        return False
    if not _env_is_clean(settings_text):
        return False
    if not this_machine:
        return True
    return command in _machine_commands(match.group("event"), match.group("agent"), root)


def looks_like_skylos_hook(command: object) -> bool:
    return isinstance(command, str) and bool(_LOOSE_RE.search(command))


def machine_prefixes() -> list[list[str]]:
    """The program prefixes ``install-hooks`` writes on this machine."""
    from skylos.commands.install_hooks_cmd import _current_console_script

    prefixes: list[list[str]] = []
    script = _current_console_script()
    if script:
        prefixes.append([script])
    found = shutil.which("skylos")
    if found:
        prefixes.append([os.path.abspath(found)])
        prefixes.append(["skylos"])
    return prefixes


def _machine_commands(event: str, agent: str, root: Path) -> set[str]:
    from skylos.commands.install_hooks_cmd import hook_command

    commands = set()
    for prefix in machine_prefixes():
        if prefix[0].startswith("/") and not _outside(prefix[0], root):
            continue
        commands.add(hook_command(prefix, event, agent))
    return commands


def _outside(program: str, root: Path) -> bool:
    parts = PurePosixPath(program).parts
    if ".." in parts or "." in parts or "//" in program or program.startswith(WORLD_WRITABLE):
        return False
    try:
        written = Path(os.path.abspath(program))
        real = Path(os.path.realpath(program))
        for base in {Path(os.path.abspath(root)), Path(os.path.realpath(root))}:
            if written.is_relative_to(base) or real.is_relative_to(base):
                return False
    except (OSError, ValueError):
        return False
    return True


def _env_is_clean(settings_text: str | None) -> bool:
    if settings_text is None:
        return False
    try:
        data: Any = json.loads(settings_text)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    env = data.get("env", {})
    if not isinstance(env, dict):
        return False
    for name in env:
        key = str(name).upper()
        if key in LOADER_VARIABLES or key.startswith(LOADER_PREFIXES):
            return False
    return True


__all__ = [
    "FALLBACKS",
    "HOOK_EVENTS",
    "is_skylos_hook_command",
    "looks_like_skylos_hook",
    "machine_prefixes",
]
