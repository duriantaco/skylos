"""Agent config files the hooks guard: MCP servers and commands that run on their own.

What a file runs is read by ca9 (``ca9.api.agent_config``): this module copies
the files' text into a private directory, asks ca9 for that directory's
inventory, and compares inventories. It never reads a hook or server entry
itself, so JSON with comments, ``.vscode/tasks.json`` ``folderOpen`` tasks and
the other formats are understood exactly as the scanner understands them.

Files: the project's ``.mcp.json``, ``.cursor/mcp.json``, ``.vscode/mcp.json``,
``.vscode/tasks.json``, ``.gemini/settings.json``, ``.claude/settings(.local).json``,
``.cursor/hooks.json``, ``.codex/hooks.json`` and ``.codex/config.toml``; the
user's ``~/.claude.json`` (user scope and this project's local scope),
``~/.claude/settings.json``, ``~/.cursor/mcp.json``, ``~/.gemini/settings.json``,
``~/.codex/config.toml``, ``~/.codex/hooks.json`` and ``~/.cursor/hooks.json``.

A snapshot of what each file runs (hashes and names only, never commands or
values) is kept in ``.skylos/cache/agent-configs.json`` so the session-start
hook can report changes no checked agent action made.

A hook entry is Skylos's own only when its command is exactly what
``skylos agent install-hooks`` writes and it runs the same Skylos executable
that is checking it; the word "skylos" in a command proves nothing.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_FILES = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".vscode/tasks.json",
    ".gemini/settings.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/hooks.json",
    ".codex/hooks.json",
    ".codex/config.toml",
)
HOME_FILES = (
    ".claude/settings.json",
    ".cursor/mcp.json",
    ".gemini/settings.json",
    ".codex/config.toml",
    ".codex/hooks.json",
    ".cursor/hooks.json",
)
CLAUDE_JSON = ".claude.json"
MAX_CONFIG_BYTES = 32_000_000
SNAPSHOT_PATH = Path(".skylos") / "cache" / "agent-configs.json"
SNAPSHOT_LOCK_PATH = Path(".skylos") / "cache" / "agent-configs.lock"
SNAPSHOT_VERSION = 1
PENDING_SECONDS = 15 * 60
MAX_SHOWN_CHARS = 90
ENGINE_MISSING = "the installed ca9 cannot read agent configs (pip install -U ca9)"

_OURS_RE = re.compile(
    r"(?P<prefix>.+?) hook (?P<name>[a-z-]+) --client (?P<agent>claude|codex|cursor) "
    r"\|\| (?P<fallback>.+)",
    re.DOTALL,
)


@dataclass(frozen=True)
class ConfigFile:
    label: str
    path: Path
    mirror: str
    scope: str = ""


@dataclass
class FileScan:
    servers: list[dict[str, Any]] = field(default_factory=list)
    hooks: list[dict[str, Any]] = field(default_factory=list)
    env: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    hooks_off: bool = False
    error: str = ""


@dataclass(frozen=True)
class Change:
    kind: str
    key: str
    name: str
    added: bool
    removed: bool
    detail: str = ""


def config_files(root: Path, home: Path | None) -> list[ConfigFile]:
    files = [ConfigFile(rel, root / rel, f"r/{rel}") for rel in REPO_FILES]
    if home is None:
        return files
    files += [ConfigFile(f"~/{rel}", home / rel, f"h/{rel}") for rel in HOME_FILES]
    files.append(ConfigFile(f"~/{CLAUDE_JSON}", home / CLAUDE_JSON, "u/.mcp.json", "user"))
    files.append(ConfigFile(f"~/{CLAUDE_JSON} (this project)", home / CLAUDE_JSON,
                            "l/.mcp.json", "local"))  # fmt: skip
    return files


def guarded_file(path: Path, root: Path, home: Path | None) -> list[ConfigFile]:
    """The agent config entries ``path`` holds (two for ``~/.claude.json``)."""
    wanted = _path_key(path)
    return [cf for cf in config_files(root, home) if _path_key(cf.path) == wanted]


def home_dir(env: dict[str, str]) -> Path | None:
    value = env.get("HOME") or env.get("USERPROFILE")
    if value:
        return Path(value).expanduser()
    with contextlib.suppress(RuntimeError, KeyError):
        return Path.home()
    return None


def read_config(path: Path) -> str | None:
    """Text of an existing config file, following a dotfiles symlink; None
    when it is missing, too large or unreadable."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
            return None
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return None


def engine_ready() -> bool:
    return ca9_function("agent_config") is not None and ca9_function("parse_mcp_server") is not None


def ca9_function(name: str):
    from skylos.commands.hook_supply_chain import _ca9_function

    return _ca9_function(name)


def scan_texts(pairs: list[tuple[ConfigFile, str]], root: Path) -> dict[str, FileScan] | None:
    """What each file runs, read by ca9; None when ca9 cannot read agent configs."""
    function = ca9_function("agent_config")
    if function is None:
        return None
    scans = {cf.label: FileScan() for cf, _text in pairs}
    by_mirror = {cf.mirror: cf for cf, _text in pairs}
    with tempfile.TemporaryDirectory(prefix="skylos-agent-config-") as tmp:
        base = Path(tmp)
        for cf, text in pairs:
            body = _mirror_text(cf, text, root)
            if body is None:
                scans[cf.label].error = "could not be read as JSON"
                continue
            target = base / cf.mirror
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
            scans[cf.label].hooks_off = _hooks_off(cf, text)
        try:
            answer = function(base)
        except Exception:  # noqa: BLE001
            return None
    if not isinstance(answer, dict):
        return None
    inventory = answer.get("inventory")
    if not isinstance(inventory, dict):
        return None
    for key, bucket in (("mcp_servers", "servers"), ("hooks", "hooks"), ("env_overrides", "env")):
        for item in inventory.get(key) or []:
            target = _scan_for(item, by_mirror, scans)
            if target is not None:
                getattr(target, bucket).append(item)
    for finding in answer.get("findings") or []:
        target = _scan_for(finding, by_mirror, scans)
        if target is not None:
            target.findings.append(finding)
    for error in inventory.get("errors") or []:
        target = _scan_for(error, by_mirror, scans)
        if target is not None:
            target.error = str(error.get("reason") or "could not be read")
    return scans


def scan_files(files: list[ConfigFile], root: Path) -> dict[str, FileScan] | None:
    pairs = []
    for cf in files:
        text = read_config(cf.path)
        if text is not None:
            pairs.append((cf, text))
    scans = scan_texts(pairs, root)
    if scans is None:
        return None
    for cf in files:
        scans.setdefault(cf.label, FileScan())
    return scans


def entries(scan: FileScan) -> tuple[dict[str, str], dict[str, str]]:
    """``key -> digest`` for what one file runs, and ``key -> display`` text."""
    values: dict[str, str] = {}
    shown: dict[str, str] = {}
    ours = 0
    for server in scan.servers:
        key = f"server {server.get('name')}"
        values[key] = _digest([server.get("argv"), server.get("url"), server.get("transport"),
                               server.get("command")])  # fmt: skip
        shown[key] = server_display(server)
    for hook in scan.hooks:
        command = str(hook.get("command") or "")
        if is_skylos_hook(command):
            ours += 1
            continue
        event = str(hook.get("event") or "hook")
        key = (f"hook {_word(hook.get('kind'))} {_word(event)} "
               f"{_digest([hook.get('matcher'), command, hook.get('label')])}")  # fmt: skip
        values[key] = "1"
        shown[key] = f"{event} command: {short(command)}"
    for override in scan.env:
        key = f"env {override.get('variable')}"
        values[key] = _digest(override.get("target"))
        shown[key] = f"{override.get('variable')} set to {short(str(override.get('target') or ''))}"
    if ours:
        values["skylos"] = str(ours)
    if scan.hooks_off:
        values["hooks-off"] = "1"
    return values, shown


def changes(before: dict[str, str], after: dict[str, str], shown: dict[str, str]) -> list[Change]:
    found = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        kind, _space, rest = key.partition(" ")
        if kind == "skylos":
            if int(new or 0) < int(old or 0):
                found.append(Change("skylos", key, "Skylos", False, True))
            continue
        name = rest
        if kind == "hook":
            name = rest.split(" ")[1] if " " in rest else rest
        found.append(Change(kind, key, name, old is None, new is None, shown.get(key, "")))
    return found


def change_line(label: str, change: Change) -> str | None:
    if change.kind == "server":
        if change.added:
            return f"{label}: MCP server '{change.name}' added since the last check ({change.detail})"
        if change.removed:
            return f"{label}: MCP server '{change.name}' removed since the last check"
        return f"{label}: MCP server '{change.name}' changed since the last check ({change.detail})"
    if change.kind == "hook":
        if change.removed:
            return f"{label}: a {change.name} command was removed since the last check"
        return f"{label}: new since the last check: {change.detail}"
    if change.kind == "env":
        if change.removed:
            return None
        return f"{label}: new since the last check: {change.detail}"
    if change.kind == "skylos":
        return f"{label}: Skylos hooks removed since the last check"
    if change.kind == "hooks-off" and not change.removed:
        return f"{label}: disableAllHooks turned on since the last check (no hooks run)"
    return None


def needs_approval(change: Change) -> str | None:
    """Why a change to commands that run on their own needs the user, or None."""
    if change.kind == "hook" and not change.removed:
        return f"adds a command that runs on its own ({change.detail})"
    if change.kind == "env" and not change.removed:
        return f"points the agent at another endpoint ({change.detail})"
    if change.kind == "skylos":
        return "removes Skylos's own hooks"
    if change.kind == "hooks-off" and not change.removed:
        return "turns off every hook (disableAllHooks)"
    return None


def is_skylos_hook(command: str) -> bool:
    from skylos.commands.install_hooks_cmd import AGENTS, hook_command

    match = _OURS_RE.fullmatch(command or "")
    if match is None or match["agent"] not in AGENTS:
        return False
    try:
        parts = shlex.split(match["prefix"], posix=os.name != "nt")
    except ValueError:
        return False
    if not parts or hook_command(parts, match["name"], match["agent"]) != command:
        return False
    return runs_this_skylos(parts)


def runs_this_skylos(parts: list[str]) -> bool:
    if parts == [sys.executable, "-m", "skylos.entry"]:
        return True
    if len(parts) != 1:
        return False
    running = _running_script()
    if running is None:
        return False
    target = parts[0]
    if os.sep not in target and not (os.altsep and os.altsep in target):
        import shutil

        found = shutil.which(target)
        if found is None:
            return False
        target = found
    try:
        return os.path.samefile(target, running)
    except OSError:
        return False


def server_display(server: dict[str, Any]) -> str:
    if server.get("url"):
        return short(str(server.get("url")))
    argv = server.get("argv")
    if isinstance(argv, list) and argv:
        return short(" ".join(str(part) for part in argv))
    return short(str(server.get("command") or "?"))


def short(text: str) -> str:
    flat = " ".join(str(text).split())
    if len(flat) <= MAX_SHOWN_CHARS:
        return flat
    return flat[: MAX_SHOWN_CHARS - 1] + "…"


def load_snapshot(state_root: Path) -> dict[str, Any]:
    from skylos.core.safe_cache_io import load_project_json_cache

    data = load_project_json_cache(state_root, SNAPSHOT_PATH, max_bytes=4_000_000)
    if data.get("version") != SNAPSHOT_VERSION:
        return {}
    return data


def update_snapshot(state_root: Path, mutate) -> bool:
    from skylos.core.safe_cache_io import (
        project_cache_lock,
        save_project_json_cache,
    )

    with project_cache_lock(state_root, SNAPSHOT_LOCK_PATH, timeout_seconds=2.0) as locked:
        if not locked:
            return False
        data = load_snapshot(state_root) or {"version": SNAPSHOT_VERSION, "files": {}}
        data.setdefault("files", {})
        data.setdefault("pending", {})
        mutate(data)
        _drop_stale_pending(data)
        return save_project_json_cache(state_root, SNAPSHOT_PATH, data, indent=None)


def remember_pending(state_root: Path, token: str, before: dict[str, dict[str, str]]) -> None:
    """What the files looked like before a checked agent action, so the
    action's own change can be accepted once it lands."""

    def mutate(data):
        data["pending"][token] = {"at": time.time(), "files": before}

    update_snapshot(state_root, mutate)


def accept_pending(state_root: Path, token: str, labels: set[str] | None,
                   current: dict[str, dict[str, str]]) -> None:  # fmt: skip
    """Fold a checked action's own changes into the snapshot. Entries the
    action did not touch keep their snapshot value, so a change made outside
    the agent at the same time is still reported."""

    def mutate(data):
        pending = data["pending"].pop(token, None)
        if not isinstance(pending, dict) or not data["files"]:
            return
        for label, before in (pending.get("files") or {}).items():
            if labels is not None and label not in labels:
                continue
            after = current.get(label)
            if after is None or not isinstance(before, dict):
                continue
            known = data["files"].setdefault(label, {})
            for key in set(before) | set(after):
                if before.get(key) == after.get(key):
                    continue
                if key in after:
                    known[key] = after[key]
                else:
                    known.pop(key, None)

    update_snapshot(state_root, mutate)


def _drop_stale_pending(data: dict[str, Any]) -> None:
    now = time.time()
    pending = data.get("pending")
    if not isinstance(pending, dict):
        data["pending"] = {}
        return
    for token in list(pending):
        entry = pending[token]
        if not isinstance(entry, dict) or now - float(entry.get("at") or 0) > PENDING_SECONDS:
            del pending[token]


def _scan_for(item: Any, by_mirror: dict[str, ConfigFile], scans: dict[str, FileScan]):
    if not isinstance(item, dict):
        return None
    cf = by_mirror.get(str(item.get("file") or "").replace(os.sep, "/"))
    if cf is None:
        return None
    return scans[cf.label]


def _mirror_text(cf: ConfigFile, text: str, root: Path) -> str | None:
    if not cf.scope:
        return text
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    servers: Any = None
    if cf.scope == "user":
        servers = data.get("mcpServers")
    else:
        projects = data.get("projects")
        if isinstance(projects, dict):
            for key in _project_keys(root):
                entry = projects.get(key)
                if isinstance(entry, dict):
                    servers = entry.get("mcpServers")
                    break
    if not isinstance(servers, dict):
        servers = {}
    return json.dumps({"mcpServers": servers})


def _project_keys(root: Path) -> list[str]:
    keys = [str(root)]
    with contextlib.suppress(OSError):
        keys.append(str(root.resolve()))
    return list(dict.fromkeys(keys))


def _hooks_off(cf: ConfigFile, text: str) -> bool:
    if not cf.label.endswith((".claude/settings.json", ".claude/settings.local.json")):
        return False
    try:
        data = json.loads(text)
    except ValueError:
        return bool(re.search(r'"disableAllHooks"\s*:\s*true', text))
    return isinstance(data, dict) and data.get("disableAllHooks") is True


def _running_script() -> str | None:
    argv0 = sys.argv[0] if sys.argv else ""
    if Path(argv0).name.lower() not in {"skylos", "skylos.exe"}:
        return None
    path = Path(argv0).absolute()
    if path.is_file():
        return str(path)
    return None


def _path_key(path: Path) -> str:
    try:
        text = os.path.realpath(os.path.abspath(os.path.expanduser(str(path))))
    except (OSError, ValueError):
        text = str(path)
    if sys.platform in ("darwin", "win32"):
        return text.lower()
    return text


def _digest(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _word(value: Any) -> str:
    return re.sub(r"\s+", "_", str(value or "-"))


__all__ = [
    "Change",
    "ConfigFile",
    "FileScan",
    "accept_pending",
    "change_line",
    "changes",
    "config_files",
    "engine_ready",
    "entries",
    "guarded_file",
    "home_dir",
    "is_skylos_hook",
    "load_snapshot",
    "needs_approval",
    "read_config",
    "remember_pending",
    "scan_files",
    "scan_texts",
    "update_snapshot",
]
