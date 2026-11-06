"""Agent config files the hooks guard: MCP servers and commands that run on their own.

ca9 (``ca9.api.agent_config``) reads what a file runs: this module copies the
files' text into a private directory, asks ca9 for that directory's
inventory, and compares inventories. Skylos parses the files itself only for
what the inventory leaves out: duplicate keys (agents keep the last value),
server ``env``, settings that load code (``env`` such as ``NODE_OPTIONS``,
plugins, marketplaces, project MCP approval, Codex ``notify``), hooks in
``.claude/agents/*.md`` frontmatter, and Skylos's own hook entries with their
event, matcher and timeout.

Files: the project's ``.mcp.json``, ``.cursor/mcp.json``, ``.vscode/mcp.json``,
``.vscode/tasks.json``, ``.gemini/settings.json``, ``.claude/settings(.local).json``,
``.claude/agents/*.md``, ``.cursor/hooks.json``, ``.codex/hooks.json`` and
``.codex/config.toml``; the user's ``~/.claude.json`` (user scope and every
project's scope), ``~/.claude/settings.json``, ``~/.claude/agents/*.md``,
``~/.cursor/mcp.json``, ``~/.gemini/settings.json``, ``~/.codex/config.toml``,
``~/.codex/hooks.json`` and ``~/.cursor/hooks.json``.

A snapshot of what each file runs (hashes and names only, never commands or
values) is kept in ``.skylos/cache/agent-configs.json`` so the session-start
hook can report changes no checked agent action made. Whether a hook is
Skylos's own is decided by :mod:`skylos.core.skylos_hooks`, never by name.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
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
CONFIG_DIRS = (".claude", ".claude/agents", ".cursor", ".vscode", ".gemini", ".codex")
AGENTS_DIR = ".claude/agents"
CLAUDE_JSON = ".claude.json"
MAX_CONFIG_BYTES = 32_000_000
MAX_AGENT_FILES = 100
MAX_PROJECTS = 200
SNAPSHOT_PATH = Path(".skylos") / "cache" / "agent-configs.json"
SNAPSHOT_LOCK_PATH = Path(".skylos") / "cache" / "agent-configs.lock"
SNAPSHOT_VERSION = 2
PENDING_SECONDS = 15 * 60
MAX_SHOWN_CHARS = 90
ENGINE_MISSING = "the installed ca9 cannot read agent configs (pip install -U ca9)"
RISKY_ENV = frozenset(
    {"PATH", "BASH_ENV", "ENV", "ZDOTDIR", "SHELL", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
     "PYTHONUSERBASE", "NODE_OPTIONS", "NODE_PATH", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
     "NPM_CONFIG_REGISTRY", "YARN_REGISTRY", "BUN_CONFIG_REGISTRY", "PIP_INDEX_URL",
     "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_INDEX",
     "CLAUDE_CODE_SHELL_PREFIX", "GIT_SSH_COMMAND", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"}
)  # fmt: skip
RISKY_ENV_PREFIXES = ("LD_", "DYLD_", "NPM_CONFIG_@")
CODE_SETTINGS = ("enabledPlugins", "extraKnownMarketplaces", "enabledMcpjsonServers",
                 "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")  # fmt: skip
SETTINGS_SUFFIXES = (".claude/settings.json", ".claude/settings.local.json")


@dataclass(frozen=True)
class ConfigFile:
    label: str
    path: Path
    mirror: str
    kind: str = "json"


@dataclass
class FileScan:
    servers: list[dict[str, Any]] = field(default_factory=list)
    hooks: list[dict[str, Any]] = field(default_factory=list)
    env: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    own: dict[str, str] = field(default_factory=dict)
    own_shown: dict[str, str] = field(default_factory=dict)
    skylos: list[dict[str, Any]] = field(default_factory=list)
    agent: str = ""
    text: str | None = None
    root: str = ""
    server_env: dict[str, Any] = field(default_factory=dict)
    dupes: bool = False
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
    files = [ConfigFile(rel, root / rel, f"r/{rel}", _kind(rel)) for rel in REPO_FILES]
    files += _agent_files(root / AGENTS_DIR, AGENTS_DIR)
    if home is None:
        return files
    files += [ConfigFile(f"~/{rel}", home / rel, f"h/{rel}", _kind(rel)) for rel in HOME_FILES]
    files.append(ConfigFile(f"~/{CLAUDE_JSON}", home / CLAUDE_JSON, "c", "claude-json"))
    files += _agent_files(home / AGENTS_DIR, f"~/{AGENTS_DIR}")
    return files


def guarded_file(path: Path, root: Path, home: Path | None) -> list[ConfigFile]:
    """The agent config ``path`` is, if any."""
    wanted = _path_key(path)
    found = [cf for cf in config_files(root, home) if _path_key(cf.path) == wanted]
    if found or path.suffix.lower() != ".md":
        return found
    for base, label in ((root, AGENTS_DIR), (home, f"~/{AGENTS_DIR}")):
        if base is not None and _path_key(path.parent) == _path_key(base / AGENTS_DIR):
            return [ConfigFile(f"{label}/{path.name}", path, "", "agent-md")]
    return []


def config_dirs(root: Path, home: Path | None) -> list[Path]:
    bases = [root] + ([home] if home is not None else [])
    return [base / rel for base in bases for rel in CONFIG_DIRS]


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


def parse_json(text: str) -> tuple[Any, bool] | None:
    """``(data, has duplicate keys)`` for JSON or JSON with comments and
    trailing commas; None when it is neither."""
    seen = [False]

    def pairs(items):
        keys = [key for key, _value in items]
        if len(keys) != len(set(keys)):
            seen[0] = True
        return dict(items)

    for candidate in (text, _strip_jsonc(text)):
        seen[0] = False
        try:
            return json.loads(candidate, object_pairs_hook=pairs), seen[0]
        except ValueError:
            continue
    return None


def scan_texts(pairs: list[tuple[ConfigFile, str]], root: Path) -> dict[str, FileScan] | None:
    """What each file runs; None when ca9 cannot read agent configs."""
    function = ca9_function("agent_config")
    if function is None:
        return None
    scans: dict[str, FileScan] = {}
    by_mirror: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="skylos-agent-config-") as tmp:
        base = Path(tmp)
        for cf, text in pairs:
            for label, mirror, body in _mirror_parts(cf, text, root):
                scan = scans.setdefault(label, FileScan(text=text, root=str(root)))
                _own_facts(cf, label, text, body, scan)
                if not mirror:
                    continue
                if body is None:
                    scan.error = scan.error or "could not be read"
                    continue
                target = base / mirror
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body, encoding="utf-8")
                by_mirror[mirror] = label
        if not by_mirror:
            return scans
        try:
            answer = function(base)
        except Exception:  # noqa: BLE001
            return None
    if not isinstance(answer, dict) or not isinstance(answer.get("inventory"), dict):
        return None
    inventory = answer["inventory"]
    for key, bucket in (("mcp_servers", "servers"), ("hooks", "hooks"), ("env_overrides", "env")):
        for item in inventory.get(key) or []:
            target = _scan_for(item, by_mirror, scans)
            if target is not None:
                getattr(target, bucket).append(item)
                target.dupes = target.dupes or item.get("duplicate_keys") is True
    for finding in answer.get("findings") or []:
        target = _scan_for(finding, by_mirror, scans)
        if target is not None:
            target.findings.append(finding)
            target.dupes = target.dupes or finding.get("signal_type") == "agent_config_ambiguous"
    for error in inventory.get("errors") or []:
        target = _scan_for(error, by_mirror, scans)
        if target is not None:
            target.error = str(error.get("reason") or "could not be read")
    for scan in scans.values():
        _attach_server_env(scan)
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
        if cf.kind != "claude-json":
            scans.setdefault(cf.label, FileScan())
    return scans


def entries(scan: FileScan) -> tuple[dict[str, str], dict[str, str]]:
    """``key -> digest`` for what one file runs, and ``key -> display`` text."""
    from skylos.core.skylos_hooks import is_skylos_hook_command

    values: dict[str, str] = {}
    shown: dict[str, str] = {}
    for server in scan.servers:
        key = f"server {server.get('name')}"
        values[key] = _digest([server.get("argv"), server.get("url"), server.get("transport"),
                               server.get("command"), server.get("env")])  # fmt: skip
        shown[key] = server_display(server)
    for hook in scan.hooks:
        command = str(hook.get("command") or "")
        if is_skylos_hook_command(command, root=Path(scan.root or "."),
                                  settings_text=_settings_json(scan), this_machine=True):  # fmt: skip
            continue
        event = str(hook.get("event") or "hook")
        key = (f"hook {_word(hook.get('kind'))} {_word(event)} "
               f"{_digest([hook.get('matcher'), command, hook.get('label')])}")  # fmt: skip
        values[key] = "1"
        shown[key] = f"{event} command: {short(command)}"
    for override in scan.env:
        key = f"env {str(override.get('variable')).upper()}"
        values[key] = _digest(override.get("target"))
        shown[key] = f"{override.get('variable')} set to {short(str(override.get('target') or ''))}"
    for entry in scan.skylos:
        values[f"skylos {_digest(entry)}"] = "1"
    values.update(scan.own)
    shown.update(scan.own_shown)
    if scan.dupes:
        values["dupes"] = "1"
    return values, shown


def changes(before: dict[str, str], after: dict[str, str], shown: dict[str, str]) -> list[Change]:
    found = []
    skylos_removed = False
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        kind, _space, rest = key.partition(" ")
        if kind == "skylos":
            skylos_removed = skylos_removed or new is None
            continue
        name = rest
        if kind == "hook":
            name = rest.split(" ")[1] if " " in rest else rest
        found.append(Change(kind, key, name, old is None, new is None, shown.get(key, "")))
    if skylos_removed:
        found.append(Change("skylos", "skylos", "Skylos", False, True))
    return found


def change_line(label: str, change: Change) -> str | None:
    since = "since the last check"
    if change.kind == "server":
        if change.added:
            return f"{label}: MCP server '{change.name}' added {since} ({change.detail})"
        if change.removed:
            return f"{label}: MCP server '{change.name}' removed {since}"
        return f"{label}: MCP server '{change.name}' changed {since} ({change.detail})"
    if change.removed and change.kind != "skylos":
        if change.kind == "hook":
            return f"{label}: a {change.name} command was removed {since}"
        return None
    if change.kind in ("hook", "env", "setting"):
        return f"{label}: new {since}: {change.detail}"
    if change.kind == "skylos":
        return f"{label}: Skylos's own hooks removed or changed {since}"
    if change.kind == "hooks-off":
        return f"{label}: disableAllHooks turned on {since} (no hooks run)"
    if change.kind == "dupes":
        return f"{label}: has duplicate keys {since} (agents use the last one)"
    return None


def needs_approval(change: Change) -> str | None:
    """Why a change to what runs on its own needs the user, or None."""
    if change.removed and change.kind != "skylos":
        return None
    reasons = {
        "hook": f"adds a command that runs on its own ({change.detail})",
        "env": f"sets an environment variable that changes what runs ({change.detail})",
        "setting": f"changes a setting that loads code ({change.detail})",
        "skylos": "removes Skylos's own hooks or weakens them (event, matcher or timeout)",
        "hooks-off": "turns off every hook (disableAllHooks)",
        "dupes": "has duplicate keys; agents use the last one, so Skylos cannot tell what runs",
    }
    return reasons.get(change.kind)


def installs_cleanly(scan: FileScan, root: Path) -> bool:
    """The file's Skylos entries are exactly what ``install-hooks`` writes on
    this machine (a reinstall or upgrade), so changing them is not a weakening."""
    from skylos.commands.install_hooks_cmd import install_hooks
    from skylos.core.skylos_hooks import machine_prefixes

    if not scan.agent or not scan.skylos:
        return False
    current = {_digest(entry) for entry in scan.skylos}
    for prefix in machine_prefixes():
        config, _removed, _added = install_hooks({}, scan.agent, prefix)
        if {_digest(entry) for entry in _skylos_entries(config, scan.agent)} == current:
            return True
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


def remember_pending(state_root: Path, token: str, expected: dict[str, dict[str, str | None]]) -> None:
    """The exact entries a checked agent action may write (``None``: removes),
    so only that change is accepted once it lands."""

    def mutate(data):
        data["pending"][token] = {"at": time.time(), "files": expected}

    update_snapshot(state_root, mutate)


def accept_pending(state_root: Path, token: str, current: dict[str, dict[str, str]]) -> None:
    """Fold the checked change into the snapshot, entry by entry, only where
    the file now holds exactly the value that was checked. Anything else in
    the same files is still reported at the next prompt."""

    def mutate(data):
        pending = data["pending"].pop(token, None)
        if not isinstance(pending, dict) or not data["files"]:
            return
        for label, expected in (pending.get("files") or {}).items():
            now = current.get(label)
            if now is None or not isinstance(expected, dict):
                continue
            known = data["files"].setdefault(label, {})
            for key, value in expected.items():
                if now.get(key) != value:
                    continue
                if value is None:
                    known.pop(key, None)
                else:
                    known[key] = value

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


def _mirror_parts(cf: ConfigFile, text: str, root: Path) -> list[tuple[str, str, str | None]]:
    """``(label, mirror path, text for ca9)`` for each part of one file."""
    if cf.kind == "agent-md":
        return [(cf.label, "", text)]
    if cf.kind != "claude-json":
        return [(cf.label, cf.mirror, text)]
    parsed = parse_json(text)
    data = parsed[0] if parsed else None
    if not isinstance(data, dict):
        return [(cf.label, "c/u/.mcp.json", None)]
    parts = [(cf.label, "c/u/.mcp.json", _servers_json(data.get("mcpServers")))]
    projects = data.get("projects")
    if not isinstance(projects, dict):
        projects = {}
    mine = set(_project_keys(root))
    for index, key in enumerate(sorted(k for k in projects if isinstance(k, str))[:MAX_PROJECTS]):
        entry = projects.get(key)
        servers = entry.get("mcpServers") if isinstance(entry, dict) else None
        label = f"{cf.label} ({key})"
        if key in mine:
            label = f"{cf.label} (this project)"
        if servers or key in mine:
            parts.append((label, f"c/p{index}/.mcp.json", _servers_json(servers)))
    return parts


def _own_facts(cf: ConfigFile, label: str, text: str, body: str | None, scan: FileScan) -> None:
    if cf.kind == "agent-md":
        _agent_md_facts(label, text, scan)
        return
    if cf.kind == "toml":
        _toml_facts(text, scan)
        return
    parsed = parse_json(text)
    if parsed is None:
        return
    data, dupes = parsed
    scan.dupes = scan.dupes or dupes
    if cf.kind == "claude-json" and body is not None:
        data = json.loads(body)
    if not isinstance(data, dict):
        return
    if cf.label.endswith(SETTINGS_SUFFIXES):
        scan.agent = "claude"
        _settings_facts(data, scan)
    elif cf.label.endswith(".codex/hooks.json"):
        scan.agent = "codex"
    elif cf.label.endswith(".cursor/hooks.json"):
        scan.agent = "cursor"
    if scan.agent:
        scan.skylos = _skylos_entries(data, scan.agent)
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = data.get("servers")
    scan.server_env = _server_envs(servers)


def _settings_facts(data: dict[str, Any], scan: FileScan) -> None:
    env = data.get("env")
    if isinstance(env, dict):
        for name, value in env.items():
            upper = str(name).upper()
            if upper in RISKY_ENV or upper.startswith(RISKY_ENV_PREFIXES):
                key = f"env {upper}"
                scan.own[key] = _digest(value)
                scan.own_shown[key] = f"{name} set to {short(str(value))}"
    for name in CODE_SETTINGS:
        if data.get(name):
            key = f"setting {name}"
            scan.own[key] = _digest(data[name])
            scan.own_shown[key] = f"{name} {short(json.dumps(data[name]))}"
    if data.get("enableAllProjectMcpServers") is True:
        scan.own["setting enableAllProjectMcpServers"] = "1"
        scan.own_shown["setting enableAllProjectMcpServers"] = "enableAllProjectMcpServers turned on"
    if data.get("disableAllHooks") is True:
        scan.own["hooks-off"] = "1"


def _toml_facts(text: str, scan: FileScan) -> None:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        data = tomllib.loads(text)
    except ValueError:
        scan.error = "could not be read as TOML (duplicate or invalid keys)"
        return
    notify = data.get("notify")
    if notify:
        scan.own["setting notify"] = _digest(notify)
        scan.own_shown["setting notify"] = f"notify runs {short(json.dumps(notify))}"
    scan.server_env = _server_envs(data.get("mcp_servers"))


def _agent_md_facts(label: str, text: str, scan: FileScan) -> None:
    match = re.match(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", text, re.DOTALL)
    if match is None:
        return
    try:
        import yaml

        data = yaml.safe_load(match.group(1))
    except Exception:  # noqa: BLE001
        scan.error = "its frontmatter could not be read"
        return
    if not isinstance(data, dict):
        return
    for name in ("hooks", "mcpServers"):
        if data.get(name):
            key = f"hook agent-md {name} {_digest(data[name])}"
            scan.own[key] = "1"
            scan.own_shown[key] = f"{name} in {label} frontmatter: {short(json.dumps(data[name], default=str))}"


def _skylos_entries(data: dict[str, Any], agent: str) -> list[dict[str, Any]]:
    from skylos.core.skylos_hooks import looks_like_skylos_hook

    found = []
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return found
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            if agent == "cursor":
                handlers = [group]
            else:
                handlers = group.get("hooks") if isinstance(group.get("hooks"), list) else []
            for handler in handlers:
                if not isinstance(handler, dict) or not looks_like_skylos_hook(handler.get("command")):
                    continue
                found.append({"event": event, "matcher": group.get("matcher"),
                              "command": handler.get("command"), "type": handler.get("type"),
                              "timeout": handler.get("timeout"),
                              "loop_limit": handler.get("loop_limit")})  # fmt: skip
    return found


def _server_envs(servers: Any) -> dict[str, Any]:
    if not isinstance(servers, dict):
        return {}
    return {str(name): entry.get("env") for name, entry in servers.items()
            if isinstance(entry, dict) and isinstance(entry.get("env"), dict)}  # fmt: skip


def _attach_server_env(scan: FileScan) -> None:
    for server in scan.servers:
        env = scan.server_env.get(str(server.get("name")))
        if isinstance(env, dict) and env:
            server["env"] = {str(k): str(v) for k, v in env.items()}


def _settings_json(scan: FileScan) -> str:
    parsed = parse_json(scan.text or "{}")
    if parsed is None or not isinstance(parsed[0], dict):
        return "{}"
    return json.dumps({"env": parsed[0].get("env", {})})


def _servers_json(servers: Any) -> str:
    if not isinstance(servers, dict):
        servers = {}
    return json.dumps({"mcpServers": servers})


def _scan_for(item: Any, by_mirror: dict[str, str], scans: dict[str, FileScan]):
    if not isinstance(item, dict):
        return None
    label = by_mirror.get(str(item.get("file") or "").replace(os.sep, "/"))
    if label is None:
        return None
    return scans[label]


def _agent_files(directory: Path, label: str) -> list[ConfigFile]:
    try:
        found = sorted(p for p in directory.glob("*.md") if p.is_file())[:MAX_AGENT_FILES]
    except OSError:
        return []
    return [ConfigFile(f"{label}/{p.name}", p, "", "agent-md") for p in found]


def _kind(rel: str) -> str:
    if rel.endswith(".toml"):
        return "toml"
    return "json"


def _strip_jsonc(text: str) -> str:
    out = []
    index = 0
    quote = False
    while index < len(text):
        char = text[index]
        if quote:
            out.append(char)
            if char == "\\" and index + 1 < len(text):
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                quote = False
            index += 1
            continue
        if char == '"':
            quote = True
            out.append(char)
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        else:
            out.append(char)
        index += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _project_keys(root: Path) -> list[str]:
    keys = [str(root)]
    with contextlib.suppress(OSError):
        keys.append(str(root.resolve()))
    return list(dict.fromkeys(keys))


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
    "config_dirs",
    "config_files",
    "engine_ready",
    "entries",
    "guarded_file",
    "home_dir",
    "installs_cleanly",
    "load_snapshot",
    "needs_approval",
    "parse_json",
    "read_config",
    "remember_pending",
    "scan_files",
    "scan_texts",
    "update_snapshot",
]
