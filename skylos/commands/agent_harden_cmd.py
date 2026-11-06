"""``skylos agent harden``: each agent's own settings that keep it away from
credentials and limit it to the MCP servers this project pins.

Policy and audit, not protection: Skylos writes the agents' native settings
and enforces none of them. Claude Code's permission rules cover its own file
tools and the file commands it recognizes, not a script the agent runs; its
sandbox covers shell commands, not hooks, MCP servers or the status line.

Sources for every key (fetched 5-6 Nov 2026):
https://code.claude.com/docs/en/sandboxing (``sandbox.credentials.files``,
``failIfUnavailable``, ``allowUnsandboxedCommands``),
https://code.claude.com/docs/en/permissions (``Read(~/...)`` / ``Read(./...)``),
https://code.claude.com/docs/en/managed-mcp (``allowedMcpServers`` with
``serverCommand`` exact arrays and ``serverUrl``),
https://cursor.com/docs/reference/sandbox (``readBoundary``, Cursor 3.23+),
https://learn.chatgpt.com/docs/agent-approvals-security.md (Codex sandbox and
network; it documents no read deny list and no MCP allowlist keys, so none is
generated).

``--print`` (the default) writes nothing. ``--write`` merges the JSON files
only from an interactive terminal after a yes, so an agent cannot run it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

HOME_CREDENTIALS = ("~/.ssh", "~/.aws", "~/.config/gcloud", "~/.npmrc", "~/.pypirc", "~/.claude.json")
PROJECT_SECRETS = ("./.env", "./.env.*")
LOOKUP_SECONDS = 20.0
CODEX_TOML = (
    'sandbox_mode = "workspace-write"\n'
    'approval_policy = "on-request"\n\n'
    "[sandbox_workspace_write]\n"
    "network_access = false\n"
)
FRAMING = (
    "Policy and audit, not protection: these are each agent's own settings, and Skylos "
    "enforces none of them. A script the agent runs can still read files directly unless "
    "the agent's OS sandbox is on and blocks the path."
)


def add_agent_harden_parser(agent_sub) -> None:
    parser = agent_sub.add_parser(
        "harden",
        help="Print each agent's own settings that deny credential reads and pin MCP servers",
        description=(
            "Generate Claude Code, Cursor and Codex settings: credential-file denies, "
            "Claude Code's sandbox, and an exact-pinned allowedMcpServers list from this "
            "project's MCP configs. Prints only, unless you run --write yourself."
        ),
    )
    parser.add_argument("--path", default=".", help="Project root (default: .).")
    parser.add_argument("--print", dest="write", action="store_false",
                        help="Print the settings and write nothing (default).")  # fmt: skip
    parser.add_argument("--write", dest="write", action="store_true",
                        help="Merge the JSON settings into their files (asks first; needs a terminal).")  # fmt: skip
    parser.add_argument("--offline", action="store_true",
                        help="Do not look up versions; unpinned MCP servers are left out.")  # fmt: skip
    parser.set_defaults(write=False)


def run_agent_harden_command(args: argparse.Namespace, *, stdin=None, stdout=None,
                             env: dict[str, str] | None = None, sources: Any = None) -> int:  # fmt: skip
    import os

    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    env = dict(os.environ) if env is None else env
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        stdout.write(f"skylos agent harden: {args.path} is not a directory\n")
        return 2
    plan = build_plan(root, env, offline=args.offline, sources=sources)
    stdout.write(render_plan(plan))
    if not args.write:
        return 0
    if not getattr(stdin, "isatty", lambda: False)():
        stdout.write("\nNot written: --write needs you at a terminal (it never runs for an agent).\n")
        return 2
    targets = ", ".join(str(t["path"]) for t in plan["writes"])
    stdout.write(f"\nMerge these settings into {targets}? [y/N] ")
    stdout.flush()
    if stdin.readline().strip().lower() not in ("y", "yes"):
        stdout.write("Nothing written.\n")
        return 1
    failed = 0
    for target in plan["writes"]:
        problem = merge_file(Path(target["path"]), target["settings"])
        if problem:
            failed += 1
            stdout.write(f"- {target['path']}: not written ({problem})\n")
        else:
            stdout.write(f"- {target['path']}: updated\n")
    stdout.write("Codex: add the TOML lines above to ~/.codex/config.toml yourself.\n")
    return 1 if failed else 0


def build_plan(root: Path, env: dict[str, str], *, offline: bool = False,
               sources: Any = None) -> dict[str, Any]:  # fmt: skip
    from skylos.commands.hook_agent_configs import home_dir

    home = home_dir(env) or Path.home()
    servers, notes = pinned_servers(root, env, offline=offline, sources=sources)
    user = {
        "permissions": {"deny": [f"Read({path}/**)" if _is_dir_like(path) else f"Read({path})"
                                 for path in HOME_CREDENTIALS]},
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "credentials": {"files": [{"path": path, "mode": "deny"} for path in HOME_CREDENTIALS]},
        },
    }  # fmt: skip
    project: dict[str, Any] = {"permissions": {"deny": [f"Read({path})" for path in PROJECT_SECRETS]}}
    if servers:
        project["allowedMcpServers"] = servers
    return {
        "root": root,
        "user": user,
        "project": project,
        "cursor": {"readBoundary": "workspace"},
        "notes": notes,
        "writes": [
            {"path": home / ".claude" / "settings.json", "settings": user},
            {"path": root / ".claude" / "settings.json", "settings": project},
            {"path": root / ".cursor" / "sandbox.json", "settings": {"readBoundary": "workspace"}},
        ],
    }


def pinned_servers(root: Path, env: dict[str, str], *, offline: bool,
                   sources: Any = None) -> tuple[list[dict[str, Any]], list[str]]:  # fmt: skip
    """``allowedMcpServers`` entries for this project's MCP servers, and one
    line per server saying what was pinned or why it was left out."""
    from skylos.commands.hook_agent_configs import (
        ENGINE_MISSING,
        config_files,
        scan_files,
    )
    from skylos.commands.hook_cmd import _state_root
    from skylos.commands.hook_mcp import ALLOW, NOTE, vet_servers

    files = [cf for cf in config_files(root, None) if not cf.label.endswith(("tasks.json", "hooks.json"))]
    scans = scan_files(files, root)
    if scans is None:
        return [], [f"MCP servers not read: {ENGINE_MISSING}."]
    servers = [{**s, "_label": label} for label, scan in scans.items() for s in scan.servers]
    findings = [{**f, "_label": label} for label, scan in scans.items() for f in scan.findings]
    if not servers:
        return [], ["No MCP servers configured in this project."]
    outcomes = vet_servers(servers, label="", findings=findings, root=root, cwd=root, env=env,
                           state_root=_state_root(root), sources=sources,
                           deadline=time.monotonic() + LOOKUP_SECONDS, notes=False,
                           offline=offline)  # fmt: skip
    entries: list[dict[str, Any]] = []
    notes = []
    for server, outcome in zip(servers, outcomes):
        where = f"{server['_label']} '{server.get('name')}'"
        argv = server.get("argv")
        if server.get("url") and not argv:
            entries.append({"serverUrl": server["url"]})
            notes.append(f"{where}: allowed by URL {server['url']}")
        elif not isinstance(argv, list) or not argv:
            notes.append(f"{where}: left out (its command could not be read)")
        elif outcome.wrapped:
            notes.append(f"{where}: left out (started through a wrapper such as timeout, sudo or "
                         "sh -c; Skylos allowlists only the launcher itself)")  # fmt: skip
        elif outcome.decision in (ALLOW, NOTE):
            entries.append({"serverCommand": argv})
            notes.append(f"{where}: allowed as {' '.join(argv)}")
        elif outcome.pinned:
            entries.append({"serverCommand": outcome.pinned})
            notes.append(f"{where}: pinned to {' '.join(outcome.pinned)} (checked for malware and "
                         "release age); change the config to the same command, the allowlist "
                         "matches it exactly")  # fmt: skip
        elif offline and outcome.kind == "unpinned":
            notes.append(f"{where}: left out (not pinned; run without --offline to pin it)")
        else:
            notes.append(f"{where}: left out: {outcome.text}")
    unique = list({json.dumps(e, sort_keys=True): e for e in entries}.values())
    return unique, notes


PERMISSIONS_NOTE = (
    "- permissions.deny: Claude's Read/Edit tools and the file commands it recognizes "
    "(cat, head, sed...) refuse these paths. A Python or Node script the agent runs does not."
)
SANDBOX_NOTE = (
    "- sandbox: shell commands run in Claude Code's OS sandbox, which cannot read the "
    "credentials.files paths; failIfUnavailable stops Claude Code instead of running "
    "unsandboxed. Hooks, MCP servers, the status line and apiKeyHelper still run outside it."
)
ALLOWLIST_NOTE = (
    "- allowedMcpServers: only these exact commands and URLs start in this project, "
    "including servers you added in other scopes. Anyone who can edit a settings file can "
    "widen it; an admin makes it binding with allowManagedMcpServersOnly in managed settings."
)
CURSOR_NOTE = (
    "- The agent asks before reading files outside this folder. Cursor's MCP allowlist is "
    "admin policy matched by name, so Skylos generates none: pin versions in .cursor/mcp.json."
)
CODEX_NOTE = (
    "- Writes stay in the workspace and the network stays off. Codex documents no read deny "
    "list, so it can still read ~/.ssh and ~/.aws; no Codex MCP allowlist is generated (its "
    "requirements.toml keys are not documented)."
)


def render_plan(plan: dict[str, Any]) -> str:
    out = [f"Skylos agent hardening for {plan['root']}", FRAMING, ""]
    out += ["Claude Code: ~/.claude/settings.json (your user settings)",
            json.dumps(plan["user"], indent=2), PERMISSIONS_NOTE, SANDBOX_NOTE, ""]  # fmt: skip
    out += ["Claude Code: .claude/settings.json (this project)",
            json.dumps(plan["project"], indent=2)]  # fmt: skip
    if plan["project"].get("allowedMcpServers"):
        out.append(ALLOWLIST_NOTE)
    out += ["", "Cursor: .cursor/sandbox.json (this project; Cursor 3.23+)",
            json.dumps(plan["cursor"], indent=2), CURSOR_NOTE, "",
            "Codex: ~/.codex/config.toml (printed only)", CODEX_TOML.rstrip(), CODEX_NOTE, "",
            "MCP servers in this project:"]  # fmt: skip
    out += [f"- {note}" for note in plan["notes"]]
    out.append("")
    out.append("Run `skylos agent harden --write` yourself in a terminal to merge the JSON settings.")
    return "\n".join(out) + "\n"


def merge_file(path: Path, settings: dict[str, Any]) -> str | None:
    from skylos.core.safe_cache_io import read_text_no_symlink, write_text_no_symlink

    current: Any = {}
    if path.exists():
        text = read_text_no_symlink(path, max_bytes=4_000_000)
        if text is None:
            return "it is a symlink, too large or unreadable"
        if text.strip():
            try:
                current = json.loads(text)
            except ValueError:
                return "it is not valid JSON; fix it first"
    if not isinstance(current, dict):
        return "its top level is not an object"
    merged = merge_settings(current, settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not write_text_no_symlink(path, json.dumps(merged, indent=2) + "\n"):
        return "could not write it"
    return None


def merge_settings(current: dict[str, Any], add: dict[str, Any]) -> dict[str, Any]:
    """Lists gain the missing items, objects merge, other values are set."""
    merged = dict(current)
    for key, value in add.items():
        old = merged.get(key)
        if isinstance(value, dict) and isinstance(old, dict):
            merged[key] = merge_settings(old, value)
        elif isinstance(value, list) and isinstance(old, list):
            seen = {json.dumps(item, sort_keys=True) for item in old}
            merged[key] = old + [item for item in value if json.dumps(item, sort_keys=True) not in seen]
        else:
            merged[key] = value
    return merged


def _is_dir_like(path: str) -> bool:
    return path in ("~/.ssh", "~/.aws", "~/.config/gcloud")


__all__ = [
    "add_agent_harden_parser",
    "build_plan",
    "merge_settings",
    "pinned_servers",
    "render_plan",
    "run_agent_harden_command",
]
