"""``skylos agent install-hooks``: wire ``skylos hook`` into coding agents.

Merges Skylos entries into the agent's hook config without touching other
hooks, idempotently. ``--uninstall`` removes only Skylos entries.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from skylos.core.safe_cache_io import read_text_no_symlink, write_text_no_symlink

AGENTS = ("claude", "codex", "cursor")
MAX_CONFIG_BYTES = 2_000_000
OUR_COMMAND_RE = re.compile(
    r"(?:^|[\s/\\'\"])skylos(?:\.exe|\.entry)?['\"]?\s+hook\s+"
    r"(?:post-edit|pre-read|pre-bash|stop)\b"
)
PROBE_TIMEOUT_SECONDS = 30
# Local hook state, never meant for version control. ``.skylos/`` itself also
# holds committed files (config, AI contract, rules), so only these paths.
GITIGNORE_ENTRIES = (".skylos/cache/", ".skylos/agent-session.*", ".skylos/hook.log*")
GITIGNORE_HEADER = "# Skylos agent hooks: local session state, log and cache"
# What the wrapper prints when the Skylos command itself cannot run (missing,
# too old, broken). Claude Code treats exit 2 as "block", and Cursor treats
# empty output from a permission hook as "deny", so the wrapper must never
# surface either.
CURSOR_PERMISSION_FALLBACK = '{"permission":"allow"}'

Probe = Callable[[Sequence[str]], "str | None"]

# (event name in the agent's config, matcher or None, skylos hook, timeout s)
CLAUDE_HOOKS = (
    ("PreToolUse", "Read", "pre-read", 15),
    ("PreToolUse", "Bash|PowerShell", "pre-bash", 30),
    ("PostToolUse", "Edit|Write|MultiEdit", "post-edit", 120),
    ("Stop", None, "stop", 180),
)
CODEX_HOOKS = (
    ("PreToolUse", "^Bash$", "pre-bash", 30),
    ("PostToolUse", "apply_patch|Edit|Write", "post-edit", 120),
    ("Stop", None, "stop", 180),
)
CURSOR_HOOKS = (
    ("beforeReadFile", None, "pre-read", 15),
    ("beforeShellExecution", None, "pre-bash", 30),
    ("afterFileEdit", None, "post-edit", 120),
    ("stop", None, "stop", 180),
)
STATUS_MESSAGES = {
    "pre-read": "Skylos: checking file for secrets",
    "pre-bash": "Skylos: checking packages",
    "post-edit": "Skylos: verifying edit",
    "stop": "Skylos: checking session edits",
}
CURSOR_STOP_LOOP_LIMIT = 3


def add_install_hooks_parser(agent_sub) -> None:
    parser = agent_sub.add_parser(
        "install-hooks",
        help="Install Skylos agent-loop hooks for Claude Code, Codex, or Cursor",
        description=(
            "Merge Skylos hooks (post-edit verify, secret-read guard, "
            "package-install guard, stop gate) into the agent's hook config. "
            "Existing hooks are preserved; re-running is a no-op."
        ),
    )
    agent = parser.add_mutually_exclusive_group()
    agent.add_argument("--claude", dest="agent", action="store_const", const="claude")
    agent.add_argument("--codex", dest="agent", action="store_const", const="codex")
    agent.add_argument("--cursor", dest="agent", action="store_const", const="cursor")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--project",
        dest="scope",
        action="store_const",
        const="project",
        help="Write the project config (default).",
    )
    scope.add_argument(
        "--user",
        dest="scope",
        action="store_const",
        const="user",
        help="Write the user-level config in your home directory.",
    )
    parser.add_argument(
        "--uninstall", action="store_true", help="Remove Skylos hooks only."
    )
    parser.add_argument(
        "--path", default=".", help="Project root for --project (default: .)."
    )
    parser.add_argument(
        "--skylos-bin",
        default=None,
        help=(
            "Skylos executable the hooks run. Default: the Skylos running this "
            "command, by absolute path. A relative path is made absolute; a bare "
            "name (e.g. `skylos`) is kept as-is and resolved on the agent's PATH."
        ),
    )
    parser.add_argument(
        "--no-check",
        dest="check_bin",
        action="store_false",
        default=True,
        help="Do not run the hook command once to confirm it supports `skylos hook`.",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print the resulting config only."
    )
    parser.set_defaults(agent=None, scope=None, check_bin=True)


def run_install_hooks_command(
    args: argparse.Namespace,
    *,
    print_func: Callable[[str], None] = print,
    home: Path | None = None,
    which: Callable[[str], str | None] = shutil.which,
    probe: Probe | None = None,
) -> int:
    agent = args.agent or "claude"
    scope = args.scope or "project"
    home = home if home is not None else Path.home()
    config_path = config_path_for(agent, scope, Path(args.path), home)

    existing, error = _load_config(config_path)
    if error:
        print_func(f"Refusing to modify {config_path}: {error}")
        return 1

    version = None
    if args.uninstall:
        updated, removed = uninstall_hooks(existing, agent)
        added = 0
    else:
        check = getattr(args, "check_bin", True)
        command, version, problem = resolve_skylos_command(
            args.skylos_bin, which=which, probe=(probe or probe_hook_support) if check else None
        )
        if command is None:
            print_func(problem or "Cannot find a Skylos that supports `skylos hook`.")
            return 1
        updated, removed, added = install_hooks(existing, agent, command)

    rendered = json.dumps(updated, indent=2) + "\n"
    if args.dry_run:
        print_func(rendered.rstrip("\n"))
        return 0

    if updated == existing and config_path.exists():
        state = "not installed" if args.uninstall else "already installed"
        print_func(f"Skylos hooks {state} in {config_path} (no change).")
        return 0
    if args.uninstall and not config_path.exists():
        print_func(f"No {config_path}; nothing to uninstall.")
        return 0

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print_func(f"Cannot create {config_path.parent}: {exc}")
        return 1
    if not write_text_no_symlink(config_path, rendered):
        print_func(
            f"Cannot safely write {config_path} (symlink or not a regular file)."
        )
        return 1

    if args.uninstall:
        print_func(f"Removed {removed} Skylos hook(s) from {config_path}.")
    else:
        suffix = f" (skylos {version})" if version else ""
        print_func(f"Installed {added} Skylos hook(s) in {config_path}{suffix}.")
        if scope == "project":
            note = ensure_gitignored(config_path.parent.parent)
            if note:
                print_func(note)
            print_func(
                f"{config_path.relative_to(config_path.parent.parent)} is usually "
                "committed. The hook command uses this machine's Skylos path; on a "
                "machine without it the hooks do nothing (they never block). "
                "Teammates who want the checks run `skylos agent install-hooks` "
                "themselves, or install with `--skylos-bin skylos` to use PATH."
            )
        for line in _next_steps(agent):
            print_func(line)
        print_func(
            "Large repo? Run `skylos agent warm-cache` once so the first edit "
            "check does not build the project index."
        )
    return 0


def config_path_for(agent: str, scope: str, project: Path, home: Path) -> Path:
    base = home if scope == "user" else _project_root(project)
    if agent == "claude":
        return base / ".claude" / "settings.json"
    if agent == "codex":
        return base / ".codex" / "hooks.json"
    return base / ".cursor" / "hooks.json"


def install_hooks(
    config: dict[str, Any], agent: str, skylos_bin: str | Sequence[str]
) -> tuple[dict[str, Any], int, int]:
    cleaned, removed = uninstall_hooks(config, agent)
    hooks = cleaned.setdefault("hooks", {})
    added = 0
    if agent == "cursor":
        cleaned.setdefault("version", 1)
        for event, _matcher, name, timeout in CURSOR_HOOKS:
            entry: dict[str, Any] = {
                "command": hook_command(skylos_bin, name, agent),
                "timeout": timeout,
            }
            if name == "stop":
                entry["loop_limit"] = CURSOR_STOP_LOOP_LIMIT
            hooks.setdefault(event, []).append(entry)
            added += 1
        return cleaned, removed, added

    specs = CLAUDE_HOOKS if agent == "claude" else CODEX_HOOKS
    for event, matcher, name, timeout in specs:
        handler: dict[str, Any] = {
            "type": "command",
            "command": hook_command(skylos_bin, name, agent),
            "timeout": timeout,
        }
        if agent == "codex":
            handler["statusMessage"] = STATUS_MESSAGES[name]
        group: dict[str, Any] = {"hooks": [handler]}
        if matcher is not None:
            group = {"matcher": matcher, **group}
        hooks.setdefault(event, []).append(group)
        added += 1
    return cleaned, removed, added


def uninstall_hooks(config: dict[str, Any], agent: str) -> tuple[dict[str, Any], int]:
    updated = json.loads(json.dumps(config))  # deep copy, JSON-only values
    hooks = updated.get("hooks")
    if not isinstance(hooks, dict):
        return updated, 0
    removed = 0
    for event in list(hooks):
        entries = hooks[event]
        if not isinstance(entries, list):
            continue
        kept = []
        for entry in entries:
            if agent == "cursor":
                if _is_ours(entry):
                    removed += 1
                    continue
                kept.append(entry)
                continue
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                kept.append(entry)
                continue
            handlers = [h for h in entry["hooks"] if not _is_ours(h)]
            dropped = len(entry["hooks"]) - len(handlers)
            removed += dropped
            if dropped and not handlers:
                continue
            kept.append({**entry, "hooks": handlers})
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if not hooks and agent == "claude":
        del updated["hooks"]
    return updated, removed


def hook_command(skylos_bin: str | Sequence[str], name: str, agent: str) -> str:
    """Shell command for one hook, wrapped so a broken Skylos never blocks.

    ``skylos_bin`` is the argv prefix (``["/venv/bin/skylos"]`` or
    ``[python, "-m", "skylos.entry"]``); a string is a single executable.
    Skylos itself always exits 0 and puts decisions in stdout JSON. A non-zero
    exit therefore means the command could not run at all (not installed on
    this machine, an older Skylos without ``hook``, a broken venv), and the
    fallback turns that into "no opinion" instead of an argparse exit 2.
    """
    parts = [skylos_bin] if isinstance(skylos_bin, str) else list(skylos_bin)
    prefix = " ".join(_quote(part) for part in parts)
    return f"{prefix} hook {name} --client {agent} || {_fallback(name, agent)}"


def _fallback(name: str, agent: str) -> str:
    if agent == "cursor" and name in {"pre-read", "pre-bash"}:
        payload = CURSOR_PERMISSION_FALLBACK
    elif name == "stop":
        payload = "{}"  # Codex requires JSON from Stop
    else:
        return "exit 0"
    if os.name == "nt":
        return f"echo {payload}"
    return f"echo '{payload}'"


def _quote(part: str) -> str:
    if os.name == "nt":
        return f'"{part}"' if re.search(r'[\s&|<>^"]', part) else part
    return shlex.quote(part)


def resolve_skylos_command(
    skylos_bin: str | None,
    *,
    which: Callable[[str], str | None] = shutil.which,
    probe: Probe | None = None,
) -> tuple[list[str] | None, str | None, str | None]:
    """Pick the argv prefix the hooks run, and check it supports ``hook``.

    Returns ``(command, version, problem)``; ``command`` is None on failure.
    """
    candidates: list[list[str]] = []
    if skylos_bin:
        raw = os.path.expanduser(skylos_bin)
        if os.sep in raw or (os.altsep and os.altsep in raw):
            candidates.append([os.path.abspath(raw)])
        else:
            candidates.append([raw])  # bare name: explicitly "use PATH"
    else:
        script = _current_console_script()
        if script is not None:
            candidates.append([script])
        candidates.append([sys.executable, "-m", "skylos.entry"])
        on_path = which("skylos")
        if on_path:
            candidates.append([on_path])

    if probe is None:
        return candidates[0], None, None
    failures = []
    for candidate in candidates:
        version = probe(candidate)
        if version is not None:
            return candidate, version or None, None
        failures.append(" ".join(candidate))
    return (
        None,
        None,
        "Refusing to install: none of these supports `skylos hook` "
        f"({'; '.join(failures)}). An older Skylos on the agent's PATH would "
        "fail every hook. Upgrade it (`pip install -U skylos`) or pass "
        "--skylos-bin /path/to/new/skylos.",
    )


def _current_console_script() -> str | None:
    argv0 = sys.argv[0] if sys.argv else ""
    if Path(argv0).name.lower() not in {"skylos", "skylos.exe"}:
        return None
    # absolute(), not resolve(): keep pipx/venv symlinks that survive upgrades.
    path = Path(argv0).absolute()
    return str(path) if path.is_file() else None


def probe_hook_support(command: Sequence[str]) -> str | None:
    """Run ``<command> hook help``; return the version ("" if unknown) or None."""
    try:
        proc = subprocess.run(
            [*command, "hook", "help"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or "skylos hook" not in proc.stdout:
        return None
    if "recheck" not in proc.stdout:
        return None  # predates the policy the hook messages refer to
    try:
        version = subprocess.run(
            [*command, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    match = re.search(r"\d+\.\d+[\w.+-]*", version or "")
    return match.group(0) if match else ""


def ensure_gitignored(project: Path) -> str | None:
    """Keep hook state out of Git. Returns a message when something changed."""
    if not (project / ".git").exists():
        return None
    if _already_ignored(project):
        return None
    gitignore = project / ".gitignore"
    if gitignore.exists():
        text = read_text_no_symlink(gitignore, max_bytes=MAX_CONFIG_BYTES, encoding="utf-8")
        if text is None:
            return f"Could not update {gitignore}; add {', '.join(GITIGNORE_ENTRIES)}."
        present = {line.strip() for line in text.splitlines()}
        missing = [entry for entry in GITIGNORE_ENTRIES if entry not in present]
        if not missing:
            return None
        block = ("" if text.endswith("\n") or not text else "\n") + "\n".join(
            [GITIGNORE_HEADER, *missing]
        ) + "\n"
        if not write_text_no_symlink(gitignore, text + block):
            return f"Could not update {gitignore}; add {', '.join(missing)}."
        return f"Added {', '.join(missing)} to {gitignore}."
    local = project / ".skylos" / ".gitignore"
    if local.exists():
        return None
    try:
        local.parent.mkdir(exist_ok=True)
    except OSError:
        return None
    body = "\n".join(
        [GITIGNORE_HEADER, *(e.replace(".skylos/", "", 1) for e in GITIGNORE_ENTRIES)]
    )
    if write_text_no_symlink(local, body + "\n"):
        return f"Wrote {local} so hook state stays out of Git."
    return None


def _already_ignored(project: Path) -> bool:
    for path in (".skylos/cache/x", ".skylos/agent-session.json", ".skylos/hook.log"):
        try:
            proc = subprocess.run(
                ["git", "check-ignore", "--no-index", "-q", "--", path],
                cwd=str(project),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if proc.returncode != 0:
            return False
    return True


def _is_ours(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    command = entry.get("command")
    return isinstance(command, str) and bool(OUR_COMMAND_RE.search(command))


def _load_config(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {}, None
    text = read_text_no_symlink(path, max_bytes=MAX_CONFIG_BYTES, encoding="utf-8")
    if text is None:
        return {}, "file is a symlink, too large, or unreadable"
    if not text.strip():
        return {}, None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {}, f"invalid JSON ({exc.msg} at line {exc.lineno}); fix it first"
    if not isinstance(data, dict):
        return {}, "top-level JSON value is not an object"
    if "hooks" in data and not isinstance(data["hooks"], dict):
        return {}, '"hooks" is not an object'
    return data, None


def _project_root(path: Path) -> Path:
    start = path.expanduser().resolve()
    for parent in (start, *start.parents):
        if (parent / ".git").exists():
            return parent
    return start


def _next_steps(agent: str) -> list[str]:
    if agent == "claude":
        return [
            "Claude Code picks up settings changes on the next session; "
            "run /hooks to review them.",
            "Turn one off: SKYLOS_HOOKS_DISABLE=pre-read (comma list or 'all').",
        ]
    if agent == "codex":
        return [
            "Codex skips new hooks until you trust them: open /hooks in Codex "
            "and trust the Skylos entries.",
        ]
    return [
        "Cursor reloads hooks.json automatically. afterFileEdit cannot send "
        "feedback, so Cursor sees Skylos findings at stop as a follow-up message.",
    ]
