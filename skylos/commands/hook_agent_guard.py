"""The hook side of the agent-config guard.

* pre-bash: ``claude|codex|gemini mcp add`` (all forms) is vetted server by
  server; a shell command that writes an agent config file directly, or
  removes Skylos's own hooks, needs the user.
* pre-edit: an edit to an agent config file is replayed on the current text;
  ca9 reads both versions. New or changed MCP servers are vetted, and new
  commands that run on their own (agent hooks, ``statusLine``,
  ``apiKeyHelper``, ``folderOpen`` tasks), endpoint overrides, removal of
  Skylos's own hooks and ``disableAllHooks`` need the user.
* post-edit / post-bash: a change Skylos checked is folded into the snapshot.
* session start: changes to the files since the snapshot are reported (one
  line each), and configured MCP servers are re-checked (what an unpinned one
  would fetch now), at most once per session or hour within a time budget.

Decisions come back as ``(decision, text)``; ``hook_cmd`` turns them into the
agent's output.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.commands.hook_agent_configs import (
    ENGINE_MISSING,
    ConfigFile,
    accept_pending,
    change_line,
    changes,
    config_files,
    engine_ready,
    entries,
    guarded_file,
    home_dir,
    installs_cleanly,
    load_snapshot,
    needs_approval,
    read_config,
    remember_pending,
    scan_files,
    scan_texts,
    update_snapshot,
)
from skylos.commands.hook_mcp import (
    ALLOW,
    ASK,
    DENY,
    NOTE,
    RANK,
    Outcome,
    mcp_additions,
    plugin_installs,
    server_from_addition,
    uninstalls_skylos_hooks,
    vet_servers,
    worst,
)

SESSION_SECONDS = 8.0
RECHECK_SECONDS = 3600
MAX_LINES = 10
UNCHECKED = "Skylos could not check the MCP servers or agent hooks"
EDIT_TOOLS = frozenset({"Edit", "Write", "MultiEdit"})
CLI_WRITES = {
    "claude": (".mcp.json", "~/.claude.json", "~/.claude.json (this project)"),
    "codex": ("~/.codex/config.toml",),
    "gemini": (".gemini/settings.json", "~/.gemini/settings.json"),
}


@dataclass
class Planned:
    path: Path
    text: str
    known: bool = True


def check_agent_bash(command: str, cwd: Path, root: Path, deps: Any, payload: dict[str, Any],
                     record: dict[str, Any]) -> tuple[str, str] | None:  # fmt: skip
    from skylos.commands.hook_config_writes import config_writes
    from skylos.commands.hook_shell_commands import walk

    commands, unknown = walk(command, cwd)
    home = home_dir(deps.env)
    additions = mcp_additions(commands, unknown)
    plugins = plugin_installs(commands, unknown)
    writes = config_writes(commands, root, home)
    uninstall = uninstalls_skylos_hooks(commands)
    if not additions and not writes and not uninstall and not plugins:
        return None
    try:
        return _bash_verdict(additions, plugins, writes, uninstall, cwd, root, home, deps, payload,
                             record)  # fmt: skip
    except Exception:  # noqa: BLE001
        return ASK, f"{UNCHECKED} this command changes; could not verify it."


def _bash_verdict(additions, plugins, writes, uninstall, cwd, root, home, deps, payload, record):
    from skylos.commands.hook_cmd import _state_root

    policy = _install_policy(root)
    outcomes: list[Outcome] = []
    if uninstall:
        outcomes.append(Outcome("command", "", ASK, "It removes Skylos's own agent hooks."))
    if writes:
        outcomes.append(Outcome("command", "", ASK,
                                f"It writes {', '.join(writes[:3])} directly, so Skylos cannot "
                                "check what it adds; use the edit tool instead."))  # fmt: skip
    outcomes += [Outcome("command", "", ASK, f"{text[0].upper()}{text[1:]}.") for text in plugins]
    for addition in additions:
        if addition.server is None:
            who = f"{addition.client} mcp"
            if addition.name != "?":
                who = f"'{addition.name}'"
            outcomes.append(Outcome("command", addition.name, policy.on_unverified,
                                    f"{who}: could not verify: {addition.problem}."))  # fmt: skip
    servers = [a for a in additions if a.server is not None]
    expected: dict[str, dict[str, str | None]] = {}
    if servers:
        if not engine_ready():
            outcomes += [Outcome("command", a.name, policy.on_unverified,
                                 f"'{a.name}': could not verify ({ENGINE_MISSING}).") for a in servers]  # fmt: skip
        else:
            mirrored, findings = _mirror_servers([server_from_addition(a) for a in servers], root)
            found = vet_servers(mirrored, label="command", findings=findings, root=root, cwd=cwd,
                                env=deps.env, state_root=_state_root(root),
                                sources=deps.supply_chain_sources, record=record)  # fmt: skip
            for addition, entry, outcome in zip(servers, mirrored, found):
                if outcome.pinned and addition.render is not None:
                    outcome.text += f"\n  Use: {addition.render(outcome.pinned)}"
                for label in CLI_WRITES.get(addition.client, ()):
                    expected.setdefault(label, {})[f"server {addition.name}"] = entry["_digest"]
            outcomes += found
    record["agent_config"] = len(outcomes)
    decision = worst(outcomes)
    if decision in (ALLOW, NOTE) and expected and not writes:
        remember_pending(_state_root(root), _token(payload), expected)
    return _verdict(decision, outcomes, "this command")


def check_agent_edit(payload: dict[str, Any], root: Path, deps: Any,
                     record: dict[str, Any]) -> tuple[str, str] | None:  # fmt: skip
    from skylos.commands.hook_cmd import _cwd

    home = home_dir(deps.env)
    planned = planned_writes(payload, _cwd(payload, root),
                             wanted=lambda path: bool(guarded_file(path, root, home)))  # fmt: skip
    guarded = [(p, guarded_file(p.path, root, home)) for p in planned]
    guarded = [(p, files) for p, files in guarded if files]
    if not guarded:
        return None
    labels = ", ".join(files[0].label for _p, files in guarded)
    record["agent_config"] = len(guarded)
    try:
        return _edit_verdict(guarded, labels, payload, root, deps, record)
    except Exception:  # noqa: BLE001
        return ASK, f"{UNCHECKED} this edit to {labels} changes; could not verify it."


def _edit_verdict(guarded, labels, payload, root, deps, record):
    from skylos.commands.hook_cmd import _cwd, _state_root

    policy = _install_policy(root)
    if not engine_ready():
        outcome = Outcome(labels, "", policy.on_unverified, f"Could not verify it ({ENGINE_MISSING}).")
        return _verdict(outcome.decision, [outcome], f"this edit to {labels}")
    outcomes: list[Outcome] = []
    expected: dict[str, dict[str, str | None]] = {}
    for plan, files in guarded:
        if not plan.known:
            outcomes.append(Outcome(files[0].label, "", policy.on_unverified,
                                    "Skylos could not work out the file this edit produces; "
                                    "could not verify it."))  # fmt: skip
            continue
        old_text = read_config(plan.path) or ""
        before = scan_texts([(cf, old_text) for cf in files], root) or {}
        after = scan_texts([(cf, plan.text) for cf in files], root) or {}
        for label in sorted(set(before) | set(after)):
            old_values, _shown = entries(before.get(label) or _empty())
            scan = after.get(label) or _empty()
            new_values, shown = entries(scan)
            if scan.error and plan.text.strip():
                outcomes.append(Outcome(label, "", policy.on_unverified,
                                        f"Skylos could not read {label} after this edit "
                                        f"({scan.error}); could not verify it."))  # fmt: skip
            found = changes(old_values, new_values, shown)
            if scan.dupes:
                found = [c for c in found if c.kind != "dupes"]
                outcomes.append(Outcome(label, "", ASK, f"{label}: {needs_approval_dupes()}."))
            if installs_cleanly(scan, root):
                found = [c for c in found if c.kind != "skylos"]
            for change in found:
                reason = needs_approval(change)
                if reason:
                    outcomes.append(Outcome(label, change.name, ASK, f"{label}: {reason}."))
            expected[label] = {c.key: new_values.get(c.key) for c in found if c.kind != "skylos"}
            expected[label].update({k: v for k, v in new_values.items() if k.startswith("skylos ")
                                    and old_values.get(k) != v})  # fmt: skip
            expected[label].update({k: None for k in old_values if k.startswith("skylos ")
                                    and k not in new_values})  # fmt: skip
            names = {c.name for c in found if c.kind == "server" and not c.removed}
            servers = [s for s in scan.servers if str(s.get("name")) in names]
            vetted = vet_servers(servers, label=label, findings=scan.findings, root=root,
                                 cwd=_cwd(payload, root), env=deps.env,
                                 state_root=_state_root(root), sources=deps.supply_chain_sources,
                                 record=record)  # fmt: skip
            for outcome in vetted:
                if outcome.pinned:
                    outcome.text += f"\n  Use: {_render_entry(label, outcome.pinned)}"
            outcomes += vetted
    decision = worst(outcomes)
    if decision != DENY and expected:
        remember_pending(_state_root(root), _token(payload), expected)
    return _verdict(decision, outcomes, f"this edit to {labels}")


def needs_approval_dupes() -> str:
    from skylos.commands.hook_agent_configs import Change

    return str(needs_approval(Change("dupes", "dupes", "", True, False)))


def accept_agent_action(payload: dict[str, Any], root: Path, deps: Any, *, edit: bool) -> None:
    """After a checked edit or command: fold exactly the checked change into
    the snapshot, so it is not reported at the next prompt."""
    from skylos.commands.hook_cmd import _state_root

    state_root = _state_root(root)
    token = _token(payload)
    pending = (load_snapshot(state_root).get("pending") or {}).get(token)
    if not isinstance(pending, dict):
        return
    labels = set((pending.get("files") or {}).keys())
    home = home_dir(deps.env)
    files = [cf for cf in config_files(root, home)
             if any(label == cf.label or label.startswith(cf.label + " (") for label in labels)]  # fmt: skip
    if not files:
        return
    scans = scan_files(files, root)
    if scans is None:
        return
    current = {label: entries(scan)[0] for label, scan in scans.items()}
    accept_pending(state_root, token, current)


def session_agent_check(payload: dict[str, Any], root: Path, deps: Any,
                        record: dict[str, Any]) -> str | None:  # fmt: skip
    from skylos.commands.hook_cmd import _session_id, _state_root

    state_root = _state_root(root)
    session = _session_id(payload)
    snapshot = load_snapshot(state_root)
    if not engine_ready():
        if snapshot.get("engine_note") == session:
            return None
        update_snapshot(state_root, lambda data: data.__setitem__("engine_note", session))
        return f"Skylos did not check agent configs or MCP servers: {ENGINE_MISSING}."
    deadline = time.monotonic() + SESSION_SECONDS
    home = home_dir(deps.env)
    scans = scan_files(config_files(root, home), root)
    if scans is None:
        return None
    current = {label: entries(scan) for label, scan in scans.items()}
    known = snapshot.get("files") or {}
    lines: list[str] = []
    changed: dict[str, set[str]] = {}
    if snapshot:
        for label in sorted(set(current) | set(known)):
            values, shown = current.get(label) or ({}, {})
            for change in changes(known.get(label) or {}, values, shown):
                line = change_line(label, change)
                if line:
                    lines.append(line)
                if change.kind == "server" and not change.removed:
                    changed.setdefault(label, set()).add(change.name)
    digest = _servers_digest(scans)
    recheck = snapshot.get("recheck") or {}
    due = (recheck.get("session") != session or recheck.get("digest") != digest
           or time.time() - float(recheck.get("at") or 0) > RECHECK_SECONDS)  # fmt: skip
    servers = []
    findings = []
    for label, scan in scans.items():
        for server in scan.servers:
            if due or str(server.get("name")) in changed.get(label, set()):
                servers.append({**server, "_label": label})
        findings += [{**f, "_label": label} for f in scan.findings]
    unchecked = 0
    if servers:
        outcomes = vet_servers(servers, label="", findings=findings, root=root, cwd=root,
                               env=deps.env, state_root=state_root,
                               sources=deps.supply_chain_sources, deadline=deadline,
                               record=record, notes=False)  # fmt: skip
        for server, outcome in zip(servers, outcomes):
            fresh = str(server.get("name")) in changed.get(server["_label"], set())
            if outcome.kind == "unverified" and not fresh:
                unchecked += 1
            elif outcome.kind == "finding" or (fresh and outcome.decision != ALLOW):
                lines.append(f"{outcome.label}: {outcome.text}")
        record["mcp_rechecked"] = len(servers)
    if unchecked:
        lines.append(f"{unchecked} configured MCP server(s) could not be verified now.")

    def mutate(data):
        data["files"] = {label: values for label, (values, _shown) in current.items()}
        if due:
            data["recheck"] = {"session": session, "digest": digest, "at": time.time()}

    update_snapshot(state_root, mutate)
    record["agent_config_lines"] = len(lines)
    if not lines:
        return None
    shown = [f"- {line}" for line in lines[:MAX_LINES]]
    if len(lines) > MAX_LINES:
        shown.append(f"- (+{len(lines) - MAX_LINES} more)")
    return "Skylos agent config check:\n" + "\n".join(shown)


def planned_writes(payload: dict[str, Any], base: Path, *, wanted=None,
                   replay: bool = True) -> list[Planned]:  # fmt: skip
    """The files an edit tool call would write, with their new text (only for
    paths ``wanted`` accepts; ``replay=False`` names the paths only)."""
    from skylos.commands.hook_cmd import _abs_path

    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    patch = next((v for v in (tool_input.get("command"), tool_input.get("input"),
                              tool_input.get("patch"))
                  if isinstance(v, str) and "*** Begin Patch" in v), None)  # fmt: skip
    if patch is not None:
        return _patch_writes(patch, base, wanted, replay)
    if tool not in EDIT_TOOLS:
        return []
    path = _abs_path(tool_input.get("file_path"), base)
    if path is None or (wanted is not None and not wanted(path)):
        return []
    if not replay:
        return [Planned(path, "", known=False)]
    if tool == "Write":
        content = tool_input.get("content")
        if isinstance(content, str):
            return [Planned(path, content)]
        return [Planned(path, "", known=False)]
    edits = [tool_input]
    if tool == "MultiEdit":
        edits = tool_input.get("edits") if isinstance(tool_input.get("edits"), list) else []
    text = read_config(path) or ""
    for edit in edits:
        replaced = _replace(text, edit)
        if replaced is None:
            return [Planned(path, "", known=False)]
        text = replaced
    return [Planned(path, text)]


def _replace(text: str, edit: Any) -> str | None:
    if not isinstance(edit, dict):
        return None
    old, new = edit.get("old_string"), edit.get("new_string")
    if not isinstance(old, str) or not isinstance(new, str):
        return None
    if old == "":
        if text == "":
            return new
        return None
    if old not in text:
        return None
    if edit.get("replace_all"):
        return text.replace(old, new)
    return text.replace(old, new, 1)


def _patch_writes(patch: str, base: Path, wanted, replay: bool) -> list[Planned]:
    from skylos.commands.hook_cmd import _abs_path

    ops: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in patch.splitlines():
        header = None
        for prefix, kind in (("*** Add File: ", "add"), ("*** Update File: ", "update"),
                             ("*** Delete File: ", "delete")):  # fmt: skip
            if line.startswith(prefix):
                header = (kind, line[len(prefix):].strip())
        if header is not None:
            current = {"kind": header[0], "path": _abs_path(header[1], base), "body": [], "hunks": [[]]}
            ops.append(current)
            continue
        if line.startswith("*** Move to: ") and current is not None:
            current["move"] = _abs_path(line[len("*** Move to: "):].strip(), base)
            continue
        if line.startswith("*** ") or current is None:
            continue
        if current["kind"] == "add" and line.startswith("+"):
            current["body"].append(line[1:])
        elif current["kind"] == "update":
            if line.startswith("@@"):
                current["hunks"].append([])
            else:
                current["hunks"][-1].append(line)
    planned = []
    for op in ops:
        path = op["path"]
        if path is None:
            continue
        if wanted is not None and not wanted(path) and not (op.get("move") and wanted(op["move"])):
            continue
        if not replay:
            planned += [Planned(p, "", known=False) for p in (path, op.get("move")) if p is not None]
            continue
        if op["kind"] == "add":
            planned.append(Planned(path, "\n".join(op["body"]) + "\n"))
        elif op["kind"] == "delete":
            planned.append(Planned(path, ""))
        else:
            text = _apply_hunks(read_config(path) or "", op["hunks"])
            target = op.get("move") or path
            if op.get("move"):
                planned.append(Planned(path, ""))
            planned.append(Planned(target, text or "", known=text is not None))
    return planned


def _apply_hunks(text: str, hunks: list[list[str]]) -> str | None:
    lines = text.split("\n")
    position = 0
    for hunk in hunks:
        old = [_body(line) for line in hunk if line[:1] in (" ", "-", "")]
        new = [_body(line) for line in hunk if line[:1] in (" ", "+", "")]
        if not old and not new:
            continue
        index = _find(lines, old, position)
        if index is None:
            return None
        lines[index : index + len(old)] = new
        position = index + len(new)
    return "\n".join(lines)


def _body(line: str) -> str:
    if line[:1] in (" ", "-", "+"):
        return line[1:]
    return line


def _find(lines: list[str], block: list[str], start: int) -> int | None:
    if not block:
        return len(lines)
    for strip in (False, True):
        for index in range(start, len(lines) - len(block) + 1):
            window = lines[index : index + len(block)]
            if strip:
                window = [w.rstrip() for w in window]
                if window == [b.rstrip() for b in block]:
                    return index
            elif window == block:
                return index
    return None


def _mirror_servers(servers: list[dict[str, Any]], root: Path):
    """Servers a CLI command adds, read by ca9 like a config file would be;
    each carries ``_digest``, the snapshot value it has once written."""
    mirror = ConfigFile("command", Path("-"), "c/.mcp.json")
    names = {f"s{index}": server for index, server in enumerate(servers)}
    body = {key: {k: v for k, v in server.items() if k != "name"} for key, server in names.items()}
    scans = scan_texts([(mirror, json.dumps({"mcpServers": body}))], root) or {}
    scan = scans.get("command") or _empty()
    values, _shown = entries(scan)
    by_key = {str(s.get("name")): s for s in scan.servers}
    found = []
    for key, server in names.items():
        entry = dict(by_key.get(key) or {})
        if not entry:
            command = server.get("command")
            if command:
                entry["argv"] = [command, *(server.get("args") or [])]
            entry["url"] = server.get("url")
        entry["name"] = server.get("name")
        entry["_digest"] = values.get(f"server {key}")
        found.append(entry)
    findings = []
    for finding in scan.findings:
        server = names.get(str(finding.get("name")))
        if server is not None:
            findings.append({**finding, "name": server.get("name")})
    return found, findings


def _verdict(decision: str, outcomes: list[Outcome], what: str) -> tuple[str, str] | None:
    shown = [o for o in outcomes if o.text and RANK[o.decision] >= RANK[NOTE]]
    if decision == ALLOW or not shown:
        return None
    items = "\n".join(f"- {o.text}" for o in shown[:MAX_LINES])
    if decision == DENY:
        return DENY, f"Skylos blocked {what}:\n{items}"
    if decision == ASK:
        return ASK, (f"Skylos needs your approval for {what}:\n{items}\n"
                     "Approve only if you asked for this change.")  # fmt: skip
    return NOTE, f"Skylos checked {what}:\n{items}"


def _render_entry(label: str, argv: list[str]) -> str:
    if label.endswith(".toml"):
        return f"command = {json.dumps(argv[0])}, args = {json.dumps(argv[1:])}"
    return f'"command": {json.dumps(argv[0])}, "args": {json.dumps(argv[1:])}'


def _servers_digest(scans) -> str:
    import hashlib

    items = sorted((label, str(s.get("name")), json.dumps(s.get("argv")), str(s.get("url")))
                   for label, scan in scans.items() for s in scan.servers)  # fmt: skip
    return hashlib.sha256(json.dumps(items).encode()).hexdigest()[:16]


def _token(payload: dict[str, Any]) -> str:
    from skylos.commands.hook_cmd import _session_id

    value = payload.get("tool_use_id")
    if isinstance(value, str) and value.strip():
        return value.strip()[:128]
    return _session_id(payload)


def _empty():
    from skylos.commands.hook_agent_configs import FileScan

    return FileScan()


def _install_policy(root: Path):
    from skylos.commands.hook_install_policy import load_install_policy

    return load_install_policy(root)


__all__ = [
    "accept_agent_action",
    "check_agent_bash",
    "check_agent_edit",
    "planned_writes",
    "session_agent_check",
]
