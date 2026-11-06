"""MCP servers an agent adds, and what each one would run.

``vet_servers`` takes servers in the shape ca9's agent-config inventory uses
(``name``, ``argv``, ``url``, ``transport``) and decides each one:

* a package server (``npx``, ``uvx``, ``bunx``, ``pnpm dlx`` ...; read by
  ``ca9.api.parse_mcp_server``) is checked like ``npx -y <pkg>`` would be by
  the install hook: existence, malware and release age on the exact version
  that would run, resolving an unpinned spec to the version the launcher
  fetches today. A clean server must name that exact version; an unpinned one
  is denied with the pinned command (``parse_mcp_server(..., version=)``);
* a server ca9 marks as a hidden-path script or a vendor impersonation, a git
  or URL source, an image without a digest, or anything Skylos could not read
  needs the user (``ask``; Codex denies);
* a local script or an installed ``python -m`` module runs nothing new and
  passes; a remote server passes with a note, which says "could not verify"
  for plain ``http`` to a non-local host.

``mcp_additions`` reads ``claude mcp add`` / ``add-json`` /
``add-from-claude-desktop``, ``codex mcp add`` and ``gemini mcp add`` out of a
shell command; ``config_writes`` finds shell commands that write an agent
config file directly (redirects, ``tee``, ``cp``/``mv``, ``sed -i``).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ALLOW = "allow"
NOTE = "note"
ASK = "ask"
DENY = "deny"
RANK = {ALLOW: 0, NOTE: 1, ASK: 2, DENY: 3}
MCP_SECONDS = 12.0
AGENT_CLIS = frozenset({"claude", "codex", "gemini"})
_CLAUDE_VALUE_OPTIONS = frozenset({"-s", "--scope", "-t", "--transport", "--client-id",
                                   "--callback-port", "--timeout"})  # fmt: skip
_CLAUDE_LIST_OPTIONS = frozenset({"-e", "--env", "-H", "--header"})
_CODEX_VALUE_OPTIONS = frozenset({"--env", "--url", "--bearer-token-env-var"})
_GEMINI_VALUE_OPTIONS = frozenset({"-s", "--scope", "-t", "--transport", "-e", "--env", "-H",
                                   "--header", "--timeout", "--description", "--include-tools",
                                   "--exclude-tools"})  # fmt: skip
_WRITERS = frozenset({"cp", "mv", "install", "ln", "rsync", "tee", "dd"})
_IN_PLACE = frozenset({"sed", "gsed", "perl", "ruby"})
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"})


@dataclass
class Addition:
    """One server a CLI command adds; ``render`` turns a pinned argv back
    into the command the agent should run instead."""

    client: str
    name: str
    server: dict[str, Any] | None
    render: Callable[[list[str]], str] | None = None
    problem: str = ""


@dataclass
class Outcome:
    label: str
    name: str
    decision: str
    text: str
    pinned: list[str] | None = None
    kind: str = ""


@dataclass
class _Pending:
    index: int
    entry: dict[str, Any]
    parsed: dict[str, Any]
    targets: list[Any] = field(default_factory=list)


def mcp_additions(commands: list[Any]) -> list[Addition]:
    additions = []
    for simple in commands:
        program = _program(simple.program)
        args = list(simple.args)
        if program not in AGENT_CLIS or len(args) < 2 or args[0] != "mcp":
            continue
        verb = args[1]
        dynamic = [i for i in range(len(args)) if simple.is_dynamic(i) and not _literal_json(args[i])]
        if dynamic and verb.startswith("add"):
            additions.append(Addition(program, "?", None,
                                      problem="its arguments are only known when it runs"))  # fmt: skip
            continue
        if program == "claude" and verb == "add-json":
            additions.append(_claude_add_json(args[2:]))
        elif program == "claude" and verb == "add-from-claude-desktop":
            additions.append(Addition(program, "?", None,
                                      problem="it imports servers Skylos cannot see"))  # fmt: skip
        elif verb == "add" and program == "claude":
            additions.append(_cli_add(program, args, _CLAUDE_VALUE_OPTIONS, _CLAUDE_LIST_OPTIONS))
        elif verb == "add" and program == "codex":
            additions.append(_codex_add(args))
        elif verb == "add" and program == "gemini":
            additions.append(_cli_add(program, args, _GEMINI_VALUE_OPTIONS, frozenset()))
    return additions


def uninstalls_skylos_hooks(commands: list[Any]) -> bool:
    for simple in commands:
        args = list(simple.args)
        program = _program(simple.program)
        if re.fullmatch(r"python[0-9.]*|py", program) and args[:2] == ["-m", "skylos.entry"]:
            args = args[2:]
        elif program != "skylos":
            continue
        if args[:2] == ["agent", "install-hooks"] and "--uninstall" in args:
            return True
    return False


def config_writes(commands: list[Any], guarded: Callable[[Path], bool]) -> list[str]:
    """Agent config files a shell command writes without the edit tools."""
    found = []
    for simple in commands:
        cwd = Path(simple.cwd)
        words = [str(target) for target in simple.outputs]
        program = _program(simple.program)
        args = list(simple.args)
        if program in _WRITERS:
            words += [_after_of(a) for a in args if not a.startswith("-")]
        elif program in _IN_PLACE and any(a.startswith(("-i", "--in-place")) for a in args):
            words += [a for a in args if not a.startswith("-")]
        for word in words:
            path = Path(word).expanduser()
            if not path.is_absolute():
                path = cwd / path
            if guarded(path):
                found.append(word)
    return list(dict.fromkeys(found))


def vet_servers(servers: list[dict[str, Any]], *, label: str, findings: list[dict[str, Any]],
                root: Path, cwd: Path, env: dict[str, str], state_root: Path, sources: Any = None,
                deadline: float | None = None, record: dict[str, Any] | None = None,
                notes: bool = True) -> list[Outcome]:  # fmt: skip
    """One :class:`Outcome` per server, in order. ``findings`` are ca9's
    agent-config findings for the same file; ``notes=False`` drops remote
    server notes (session start repeats nothing that needs no action)."""
    from skylos.commands.hook_agent_configs import ca9_function

    if deadline is None:
        deadline = time.monotonic() + MCP_SECONDS
    parse = ca9_function("parse_mcp_server")
    policy = _install_policy(root)
    flagged = _flagged(findings, label)
    outcomes: list[Outcome | None] = [None] * len(servers)
    pending: list[_Pending] = []
    for index, entry in enumerate(servers):
        name = str(entry.get("name") or "?")
        where = str(entry.get("_label") or label)
        outcome, parsed = _first_look(entry, name, where, parse, policy, notes)
        if outcome is not None:
            outcomes[index] = outcome
        else:
            pending.append(_Pending(index, entry, parsed))
    _registry_vet(pending, outcomes, label=label, root=root, cwd=cwd, env=env,
                  state_root=state_root, sources=sources, deadline=deadline, record=record,
                  policy=policy, parse=parse)  # fmt: skip
    final = []
    for entry, outcome in zip(servers, outcomes):
        if outcome is None:
            continue
        name = str(entry.get("name") or "?")
        reason = flagged.get(str(entry.get("_label") or label), {}).get(name)
        if reason and RANK[outcome.decision] < RANK[ASK]:
            outcome = Outcome(outcome.label, name, ASK, f"'{name}': {reason}", kind="flagged")
        final.append(outcome)
    return final


def worst(outcomes: list[Outcome]) -> str:
    decision = ALLOW
    for outcome in outcomes:
        if RANK[outcome.decision] > RANK[decision]:
            decision = outcome.decision
    return decision


def server_from_addition(addition: Addition) -> dict[str, Any]:
    return {"name": addition.name, **(addition.server or {})}


def is_remote(server: dict[str, Any]) -> bool:
    return bool(server.get("url")) and not server.get("command")


def _first_look(entry, name, label, parse, policy, notes):
    url = str(entry.get("url") or "")
    argv = entry.get("argv")
    if url and not argv:
        return _remote(entry, name, label, url, notes), None
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return _unverified(label, name, policy, "Skylos could not read its command"), None
    if parse is None:
        return _unverified(label, name, policy, _engine_missing()), None
    try:
        parsed = parse(argv[0], argv[1:])
    except Exception:  # noqa: BLE001
        parsed = None
    if not isinstance(parsed, dict):
        return _unverified(label, name, policy, f"Skylos could not tell what {argv[0]} runs"), None
    ecosystem = str(parsed.get("ecosystem") or "")
    source = str(parsed.get("source") or "registry")
    package = str(parsed.get("package") or "?")
    if parsed.get("fetches") is False or ecosystem == "local":
        return Outcome(label, name, ALLOW, ""), None
    if ecosystem == "docker":
        if parsed.get("pinned"):
            return Outcome(label, name, NOTE if notes else ALLOW,
                           f"'{name}': image {package} is pinned by digest; Skylos does not "
                           "check images."), None  # fmt: skip
        return Outcome(label, name, policy.on_unverified,
                       f"'{name}': could not verify image {package}; pin it by digest "
                       f"({package}@sha256:...).", kind="unpinned"), None  # fmt: skip
    if source in ("git", "url"):
        return Outcome(label, name, policy.direct_source,
                       f"'{name}': runs {package} from a {source} source Skylos cannot check."), None  # fmt: skip
    if ecosystem not in ("npm", "pypi"):
        return _unverified(label, name, policy, f"{package} is a {ecosystem or 'unknown'} package"), None
    return None, parsed


def _remote(entry, name, label, url, notes) -> Outcome:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host in _LOCAL_HOSTS or not notes:
        return Outcome(label, name, ALLOW, "")
    if parts.scheme == "https":
        return Outcome(label, name, NOTE,
                       f"'{name}' is a remote server ({host}); Skylos checks packages, not "
                       "remote servers.")  # fmt: skip
    return Outcome(label, name, NOTE,
                   f"'{name}' uses {parts.scheme or 'no'}:// to {host or url}; Skylos could not "
                   "verify it (not https).")  # fmt: skip


def _registry_vet(pending, outcomes, *, label, root, cwd, env, state_root, sources, deadline,
                  record, policy, parse) -> None:  # fmt: skip
    from skylos.commands.hook_install_parse import (
        DIRECT,
        LOCAL,
        NPM,
        PYPI,
        REGISTRY,
        install_targets,
    )

    ready: list[_Pending] = []
    for item in pending:
        name = str(item.entry.get("name") or "?")
        where = str(item.entry.get("_label") or label)
        spec = str(item.parsed.get("spec") or item.parsed.get("package") or "")
        argv = ["npx", "--yes", spec]
        if item.parsed.get("ecosystem") == "pypi":
            argv = ["uvx", "--from", spec, "mcp-server"]
        targets = install_targets(shlex.join(argv), cwd, root=root)
        kinds = {t.kind for t in targets}
        if LOCAL in kinds and REGISTRY not in kinds:
            outcomes[item.index] = Outcome(where, name, ALLOW, "")
        elif DIRECT in kinds:
            outcomes[item.index] = Outcome(where, name, policy.direct_source,
                                           f"'{name}': runs {spec} from a source Skylos cannot check.")  # fmt: skip
        elif [t.kind for t in targets] != [REGISTRY] or targets[0].ecosystem not in (NPM, PYPI):
            outcomes[item.index] = _unverified(where, name, policy, f"Skylos could not read the package {spec}")
        else:
            item.targets = targets
            ready.append(item)
    for batch in _rounds(ready):
        results = _check_batch(batch, root=root, cwd=cwd, env=env, state_root=state_root,
                               sources=sources, deadline=deadline, record=record, policy=policy)  # fmt: skip
        for item in batch:
            outcomes[item.index] = _registry_outcome(item, results, str(item.entry.get("_label") or label),
                                                     policy, parse)  # fmt: skip


def _rounds(items: list[_Pending]) -> list[list[_Pending]]:
    rounds: list[list[_Pending]] = []
    for item in items:
        key = _package_key(item.targets[0].ecosystem, item.targets[0].name)
        for batch in rounds:
            if all(_package_key(o.targets[0].ecosystem, o.targets[0].name) != key for o in batch):
                batch.append(item)
                break
        else:
            rounds.append([item])
    return rounds


def _check_batch(batch, *, root, cwd, env, state_root, sources, deadline, record, policy):
    from skylos.commands.hook_cmd import _declared_registries, _supply_chain_policy
    from skylos.commands.hook_supply_chain import check_supply_chain
    from skylos.rules.ai_defect.install_command import check_install_command

    targets = [t for item in batch for t in item.targets]
    chain, chain_problem = _supply_chain_policy(root)
    trusted = _declared_registries(policy, chain)
    result = check_install_command("", root, cache_root=state_root, cwd=cwd, env=env,
                                   trusted_registries=trusted, home=env.get("HOME") or None,
                                   targets=targets, deadline=deadline)  # fmt: skip
    try:
        check_supply_chain(result, targets, root=root, sources=sources, record=record,
                           deadline=deadline, policy=chain, trusted=trusted)  # fmt: skip
    except Exception:  # noqa: BLE001
        result["stage_failed"] = True
    result["age_hours"] = chain.hook_release_age_hours()
    if chain_problem:
        result["chain_problem"] = chain_problem
    return result


def _registry_outcome(item: _Pending, result: dict[str, Any], label, policy, parse) -> Outcome:
    from skylos.rules.ai_defect.install_command import (
        OUTCOME_ALLOWLISTED,
        OUTCOME_PRIVATE,
    )

    name = str(item.entry.get("name") or "?")
    target = item.targets[0]
    key = _package_key(target.ecosystem, target.name)
    package = target.name
    pinned = bool(item.parsed.get("pinned"))
    mine = [f for f in result.get("findings") or [] if _package_key(f.get("ecosystem"), f.get("name")) == key]
    if mine:
        return _finding_outcome(item, mine, label, result.get("age_hours"), parse)
    if result.get("stage_failed") or result.get("chain_problem"):
        reason = result.get("chain_problem") or "the malware and release-age check failed"
        return Outcome(label, name, policy.on_unverified, f"'{name}' ({package}): could not verify: {reason}.",
                       kind="unverified")
    unverified = [u for u in result.get("unverified") or []
                  if _package_key(u.get("ecosystem"), u.get("name")) == key]  # fmt: skip
    trusted = [u for u in unverified if u.get("outcome") in (OUTCOME_ALLOWLISTED, OUTCOME_PRIVATE)]
    others = [u for u in unverified if u not in trusted]
    if others:
        reason = "; ".join(dict.fromkeys(str(u.get("reason") or "not checked") for u in others))
        decision = policy.on_unverified
        if any(u.get("outcome") == "registry_override" for u in others):
            decision = policy.direct_source
        return Outcome(label, name, decision, f"'{name}' ({package}): could not verify: {reason}.",
                       kind="unverified")
    if pinned:
        return Outcome(label, name, ALLOW, "")
    checked = [c for c in result.get("checked") or []
               if _package_key(c.get("ecosystem"), c.get("name")) == key]  # fmt: skip
    version = ""
    if checked and not trusted:
        version = str(checked[0].get("resolved") or "")
    return _unpinned(item, name, package, version, label, parse)


def _finding_outcome(item, findings, label, age_hours, parse) -> Outcome:
    name = str(item.entry.get("name") or "?")
    package = item.targets[0].name
    kinds = {f.get("kind") for f in findings}
    first = findings[0]
    version = str(first.get("version") or "")
    if "malware" in kinds:
        malware = next(f for f in findings if f.get("kind") == "malware")
        ids = ", ".join(malware.get("advisories") or []) or "malware feed"
        return Outcome(label, name, DENY,
                       f"'{name}' would run {package} {malware.get('version')}: known malware "
                       f"({ids}). Do not use it.", kind="finding")  # fmt: skip
    if "too_new" in kinds:
        young = next(f for f in findings if f.get("kind") == "too_new")
        from skylos.commands.hook_supply_chain import _age_text

        text = (f"'{name}' would run {package} {young.get('version')}, published "
                f"{_age_text(young.get('age_hours'))}; new versions wait {age_hours} hours.")  # fmt: skip
        suggested = young.get("suggested_version")
        pinned = None
        if isinstance(suggested, str) and suggested:
            pinned = _pinned_argv(item, suggested, parse)
            text += f" Pin {package} {suggested} instead."
        else:
            text += " There is no older version to pin."
        return Outcome(label, name, DENY, text, pinned, kind="finding")
    if "provenance" in kinds:
        return Outcome(label, name, DENY,
                       f"'{name}' would run {package} {version}: it lost the provenance its "
                       "earlier versions had. Pin an earlier version.", kind="finding")  # fmt: skip
    return Outcome(label, name, DENY, f"'{name}': {first.get('message')}", kind="finding")


def _unpinned(item, name, package, version, label, parse) -> Outcome:
    text = f"'{name}' runs {package} with no fixed version, so each launch can fetch a new release."
    if not version:
        return Outcome(label, name, DENY, text + f" Pin an exact version of {package}.", kind="unpinned")
    pinned = _pinned_argv(item, version, parse)
    return Outcome(label, name, DENY, text + f" Pin the checked version {version}.", pinned,
                   kind="unpinned")


def _pinned_argv(item: _Pending, version: str, parse) -> list[str] | None:
    argv = item.entry.get("argv")
    if parse is None or not isinstance(argv, list) or not argv:
        return None
    try:
        answer = parse(argv[0], argv[1:], version=version)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(answer, dict):
        return None
    pinned = answer.get("pinned_command")
    if isinstance(pinned, list) and pinned and all(isinstance(p, str) for p in pinned):
        return pinned
    return None


def _flagged(findings: list[dict[str, Any]], label: str) -> dict[str, dict[str, str]]:
    reasons: dict[str, dict[str, str]] = {}
    for finding in findings:
        kind = finding.get("signal_type")
        where = reasons.setdefault(str(finding.get("_label") or label), {})
        name = str(finding.get("name") or "")
        if kind == "mcp_server_hidden_path":
            where[name] = "runs a script from a hidden folder; approve only if you put it there."
        elif kind == "mcp_server_impersonation":
            where[name] = "its package name imitates a known vendor's; check the real package name."
    return reasons


def _unverified(label: str, name: str, policy: Any, reason: str) -> Outcome:
    return Outcome(label, name, policy.on_unverified, f"'{name}': could not verify ({reason}).",
                   kind="unverified")


def _install_policy(root: Path):
    from skylos.commands.hook_install_policy import load_install_policy

    return load_install_policy(root)


def _engine_missing() -> str:
    from skylos.commands.hook_agent_configs import ENGINE_MISSING

    return ENGINE_MISSING


def _package_key(ecosystem: Any, name: Any) -> tuple[str, str]:
    return str(ecosystem or "").lower(), re.sub(r"[-_.]+", "-", str(name or "").strip().lower())


def _program(word: str) -> str:
    base = os.path.basename(word).lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return base


def _cli_add(program, args, value_options, list_options) -> Addition:
    rest = args[2:]
    positional: list[int] = []
    transport = ""
    tail: list[str] | None = None
    split = -1
    index = 0
    while index < len(rest):
        word = rest[index]
        if word == "--":
            tail = rest[index + 1 :]
            split = index + 1
            break
        if len(positional) >= 2 or not word.startswith("-"):
            positional.append(index)
            index += 1
            continue
        option, _eq, inline = word.partition("=")
        if option in ("-t", "--transport"):
            transport = inline or _at(rest, index + 1)
        if option in list_options and not inline:
            index += 1
            while index < len(rest) and _looks_like_pair(rest[index]):
                index += 1
            continue
        if option in value_options and not inline:
            index += 2
            continue
        index += 1
    if not positional:
        return Addition(program, "?", None, problem="Skylos could not read the server it adds")
    name = rest[positional[0]]
    if tail is None:
        argv = [rest[i] for i in positional[1:]]
        split = positional[1] if len(positional) > 1 else len(rest)
    else:
        argv = tail
    if not argv:
        return Addition(program, name, None, problem="Skylos could not read the server it adds")
    if transport in ("http", "sse") or re.match(r"(?i)^https?://", argv[0]):
        return Addition(program, name, {"type": transport or "http", "url": argv[0]})
    prefix = [program, "mcp", "add", *rest[:split]]

    def render(pinned: list[str]) -> str:
        return shlex.join(prefix + pinned)

    return Addition(program, name, {"command": argv[0], "args": argv[1:]}, render)


def _at(words: list[str], index: int) -> str:
    if 0 <= index < len(words):
        return words[index]
    return ""


def _codex_add(args: list[str]) -> Addition:
    rest = args[2:]
    name = ""
    url = ""
    index = 0
    head = ["codex", "mcp", "add"]
    while index < len(rest):
        word = rest[index]
        if word == "--":
            argv = rest[index + 1 :]
            prefix = head + rest[: index + 1]
            if not name or not argv:
                break

            def render(pinned: list[str], prefix=prefix) -> str:
                return shlex.join(prefix + pinned)

            return Addition("codex", name, {"command": argv[0], "args": argv[1:]}, render)
        option, _eq, inline = word.partition("=")
        if option == "--url":
            url = inline or _at(rest, index + 1)
        if option in _CODEX_VALUE_OPTIONS and not inline:
            index += 2
            continue
        if not word.startswith("-") and not name:
            name = word
        index += 1
    if name and url:
        return Addition("codex", name, {"type": "http", "url": url})
    return Addition("codex", name or "?", None, problem="Skylos could not read the server it adds")


def _claude_add_json(rest: list[str]) -> Addition:
    positional = []
    index = 0
    options = []
    while index < len(rest):
        word = rest[index]
        if word in ("-s", "--scope"):
            options += rest[index : index + 2]
            index += 2
            continue
        if word.startswith("-"):
            options.append(word)
            index += 1
            continue
        positional.append(word)
        index += 1
    if len(positional) < 2:
        return Addition("claude", "?", None, problem="Skylos could not read the server it adds")
    name, raw = positional[0], positional[1]
    try:
        data = json.loads(raw)
    except ValueError:
        return Addition("claude", name, None, problem="its JSON could not be read")
    if not isinstance(data, dict):
        return Addition("claude", name, None, problem="its JSON is not an object")

    def render(pinned: list[str]) -> str:
        fixed = {**data, "command": pinned[0], "args": pinned[1:]}
        return shlex.join(["claude", "mcp", "add-json", *options, name, json.dumps(fixed)])

    return Addition("claude", name, data, render)


def _literal_json(word: str) -> bool:
    if "$" in word or "`" in word or not word.lstrip().startswith("{"):
        return False
    try:
        return isinstance(json.loads(word), dict)
    except ValueError:
        return False


def _after_of(word: str) -> str:
    if word.startswith("of="):
        return word[3:]
    return word


def _looks_like_pair(word: str) -> bool:
    return not word.startswith("-") and ("=" in word or ":" in word)


__all__ = [
    "ALLOW",
    "ASK",
    "DENY",
    "NOTE",
    "Addition",
    "Outcome",
    "config_writes",
    "is_remote",
    "mcp_additions",
    "server_from_addition",
    "uninstalls_skylos_hooks",
    "vet_servers",
    "worst",
]
