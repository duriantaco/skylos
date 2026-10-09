"""The Claude Code and Cursor plugin in plugins/skylos stays in step with the CLI.

The plugin ships static hook files that call ``skylos hook <event>`` from the
user's PATH. These tests keep them identical to what ``skylos agent
install-hooks`` writes, limited to the hooks in the released CLI, and check
the manifests, the fail-open fallbacks and the documentation.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from skylos.commands import hook_cmd
from skylos.commands import install_hooks_cmd as installer

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

REPO = Path(__file__).resolve().parents[1]
PLUGIN = REPO / "plugins" / "skylos"
CLAUDE_MANIFEST = PLUGIN / ".claude-plugin" / "plugin.json"
CURSOR_MANIFEST = PLUGIN / ".cursor-plugin" / "plugin.json"
CLAUDE_HOOKS_FILE = PLUGIN / "hooks" / "hooks.json"
CURSOR_HOOKS_FILE = PLUGIN / "hooks" / "cursor-hooks.json"
SKILL_FILE = PLUGIN / "skills" / "skylos" / "SKILL.md"
README = PLUGIN / "README.md"

# Hooks in the released CLI (PyPI 4.47.1, tag v4.47.2). The plugin calls only
# these. When a release ships more hooks, add them here and to both hook files.
RELEASED_HOOKS = frozenset({"session-start", "pre-read", "pre-bash", "post-edit", "stop"})
# Agent edit provenance (#958) is on main but not released yet.
UNRELEASED_HOOKS = frozenset({"pre-edit", "post-bash", "post-failure"})
# `skylos hook session-start` first shipped in 4.44.0; older versions have no
# prompt baseline, so the session-start notice treats them as missing.
MIN_VERSION = "4.44.0"
NOTICE_PROBE = "skylos hook help 2>&1 | grep -q session-start"

# Top-level keys allowed by Cursor's plugin schema (additionalProperties is
# false): https://github.com/cursor/plugins/blob/main/schemas/plugin.schema.json
CURSOR_MANIFEST_KEYS = frozenset(
    {
        "name", "displayName", "description", "version", "minClientVersions",
        "author", "publisher", "homepage", "repository", "license", "logo",
        "keywords", "category", "tags", "commands", "agents", "skills", "rules",
        "hooks", "variables", "mcpServers",
    }
)  # fmt: skip

HOOK_CALL_RE = re.compile(r"^skylos hook (?P<name>[a-z-]+)(?: --client (?P<client>\w+))?")
ECHO_JSON_RE = re.compile(r"echo '(\{[^']*\})'")

posix_only = pytest.mark.skipif(
    os.name == "nt", reason="the plugin's hook commands are POSIX shell strings"
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _claude_handlers() -> list[tuple[str, str | None, dict]]:
    hooks = _load(CLAUDE_HOOKS_FILE)["hooks"]
    return [
        (event, group.get("matcher"), handler)
        for event, groups in hooks.items()
        for group in groups
        for handler in group["hooks"]
    ]


def _cursor_handlers() -> list[tuple[str, dict]]:
    hooks = _load(CURSOR_HOOKS_FILE)["hooks"]
    return [(event, entry) for event, entries in hooks.items() for entry in entries]


def _all_commands() -> list[tuple[str, str]]:
    claude = [("claude", h["command"]) for _e, _m, h in _claude_handlers()]
    cursor = [("cursor", e["command"]) for _e, e in _cursor_handlers()]
    return claude + cursor


def _released(rows):
    return [row for row in rows if row[2] in RELEASED_HOOKS]


def test_released_hook_set_is_explicit():
    assert RELEASED_HOOKS <= set(hook_cmd.EVENTS)
    assert set(hook_cmd.EVENTS) - RELEASED_HOOKS == UNRELEASED_HOOKS, (
        "skylos hook gained or lost an event. Decide whether the plugin should "
        "call it (only once it is in a release), then update RELEASED_HOOKS and "
        "plugins/skylos/hooks/*.json."
    )


def test_manifests_parse_and_agree():
    claude = _load(CLAUDE_MANIFEST)
    cursor = _load(CURSOR_MANIFEST)
    for manifest in (claude, cursor):
        assert manifest["name"] == "skylos"
        assert manifest["displayName"] == "Skylos"
        assert manifest["license"] == "Apache-2.0"
        assert manifest["author"]["name"]
        assert "pip install skylos" in manifest["description"]
        assert MIN_VERSION in manifest["description"]
        assert manifest["repository"] == "https://github.com/duriantaco/skylos"
    assert claude["version"] == cursor["version"]
    assert claude["homepage"] == cursor["homepage"]
    # No personal email in a public listing.
    assert "email" not in claude["author"] and "email" not in cursor["author"]


def test_plugin_versions_match_release():
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    for path in (CLAUDE_MANIFEST, CURSOR_MANIFEST):
        assert _load(path)["version"] == version, (
            f"{path.relative_to(REPO)} is not at {version}. Add both plugin.json "
            "files to tools/release/release-please-config.json extra-files "
            '({"type": "json", "path": ..., "jsonpath": "$.version"}).'
        )


def test_cursor_manifest_uses_only_schema_fields():
    cursor = _load(CURSOR_MANIFEST)
    assert set(cursor) <= CURSOR_MANIFEST_KEYS
    assert set(cursor["author"]) <= {"name", "email"}
    assert re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", cursor["name"])


def test_manifests_reference_existing_files():
    claude = _load(CLAUDE_MANIFEST)
    cursor = _load(CURSOR_MANIFEST)
    assert claude["icon"].startswith("./")
    assert (PLUGIN / claude["icon"]).is_file()
    assert (PLUGIN / cursor["logo"]).is_file()
    assert not Path(cursor["logo"]).is_absolute() and ".." not in cursor["logo"]
    for key in ("hooks", "skills"):
        value = cursor[key]
        assert value.startswith("./") and ".." not in value
        assert (PLUGIN / value).exists(), f"Cursor manifest {key} path is missing"
    assert (PLUGIN / cursor["hooks"]).resolve() == CURSOR_HOOKS_FILE.resolve()
    # Claude Code loads hooks/hooks.json by default; naming it again is a warning.
    assert "hooks" not in claude and CLAUDE_HOOKS_FILE.is_file()
    for url_key in ("documentationUrl", "supportUrl", "privacyPolicyUrl", "termsOfServiceUrl"):
        assert claude[url_key].startswith("https://")


def test_repo_marketplaces_point_at_the_plugin_when_present():
    for path in (
        REPO / ".claude-plugin" / "marketplace.json",
        REPO / ".cursor-plugin" / "marketplace.json",
    ):
        if not path.exists():
            continue
        entries = [p for p in _load(path)["plugins"] if p["name"] == "skylos"]
        assert len(entries) == 1, path
        manifest = REPO / entries[0]["source"] / path.parent.name / "plugin.json"
        assert manifest.resolve().parent.parent == PLUGIN.resolve(), path
        assert manifest.is_file(), path


def test_no_mcp_server_in_v1():
    for manifest in (_load(CLAUDE_MANIFEST), _load(CURSOR_MANIFEST)):
        assert "mcpServers" not in manifest
    for name in (".mcp.json", "mcp.json"):
        assert not (PLUGIN / name).exists()


@posix_only
def test_claude_hooks_match_installer():
    handlers = _claude_handlers()
    expected = _released(installer.CLAUDE_HOOKS)
    assert expected, "no released Claude hooks found"
    skylos_handlers = [
        (event, matcher, h)
        for event, matcher, h in handlers
        if not h["command"].startswith(NOTICE_PROBE)
    ]
    assert len(skylos_handlers) == len(expected)
    for event, matcher, name, timeout in expected:
        command = installer.hook_command("skylos", name, "claude")
        matches = [
            h
            for e, m, h in skylos_handlers
            if e == event and m == matcher and h["command"] == command
        ]
        assert len(matches) == 1, f"{event} {matcher} {name}"
        assert matches[0] == {"type": "command", "command": command, "timeout": timeout}


@posix_only
def test_cursor_hooks_match_installer():
    data = _load(CURSOR_HOOKS_FILE)
    assert data["version"] == 1
    entries = [
        (event, entry)
        for event, entry in _cursor_handlers()
        if not entry["command"].startswith(NOTICE_PROBE)
    ]
    expected = _released(installer.CURSOR_HOOKS)
    assert len(entries) == len(expected)
    for event, _matcher, name, timeout in expected:
        command = installer.hook_command("skylos", name, "cursor")
        if name == "session-start":
            # Before 4.44.0 `skylos hook session-start` exits 0 with no output,
            # which skips `||`. Forward only non-empty output, else continue.
            command = command.replace(" || ", " | grep . || ", 1)
        matches = [entry for e, entry in entries if e == event]
        assert len(matches) == 1, event
        want = {"command": command, "timeout": timeout}
        if name == "stop":
            want["loop_limit"] = installer.CURSOR_STOP_LOOP_LIMIT
        assert matches[0] == want


def test_notice_hooks_probe_for_session_start():
    claude = [
        (event, matcher, h)
        for event, matcher, h in _claude_handlers()
        if h["command"].startswith(NOTICE_PROBE)
    ]
    assert [(e, m) for e, m, _h in claude] == [("SessionStart", "startup|resume")]
    message = json.loads(ECHO_JSON_RE.search(claude[0][2]["command"]).group(1))
    assert set(message) == {"systemMessage"}
    assert MIN_VERSION in message["systemMessage"]

    cursor = [
        (event, entry)
        for event, entry in _cursor_handlers()
        if entry["command"].startswith(NOTICE_PROBE)
    ]
    assert [e for e, _entry in cursor] == ["sessionStart"]
    payloads = [json.loads(p) for p in ECHO_JSON_RE.findall(cursor[0][1]["command"])]
    assert payloads[0] == {}
    assert set(payloads[1]) == {"additional_context"}
    assert MIN_VERSION in payloads[1]["additional_context"]


def test_hook_commands_call_real_released_subcommands():
    for client, command in _all_commands():
        match = HOOK_CALL_RE.match(command)
        assert match, f"not a skylos hook call: {command}"
        name = match.group("name")
        assert name in RELEASED_HOOKS | {"help"}
        assert name == "help" or name in hook_cmd.EVENTS
        if name != "help":
            assert match.group("client") == client
            assert installer.OUR_COMMAND_RE.search(command)
        # Directory rule: no paths, variables or substitutions in hook commands.
        for forbidden in ("/", "$", "`", "*"):
            assert forbidden not in command, (forbidden, command)
        for payload in ECHO_JSON_RE.findall(command):
            json.loads(payload)


def _fake_skylos(bin_dir: Path, script: str) -> None:
    bin_dir.mkdir()
    path = bin_dir / "skylos"
    path.write_text("#!/bin/sh\n" + script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _run(command: str, path: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/bin/sh", "-c", command],
        input="{}",
        capture_output=True,
        text=True,
        cwd=cwd,
        env={"PATH": path},
        timeout=30,
        check=False,
    )


@posix_only
def test_every_hook_fails_open_without_skylos(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    for client, command in _all_commands():
        proc = _run(command, f"{empty}:/usr/bin:/bin", tmp_path)
        assert proc.returncode == 0, command
        out = proc.stdout.strip()
        if "--client" in command:
            name = HOOK_CALL_RE.match(command).group("name")
            fallback = installer.hook_command("skylos", name, client).split(" || ", 1)[1]
            expected = "" if fallback == "exit 0" else ECHO_JSON_RE.search(fallback).group(1)
            assert out == expected, command
        else:
            assert MIN_VERSION in json.loads(out)[
                "systemMessage" if client == "claude" else "additional_context"
            ]


@posix_only
def test_notice_is_silent_with_a_current_skylos(tmp_path):
    _fake_skylos(
        tmp_path / "bin",
        "echo 'usage: skylos hook {session-start,post-edit,pre-read,pre-bash,stop}'\n",
    )
    path = f"{tmp_path / 'bin'}:/usr/bin:/bin"
    notices = [c for c in _all_commands() if c[1].startswith(NOTICE_PROBE)]
    assert len(notices) == 2
    for client, command in notices:
        out = _run(command, path, tmp_path).stdout.strip()
        assert out == ("" if client == "claude" else "{}")


@posix_only
def test_cursor_prompt_hook_continues_when_old_skylos_prints_nothing(tmp_path):
    (command,) = [
        e["command"] for event, e in _cursor_handlers() if event == "beforeSubmitPrompt"
    ]
    _fake_skylos(tmp_path / "old", "exit 0\n")
    old = _run(command, f"{tmp_path / 'old'}:/usr/bin:/bin", tmp_path)
    assert json.loads(old.stdout) == {"continue": True}

    _fake_skylos(tmp_path / "new", "echo '{\"continue\": true}'\n")
    new = _run(command, f"{tmp_path / 'new'}:/usr/bin:/bin", tmp_path)
    assert new.stdout.strip().splitlines() == ['{"continue": true}']


def test_skill_frontmatter_and_content():
    text = SKILL_FILE.read_text(encoding="utf-8")
    _, front, body = text.split("---", 2)
    meta = yaml.safe_load(front)
    assert meta["name"] == "skylos"
    assert isinstance(meta["description"], str) and len(meta["description"]) <= 1024
    for needle in (
        "skylos done --base main",
        "skylos verify . --diff",
        "--format json",
        "incomplete",
        "SKY-A114",
        "skylos hook recheck",
    ):
        assert needle in body, needle


def test_readme_covers_listing_requirements():
    text = README.read_text(encoding="utf-8")
    prose = re.sub(r"```.*?```", "", text, flags=re.S)
    assert len(prose.split()) >= 40  # Anthropic's directory minimum
    for needle in (
        "skylos agent install-hooks --uninstall",
        "SKYLOS_HOOKS_DISABLE",
        MIN_VERSION,
        "pypi.org",
        "registry.npmjs.org",
        "proxy.golang.org",
        ".skylos/hook.log*",
    ):
        assert needle in text, needle
    # Every .gitignore line the installer writes is listed for plugin users.
    for entry in installer.GITIGNORE_ENTRIES:
        if entry != ".skylos/agent-traces/":  # #958, unreleased
            assert entry in text, entry


def test_plugin_folder_has_no_system_files():
    names = {p.name for p in PLUGIN.rglob("*")}
    assert not names & {".DS_Store", "Thumbs.db", "desktop.ini", "__MACOSX"}
