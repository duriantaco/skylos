import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from types import SimpleNamespace

import pytest


pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="local eval hooks require POSIX file locking"
)


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install_eval_hooks.py"
SPEC = importlib.util.spec_from_file_location("_install_eval_hooks", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


def _git(repo, *arguments):
    return subprocess.run(
        ["git", "-C", str(repo), *arguments], check=True, capture_output=True, text=True
    )


@pytest.fixture
def checkout(tmp_path):
    repo = tmp_path / "repo with spaces"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "scripts").mkdir()
    for name in ("eval_check.py", "eval_hook.py"):
        (repo / "scripts" / name).write_text("# trusted test-only entry point\n")
    return repo


def _read(repo, relative):
    return json.loads((repo / relative).read_text())


def _handlers(document, event):
    return [handler for group in document["hooks"][event] for handler in group["hooks"]]


def test_install_preserves_settings_hooks_modes_and_makes_private_backups(checkout):
    existing = {
        "permissions": {"allow": ["Bash(pytest:*)"]},
        "env": {"AN_EXAMPLE_PRIVATE_SETTING": "kept locally"},
        "hooks": {
            "Stop": [
                {
                    "matcher": "",
                    "hooks": [{"type": "command", "command": "existing-check"}],
                }
            ],
            "Notification": [
                {"hooks": [{"type": "command", "command": "existing-notify"}]}
            ],
        },
    }
    claude = checkout / ".claude/settings.local.json"
    claude.parent.mkdir()
    previous = (json.dumps(existing) + "\n").encode()
    claude.write_bytes(previous)
    claude.chmod(0o640)
    report = installer.install_hooks(checkout, Path(sys.executable))
    after = _read(checkout, ".claude/settings.local.json")
    assert after["permissions"] == existing["permissions"]
    assert after["env"] == existing["env"]
    assert after["hooks"]["Notification"] == existing["hooks"]["Notification"]
    assert _handlers(after, "Stop")[0]["command"] == "existing-check"
    assert claude.stat().st_mode & 0o777 == 0o640
    backup = Path(report["backup_directory"])
    assert (backup / ".claude__settings.local.json.before").read_bytes() == previous
    assert (
        backup / ".claude__settings.local.json.before"
    ).stat().st_mode & 0o777 == 0o600
    assert backup.stat().st_mode & 0o777 == 0o700
    for relative in (
        ".claude/settings.local.json",
        ".codex/hooks.json",
        str(backup.relative_to(checkout)) + "/receipt.json",
    ):
        assert _git(checkout, "check-ignore", relative).returncode == 0


def test_native_hook_contracts_quote_absolute_paths_and_keep_venv_python(checkout):
    # A venv path is intentionally retained even when its executable is a symlink.
    venv = checkout / "env/bin/python"
    venv.parent.mkdir(parents=True)
    venv.symlink_to(sys.executable)
    installer.install_hooks(checkout, venv)
    for client, relative in installer.CONFIGS.items():
        document = _read(checkout, relative)
        assert set(document["hooks"]) == set(installer.EVENTS)
        for event in installer.EVENTS:
            handlers = _handlers(document, event)
            assert len(handlers) == 1
            handler = handlers[0]
            assert shlex.split(handler["command"]) == [
                str(venv),
                "-B",
                str(checkout / "scripts/eval_hook.py"),
                "--client",
                client,
                "--repo",
                str(checkout),
            ]
            assert handler["timeout"] == 300
            assert handler.get("onFailure") == (
                "block" if client == "claude" and event != "Stop" else None
            )
        assert document["hooks"]["PreToolUse"][0]["matcher"] == installer.TOOL_MATCHER
        assert document["hooks"]["PreToolUse"][0]["matcher"] == "*"


def test_reinstall_is_idempotent_and_does_not_duplicate_handlers_or_backups(checkout):
    first = installer.install_hooks(checkout, Path(sys.executable))
    before = {rel: (checkout / rel).read_bytes() for rel in installer.CONFIGS.values()}
    second = installer.install_hooks(checkout, Path(sys.executable))
    assert second["changed_config_paths"] == []
    assert second["exclude_changed"] is False
    assert second["backup_directory"] is None
    assert {
        rel: (checkout / rel).read_bytes() for rel in installer.CONFIGS.values()
    } == before
    assert len(list(Path(first["backup_directory"]).parent.iterdir())) == 1


def test_updates_own_handlers_and_retains_other_handlers_in_same_group(checkout):
    installer.install_hooks(checkout, Path(sys.executable))
    path = checkout / ".codex/hooks.json"
    document = json.loads(path.read_text())
    old_own = document["hooks"]["PreToolUse"][0]["hooks"][0]
    old_own["timeout"] = 1
    unrelated = {"type": "command", "command": "another-check"}
    document["hooks"]["PreToolUse"][0]["hooks"].append(unrelated)
    path.write_text(json.dumps(document))
    installer.install_hooks(checkout, Path(sys.executable))
    handlers = _handlers(_read(checkout, ".codex/hooks.json"), "PreToolUse")
    assert unrelated in handlers
    assert len(handlers) == 2
    assert (
        next(handler for handler in handlers if handler != unrelated)["timeout"] == 300
    )


@pytest.mark.parametrize("missing", ["eval_check.py", "eval_hook.py"])
def test_missing_runner_refuses_without_touching_settings(checkout, missing):
    (checkout / "scripts" / missing).unlink()
    exclude = checkout / ".git/info/exclude"
    before = exclude.read_bytes()
    with pytest.raises(ValueError, match="no other checkout is substituted"):
        installer.install_hooks(checkout, Path(sys.executable))
    assert exclude.read_bytes() == before
    assert not (checkout / ".codex").exists()


@pytest.mark.parametrize(
    "invalid", ["{broken", "[]", '{"hooks": []}', '{"hooks":{"Stop":{}}}']
)
def test_invalid_existing_json_is_not_overwritten(checkout, invalid):
    path = checkout / ".claude/settings.local.json"
    path.parent.mkdir()
    path.write_text(invalid)
    exclude = checkout / ".git/info/exclude"
    before = exclude.read_bytes()
    with pytest.raises(ValueError):
        installer.install_hooks(checkout, Path(sys.executable))
    assert path.read_text() == invalid
    assert exclude.read_bytes() == before
    assert not (checkout / ".codex/hooks.json").exists()


@pytest.mark.parametrize("directory", [True, False])
def test_symlinked_config_cannot_escape_checkout(checkout, tmp_path, directory):
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / "settings.local.json"
    protected.write_text('{"permissions": {}}')
    if directory:
        (checkout / ".claude").symlink_to(outside, target_is_directory=True)
    else:
        (checkout / ".claude").mkdir()
        (checkout / ".claude/settings.local.json").symlink_to(protected)
    with pytest.raises(ValueError, match="symlink"):
        installer.install_hooks(checkout, Path(sys.executable))
    assert protected.read_text() == '{"permissions": {}}'


def test_dry_run_creates_no_settings_exclusions_or_backups(checkout):
    exclude = checkout / ".git/info/exclude"
    before = exclude.read_bytes()
    report = installer.install_hooks(checkout, Path(sys.executable), dry_run=True)
    assert len(report["changed_config_paths"]) == 2
    assert report["backup_directory"] is None
    assert exclude.read_bytes() == before
    assert not (checkout / ".codex").exists()
    assert not (checkout / ".skylos").exists()


def test_non_posix_host_is_refused_before_any_configuration_changes(
    checkout, monkeypatch
):
    exclude = checkout / ".git/info/exclude"
    before = exclude.read_bytes()
    python = Path(sys.executable)
    # Replace only the installer's module binding; changing the process-wide
    # os.name would also change pathlib's class selection inside pytest.
    monkeypatch.setattr(installer, "os", SimpleNamespace(name="nt"))
    with pytest.raises(ValueError, match="POSIX"):
        installer.install_hooks(checkout, python)
    assert exclude.read_bytes() == before
    assert not (checkout / ".codex").exists()
    assert not (checkout / ".claude").exists()
    assert not (checkout / ".skylos").exists()


def test_read_only_git_exclusion_is_not_bypassed_by_atomic_replacement(checkout):
    exclude = checkout / ".git/info/exclude"
    before = exclude.read_bytes()
    exclude.chmod(0o444)
    try:
        with pytest.raises(PermissionError, match="read-only"):
            installer.install_hooks(checkout, Path(sys.executable))
        assert exclude.read_bytes() == before
        assert exclude.stat().st_mode & 0o777 == 0o444
        assert not (checkout / ".codex/hooks.json").exists()
        assert not (checkout / ".claude/settings.local.json").exists()
    finally:
        exclude.chmod(0o644)


@pytest.mark.parametrize("relative", list(installer.CONFIGS.values()))
def test_git_tracked_destination_refuses_before_any_mutation(checkout, relative):
    target = checkout / relative
    target.parent.mkdir(parents=True)
    target.write_text('{"existing":true}\n')
    # The user's global ignore can already hide Claude's local settings. This
    # synthetic fixture deliberately models a file that was force-tracked.
    _git(checkout, "add", "-f", relative)
    exclude = checkout / ".git/info/exclude"
    original_exclude = exclude.read_bytes()
    original_config = target.read_bytes()
    with pytest.raises(ValueError, match="Git-tracked"):
        installer.install_hooks(checkout, Path(sys.executable))
    assert target.read_bytes() == original_config
    assert exclude.read_bytes() == original_exclude
    assert not (checkout / ".skylos").exists()


def test_concurrent_external_edit_is_preserved_and_prior_write_rolled_back(
    checkout, monkeypatch
):
    original_write = installer._atomic_write
    protected = checkout / ".claude/settings.local.json"

    def racing_write(path, content, expected):
        if path == protected:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"external":true}')
        return original_write(path, content, expected)

    monkeypatch.setattr(installer, "_atomic_write", racing_write)
    with pytest.raises(ValueError, match="changed concurrently"):
        installer.install_hooks(checkout, Path(sys.executable))
    assert _read(checkout, ".claude/settings.local.json") == {"external": True}
    assert not (checkout / ".codex/hooks.json").exists()


def test_cli_reports_required_activation_without_granting_trust(checkout):
    result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--repo", str(checkout), "--dry-run"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert any("review/trust" in line for line in report["activation"])
    assert any("Work Cloud" in line for line in report["activation"])
    assert not (checkout / ".codex/config.toml").exists()
