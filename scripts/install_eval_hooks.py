#!/usr/bin/env python3
"""Prepare private, repository-local Codex and Claude eval hooks.

This writes configuration only. It never changes project trust, invokes a model,
or installs hooks in global settings. Review native hooks in each client before
relying on them.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parent.parent
EVENTS = ("UserPromptSubmit", "PreToolUse", "Stop")
# Observe unfamiliar tools too; the adapter skips known native read-only tools.
TOOL_MATCHER = "*"
CONFIGS = {"codex": ".codex/hooks.json", "claude": ".claude/settings.local.json"}
EXCLUDES = (
    "/.codex/hooks.json",
    "/.claude/settings.local.json",
    "/.skylos/evals/hooks/setup/",
)


@dataclass(frozen=True)
class FileState:
    content: bytes | None
    mode: int | None


def _safe_local_path(repo: Path, path: Path) -> Path:
    """Refuse local config or backup paths redirected through symlinks."""
    if not path.is_relative_to(repo):
        raise ValueError("hook configuration must remain inside its checkout")
    for candidate in (path, *path.parents):
        if candidate == repo:
            break
        if candidate.is_symlink():
            raise ValueError(
                f"symlinked hook configuration path is unsupported: {path}"
            )
    return path


def _read_state(path: Path) -> FileState:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return FileState(None, None)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"hook configuration must be a regular file: {path}")
    return FileState(path.read_bytes(), stat.S_IMODE(info.st_mode))


def _atomic_write(path: Path, content: bytes, expected: FileState) -> None:
    """Preserve modes and reject a changed file before replacing its contents."""
    if _read_state(path) != expected:
        raise ValueError(f"hook configuration changed concurrently: {path}")
    if expected.mode is not None and not expected.mode & 0o222:
        raise PermissionError(
            f"refusing to replace read-only hook configuration: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".eval-hooks-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(
                output.fileno(), expected.mode if expected.mode is not None else 0o600
            )
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if _read_state(path) != expected:
            raise ValueError(f"hook configuration changed concurrently: {path}")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _document(state: FileState, path: Path) -> dict:
    if state.content is None:
        return {}
    try:
        value = json.loads(state.content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid existing hook JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"hook settings must be a JSON object: {path}")
    hooks = value.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"hooks must be an object: {path}")
    for groups in hooks.values():
        if not isinstance(groups, list) or any(
            not isinstance(group, dict)
            or not isinstance(group.get("hooks"), list)
            or any(not isinstance(handler, dict) for handler in group["hooks"])
            for group in groups
        ):
            raise ValueError(f"invalid existing hook groups: {path}")
    return value


def _owned(handler: dict, script: Path, client: str) -> bool:
    command = handler.get("command")
    if handler.get("type") != "command" or not isinstance(command, str):
        return False
    try:
        arguments = shlex.split(command)
    except ValueError:
        return False
    return str(script) in arguments and any(
        arguments[index : index + 2] == ["--client", client]
        for index in range(len(arguments) - 1)
    )


def _merge(document: dict, *, client: str, repo: Path, python: Path) -> dict:
    result = copy.deepcopy(document)
    hooks = result.setdefault("hooks", {})
    script = repo / "scripts/eval_hook.py"
    command = shlex.join(
        [str(python), "-B", str(script), "--client", client, "--repo", str(repo)]
    )
    # Remove only this installer's handlers, wherever an earlier run placed them.
    for event, groups in list(hooks.items()):
        retained = []
        for group in groups:
            others = [
                handler
                for handler in group["hooks"]
                if not _owned(handler, script, client)
            ]
            if others or len(others) == len(group["hooks"]):
                retained.append({**group, "hooks": others})
        hooks[event] = retained
    for event in EVENTS:
        handler = {"type": "command", "command": command, "timeout": 300}
        if client == "claude" and event in {"UserPromptSubmit", "PreToolUse"}:
            handler["onFailure"] = "block"
        group = {"hooks": [handler]}
        if event == "PreToolUse":
            group["matcher"] = TOOL_MATCHER
        hooks.setdefault(event, []).append(group)
    return result


def _git(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("eval hooks require a valid Git checkout") from error
    return result.stdout.strip()


def _encode(document: dict) -> bytes:
    return (
        json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode()


def install_hooks(repo: Path, python: Path, *, dry_run: bool = False) -> dict:
    """Merge POSIX-only local hooks without granting native client trust.

    The adapter uses POSIX file locking. Unsupported hosts are refused before
    resolving paths or changing configuration, so they cannot enable broken hooks.
    """
    if os.name != "posix":
        raise ValueError("automatic eval hooks currently require POSIX (macOS/Linux)")
    repo = Path(repo).resolve(strict=True)
    # Keep the venv spelling: resolving its Python symlink loses its site packages.
    python = Path(os.path.abspath(python))
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("--python must name an executable Python interpreter")
    if Path(_git(repo, "rev-parse", "--show-toplevel")).resolve() != repo:
        raise ValueError("--repo must be a Git checkout root")
    tracked = _git(repo, "ls-files", "--", *CONFIGS.values())
    if tracked:
        raise ValueError(
            "private hook destination is Git-tracked; excludes cannot protect it"
        )
    for relative in ("scripts/eval_check.py", "scripts/eval_hook.py"):
        path = _safe_local_path(repo, repo / relative)
        if not path.is_file():
            raise ValueError(
                f"target checkout lacks {relative}; no other checkout is substituted"
            )

    states, writes = {}, {}
    for client, relative in CONFIGS.items():
        path = _safe_local_path(repo, repo / relative)
        state = _read_state(path)
        document = _document(state, path)
        content = _encode(_merge(document, client=client, repo=repo, python=python))
        states[path] = state
        if content != state.content:
            writes[path] = content

    exclude = Path(
        _git(repo, "rev-parse", "--path-format=absolute", "--git-path", "info/exclude")
    )
    if any(path.is_symlink() for path in (exclude, *exclude.parents)):
        raise ValueError("Git exclude path must not contain symlinks")
    exclude_state = _read_state(exclude)
    old_exclude = (exclude_state.content or b"").decode("utf-8")
    missing = [line for line in EXCLUDES if line not in old_exclude.splitlines()]
    exclude_content = exclude_state.content or b""
    if missing:
        exclude_content += (
            "" if not old_exclude or old_exclude.endswith("\n") else "\n"
        ).encode()
        exclude_content += ("\n".join(missing) + "\n").encode()

    report = {
        "repository": str(repo),
        "python": str(python),
        "dry_run": dry_run,
        "config_paths": {
            client: str(repo / relative) for client, relative in CONFIGS.items()
        },
        "changed_config_paths": [str(path) for path in writes],
        "exclude_path": str(exclude),
        "exclude_changed": exclude_content != exclude_state.content,
        "backup_directory": None,
        "activation": [
            "Codex: trust this project and review/trust the new definitions in /hooks; this installer grants no trust.",
            "Claude Code: open /hooks in a new session and confirm these project hooks are discovered.",
            "Local command hooks do not run in Work Cloud orchestration; use supported local clients and CI validation.",
        ],
    }
    if dry_run or (not writes and not report["exclude_changed"]):
        return report

    # Privacy exclusion is installed before any settings backup is written.
    if report["exclude_changed"]:
        _atomic_write(exclude, exclude_content, exclude_state)
    backup = _safe_local_path(
        repo,
        repo / ".skylos/evals/hooks/setup" / f"{time.time_ns()}-{uuid.uuid4().hex[:8]}",
    )
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(backup, 0o700)
    for path, state in {exclude: exclude_state, **states}.items():
        if state.content is None:
            continue
        name = (
            "git-info-exclude.before"
            if path == exclude
            else path.relative_to(repo).as_posix().replace("/", "__") + ".before"
        )
        _atomic_write(backup / name, state.content, FileState(None, None))
    installed = []
    try:
        for path, content in writes.items():
            _safe_local_path(repo, path)
            _atomic_write(path, content, states[path])
            installed.append(path)
    except BaseException:
        # Restore only bytes we wrote; never overwrite a subsequent external edit.
        for path in reversed(installed):
            current = _read_state(path)
            if current.content != writes[path]:
                continue
            previous = states[path]
            if previous.content is None:
                path.unlink()
            else:
                _atomic_write(path, previous.content, current)
        raise
    report["backup_directory"] = str(backup)
    manifest = {
        "repository": str(repo),
        "previous_sha256": {
            str(path): hashlib.sha256(state.content).hexdigest()
            if state.content is not None
            else None
            for path, state in {exclude: exclude_state, **states}.items()
        },
        "installed_sha256": {
            str(path): hashlib.sha256(content).hexdigest()
            for path, content in writes.items()
        },
    }
    _atomic_write(backup / "receipt.json", _encode(manifest), FileState(None, None))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        report = install_hooks(
            arguments.repo, arguments.python, dry_run=arguments.dry_run
        )
    except (OSError, ValueError) as error:
        print(f"Eval hooks were not installed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
