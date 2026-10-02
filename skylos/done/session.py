"""Capture and reuse a session's initial working tree without changing its index.

Only committed Done configuration opts a repository into test execution.
Snapshots are local, dangling Git objects: no ref, user index or worktree is
changed. Ignored untracked files are excluded. Changed regular files are read
without following symlinks or executing Git filters. This is a baseline for
feedback, not an attestation or an agent sandbox; CI must verify independently.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import (
    _open_output_parent,
    project_cache_lock,
    read_project_text_no_symlink,
    save_project_json_cache,
)
from skylos.done.base import (
    MAX_FILE_BYTES,
    Comparison,
    DoneError,
    _changed_files,
    _command,
    _git_bytes,
    _git_text,
    _resolve_commit,
    is_runtime_path,
    open_comparison,
)
from skylos.done.config import parse_done_config

SESSION_PATH = Path(".skylos/agent-session.json")
LOCK_PATH = Path(".skylos/agent-session.lock")
MAX_SNAPSHOT_FILES = 1000
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_STATE_BYTES = 2_000_000
MAX_SESSIONS = 20
MAX_TREE_FILES = 50_000
MAX_TREE_BYTES = 256 * 1024 * 1024
_SESSION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def invalidate_latest_receipt(path: str | Path) -> bool:
    """Make an unavailable verification unreadable as a previous passing result.

    Atomic cache publication can replace a read-only latest file without
    following a symlink. Historical named receipts are preserved.
    """
    return save_project_json_cache(
        Path(path),
        Path(".skylos/receipts/latest.json"),
        {
            "schema": "skylos.done-unavailable/v1",
            "reason": "Verification could not run",
        },
    )


def capture_session(
    path: str | Path, session_id: str, *, before_edit: bool = True
) -> dict[str, Any] | None:
    """Capture once, before edits; late events explicitly lack session coverage.

    Existing baselines survive subsequent prompts and agent-made commits.
    Capture failures are retained: a later hook cannot silently reset the base.
    """
    _validate_id(session_id)
    try:
        comparison = open_comparison(path)
    except DoneError as exc:
        if "not inside a Git repository" in str(exc) or "no commits yet" in str(exc):
            return None
        raise
    root = comparison.root
    with project_cache_lock(root, LOCK_PATH, timeout_seconds=5) as locked:
        if not locked:
            raise DoneError(
                "could not lock the agent session; verification is unfinished"
            )
        state = _read_state(root)
        sessions = state["sessions"]
        session = sessions.get(session_id)
        if not isinstance(session, dict):
            session = {"files": {}}
        if "done_base" in session:
            record = session["done_base"]
            _validate_record(comparison, record)
            return record
        config = parse_done_config(comparison.base_text("pyproject.toml"))
        if not config.configured:
            return None
        try:
            if before_edit:
                tree = _stable_tree(comparison)
                head_tree = _git_text(comparison._context, "rev-parse", "HEAD^{tree}")
                if tree == (head_tree or "").strip():
                    base_sha = comparison.head_sha
                else:
                    base_sha = _snapshot_commit(comparison, tree)
            else:
                base_sha = comparison.head_sha
                tree = (
                    _git_text(comparison._context, "rev-parse", "HEAD^{tree}") or ""
                ).strip()
                _require_object_id(tree)
            record = {
                "schema": 1,
                "repository": root.as_posix(),
                "base_sha": base_sha,
                "config_sha": comparison.head_sha,
                "source": "session" if before_edit else "head_fallback",
                "config_digest": config.digest(),
                "tree_digest": _tree_digest(comparison, base_sha),
                "captured_at": int(time.time()),
            }
        except DoneError as exc:
            session["done_base"] = {"error": str(exc)[:300]}
            _publish(root, state, session_id, session)
            raise
        session["done_base"] = record
        _publish(root, state, session_id, session)
        return record


def open_session_comparison(path: str | Path, session_id: str) -> Comparison:
    """Compare the entire current working tree with the recorded session tree."""
    _validate_id(session_id)
    comparison = open_comparison(path)
    state = _read_state(comparison.root)
    session = state["sessions"].get(session_id)
    record = session.get("done_base") if isinstance(session, dict) else None
    _validate_record(comparison, record)
    tree = _stable_tree(comparison)
    changed, untracked = _changed_files(
        comparison._context, record["base_sha"], head_tree=tree
    )
    comparison.base_sha = record["base_sha"]
    comparison.base_source = "session" if record["source"] == "session" else "head"
    comparison.config_sha = record["config_sha"]
    comparison.changed = changed
    comparison._untracked = untracked
    comparison._head_tree = tree
    comparison._session_late = record["source"] == "head_fallback"
    # Inventory code uses ls-files. A private index of the actual tree also
    # includes initially untracked files and ignored, previously tracked files
    # that a staged deletion removed from the real index.
    owner = tempfile.TemporaryDirectory(prefix="skylos-done-inventory-")
    env = dict(comparison._context.env, GIT_INDEX_FILE=str(Path(owner.name) / "index"))
    try:
        _write_git(comparison, env, "read-tree", tree)
    except BaseException:
        owner.cleanup()
        raise
    comparison._context = replace(comparison._context, env=env)
    comparison._index_owner = owner
    comparison.head_dirty = comparison.head_dirty or _raw_tree_is_dirty(comparison)
    return comparison


def assert_session_unchanged(comparison: Comparison) -> None:
    """Do not issue a verdict for a tree different from the one tests checked."""
    current = open_comparison(comparison.root)
    if (
        current.head_sha != comparison.head_sha
        or _stable_tree(current) != comparison._head_tree
    ):
        raise DoneError(
            "the working tree changed during verification; recheck before finishing"
        )


def _raw_tree_is_dirty(comparison: Comparison) -> bool:
    """Recognize only Git's builtin CRLF normalization as clean.

    Raw snapshots still preserve every byte for session diffs. Attributes come
    from the private current-tree index, and blob reads are batched by object
    ID. Filters, ident and working-tree encodings are never executed or
    approximated. Any other difference remains dirty, including index-hidden
    edits. The snapshot's 1000 changed-file / 32 MB bounds also bound this read.
    """
    raw = _git_bytes(
        comparison._context,
        "diff",
        "--raw",
        "--no-abbrev",
        "--no-renames",
        "-z",
        comparison.head_sha,
        comparison._head_tree,
        "--",
    )
    if raw is None:
        return True
    if not raw:
        return False
    candidates = _normalization_candidates(raw)
    if candidates is None:
        return True
    modes = _normalization_modes(comparison, candidates)
    if modes is None:
        return True
    objects = list(dict.fromkeys(oid for _, oid in candidates.values()))
    blobs = _snapshot_blobs(comparison, objects)
    if blobs is None:
        return True
    algorithm = hashlib.sha1 if len(comparison.head_sha) == 40 else hashlib.sha256
    for path, (expected, oid) in candidates.items():
        normalized = blobs[oid].replace(b"\r\n", b"\n")
        # A conservative text subset for auto detection: Git refuses binary
        # bytes and lone CRs. Explicit text permits binary-looking contents.
        if modes[path] == "auto" and not _plain_auto_text(normalized):
            return True
        header = b"blob " + str(len(normalized)).encode() + b"\0"
        if algorithm(header + normalized).hexdigest() != expected:
            return True
    return False


def _normalization_candidates(raw: bytes) -> dict[str, tuple[str, str]] | None:
    tokens = raw.split(b"\0")
    candidates: dict[str, tuple[str, str]] = {}
    if tokens[-1] or len(tokens) % 2 != 1:
        return None
    try:
        for index in range(0, len(tokens) - 1, 2):
            old_mode, new_mode, old_oid, new_oid, status = (
                tokens[index].decode("ascii").split()
            )
            path = tokens[index + 1].decode("utf-8")
            if (
                status != "M"
                or old_mode != ":" + new_mode
                or new_mode not in {"100644", "100755"}
            ):
                return None
            _require_object_id(old_oid)
            _require_object_id(new_oid)
            candidates[path] = (old_oid, new_oid)
    except (ValueError, UnicodeError, DoneError):
        return None
    if not candidates or len(candidates) > MAX_SNAPSHOT_FILES:
        return None
    return candidates


def _normalization_modes(
    comparison: Comparison, candidates: dict[str, tuple[str, str]]
) -> dict[str, str] | None:
    names = ("text", "eol", "crlf", "filter", "ident", "working-tree-encoding")
    attributes = _read_git_input(
        comparison,
        ("check-attr", "--cached", "-z", "--stdin", *names),
        b"".join(path.encode("utf-8") + b"\0" for path in candidates),
    )
    if attributes is None:
        return None
    settings: dict[str, dict[str, str]] = {path: {} for path in candidates}
    try:
        triples = attributes.decode("utf-8").split("\0")
        if len(triples) != len(candidates) * len(names) * 3 + 1:
            return None
        for index in range(0, len(triples) - 1, 3):
            path, attribute, value = triples[index : index + 3]
            if (
                path not in settings
                or attribute not in names
                or attribute in settings[path]
            ):
                return None
            settings[path][attribute] = value
    except UnicodeError:
        return None
    autocrlf = (
        (_git_text(comparison._context, "config", "--get", "core.autocrlf") or "")
        .strip()
        .lower()
    )
    modes = {}
    for path, attrs in settings.items():
        mode = _crlf_mode(attrs, autocrlf)
        if mode is None:
            return None
        modes[path] = mode
    return modes


def _crlf_mode(attrs: dict[str, str], autocrlf: str) -> str | None:
    if any(
        attrs[name] not in {"unset", "unspecified"}
        for name in ("filter", "ident", "working-tree-encoding")
    ):
        return None
    text = attrs["text"]
    if text == "unspecified":
        text = {"set": "set", "unset": "unset", "input": "set"}.get(attrs["crlf"], text)
    if text == "unset":
        return None
    if text in {"set", "auto"}:
        return text
    if attrs["eol"] in {"lf", "crlf"}:
        return "set"
    if autocrlf in {"true", "yes", "on", "1", "input"}:
        return "auto"
    return None


def _snapshot_blobs(
    comparison: Comparison, objects: list[str]
) -> dict[str, bytes] | None:
    output = _read_git_input(
        comparison,
        ("cat-file", "--batch"),
        "".join(oid + "\n" for oid in objects).encode("ascii"),
    )
    if output is None or len(output) > MAX_SNAPSHOT_BYTES + len(objects) * 100:
        return None
    blobs = {}
    position = total = 0
    try:
        for oid in objects:
            end = output.index(b"\n", position)
            actual, kind, size_text = output[position:end].decode("ascii").split()
            size = int(size_text)
            total += size
            if (
                actual != oid
                or kind != "blob"
                or not 0 <= size <= MAX_FILE_BYTES
                or total > MAX_SNAPSHOT_BYTES
            ):
                return None
            position = end + 1
            blobs[oid] = output[position : position + size]
            position += size
            if output[position : position + 1] != b"\n":
                return None
            position += 1
    except (ValueError, UnicodeError):
        return None
    if position != len(output):
        return None
    return blobs


def _plain_auto_text(normalized: bytes) -> bool:
    return b"\r" not in normalized and not any(
        (byte < 32 and byte not in b"\b\t\n\x1b\f") or byte == 127
        for byte in normalized
    )


def _read_git_input(
    comparison: Comparison, args: tuple[str, ...], data: bytes
) -> bytes | None:
    """Read plumbing output without filters, hooks, textconv or network fetch."""
    try:
        result = subprocess.run(
            _command(comparison._context, args),
            cwd=comparison.root,
            env=comparison._context.env,
            input=data,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def _validate_id(session_id: str) -> None:
    if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
        raise DoneError("the session identifier is invalid")


def _read_state(root: Path) -> dict[str, Any]:
    text = read_project_text_no_symlink(root, SESSION_PATH, max_bytes=MAX_STATE_BYTES)
    if text is None:
        try:
            (root / SESSION_PATH).lstat()
        except FileNotFoundError:
            return {"schema_version": 2, "sessions": {}}
        except OSError:
            pass
        raise DoneError(
            "the agent session state is unreadable; its baseline cannot be verified"
        )
    try:
        state = json.loads(text)
    except (ValueError, TypeError):
        raise DoneError(
            "the agent session state is malformed; its baseline cannot be verified"
        ) from None
    if (
        not isinstance(state, dict)
        or state.get("schema_version") not in {1, 2}
        or not isinstance(state.get("sessions"), dict)
    ):
        raise DoneError("the agent session state has an unsupported schema")
    state["schema_version"] = 2
    return state


def _publish(root: Path, state: dict, session_id: str, session: dict) -> None:
    session["updated"] = int(time.time())
    sessions = state["sessions"]
    sessions[session_id] = session
    if len(sessions) > MAX_SESSIONS:
        others = sorted(
            (key for key in sessions if key != session_id),
            key=lambda key: (
                sessions[key].get("updated", 0)
                if isinstance(sessions[key], dict)
                else 0
            ),
        )
        for key in others[: len(sessions) - MAX_SESSIONS]:
            del sessions[key]
    if not save_project_json_cache(root, SESSION_PATH, state):
        raise DoneError(
            "could not save the agent session baseline; verification is unfinished"
        )


def _validate_record(comparison: Comparison, record: Any) -> None:
    if not isinstance(record, dict):
        raise DoneError("no session baseline is available; start a new agent session")
    if "error" in record:
        raise DoneError("the initial session capture failed; start a new agent session")
    if (
        record.get("schema") != 1
        or record.get("repository") != comparison.root.as_posix()
        or record.get("source") not in {"session", "head_fallback"}
    ):
        raise DoneError("the session baseline does not match this repository")
    for key in ("base_sha", "config_sha"):
        value = record.get(key)
        if not isinstance(value, str) or not _OBJECT_ID.fullmatch(value):
            raise DoneError("the session baseline contains an invalid commit")
        if _resolve_commit(comparison._context, value) != value:
            raise DoneError(
                "a session baseline commit is unavailable; start a new agent session"
            )
    if (
        _git_bytes(
            comparison._context,
            "merge-base",
            "--is-ancestor",
            record["config_sha"],
            record["base_sha"],
        )
        is None
    ):
        raise DoneError(
            "the session baseline and its configuration do not share the recorded history"
        )
    config = parse_done_config(
        comparison.base_text("pyproject.toml", sha=record["config_sha"])
    )
    if not config.configured or record.get("config_digest") != config.digest():
        raise DoneError("the session's trusted configuration cannot be verified")
    if record.get("tree_digest") != _tree_digest(comparison, record["base_sha"]):
        raise DoneError("the session baseline inventory cannot be verified")


def _tree_digest(comparison: Comparison, sha: str) -> str:
    data = _git_bytes(comparison._context, "ls-tree", "-r", "-z", sha)
    if data is None:
        raise DoneError("could not read the session baseline inventory")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _stable_tree(comparison: Comparison) -> str:
    tree = _snapshot_tree(comparison)
    current = open_comparison(comparison.root)
    if current.head_sha != comparison.head_sha or _snapshot_tree(current) != tree:
        raise DoneError("the working tree changed while capturing the session baseline")
    return tree


def _snapshot_tree(comparison: Comparison) -> str:
    raw = _git_bytes(comparison._context, "ls-tree", "-r", "-z", comparison.head_sha)
    current = _git_bytes(
        comparison._context,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
    )
    if raw is None or current is None:
        raise DoneError("could not inventory the session working tree")
    try:
        tracked = {}
        for row in raw.decode("utf-8").split("\0"):
            if row:
                metadata, name = row.split("\t", 1)
                mode, kind, oid = metadata.split(" ")
                tracked[name] = (mode, kind, oid)
        paths = set(tracked) | {p for p in current.decode("utf-8").split("\0") if p}
    except (UnicodeError, ValueError):
        raise DoneError("the session contains unsupported Git paths") from None
    paths = {p for p in paths if not is_runtime_path(p)}
    if len(paths) > MAX_TREE_FILES:
        raise DoneError("the session tree exceeds 50000 files")
    entries = bytearray()
    total = 0
    read_total = 0
    changed_count = 0
    with tempfile.TemporaryDirectory(prefix="skylos-done-index-") as directory:
        # Git alone creates this index within a private, exclusively created
        # temporary directory. The repository's real index is never replaced.
        env = dict(
            comparison._context.env, GIT_INDEX_FILE=str(Path(directory) / "index")
        )
        _write_git(comparison, env, "read-tree", comparison.head_sha)
        for path in sorted(paths):
            expected = tracked.get(path)
            if expected and expected[1] != "blob":
                raise DoneError(
                    "submodule contents cannot be verified by the session snapshot"
                )
            try:
                file_mode = (comparison.root / path).lstat().st_mode
            except FileNotFoundError:
                if expected:
                    entries.extend(
                        f"0 {'0' * len(comparison.head_sha)}\t{path}\0".encode()
                    )
                continue
            except OSError:
                raise DoneError("could not inspect a session file") from None
            if stat.S_ISLNK(file_mode):
                data = _read_link(comparison.root, path)
                git_mode = "120000"
            else:
                text = read_project_text_no_symlink(
                    comparison.root,
                    path,
                    max_bytes=MAX_SNAPSHOT_BYTES,
                    encoding="latin1",
                    newline="",
                )
                if text is None or not stat.S_ISREG(file_mode):
                    raise DoneError(
                        f"cannot safely snapshot {path}: nonregular, unreadable or over 32 MB"
                    )
                data = text.encode("latin1")
                git_mode = "100755" if file_mode & stat.S_IXUSR else "100644"
            read_total += len(data)
            if read_total > MAX_TREE_BYTES:
                raise DoneError("the session tree exceeds 256 MB of file contents")
            algorithm = (
                hashlib.sha1 if len(comparison.head_sha) == 40 else hashlib.sha256
            )
            actual_oid = algorithm(
                b"blob " + str(len(data)).encode() + b"\0" + data
            ).hexdigest()
            if expected == (git_mode, "blob", actual_oid):
                continue
            changed_count += 1
            if changed_count > MAX_SNAPSHOT_FILES:
                raise DoneError("the session snapshot exceeds 1000 changed files")
            if len(data) > MAX_FILE_BYTES:
                raise DoneError("a changed session file exceeds 2 MB")
            total += len(data)
            if total > MAX_SNAPSHOT_BYTES:
                raise DoneError("the session snapshot exceeds 32 MB of changed files")
            oid = _write_git(
                comparison,
                env,
                "hash-object",
                "-w",
                "--no-filters",
                "--stdin",
                data=data,
            ).strip()
            _require_object_id(oid)
            entries.extend(f"{git_mode} {oid}\t{path}\0".encode())
        if entries:
            _write_git(
                comparison,
                env,
                "update-index",
                "-z",
                "--index-info",
                data=bytes(entries),
            )
        tree = _write_git(comparison, env, "write-tree").strip()
        _require_object_id(tree)
        return tree


def _read_link(root: Path, path: str) -> bytes:
    relative = Path(path)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise DoneError("a session link is outside the repository")
    if os.readlink in os.supports_dir_fd:
        # Reuse the parent-descriptor walk: every directory, including the
        # canonical repository root, is opened without following symlinks.
        descriptor = _open_output_parent(root / relative)
        if descriptor is None:
            raise DoneError("could not safely read a session symlink")
        try:
            target = os.readlink(relative.parts[-1], dir_fd=descriptor)
        except OSError:
            raise DoneError("could not safely read a session symlink") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
    else:
        current = root
        for part in relative.parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise DoneError("a session link has a symlink parent")
        try:
            target = os.readlink(current / relative.parts[-1])
        except OSError:
            raise DoneError("could not read a session symlink") from None
    return os.fsencode(target)


def _snapshot_commit(comparison: Comparison, tree: str) -> str:
    env = dict(comparison._context.env)
    env.update(
        {
            "GIT_AUTHOR_NAME": "Skylos session",
            "GIT_COMMITTER_NAME": "Skylos session",
            "GIT_AUTHOR_EMAIL": "session@skylos.local",
            "GIT_COMMITTER_EMAIL": "session@skylos.local",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
        }
    )
    sha = _write_git(
        comparison,
        env,
        "commit-tree",
        tree,
        "-p",
        comparison.head_sha,
        "-m",
        "Skylos local session baseline",
    ).strip()
    _require_object_id(sha)
    return sha


def _require_object_id(value: str) -> None:
    if not _OBJECT_ID.fullmatch(value):
        raise DoneError("Git returned an invalid session snapshot object")


def _write_git(
    comparison: Comparison, env: dict[str, str], *args: str, data: bytes | None = None
) -> str:
    # Plumbing never checks out files or invokes hooks, filters, signing, GC or
    # maintenance. It writes only the temporary index and local Git objects.
    command = _command(comparison._context, args)
    command[1:1] = [
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "-c",
        "commit.gpgSign=false",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=comparison.root,
            env=env,
            input=data,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        raise DoneError("could not create the local session snapshot") from None
    if result.returncode:
        raise DoneError("could not create the local session snapshot")
    return result.stdout.decode("ascii", errors="strict")
