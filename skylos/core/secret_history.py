"""Scan committed source snapshots for secrets without checking them out."""

from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import NamedTuple

from skylos.audit.redaction import redact_text
from skylos.core.git_safety import read_only_git_command, read_only_git_environment
from skylos.rules.secret_text import decode_secret_file_text
from skylos.rules.secrets import (
    is_aws_credential_path,
    is_secret_scan_name,
    is_shell_script_start,
    may_be_shell_script,
    scan_ctx,
)


DEFAULT_MAX_COMMITS = 500
MAX_HISTORY_COMMITS = 10_000
_MAX_BLOBS = 20_000
_MAX_BLOB_BYTES = 1024 * 1024
_MAX_TOTAL_BLOB_BYTES = 64 * 1024 * 1024
_MAX_INVENTORY_BYTES = 64 * 1024 * 1024
_MAX_TREE_BYTES = 4 * 1024 * 1024
_MAX_FINDINGS = 10_000
_MAX_ERRORS = 100
_MAX_SECONDS = 90
_BATCH_BLOBS = 24
_OBJECT_ID = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_UTF16_OR_UTF32_BOM = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")


class _HistoryReadError(Exception):
    """A local Git object operation failed or exceeded a limit."""


class _Blob(NamedTuple):
    path: str
    oid: bytes
    size: int


def _safe_text(value: str) -> str:
    return redact_text(
        "".join(char if char.isprintable() else ascii(char)[1:-1] for char in value)
    )


def _read_git(executable, root, env, args, *, limit, deadline, requests=b""):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _HistoryReadError("Git-history scan reached its time limit.")
    command = read_only_git_command(args, literal_pathspecs=True)
    command[0] = executable
    output = bytearray()
    read_failure = []

    with tempfile.TemporaryFile() as stdin:
        stdin.write(requests)
        stdin.seek(0)
        with subprocess.Popen(
            command,
            cwd=root,
            env=env,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        ) as process:
            assert process.stdout is not None

            def read_output():
                try:
                    while chunk := process.stdout.read(
                        min(65_536, limit + 1 - len(output))
                    ):
                        output.extend(chunk)
                        if len(output) > limit:
                            read_failure.append("A Git object read exceeded its output limit.")
                            process.kill()
                            break
                except OSError:
                    read_failure.append("Could not read local Git output.")

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            try:
                process.wait(timeout=min(15, remaining))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise _HistoryReadError("A local Git read timed out.") from None
            finally:
                reader.join(timeout=1)
            if reader.is_alive():
                raise _HistoryReadError("A local Git output pipe did not close.")
            if read_failure:
                raise _HistoryReadError(read_failure[0])
            if process.returncode:
                raise _HistoryReadError("Could not read the requested local Git objects.")
    return bytes(output)


def _git_executable(root: Path) -> str:
    executable = shutil.which("git")
    if executable:
        path = Path(executable)
        resolved = path.resolve()
        if (
            path.is_absolute()
            and not path.is_relative_to(root)
            and not resolved.is_relative_to(root)
        ):
            return str(resolved)
    raise _HistoryReadError("No Git executable was found outside the scanned worktree.")


def _worktree_scope(path: str | Path) -> tuple[Path, str]:
    target = Path(os.path.abspath(Path(path).expanduser()))
    root = None
    for ancestor in (*reversed(target.parents), target):
        if root is not None and ancestor.is_symlink():
            # The historical path may have been a regular file or directory.
            # Its current link destination is irrelevant to that history.
            break
        if (ancestor / ".git").exists():
            root = ancestor
    if root is None:
        raise _HistoryReadError("Git-history scanning requires a local Git worktree.")
    return root.resolve(), target.relative_to(root).as_posix()


def _tree_blobs(data: bytes, summary: dict) -> Iterator[_Blob]:
    if data and not data.endswith(b"\x00"):
        raise _HistoryReadError("Git returned an incomplete tree inventory.")
    for row in data[:-1].split(b"\x00") if data else ():
        header, separator, name = row.partition(b"\t")
        metadata = header.split()
        if not separator or not name or len(metadata) != 4:
            raise _HistoryReadError("Git returned a malformed tree entry.")
        mode, kind, oid, size = metadata
        if mode not in {b"100644", b"100755"} or kind != b"blob":
            summary["nonregular_entries_skipped"] += 1
            continue
        try:
            path = name.decode("utf-8")
        except UnicodeError:
            raise _HistoryReadError("A historical path could not be represented as UTF-8.") from None
        name = PurePosixPath(path).name
        if not (
            is_secret_scan_name(name)
            or is_aws_credential_path(path)
            or may_be_shell_script(name)
        ):
            continue
        if not _OBJECT_ID.fullmatch(oid) or not size.isdigit() or len(size) > 20:
            raise _HistoryReadError("A supported historical blob is missing or invalid.")
        yield _Blob(path, oid, int(size))


def _batch_contents(data: bytes, entries: list[_Blob]) -> Iterator[tuple[_Blob, bytes]]:
    position = 0
    for entry in entries:
        header = b"%s blob %d\n" % (entry.oid, entry.size)
        if not data.startswith(header, position):
            raise _HistoryReadError("A supported historical blob is missing or invalid.")
        start = position + len(header)
        end = start + entry.size
        if data[end : end + 1] != b"\n":
            raise _HistoryReadError("Git returned a truncated historical blob.")
        position = end + 1
        yield entry, data[start:end]
    if position != len(data):
        raise _HistoryReadError("Git returned unexpected historical blob data.")


def _error(errors, summary, kind, message, *, path=".", commit=None):
    summary["status"] = "incomplete"
    summary["errors_count"] += 1
    if len(errors) < _MAX_ERRORS:
        row = {
            "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "severity": "HIGH",
            "kind": kind,
            "message": message,
            "file": _safe_text(path),
            "line": 1,
        }
        if commit:
            row["git_commit"] = commit
        errors.append(row)


def _scan_blob(entry, data, commit, findings, errors, summary):
    if b"\x00" in data and not data.startswith(_UTF16_OR_UTF32_BOM):
        summary["binary_blobs_skipped"] += 1
        return
    content = decode_secret_file_text(data, strict_utf8=True)
    if content is None:
        _error(
            errors, summary, "history_blob_unreadable",
            "Could not decode a historical source blob.",
            path=entry.path, commit=commit,
        )
        return
    lines = content.text.splitlines(True)
    name = PurePosixPath(entry.path).name
    if may_be_shell_script(name) and not is_aws_credential_path(entry.path) and (
        not lines or not is_shell_script_start(lines[0])
    ):
        return
    try:
        result = scan_ctx(
            {
                "relpath": entry.path,
                "lines": lines,
                "tree": None,
                "honor_inline_ignores": False,
                "provider_only": name.lower().endswith((".html", ".htm", ".css", ".map")),
            }
        )
    except Exception:
        _error(
            errors, summary, "history_secret_analysis_incomplete",
            "Could not scan a historical source blob for secrets.",
            path=entry.path, commit=commit,
        )
        return
    summary["blobs_scanned"] += 1
    for finding in result:
        if finding.get("kind") == "processing_error":
            _error(
                errors, summary, "history_secret_analysis_incomplete",
                "Secret analysis was incomplete for a historical source blob.",
                path=entry.path, commit=commit,
            )
            continue
        if len(findings) >= _MAX_FINDINGS:
            raise _HistoryReadError("Git-history scan reached its finding limit.")
        finding["file"] = _safe_text(finding["file"])
        finding["message"] = _safe_text(finding["message"])
        for location in finding.get("related_locations", []):
            location["file"] = _safe_text(location["file"])
        finding["git_commit"] = commit
        finding["git_blob"] = entry.oid.decode("ascii")
        if content.encoding is not None:
            finding["source_encoding"] = content.encoding
        findings.append(finding)


def _snapshot_history(read_git, ref, max_commits, errors, summary):
    shallow = read_git(["rev-parse", "--is-shallow-repository"], limit=16).strip()
    if shallow not in {b"true", b"false"}:
        raise _HistoryReadError("Could not determine whether Git history is shallow.")
    summary["shallow"] = shallow == b"true"
    if summary["shallow"]:
        _error(errors, summary, "history_shallow", "Local Git history is shallow.")
    try:
        tip = read_git(
            ["rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"], limit=128
        ).strip()
    except _HistoryReadError:
        raise _HistoryReadError("Could not resolve the requested local Git revision to a commit.") from None
    if not _OBJECT_ID.fullmatch(tip):
        raise _HistoryReadError("Could not resolve the requested Git commit.")
    summary["resolved_commit"] = tip.decode("ascii")
    output = read_git(
        [
            "rev-list", "--topo-order", "--no-commit-header", "--format=%H%x20%T",
            f"--max-count={max_commits + 1}", summary["resolved_commit"], "--",
        ],
        limit=(max_commits + 1) * 132,
    )
    rows = output.splitlines()
    if len(rows) > max_commits:
        _error(errors, summary, "history_commit_limit", "Git-history scan reached its commit limit.")
    for row in rows[:max_commits]:
        commit, separator, tree = row.partition(b" ")
        if not separator or not (_OBJECT_ID.fullmatch(commit) and _OBJECT_ID.fullmatch(tree)):
            raise _HistoryReadError("Git returned an invalid commit or tree identifier.")
        yield commit.decode("ascii"), tree.decode("ascii")


def _scan_snapshots(read_git, ref, scope, max_commits, findings, errors, summary, deadline):
    trees = set()
    visited = set()
    blob_bytes_scheduled = 0
    for commit, tree in _snapshot_history(read_git, ref, max_commits, errors, summary):
        if tree not in trees:
            trees.add(tree)
            raw_tree = read_git(
                ["ls-tree", "-rlz", "--full-tree", tree, "--", *([scope] if scope else [])],
                limit=min(_MAX_TREE_BYTES, _MAX_INVENTORY_BYTES - summary["inventory_bytes"]),
            )
            summary["inventory_bytes"] += len(raw_tree)
            batch = []
            for blob in _tree_blobs(raw_tree, summary):
                identity = (blob.path, blob.oid)
                if identity in visited:
                    continue
                if len(visited) >= _MAX_BLOBS:
                    _scan_batch(read_git, batch, commit, findings, errors, summary, deadline)
                    raise _HistoryReadError("Git-history scan reached its blob limit.")
                visited.add(identity)
                if blob.size > _MAX_BLOB_BYTES:
                    _error(
                        errors, summary, "history_blob_limit",
                        "A historical source blob exceeds the per-blob size limit.",
                        path=blob.path, commit=commit,
                    )
                    continue
                if blob_bytes_scheduled + blob.size > _MAX_TOTAL_BLOB_BYTES:
                    _scan_batch(read_git, batch, commit, findings, errors, summary, deadline)
                    raise _HistoryReadError("Git-history scan reached its total blob byte limit.")
                blob_bytes_scheduled += blob.size
                batch.append(blob)
                if len(batch) == _BATCH_BLOBS:
                    _scan_batch(read_git, batch, commit, findings, errors, summary, deadline)
                    batch.clear()
            if batch:
                _scan_batch(read_git, batch, commit, findings, errors, summary, deadline)
        summary["commits_scanned"] += 1


def _scan_batch(read_git, entries, commit, findings, errors, summary, deadline):
    if not entries:
        return
    data = read_git(
        ["cat-file", "--batch"],
        requests=b"".join(entry.oid + b"\n" for entry in entries),
        limit=sum(entry.size + len(entry.oid) + 32 for entry in entries),
    )
    for entry, content in _batch_contents(data, entries):
        if time.monotonic() >= deadline:
            raise _HistoryReadError("Git-history scan reached its time limit.")
        summary["blob_bytes_read"] += len(content)
        _scan_blob(entry, content, commit, findings, errors, summary)


def scan_git_history(
    path: str | Path,
    *,
    ref: str = "HEAD",
    max_commits: int = DEFAULT_MAX_COMMITS,
) -> dict:
    """Scan distinct path/blob versions reachable from a ref in a local worktree.

    A finding's commit is the first visited snapshot containing that path and
    blob. It need not be the commit that introduced the secret.
    """
    if type(max_commits) is not int or not 1 <= max_commits <= MAX_HISTORY_COMMITS:
        raise ValueError(f"max_commits must be between 1 and {MAX_HISTORY_COMMITS}")
    if (
        not isinstance(ref, str)
        or not ref.strip()
        or len(ref) > 1_024
        or not ref.isprintable()
    ):
        raise ValueError("ref must be a nonempty printable Git revision of at most 1024 characters")
    findings, errors = [], []
    summary = {
        "status": "complete",
        "ref": _safe_text(ref),
        "resolved_commit": None,
        "scope": ".",
        "max_commits": max_commits,
        "max_blobs": _MAX_BLOBS,
        "max_blob_bytes": _MAX_BLOB_BYTES,
        "max_total_blob_bytes": _MAX_TOTAL_BLOB_BYTES,
        "max_inventory_bytes": _MAX_INVENTORY_BYTES,
        "max_seconds": _MAX_SECONDS,
        "shallow": None,
        "commits_scanned": 0,
        "blobs_scanned": 0,
        "blob_bytes_read": 0,
        "inventory_bytes": 0,
        "binary_blobs_skipped": 0,
        "nonregular_entries_skipped": 0,
        "errors_count": 0,
    }
    deadline = time.monotonic() + _MAX_SECONDS
    try:
        root, scope = _worktree_scope(path)
        summary["scope"] = _safe_text(scope)
        executable = _git_executable(root)
        env = read_only_git_environment()
        # Older Git may ignore GIT_NO_LAZY_FETCH. Disallow every transport,
        # including ones enabled by repository-specific protocol configuration.
        env["GIT_ALLOW_PROTOCOL"] = ""
        env["GIT_GRAFT_FILE"] = os.devnull

        def read_git(args, *, limit, requests=b""):
            return _read_git(
                executable, root, env, args, limit=limit, deadline=deadline, requests=requests
            )

        _scan_snapshots(
            read_git, ref, None if scope == "." else scope,
            max_commits, findings, errors, summary, deadline,
        )
    except _HistoryReadError as exc:
        _error(errors, summary, "history_unavailable", str(exc))
    except (OSError, RuntimeError):
        _error(errors, summary, "history_unavailable", "Could not scan local Git history.")
    return {
        "secrets": findings,
        "analysis_errors": errors,
        "analysis_summary": {
            "git_history": summary,
            "secrets_count": len(findings),
            "analysis_error_count": summary["errors_count"],
        },
    }
