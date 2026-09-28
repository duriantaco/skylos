"""Best-effort, helper-free revision attribution for uploaded full-tree scans."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path

from skylos.constants import SUBPROCESS_TIMEOUT
from skylos.core.git_safety import read_only_git_command, read_only_git_environment


_MAX_FILES = 50_000
_MAX_BYTES = 512 * 1024 * 1024


def _git_output(root: Path, *args: str) -> bytes:
    return subprocess.check_output(
        read_only_git_command(["-C", str(root), *args]),
        env=read_only_git_environment(),
        stderr=subprocess.DEVNULL,
        timeout=SUBPROCESS_TIMEOUT,
    )


def _tree_entries(root: Path) -> dict[bytes, tuple[bytes, bytes]]:
    entries = {}
    for record in _git_output(root, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if not record:
            continue
        details, path = record.split(b"\t", 1)
        mode, kind, oid = details.split(b" ", 2)
        if kind != b"blob" or mode not in {b"100644", b"100755", b"120000"}:
            raise ValueError("unsupported Git tree entry")
        entries[path] = (mode, oid)
    return entries


def _index_entries(root: Path) -> dict[bytes, tuple[bytes, bytes]]:
    entries = {}
    for record in _git_output(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        details, path = record.split(b"\t", 1)
        mode, oid, stage = details.split(b" ", 2)
        if stage != b"0":
            raise ValueError("unmerged Git index")
        entries[path] = (mode, oid)
    return entries


def _blob_oid(root_fd: int, path: bytes, mode: bytes, oid_size: int, budget: list[int]) -> bytes:
    parts = path.split(b"/")
    if not parts or any(part in {b"", b".", b".."} for part in parts):
        raise ValueError("unsafe Git path")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("safe file opening unavailable")

    directory_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = child_fd

        leaf = parts[-1]
        file_stat = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        if mode == b"120000":
            if not stat.S_ISLNK(file_stat.st_mode):
                raise ValueError("Git symlink changed type")
            data = os.readlink(leaf, dir_fd=directory_fd)
            if isinstance(data, str):
                data = os.fsencode(data)
            if len(data) > budget[0]:
                raise ValueError("Git content budget exceeded")
            budget[0] -= len(data)
            digest = (hashlib.sha1(usedforsecurity=False)  # skylos: ignore[SKY-D208] Git SHA-1 object ID, not a security hash
                      if oid_size == 40 else hashlib.sha256())
            digest.update(f"blob {len(data)}\0".encode("ascii"))
            digest.update(data)
            return digest.hexdigest().encode("ascii")

        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("Git file changed type")
        if bool(file_stat.st_mode & 0o111) != (mode == b"100755"):
            raise ValueError("Git file changed mode")
        if file_stat.st_size > budget[0]:
            raise ValueError("Git content budget exceeded")
        budget[0] -= file_stat.st_size
        fd = os.open(  # skylos: ignore[SKY-D215] validated component below a no-follow dirfd
            leaf,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != file_stat.st_size:
                raise ValueError("Git file changed while opening")
            digest = (hashlib.sha1(usedforsecurity=False)  # skylos: ignore[SKY-D208] Git SHA-1 object ID, not a security hash
                      if oid_size == 40 else hashlib.sha256())
            digest.update(f"blob {before.st_size}\0".encode("ascii"))
            while chunk := os.read(fd, 1024 * 1024):
                digest.update(chunk)
            after = os.fstat(fd)
            if (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ino != after.st_ino
            ):
                raise ValueError("Git file changed during reading")
            return digest.hexdigest().encode("ascii")
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def source_revision_state(result: object, git_root: str | None, reported_sha: str) -> str:
    """Observe the full-scope checkout at upload time without Git filters.

    ``clean`` does not prove that the checkout was unchanged during analysis,
    or attest that an API-key upload matches the remote commit's tree.
    """

    if not isinstance(result, dict) or not git_root:
        return "unknown"
    summary = result.get("analysis_summary")
    scope = summary.get("comparison_scope") if isinstance(summary, dict) else None
    if not isinstance(scope, dict) or scope.get("complete_repository") is not True:
        return "unknown"

    scan_root = scope.get("repository_root")
    if not isinstance(scan_root, str) or not scan_root:
        return "unknown"
    try:
        root = Path(git_root).resolve(strict=False)
        Path(scan_root).resolve(strict=False).relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return "unknown"

    try:
        head = _git_output(root, "rev-parse", "--verify", "HEAD").strip()
        if len(head) not in {40, 64} or head.lower() != reported_sha.lower().encode("ascii"):
            return "unknown"
        tree = _tree_entries(root)
        if len(tree) > _MAX_FILES:
            return "unknown"
        if _index_entries(root) != tree:
            return "dirty"
        if _git_output(root, "ls-files", "--others", "--exclude-standard", "-z"):
            return "dirty"

        budget = [_MAX_BYTES]
        root_fd = os.open(  # skylos: ignore[SKY-D215] resolved Git root opened no-follow
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            for path, (mode, oid) in tree.items():
                if _blob_oid(root_fd, path, mode, len(head), budget) != oid:
                    return "dirty"
        finally:
            os.close(root_fd)
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        return "unknown"
    return "clean"
