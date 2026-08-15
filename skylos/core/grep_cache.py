from __future__ import annotations

import hashlib
import os
import threading
import time
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from skylos.core.grep_verify_common import _ALL_SOURCE_GLOBS, _GREP_EXCLUDE_DIRS

# Legacy identifiers remain importable, but GrepCache never reads or writes them.
CACHE_DIR = ".skylos/cache"
CACHE_FILE = "grep_results.json"
MAX_ENTRIES = 10_000
MAX_RESULT_CHARS = 5 * 1024 * 1024
HASH_BYTES = 8192


def file_content_hash(file_path: str | Path) -> str:
    path = Path(file_path)
    try:
        stat = path.stat()
        size = stat.st_size
        h = hashlib.sha256()
        h.update(str(size).encode())
        with open(
            path, "rb"
        ) as f:  # skylos: ignore[SKY-D215] analyzer hashes discovered files
            h.update(f.read(HASH_BYTES))
        return h.hexdigest()[:16]
    except (OSError, IOError):
        return ""


def _resolve_repository_root(project_root: str | Path) -> Path | None:
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None
    if root.is_file():
        root = root.parent
    if not root.is_dir():
        return None
    return root


def _collect_repository_evidence_files(
    root: Path,
) -> list[tuple[str, Path]] | None:
    evidence_files: list[tuple[str, Path]] = []

    try:
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            dirnames[:] = sorted(
                name
                for name in dirnames
                if not any(fnmatch(name, pattern) for pattern in _GREP_EXCLUDE_DIRS)
                and not (directory_path / name).is_symlink()
            )
            for filename in filenames:
                if not any(fnmatch(filename, pattern) for pattern in _ALL_SOURCE_GLOBS):
                    continue
                path = directory_path / filename
                if path.is_symlink():
                    continue
                relative_path = path.relative_to(root).as_posix()
                evidence_files.append((relative_path, path))
    except (OSError, ValueError):
        return None
    return evidence_files


def _update_digest_from_evidence_file(
    digest: Any,
    path: Path,
) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] in-root grep evidence
            path, flags
        )
        with os.fdopen(fd, "rb") as evidence_file:
            while chunk := evidence_file.read(64 * 1024):
                digest.update(chunk)
    except OSError:
        digest.update(b"\0<unreadable>")


def repository_evidence_fingerprint(project_root: str | Path) -> str | None:
    """Hash every file that can contribute repository-wide grep evidence."""
    root = _resolve_repository_root(project_root)
    if root is None:
        return None
    evidence_files = _collect_repository_evidence_files(root)
    if evidence_files is None:
        return None

    digest = hashlib.sha256(b"skylos-grep-evidence-v1\0")
    for relative_path, path in sorted(evidence_files):
        encoded_path = relative_path.encode("utf-8", errors="surrogateescape")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        _update_digest_from_evidence_file(digest, path)
        digest.update(b"\0")

    digest.update(len(evidence_files).to_bytes(8, "big"))
    return digest.hexdigest()[:20]


def _make_key(
    strategy: str,
    simple_name: str,
    full_name: str,
    finding_type: str,
    content_hash: str,
) -> str:
    return f"{strategy}:{simple_name}:{full_name}:{finding_type}:{content_hash}"


class GrepCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._result_chars = 0
        self._repository_fingerprint: str | None = None
        self._fingerprint_root: Path | None = None

    @property
    def repository_fingerprint(self) -> str | None:
        with self._lock:
            return self._repository_fingerprint

    def bind_repository(self, project_root: str | Path) -> str | None:
        try:
            root = Path(project_root).resolve(strict=True)
        except OSError:
            with self._lock:
                self._entries.clear()
                self._result_chars = 0
                self._fingerprint_root = None
                self._repository_fingerprint = None
            return None
        if root.is_file():
            root = root.parent

        with self._lock:
            if self._fingerprint_root == root:
                return self._repository_fingerprint
            if self._fingerprint_root is not None:
                self._entries.clear()
                self._result_chars = 0
            namespace = hashlib.sha256(
                b"skylos-grep-process-local-v1\0" + os.fsencode(root)
            ).hexdigest()[:20]
            self._fingerprint_root = root
            self._repository_fingerprint = namespace
            return namespace

    def get(self, key: str) -> list[str] | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            entry["last_access"] = time.time()
            return list(entry["results"])

    def put(self, key: str, results: list[str]) -> None:
        stored_results = list(results)
        if not all(isinstance(result, str) for result in stored_results):
            return
        result_chars = sum(len(result) for result in stored_results)
        if result_chars > MAX_RESULT_CHARS:
            return
        with self._lock:
            previous = self._entries.pop(key, None)
            if previous is not None:
                self._result_chars -= previous["result_chars"]
            self._entries[key] = {
                "results": stored_results,
                "result_chars": result_chars,
                "last_access": time.time(),
                "created": time.time(),
            }
            self._result_chars += result_chars
            self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        if (
            len(self._entries) <= MAX_ENTRIES
            and self._result_chars <= MAX_RESULT_CHARS
        ):
            return
        sorted_keys = sorted(
            self._entries.keys(),
            key=lambda k: self._entries[k].get("last_access", 0),
        )
        for key in sorted_keys:
            if (
                len(self._entries) <= MAX_ENTRIES
                and self._result_chars <= MAX_RESULT_CHARS
            ):
                break
            removed = self._entries.pop(key)
            self._result_chars -= removed["result_chars"]

    def invalidate_by_hash(self, content_hash: str) -> int:
        with self._lock:
            to_remove = [k for k in self._entries if content_hash in k]
            for k in to_remove:
                removed = self._entries.pop(k)
                self._result_chars -= removed["result_chars"]
            return len(to_remove)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._result_chars = 0

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def load(self, project_root: str | Path) -> None:
        """Bind a process-local namespace without reading repository state."""
        self.bind_repository(project_root)

    def save(self, project_root: str | Path) -> None:
        """Keep grep results process-local; project directories are untrusted."""
        del project_root

    def cached_search(
        self,
        strategy: str,
        finding: dict,
        content_hash: str,
        search_fn: Any,
    ) -> list[str]:
        simple_name = finding.get("simple_name", finding.get("name", ""))
        full_name = finding.get("full_name", "")
        finding_type = finding.get("type", "")

        key = _make_key(strategy, simple_name, full_name, finding_type, content_hash)
        cached = self.get(key)
        if cached is not None:
            return cached

        results = search_fn()
        self.put(key, results)
        return results
