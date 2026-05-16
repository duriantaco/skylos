from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CACHE_DIR = ".skylos/cache"
CACHE_FILE = "grep_results.json"
MAX_ENTRIES = 10_000
HASH_BYTES = 8192
MAX_CACHE_BYTES = 5 * 1024 * 1024


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
        self._dirty = False

    def get(self, key: str) -> list[str] | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            entry["last_access"] = time.time()
            self._dirty = True
            return entry["results"]

    def put(self, key: str, results: list[str]) -> None:
        with self._lock:
            self._entries[key] = {
                "results": results,
                "last_access": time.time(),
                "created": time.time(),
            }
            self._dirty = True
            self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        if len(self._entries) <= MAX_ENTRIES:
            return
        sorted_keys = sorted(
            self._entries.keys(),
            key=lambda k: self._entries[k].get("last_access", 0),
        )
        to_remove = len(self._entries) - MAX_ENTRIES
        for key in sorted_keys[:to_remove]:
            del self._entries[key]

    def invalidate_by_hash(self, content_hash: str) -> int:
        with self._lock:
            to_remove = [k for k in self._entries if content_hash in k]
            for k in to_remove:
                del self._entries[k]
            if to_remove:
                self._dirty = True
            return len(to_remove)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._dirty = True

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def _cache_path(self, project_root: str | Path, *, create: bool = False) -> Path | None:
        try:
            root = Path(project_root).resolve(strict=True)
        except OSError:
            return None

        cache_dir = root / CACHE_DIR
        for directory in (root / ".skylos", cache_dir):
            try:
                if directory.is_symlink():
                    return None
                if directory.exists():
                    resolved = directory.resolve(strict=True)
                    resolved.relative_to(root)
                    if not directory.is_dir():
                        return None
                elif create:
                    directory.mkdir(mode=0o700)
                else:
                    return None
            except (OSError, ValueError):
                return None

        path = cache_dir / CACHE_FILE
        try:
            if path.is_symlink():
                return None
            if path.exists():
                resolved = path.resolve(strict=True)
                resolved.relative_to(cache_dir.resolve(strict=True))
                if not path.is_file():
                    return None
        except (OSError, ValueError):
            return None

        return path

    def _read_cache_text(self, path: Path) -> str | None:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)  # skylos: ignore[SKY-D215] guarded project-local grep cache path
        except OSError:
            return None
        try:
            with os.fdopen(fd, "r", encoding="utf-8") as f:
                return f.read(MAX_CACHE_BYTES + 1)
        except OSError:
            return None

    def _normalize_entries(self, raw_entries: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(raw_entries, dict):
            return {}

        normalized: dict[str, dict[str, Any]] = {}
        for key, value in raw_entries.items():
            if len(normalized) >= MAX_ENTRIES:
                break
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            results = value.get("results")
            if not isinstance(results, list) or not all(
                isinstance(item, str) for item in results
            ):
                continue
            normalized[key] = {
                "results": results,
                "last_access": _coerce_timestamp(value.get("last_access")),
                "created": _coerce_timestamp(value.get("created")),
            }
        return normalized

    def load(self, project_root: str | Path) -> None:
        path = self._cache_path(project_root)
        if path is None:
            return
        try:
            if path.stat().st_size > MAX_CACHE_BYTES:
                return
            text = self._read_cache_text(path)
            if text is None or len(text.encode("utf-8")) > MAX_CACHE_BYTES:
                return
            data = json.loads(text)
            entries = self._normalize_entries(data.get("entries", {}))
            with self._lock:
                self._entries = entries
                self._dirty = False
            logger.debug("Loaded %d grep cache entries", len(self._entries))
        except Exception as e:
            logger.debug("Failed to load grep cache: %s", e)

    def save(self, project_root: str | Path) -> None:
        with self._lock:
            if not self._dirty:
                return
            data = {"version": 1, "entries": dict(self._entries)}
            self._dirty = False

        path = self._cache_path(project_root, create=True)
        if path is None:
            with self._lock:
                self._dirty = True
            return

        payload = json.dumps(data)
        temp_path = path.with_name(
            f".{CACHE_FILE}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(temp_path, flags, 0o600)  # skylos: ignore[SKY-D215] guarded project-local grep cache temp path
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            os.replace(temp_path, path)
            logger.debug("Saved %d grep cache entries", len(data["entries"]))
        except Exception as e:
            logger.debug("Failed to save grep cache: %s", e)
            with self._lock:
                self._dirty = True
        finally:
            try:
                if temp_path.exists() and not temp_path.is_symlink():
                    temp_path.unlink()
            except OSError:
                pass

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


def _coerce_timestamp(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
