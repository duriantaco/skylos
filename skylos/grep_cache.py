from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CACHE_DIR = ".skylos/cache"
CACHE_FILE = "grep_results.json"
MAX_ENTRIES = 10_000
HASH_BYTES = 8192


def file_content_hash(file_path: str | Path) -> str:
    path = Path(file_path)
    try:
        stat = path.stat()
        size = stat.st_size
        h = hashlib.sha256()
        h.update(str(size).encode())
        with open(path, "rb") as f:
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

    def load(self, project_root: str | Path) -> None:
        path = Path(project_root) / CACHE_DIR / CACHE_FILE
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            with self._lock:
                self._entries = data.get("entries", {})
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

        path = Path(project_root) / CACHE_DIR / CACHE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.write_text(json.dumps(data), encoding="utf-8")
            logger.debug("Saved %d grep cache entries", len(data["entries"]))
        except Exception as e:
            logger.debug("Failed to save grep cache: %s", e)

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
