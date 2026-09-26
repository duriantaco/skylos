"""Persistent per-file index of Python module facts.

The local-API hallucination check (SKY-L012/SKY-L023 and the
``python_local_api_reference`` verification check) needs the public
surface of *every* module in the project to judge references in the
edited file. Building that surface parses the whole project, which is what
made ``skylos hook post-edit`` take seconds on large repos.

This index stores, per source file, the facts the scan derives from it
(members, re-exported local modules, dynamic ``__getattr__``), so later
runs only rebuild files that changed. It is opt-in: nothing uses it unless
a caller enters :func:`module_facts_index_session` (agent hooks and
``skylos agent warm-cache`` do); every other scan behaves exactly as
before.

Correctness: an entry is reused only when all of these still hold, so a
cached run returns the same facts as an uncached one:

* the file identity is unchanged -- ``(mtime_ns, ctime_ns, size, inode,
  device)``, taken *before* the file is read, so an edit racing the read is
  seen as stale next time;
* the file maps to the same dotted module name;
* every "is X a local module?" answer the facts depended on is still the
  same. Facts depend on the set of project modules only through membership
  tests, which are recorded while the facts are built; adding or removing
  a file therefore invalidates exactly the entries whose imports could
  resolve differently;
* the index header matches: schema, Skylos version, Python ``major.minor``
  (the ``ast`` shape) and the size/mtime of the modules that compute facts.

Lives at ``<project>/.skylos/cache/module-facts.json`` (``.skylos`` is
gitignored). Writes are atomic (temp file + ``os.replace``); concurrent
hooks may drop each other's new entries, which only costs a rebuild.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import (
    load_project_json_cache,
    save_project_json_cache,
)

SCHEMA_VERSION = 1
CACHE_PATH = Path(".skylos") / "cache" / "module-facts.json"
MAX_CACHE_BYTES = 64_000_000

STATUS_OK = "ok"
STATUS_UNREADABLE = "unreadable"
STATUS_PARSE_ERROR = "parse_error"

_ACTIVE: list["ModuleFactsIndex"] = []


def file_token(path: Path) -> list[int] | None:
    """Identity of ``path`` (same fields as the run-scoped AST cache)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return [st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino, st.st_dev]


def token_size(token: list[int]) -> int:
    return token[2]


class RecordingModules:
    """Membership-only view of the local module set that records queries.

    Module facts consult the project module set only via ``name in
    local_modules``. Recording those answers lets a cached entry be
    revalidated against a later module set without rebuilding it. Any other
    use (iteration, len) raises, so a future change that depends on the
    set in another way fails loudly instead of caching stale facts.
    """

    __slots__ = ("_modules", "queries")

    def __init__(self, modules) -> None:
        self._modules = modules
        self.queries: dict[str, bool] = {}

    def __contains__(self, name) -> bool:
        result = name in self._modules
        self.queries[name] = result
        return result


def _implementation_fingerprint() -> list[Any]:
    from skylos import __version__
    from skylos.rules.ai_defect import phantom_refs
    from skylos.rules.quality import _protocols

    parts: list[Any] = [SCHEMA_VERSION, __version__, list(sys.version_info[:2])]
    for module_file in (__file__, phantom_refs.__file__, _protocols.__file__):
        try:
            st = os.stat(module_file)
            parts.append([st.st_size, st.st_mtime_ns])
        except (OSError, TypeError):
            parts.append(None)
    return parts


class ModuleFactsIndex:
    def __init__(self, project_root: str | Path) -> None:
        self.root = Path(project_root).resolve()
        self.header = _implementation_fingerprint()
        self.entries: dict[str, dict[str, Any]] = {}
        self.dirty = False
        self.loaded_entries = 0
        self.hits = 0
        self.misses = 0
        self._touched: set[str] = set()
        self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        data = load_project_json_cache(
            self.root, CACHE_PATH, max_bytes=MAX_CACHE_BYTES
        )
        if data.get("header") != self.header:
            if data:
                self.dirty = True  # rewrite with the current header
            return
        entries = data.get("entries")
        if isinstance(entries, dict):
            self.entries = entries
            self.loaded_entries = len(entries)

    def save(self) -> bool:
        if not self.dirty:
            return True
        # Drop entries for files that vanished; keep untouched entries of
        # files that still exist (another scan root may use them).
        for key in [k for k in self.entries if k not in self._touched]:
            if not os.path.exists(key):
                del self.entries[key]
        payload = {"header": self.header, "entries": self.entries}
        ok = save_project_json_cache(self.root, CACHE_PATH, payload, indent=None)
        if ok:
            self.dirty = False
        return ok

    # -- entries -------------------------------------------------------------

    def lookup(
        self,
        path: Path,
        token: list[int] | None,
        module_name: str,
        local_modules,
    ) -> dict[str, Any] | None:
        """Return a still-valid entry for ``path`` or None."""
        if token is None:
            return None
        key = str(path)
        self._touched.add(key)
        entry = self.entries.get(key)
        if (
            not isinstance(entry, dict)
            or entry.get("token") != token
            or entry.get("module") != module_name
        ):
            self.misses += 1
            return None
        deps = entry.get("deps")
        if not isinstance(deps, dict):
            self.misses += 1
            return None
        for name, expected in deps.items():
            if (name in local_modules) != expected:
                self.misses += 1
                return None
        self.hits += 1
        return entry

    def store(
        self,
        path: Path,
        token: list[int] | None,
        module_name: str,
        *,
        status: str,
        facts: dict[str, Any] | None = None,
        deps: dict[str, bool] | None = None,
    ) -> None:
        if token is None:
            return
        key = str(path)
        self._touched.add(key)
        self.entries[key] = {
            "token": token,
            "module": module_name,
            "status": status,
            "facts": facts,
            "deps": dict(deps or {}),
        }
        self.dirty = True


def active_module_facts_index() -> ModuleFactsIndex | None:
    return _ACTIVE[-1] if _ACTIVE else None


@contextmanager
def module_facts_index_session(
    project_root: str | Path,
) -> Iterator[ModuleFactsIndex | None]:
    """Use (and afterwards persist) the on-disk index for scans in this block.

    Fails open: if the index cannot be loaded the block runs uncached.
    """
    try:
        index: ModuleFactsIndex | None = ModuleFactsIndex(project_root)
    except Exception:
        index = None
    if index is None:
        yield None
        return
    _ACTIVE.append(index)
    try:
        yield index
    finally:
        _ACTIVE.remove(index)
        try:
            index.save()
        except Exception:
            pass


def describe(index: ModuleFactsIndex | None) -> dict[str, Any]:
    if index is None:
        return {"enabled": False}
    return {
        "enabled": True,
        "path": str(index.root / CACHE_PATH),
        "loaded_entries": index.loaded_entries,
        "entries": len(index.entries),
        "hits": index.hits,
        "misses": index.misses,
    }
