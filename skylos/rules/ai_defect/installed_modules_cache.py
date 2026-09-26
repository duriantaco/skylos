"""Persistent cache of the installed import-name -> distribution map.

``scan_python_dependency_hallucinations`` walks every installed
distribution's metadata to learn which import names are installed. That
depends only on the Python environment, not on the edited file, so agent
hooks (inside :func:`module_facts_index_session`) reuse it across calls.

The key is the interpreter plus the ``mtime_ns`` of every directory on
``sys.path`` and every site-packages directory: installing, upgrading or
removing a distribution adds or removes a ``*.dist-info`` directory there,
which changes that directory's mtime. Outside a session nothing is cached.
"""

from __future__ import annotations

import os
import site
import sys
from collections.abc import Callable
from pathlib import Path

from skylos.core.safe_cache_io import load_project_json_cache, save_project_json_cache
from skylos.rules.ai_defect.module_facts_index import active_module_facts_index

CACHE_PATH = Path(".skylos") / "cache" / "installed-modules.json"
MAX_CACHE_BYTES = 16_000_000
SCHEMA_VERSION = 1


def environment_key() -> list:
    dirs: list[str] = [str(entry) for entry in sys.path]
    try:
        dirs.extend(site.getsitepackages())
    except (AttributeError, OSError):
        pass
    try:
        dirs.append(site.getusersitepackages())
    except (AttributeError, OSError):
        pass
    if sys.prefix != sys.base_prefix:
        dirs.extend(str(p) for p in (Path(sys.prefix) / "lib").glob("python*/site-packages"))
    stamps = []
    for entry in dirs:
        try:
            stamps.append([entry, os.stat(entry or ".").st_mtime_ns])
        except OSError:
            stamps.append([entry, None])
    return [SCHEMA_VERSION, sys.executable, sys.version, os.getcwd(), stamps]


def installed_module_mapping(build: Callable[[], dict[str, set[str]]]):
    index = active_module_facts_index()
    if index is None:
        return build()
    key = environment_key()
    data = load_project_json_cache(index.root, CACHE_PATH, max_bytes=MAX_CACHE_BYTES)
    mapping = data.get("mapping")
    if data.get("key") == key and isinstance(mapping, dict):
        return {module: set(dists) for module, dists in mapping.items()}
    fresh = build()
    save_project_json_cache(
        index.root,
        CACHE_PATH,
        {
            "key": key,
            "mapping": {module: sorted(dists) for module, dists in fresh.items()},
        },
        indent=None,
    )
    return fresh
