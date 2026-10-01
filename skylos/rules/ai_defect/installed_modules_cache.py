"""Session cache of the installed import-name -> distribution map.

``scan_python_dependency_hallucinations`` walks every installed
distribution's metadata to learn which import names are installed. That
depends only on the Python environment, not on the edited file, so agent
hooks (inside :func:`module_facts_index_session`) reuse it across calls.

The key is the interpreter plus the ``mtime_ns`` of every directory on
``sys.path`` and every site-packages directory: installing, upgrading or
removing a distribution adds or removes a ``*.dist-info`` directory there,
which changes that directory's mtime. Outside a session nothing is cached.
Repository cache files are never evidence of what the environment provides.
"""

from __future__ import annotations

import os
import site
import sys
from collections.abc import Callable
from pathlib import Path

from skylos.rules.ai_defect.module_facts_index import active_module_facts_index

SCHEMA_VERSION = 1


def virtual_env_site_packages() -> list[str]:
    """Site-packages of the activated virtualenv ($VIRTUAL_ENV), if any.

    Skylos often runs from its own environment (pipx, a global install) while
    the user's project environment is the activated one. Its metadata is the
    best local evidence of which modules the project's packages provide.
    """
    venv = os.environ.get("VIRTUAL_ENV", "").strip()
    if not venv:
        return []
    root = Path(venv)
    try:
        dirs = [str(p) for p in (root / "lib").glob("python*/site-packages")]
        windows_dir = root / "Lib" / "site-packages"
        if windows_dir.is_dir():
            dirs.append(str(windows_dir))
    except OSError:
        return []
    return dirs


def environment_key() -> list:
    dirs: list[str] = [str(entry) for entry in sys.path]
    dirs.extend(virtual_env_site_packages())
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
    snapshot = getattr(index, "_installed_modules_snapshot", None)
    if snapshot is not None and snapshot[0] == key:
        return {module: set(dists) for module, dists in snapshot[1].items()}
    fresh = build()
    index._installed_modules_snapshot = (
        key,
        {module: frozenset(dists) for module, dists in fresh.items()},
    )
    return fresh
