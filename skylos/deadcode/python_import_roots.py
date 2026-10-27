"""Import names for Python files that live in nested projects of one scan.

A scan of a repository root names every module by its path from that root, so
``backend/app/api.py`` becomes ``backend.app.api``. The code inside a nested
project (a uv/Poetry/Hatch workspace member, a service with its own
``pyproject.toml`` or ``setup.py``, or a folder holding a top-level package)
imports it as ``app.api``. This module derives those extra import names from
the source tree only: package ``__init__.py`` files and project manifests.
"""

from __future__ import annotations

import re
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink

_SOURCE_ROOTS = frozenset({"src", "lib", "python"})
_PROJECT_FILES = ("setup.py", "setup.cfg")
_PYPROJECT_MAX_BYTES = 1_000_000
_PROJECT_TABLE = re.compile(
    r"^[ \t]*\[[ \t]*(?:project|build-system|tool[ \t]*\.[ \t]*poetry)[ \t]*[\].]",
    re.MULTILINE,
)


def _module_parts(path: Path, base: Path) -> list[str] | None:
    try:
        parts = list(path.relative_to(base).with_suffix("").parts)
    except ValueError:
        return None
    if parts and parts[-1] == "__init__":
        parts.pop()
    return parts or None


class PythonImportRoots:
    """Find the folders a nested project's code is imported relative to."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self._projects: dict[Path, bool] = {}
        self._packages: dict[Path, bool] = {}
        self._aliases: dict[Path, tuple[tuple[Path, str], ...]] = {}

    def _is_package(self, directory: Path) -> bool:
        cached = self._packages.get(directory)
        if cached is None:
            try:
                cached = (directory / "__init__.py").is_file()
            except OSError:
                cached = False
            self._packages[directory] = cached
        return cached

    def _declares_project(self, directory: Path) -> bool:
        cached = self._projects.get(directory)
        if cached is not None:
            return cached
        found = False
        try:
            found = any((directory / name).is_file() for name in _PROJECT_FILES)
        except OSError:
            found = False
        if not found:
            text = read_text_no_symlink(
                directory / "pyproject.toml", max_bytes=_PYPROJECT_MAX_BYTES
            )
            found = bool(text and _PROJECT_TABLE.search(text))
        self._projects[directory] = found
        return found

    def _inner_directories(self, path: Path):
        directory = path.parent
        while directory != self.root:
            try:
                directory.relative_to(self.root)
            except ValueError:
                return
            yield directory
            directory = directory.parent

    def _package_root(self, path: Path) -> Path | None:
        top = None
        for directory in self._inner_directories(path):
            if not self._is_package(directory):
                break
            top = directory
        if top is None or top.parent == self.root:
            return None
        return top.parent

    def _project_root(self, path: Path) -> Path | None:
        for directory in self._inner_directories(path):
            if self._is_package(directory):
                continue
            if self._declares_project(directory):
                return directory
        return None

    def aliases(self, path) -> tuple[tuple[Path, str], ...]:
        """Return ``(import root, module name)`` pairs besides the scan-root name."""
        path = Path(path).resolve()
        cached = self._aliases.get(path)
        if cached is not None:
            return cached
        found = []
        package_root = self._package_root(path)
        if package_root is not None:
            parts = _module_parts(path, package_root)
            if parts:
                found.append((package_root, ".".join(parts)))
        project_root = self._project_root(path)
        if project_root is not None and project_root != package_root:
            parts = _module_parts(path, project_root)
            if (
                parts
                and len(parts) > 1
                and parts[0] in _SOURCE_ROOTS
                and not self._is_package(project_root / parts[0])
            ):
                parts = parts[1:]
            if parts:
                found.append((project_root, ".".join(parts)))
        result = tuple(dict.fromkeys(found))
        self._aliases[path] = result
        return result


class ModuleAliases:
    """Resolve an import name to one module, preferring the importer's project."""

    def __init__(self, root: Path, modules):
        self.roots = PythonImportRoots(root)
        self._names = {}
        self._tops = set()
        self._importer_roots = {}
        self._canonical = set(modules)
        for module in modules.values():
            for import_root, name in self.roots.aliases(module.path):
                self._names.setdefault(name, []).append((import_root, module))
                self._tops.add((import_root, name.split(".", 1)[0]))

    def _roots_of(self, module):
        if module is None:
            return ()
        roots = self._importer_roots.get(module.path)
        if roots is None:
            roots = tuple(root for root, _name in self.roots.aliases(module.path))
            self._importer_roots[module.path] = roots
        return roots

    def scoped(self, name, importer=None):
        """Return (module, blocked) for a name inside the importer's projects."""
        importer_roots = self._roots_of(importer)
        if not importer_roots:
            return None, False
        scoped = {
            id(module): module
            for import_root, module in self._names.get(name, ())
            if import_root in importer_roots
        }
        if len(scoped) == 1:
            return next(iter(scoped.values())), False
        top = name.split(".", 1)[0]
        shadowed = any((root, top) in self._tops for root in importer_roots)
        return None, len(scoped) > 1 or shadowed

    def lookup(self, name, importer=None):
        candidates = self._names.get(name)
        if not candidates or name in self._canonical:
            return None
        importer_roots = self._roots_of(importer)
        top = name.split(".", 1)[0]
        if any((root, top) in self._tops for root in importer_roots):
            return None
        distinct = {id(module): module for _root, module in candidates}
        if len(distinct) == 1:
            return next(iter(distinct.values()))
        return None
