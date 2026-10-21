"""Which files a pyproject's build configuration packages, read statically.

A project that names its packages explicitly ships only those: setuptools
``packages`` (a list or ``packages.find`` with ``where``/``include``/
``exclude``) and ``py-modules``, hatch wheel ``packages``/``only-include``,
Poetry ``packages``. The manifest's dependencies describe that distribution,
not the repository's other Python files (benchmarks, maintenance scripts).

Only the configuration of the build backend the project uses counts.
Anything it does not pin down (automatic discovery, glob patterns, extra
``include`` lists, ``setup.py``) is unknown, never "outside". The file is
parsed, never built or executed.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

MAX_SELECTION_ENTRIES = 256
MAX_SELECTION_PATH_PARTS = 64
_GLOB_CHARS = frozenset("*?[]!{}")
_DOTTED_NAME = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\Z")


class PackageSelection:
    """Directories, single files and ``packages.find`` roots a build ships."""

    def __init__(self, directories=(), files=(), finders=()):
        self.directories = frozenset(directories)
        self.files = frozenset(files)
        self.finders = tuple(finders)

    def packages(self, relative_file):
        """True when ``relative_file`` (relative to the manifest) is shipped."""
        path = PurePosixPath(relative_file)
        if path in self.files:
            return True
        if any(directory in path.parents for directory in self.directories):
            return True
        for where, include, exclude in self.finders:
            if where not in path.parents:
                continue
            parts = path.parent.relative_to(where).parts
            if not parts or not all(part.isidentifier() for part in parts):
                continue
            name = ".".join(parts)
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in exclude):
                continue
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in include):
                return True
        return False


def _relative_path(value):
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if "\\" in value or re.match(r"^[A-Za-z]:", value):
        return None
    if any(char in _GLOB_CHARS for char in value):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    if len(path.parts) > MAX_SELECTION_PATH_PARTS:
        return None
    return PurePosixPath(*[part for part in path.parts if part != "."])


def _string_list(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or len(value) > MAX_SELECTION_ENTRIES:
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return value


def _patterns(value, default):
    if value is None:
        return default
    patterns = _string_list(value)
    if patterns is None or not all(patterns):
        return None
    return tuple(patterns)


def _package_directory(name, base, package_dir):
    parts = name.split(".")
    for length in range(len(parts), 0, -1):
        mapped = package_dir.get(".".join(parts[:length]))
        if mapped is not None:
            return mapped.joinpath(*parts[length:])
    return base.joinpath(*parts)


def _setuptools_selection(setuptools):
    if not isinstance(setuptools, dict):
        return None
    packages = setuptools.get("packages")
    modules = setuptools.get("py-modules")
    if packages is None and modules is None:
        return None
    raw_package_dir = setuptools.get("package-dir", {})
    if not isinstance(raw_package_dir, dict):
        return None
    package_dir = {}
    for package, directory in raw_package_dir.items():
        path = _relative_path(directory)
        if path is None or (package and not _DOTTED_NAME.match(package)):
            return None
        package_dir[package] = path
    base = package_dir.pop("", PurePosixPath())
    directories = []
    files = []
    finders = []
    if isinstance(packages, dict):
        if set(packages) != {"find"} or not isinstance(packages["find"], dict):
            return None
        find = packages["find"]
        if set(find) - {"where", "include", "exclude", "namespaces"}:
            return None
        where = _string_list(find.get("where", ["."]))
        include = _patterns(find.get("include"), ("*",))
        exclude = _patterns(find.get("exclude"), ())
        if where is None or include is None or exclude is None:
            return None
        for entry in where:
            root = _relative_path(entry)
            if root is None:
                return None
            finders.append((root, include, exclude))
    elif packages is not None:
        names = _string_list(packages)
        if names is None or not all(_DOTTED_NAME.match(name) for name in names):
            return None
        directories.extend(
            _package_directory(name, base, package_dir) for name in names
        )
    if modules is not None:
        names = _string_list(modules)
        if names is None or not all(_DOTTED_NAME.match(name) for name in names):
            return None
        for name in names:
            parts = name.split(".")
            files.append(base.joinpath(*parts[:-1], parts[-1] + ".py"))
    return PackageSelection(directories, files, finders)


def _hatch_selection(hatch):
    if not isinstance(hatch, dict):
        return None
    build = hatch.get("build", {})
    if not isinstance(build, dict):
        return None
    targets = build.get("targets", {})
    if not isinstance(targets, dict):
        return None
    wheel = targets.get("wheel", {})
    if not isinstance(wheel, dict):
        return None
    for key in ("include", "force-include"):
        if key in build or key in wheel:
            return None
    selected = []
    for key in ("packages", "only-include"):
        value = wheel.get(key, build.get(key))
        if value is None:
            continue
        entries = _string_list(value)
        if entries is None:
            return None
        selected.extend(entries)
    if not selected:
        return None
    directories = []
    files = []
    for entry in selected:
        path = _relative_path(entry)
        if path is None or not path.parts:
            return None
        if path.suffix in (".py", ".pyi", ".pyw"):
            files.append(path)
        else:
            directories.append(path)
    return PackageSelection(directories, files)


def _poetry_selection(poetry):
    if not isinstance(poetry, dict):
        return None
    packages = poetry.get("packages")
    if packages is None or "include" in poetry:
        return None
    if not isinstance(packages, list) or len(packages) > MAX_SELECTION_ENTRIES:
        return None
    directories = []
    files = []
    for entry in packages:
        if not isinstance(entry, dict) or "include" not in entry:
            return None
        include = _relative_path(entry["include"])
        source = _relative_path(entry.get("from", "."))
        if include is None or source is None or not include.parts:
            return None
        path = source / include
        if path.suffix in (".py", ".pyi", ".pyw"):
            files.append(path)
        else:
            directories.append(path)
    return PackageSelection(directories, files)


def pyproject_package_selection(text):
    """The explicit selection of the backend the pyproject builds with, or
    None when it is unknown."""
    if not isinstance(text, str):
        return None
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError):
        return None
    build_system = data.get("build-system", {})
    tool = data.get("tool", {})
    if not isinstance(build_system, dict) or not isinstance(tool, dict):
        return None
    backend = build_system.get("build-backend")
    if backend is None:
        backend = "setuptools.build_meta:__legacy__"
    if not isinstance(backend, str):
        return None
    backend_module = backend.split(":", 1)[0].strip()
    if backend_module.split(".", 1)[0] == "setuptools":
        return _setuptools_selection(tool.get("setuptools"))
    if backend_module == "hatchling.build":
        return _hatch_selection(tool.get("hatch"))
    if backend_module == "poetry.core.masonry.api":
        return _poetry_selection(tool.get("poetry"))
    return None
