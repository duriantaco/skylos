"""Whether a Python file is test code, for metrics that do not apply to it."""

from __future__ import annotations

import ast
import re
import configparser
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.constants import NON_LIBRARY_DIR_KINDS
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    read_text_no_symlink,
)

_TEST_DIR_NAMES = frozenset(
    name for name, kind in NON_LIBRARY_DIR_KINDS.items() if kind == "test"
)
# A test function or method, or a test framework import.
_COLLECTABLE_RE = re.compile(
    r"^(?:[ \t]*(?:async[ \t]+)?def[ \t]+test\w*[ \t]*\(|"
    r"(?:import|from)[ \t]+(?:pytest|unittest)\b)",
    re.M,
)
_MAX_SOURCE_BYTES = 2_000_000
_PYTEST_CONFIGS = (
    ("pytest.ini", "pytest"),
    (".pytest.ini", "pytest"),
    ("pyproject.toml", None),
    ("tox.ini", "pytest"),
    ("setup.cfg", "tool:pytest"),
)


@lru_cache(maxsize=128)
def _configured_test_classes(root, name, section, size, mtime_ns):
    try:
        source = read_project_text_no_symlink(
            root, Path(root) / name, max_bytes=_MAX_SOURCE_BYTES, errors="replace"
        )
        if source is None:
            return None
        if section is None:
            options = (
                tomllib.loads(source)
                .get("tool", {})
                .get("pytest", {})
                .get("ini_options")
            )
            if not isinstance(options, dict):
                return None
            value = options.get("python_classes", ["Test"])
        else:
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(source)
            if not parser.has_section(section):
                return None
            value = parser.get(section, "python_classes", fallback="Test")
        if isinstance(value, str):
            return tuple(value.split())
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return tuple(value)
    except (
        OSError,
        ValueError,
        RuntimeError,
        AttributeError,
        TypeError,
        configparser.Error,
    ):
        pass
    return None


def pytest_class_patterns(project_root=None) -> tuple[str, ...]:
    """Read collection names without importing the project or running pytest.

    Only size advice uses these settings; repository-controlled collection
    settings must not relax security rules.
    """
    if project_root is not None:
        root = str(Path(project_root).absolute())
        for name, section in _PYTEST_CONFIGS:
            try:
                stat = (Path(root) / name).stat()
            except OSError:
                continue
            patterns = _configured_test_classes(
                root, name, section, stat.st_size, stat.st_mtime_ns
            )
            if patterns is not None:
                return patterns
    return ("Test",)


def looks_like_python_test_path(path, project_root=None) -> bool:
    """The name or folder says test: ``conftest.py``, ``test_*.py``,
    ``*_test.py``, or a test folder below ``project_root`` (the folders a
    checkout sits in say nothing about the code; without a root only the
    name counts)."""
    file_path = Path(str(path))
    name = file_path.name.lower()
    if name == "conftest.py" or name.startswith("test_") or name.endswith("_test.py"):
        return True
    if project_root is None:
        return False
    try:
        parts = file_path.resolve().relative_to(Path(str(project_root)).resolve()).parts
    except (OSError, ValueError, RuntimeError):
        return False
    return any(part.lower() in _TEST_DIR_NAMES for part in parts[:-1])


def is_python_test_file(path, project_root=None, source: str | None = None) -> bool:
    """Test code: the name or folder says test (``looks_like_python_test_path``)
    and the file holds a test or imports a test framework (``conftest.py``
    needs neither).

    Names and folders alone collide with production code: ``ab_test.py``,
    ``smoke_test.py``, a ``test_run.py`` model in a test-management app, a
    ``tests/`` package in a lab system. A module pytest or unittest would run
    defines a test or imports the framework.
    """
    if not looks_like_python_test_path(path, project_root):
        return False
    file_path = Path(str(path))
    if file_path.name.lower() == "conftest.py":
        return True
    if source is None:
        try:
            if project_root is None:
                source = read_text_no_symlink(
                    file_path, max_bytes=_MAX_SOURCE_BYTES, errors="replace"
                )
            else:
                source = read_project_text_no_symlink(
                    project_root,
                    file_path,
                    max_bytes=_MAX_SOURCE_BYTES,
                    errors="replace",
                )
        except (OSError, ValueError, RuntimeError):
            return False
        if source is None:
            return False
    return bool(_COLLECTABLE_RE.search(source))


def is_collected_test_class(
    name: str,
    base_names,
    *,
    method_names=(),
    opted_out: bool = False,
    class_patterns=("Test",),
) -> bool:
    """A class unittest (a ``*TestCase`` base) or pytest collects. pytest
    uses its configured class prefixes/globs (``Test`` by default), requires
    ``test*`` methods and no ``__init__``. ``__test__ = False`` opts out."""
    if opted_out:
        return False
    if any(base.endswith("TestCase") for base in base_names):
        return True
    methods = set(method_names)
    return (
        any(
            name.startswith(pattern) or fnmatchcase(name, pattern)
            for pattern in class_patterns
        )
        and "__init__" not in methods
        and any(method.startswith("test") for method in methods)
    )


def is_test_package_name(module: str) -> bool:
    """A dotted module name with a test folder in it (``tests.helpers``)."""
    return bool(_TEST_DIR_NAMES & set(module.lower().split(".")))


def python_test_directory(path, project_root) -> Path | None:
    """First test directory below the scan root, never a checkout ancestor."""
    if project_root is None:
        return None
    root = Path(project_root).resolve()
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = root / file_path
    try:
        parts = file_path.resolve().relative_to(root).parts
    except (OSError, RuntimeError, ValueError):
        return None
    for index, part in enumerate(parts[:-1]):
        if part.lower() in _TEST_DIR_NAMES:
            return root.joinpath(*parts[: index + 1])
    return None


def is_python_golden_fixture(path, project_root=None) -> bool:
    """A source/expected-output pair in a test-data directory.

    This narrow fixture protocol is only used by clone advice. The source
    on both sides deliberately repeats; security checks still inspect it.
    A reader in the test suite must also split on that exact marker while
    reading text. Production imports are checked separately before dropping
    clone groups.
    """
    directory = python_test_directory(path, project_root)
    if directory is None:
        return False
    try:
        file_path = Path(path)
        if not file_path.is_absolute():
            file_path = Path(project_root) / file_path
        relative = file_path.resolve().relative_to(directory)
        if not {"data", "fixtures", "testdata", "test_data"} & set(relative.parts[:-1]):
            return False
        source = read_project_text_no_symlink(
            project_root, file_path, max_bytes=_MAX_SOURCE_BYTES, errors="replace"
        )
    except (OSError, RuntimeError, ValueError):
        return False
    if source is None:
        return False
    before, marker, after = source.partition("\n# output\n")
    return bool(
        marker
        and before.strip()
        and after.strip()
        and _has_golden_fixture_reader(directory, project_root)
    )


def _has_golden_fixture_reader(directory: Path, project_root) -> bool:
    try:
        readers = []
        for path in sorted(directory.glob("*.py"))[:128]:
            stat = path.stat()
            readers.append((str(path), stat.st_size, stat.st_mtime_ns))
    except (OSError, RuntimeError):
        return False
    return _golden_fixture_reader(str(project_root), tuple(readers))


@lru_cache(maxsize=128)
def _golden_fixture_reader(project_root, readers) -> bool:
    for filename, _size, _mtime in readers:
        try:
            source = read_project_text_no_symlink(
                project_root, filename, max_bytes=_MAX_SOURCE_BYTES, errors="replace"
            )
            if source is None or "# output" not in source:
                continue
            tree = ast.parse(source)
        except (OSError, RuntimeError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            children = tuple(ast.walk(node))
            if any(
                isinstance(child, ast.Compare)
                and any(isinstance(op, ast.Eq) for op in child.ops)
                and any(
                    isinstance(value, ast.Constant) and value.value == "# output"
                    for value in (child.left, *child.comparators)
                )
                for child in children
            ) and any(
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr in {"read_text", "readlines"}
                for child in children
            ):
                return True
    return False
