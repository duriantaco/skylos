"""Whether a Python file is test code, for metrics that do not apply to it."""

from __future__ import annotations

import re
from pathlib import Path

from skylos.constants import NON_LIBRARY_DIR_KINDS

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
            if file_path.stat().st_size > _MAX_SOURCE_BYTES:
                return False
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
    return bool(_COLLECTABLE_RE.search(source))


def is_collected_test_class(
    name: str, base_names, *, method_names=(), opted_out: bool = False
) -> bool:
    """A class unittest (a ``*TestCase`` base) or pytest collects. pytest
    collects a ``Test*`` class that has ``test*`` methods and no
    ``__init__``. ``__test__ = False`` opts out of both."""
    if opted_out:
        return False
    if any(base.endswith("TestCase") for base in base_names):
        return True
    methods = set(method_names)
    return (
        name.startswith("Test")
        and "__init__" not in methods
        and any(method.startswith("test") for method in methods)
    )


def is_test_package_name(module: str) -> bool:
    """A dotted module name with a test folder in it (``tests.helpers``)."""
    return bool(_TEST_DIR_NAMES & set(module.lower().split(".")))
