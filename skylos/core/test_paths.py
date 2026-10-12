"""Which source files are tests, by each language's own convention.

Used to keep CRITICAL for shipped code and to scope test-only proofs. A
``test_handlers.go`` or a ``tests/`` folder in a Go module is shipped code.
"""

from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

# Configuration (CI workflows, Docker, manifests) runs with real credentials
# even inside a test folder; languages without a convention here never count.
_PYTHON_SUFFIXES = frozenset({".py", ".pyi", ".pyw"})
_JS_SUFFIXES = frozenset({".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"})
_JVM_SUFFIXES = frozenset({".java", ".kt", ".kts"})
# File-based routers turn a ``test`` folder into a deployable URL segment.
_JS_ROUTE_DIRS = frozenset({"app", "pages", "routes", "api"})
# A ``test_*.py`` outside a test folder is a test module only if it uses a
# test framework; otherwise it is app code that happens to be named test_.
_PYTHON_TEST_MODULES = (
    "pytest",
    "unittest",
    "django.test",
    "hypothesis",
    "rest_framework.test",
)
_MAX_TEST_MODULE_BYTES = 2_000_000
_PROJECT_MARKERS = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "package.json",
    "go.mod",
    ".git",
)


def _relative_parts(text: str, project_root: Any) -> tuple[str, ...] | None:
    path = Path(text)
    if project_root is None:
        if path.is_absolute():
            return None
        return PurePosixPath(text.replace("\\", "/")).parts
    root = Path(project_root)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve().relative_to(root.resolve()).parts
    except (OSError, RuntimeError, ValueError):
        return None


def _is_js_route_path(parts: tuple[str, ...]) -> bool:
    for part in parts[:-1]:
        lowered = part.lower()
        if lowered in _JS_ROUTE_DIRS:
            return True
        if lowered in {"test", "tests", "__tests__"}:
            return False
    return False


def _uses_test_framework(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""] if not node.level else []
        elif isinstance(node, ast.ClassDef):
            if any(
                (isinstance(base, ast.Name) and base.id.endswith("TestCase"))
                or (isinstance(base, ast.Attribute) and base.attr.endswith("TestCase"))
                for base in node.bases
            ):
                return True
            continue
        else:
            continue
        if any(
            module == test_module or module.startswith(test_module + ".")
            for module in modules
            for test_module in _PYTHON_TEST_MODULES
        ):
            return True
    return False


@lru_cache(maxsize=4096)
def _declares_test_module(path_text: str, size: int, mtime_ns: int) -> bool:
    try:
        source = Path(path_text).read_text(  # skylos: ignore[SKY-D215] analyzer reads a discovered test file
            encoding="utf-8", errors="replace"
        )
        return _uses_test_framework(ast.parse(source))
    except (OSError, SyntaxError, ValueError):
        return False


def _is_python_test_module(path: Path | None) -> bool:
    """The file imports a test framework or defines a ``*TestCase`` class."""
    if path is None:
        return False
    try:
        if path.is_symlink():
            return False
        stat = path.stat()
    except OSError:
        return False
    if stat.st_size > _MAX_TEST_MODULE_BYTES:
        return False
    return _declares_test_module(str(path), stat.st_size, stat.st_mtime_ns)


def _is_test_parts(parts: tuple[str, ...], path: Path | None = None) -> bool:
    name = parts[-1].lower()
    suffix = PurePosixPath(name).suffix
    dirs = [part.lower() for part in parts[:-1]]
    if suffix in _PYTHON_SUFFIXES:
        # A test suite folder at the top: ``tests/`` or ``test/`` at the root,
        # ``<pkg>/tests``, ``src/<pkg>/tests``. A ``test`` folder deeper in app
        # code is shipped code. Elsewhere a ``test_*.py``/``*_test.py`` name
        # counts only when the module uses a test framework.
        if (
            name == "conftest.py"
            or bool(dirs and dirs[0] in {"test", "tests"})
            or (len(dirs) > 1 and dirs[1] == "tests")
            or (len(dirs) > 2 and dirs[0] == "src" and dirs[2] == "tests")
        ):
            return True
        if name.startswith("test_") or name[: -len(suffix)].endswith("_test"):
            return _is_python_test_module(path)
        return False
    if suffix == ".go":
        return name.endswith("_test.go")
    if suffix in _JVM_SUFFIXES:
        # Maven/Gradle layout: src/test/java, src/test/kotlin.
        return any(
            dirs[index] == "src" and dirs[index + 1] == "test"
            for index in range(len(dirs) - 1)
        )
    if suffix in _JS_SUFFIXES:
        is_test = (
            ".test." in name
            or ".spec." in name
            or "__tests__" in dirs
            or bool(dirs and dirs[0] in {"test", "tests"})
        )
        return is_test and not _is_js_route_path(parts)
    return False


def is_test_code_path(file_path: Any, project_root: Any = None) -> bool:
    """Whether ``file_path`` is test source under its language's convention.

    The path is judged relative to the project root, so a checkout that
    happens to live under a ``tests`` folder is not test code. Repository
    config (``non_library_dirs``) is deliberately not consulted: a pull
    request must not be able to relabel shipped code as tests.
    """
    if not file_path:
        return False
    parts = _relative_parts(str(file_path), project_root)
    if not parts:
        return False
    path = Path(str(file_path))
    if project_root is not None and not path.is_absolute():
        path = Path(project_root) / path
    return _is_test_parts(parts, path)


@lru_cache(maxsize=4096)
def _marked_project_root(directory: str) -> str | None:
    current = Path(directory)
    for _ in range(64):
        if any((current / marker).exists() for marker in _PROJECT_MARKERS):
            return str(current)
        if current.parent == current:
            return None
        current = current.parent
    return None


def is_test_source_file(file_path: Any) -> bool:
    """``is_test_code_path`` for a scanner that only knows the file.

    The nearest directory holding a project marker is the root. Without one,
    only the file name and contents can show it is a test.
    """
    if not file_path:
        return False
    try:
        path = Path(file_path).resolve()
    except (OSError, RuntimeError):
        return False
    root = _marked_project_root(str(path.parent))
    if root is not None:
        return is_test_code_path(path, root)
    return _is_test_parts((path.name,), path)
