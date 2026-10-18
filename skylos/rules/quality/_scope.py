"""Which Python files are test or sample code for quality-advice scoping."""

import ast
from functools import lru_cache
from pathlib import Path

from skylos.constants import get_non_library_dir_kind
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    read_text_no_symlink,
)
from skylos.core.test_paths import is_test_code_path

_MAX_SCOPE_SOURCE_BYTES = 2_000_000


@lru_cache(maxsize=4096)
def _defines_pytest_items(
    path_text: str, size: int, mtime_ns: int, project_root: str | None = None
) -> bool:
    try:
        if project_root is None:
            source = read_text_no_symlink(
                path_text, max_bytes=_MAX_SCOPE_SOURCE_BYTES, errors="replace"
            )
        else:
            source = read_project_text_no_symlink(
                project_root,
                path_text,
                max_bytes=_MAX_SCOPE_SOURCE_BYTES,
                errors="replace",
            )
        if source is None:
            return False
        tree = ast.parse(source)
    except (OSError, SyntaxError, ValueError):
        return False

    def is_test_function(node):
        return isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and node.name.startswith("test")

    # Projects rename collected classes (``python_classes``), so a class
    # counts by its test methods rather than by its own name.
    return any(
        is_test_function(node)
        or (
            isinstance(node, ast.ClassDef)
            and any(is_test_function(item) for item in node.body)
        )
        for node in tree.body
    )


def _is_pytest_module(path: Path, project_root=None) -> bool:
    """A ``test_*.py``/``*_test.py`` module that defines test functions."""
    name = path.name.lower()
    if not (name.startswith("test_") or name.endswith("_test.py")):
        return False
    path = path.absolute()
    try:
        if path.is_symlink():
            return False
        stat = path.stat()
    except OSError:
        return False
    if stat.st_size > _MAX_SCOPE_SOURCE_BYTES:
        return False
    root_text = (
        str(Path(project_root).absolute()) if project_root is not None else None
    )
    return _defines_pytest_items(str(path), stat.st_size, stat.st_mtime_ns, root_text)


def is_non_production_python(filename, project_root=None) -> bool:
    """Test suites, examples, benchmarks and build-only scripts.

    Design and size advice assumes shipped code: a test module that holds
    many cases or a fixture read whose size the test chooses is not a
    production maintainability or memory concern. Security rules do not use
    this scope.
    """
    if not filename:
        return False
    if is_test_code_path(filename, project_root):
        return True
    path = Path(str(filename))
    if project_root is not None and not path.is_absolute():
        path = Path(str(project_root)) / path
    if _is_pytest_module(path, project_root):
        return True
    return is_sample_or_build_python(filename, project_root)


def is_sample_or_build_python(filename, project_root=None) -> bool:
    """Examples, benchmarks, documentation builds and packaging scripts.

    Test code is classified separately when a metric needs collection or
    production-import evidence instead of a directory name.
    """
    if not filename:
        return False
    if project_root is None and Path(str(filename)).is_absolute():
        # Without a root, an ancestor folder of the checkout is not evidence.
        return False
    if get_non_library_dir_kind(filename, project_root) in {"example", "benchmark"}:
        return True
    # Documentation builds and the packaging script run only at build time.
    try:
        relative = Path(str(filename)).resolve().relative_to(
            Path(str(project_root)).resolve()
        ) if project_root is not None else Path(str(filename))
    except (OSError, ValueError):
        return False
    parts = [part.lower() for part in relative.parts]
    return parts == ["setup.py"] or (len(parts) > 1 and parts[0] in {"doc", "docs"})
