from __future__ import annotations

from pathlib import Path

from skylos.analysis.errors import analysis_error_payload
from skylos.core.safe_cache_io import read_text_no_symlink

from .core import CppScanError, scan_symbols

CPP_SOURCE_EXTS = (".cpp", ".cc", ".cxx")
CPP_HEADER_EXTS = (".hpp", ".hh", ".hxx")
MAX_CPP_SOURCE_BYTES = 2_000_000


class DummyVisitor:
    def __init__(self) -> None:
        self.is_test_file: bool = False
        self.test_decorated_lines: set[int] = set()
        self.dataclass_fields: set[str] = set()
        self.pydantic_models: set[str] = set()
        self.class_defs: dict = {}
        self.first_read_lineno: dict = {}
        self.framework_decorated_lines: set[int] = set()
        self.detected_frameworks: set[str] = set()


def _empty_result(config: dict, analysis_error: dict | None = None) -> tuple:
    base = (
        [],
        [],
        set(),
        set(),
        DummyVisitor(),
        DummyVisitor(),
        [],
        [],
        [],
        None,
        None,
        config,
        [],
    )
    if analysis_error is None:
        return base
    return (
        *base,
        set(),  # ignored lines
        [],  # suppressed findings
        {},  # inferred types
        {},  # instance attribute types
        set(),  # used attribute names
        set(),  # used attribute context
        [],  # reserved worker slot
        {},  # parameter method refs
        {},  # call argument types
        [],  # clone fragments
        None,  # architecture metrics
        set(),  # top-level refs
        analysis_error,
        {},  # ignored rules by line
        False,  # explicit exports
    )


def scan_cpp_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
) -> tuple:
    """Scan supported C++ source/header files for conservative dead-code data."""
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() not in CPP_SOURCE_EXTS + CPP_HEADER_EXTS:
            return _empty_result(config)
        source = read_text_no_symlink(
            path,
            max_bytes=MAX_CPP_SOURCE_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
        if source is None:
            raise OSError("C++ source is unreadable, unsafe, or exceeds the size limit")
    except Exception as exc:
        return _empty_result(
            config,
            analysis_error_payload(file_path, exc, kind="source_read_error"),
        )

    try:
        defs, refs, raw_imports = scan_symbols(str(path), source)
    except CppScanError as exc:
        return _empty_result(
            config,
            analysis_error_payload(file_path, exc, kind=exc.kind),
        )
    return (
        defs,
        refs,
        set(),
        set(),
        DummyVisitor(),
        DummyVisitor(),
        [],
        [],
        [],
        None,
        None,
        config,
        raw_imports,
    )


__all__ = ["CPP_SOURCE_EXTS", "CPP_HEADER_EXTS", "scan_cpp_file"]
