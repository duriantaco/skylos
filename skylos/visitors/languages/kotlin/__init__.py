from __future__ import annotations

from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink

from .core import scan_symbols

MAX_KOTLIN_SOURCE_BYTES = 2_000_000


class DummyVisitor:
    def __init__(
        self,
        *,
        is_test_file: bool = False,
        test_decorated_lines: set[int] | None = None,
    ) -> None:
        self.is_test_file: bool = is_test_file
        self.test_decorated_lines: set[int] = test_decorated_lines or set()
        self.dataclass_fields: set[str] = set()
        self.pydantic_models: set[str] = set()
        self.class_defs: dict = {}
        self.first_read_lineno: dict = {}
        self.framework_decorated_lines: set[int] = set()
        self.detected_frameworks: set[str] = set()


def _empty_result(config: dict) -> tuple:
    return (
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


def scan_kotlin_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
) -> tuple:
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() not in {".kt", ".kts"}:
            raise ValueError("unsupported Kotlin path")
        source = read_text_no_symlink(
            path,
            max_bytes=MAX_KOTLIN_SOURCE_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
        if source is None:
            raise ValueError("unreadable Kotlin source path")
    except Exception:
        return _empty_result(config)

    defs, refs, raw_imports = scan_symbols(str(path), source)
    test_decorated_lines = {
        definition.line
        for definition in defs
        if "@Test" in getattr(definition, "decorators", [])
    }
    visitor = DummyVisitor(
        is_test_file=_is_test_path(path),
        test_decorated_lines=test_decorated_lines,
    )

    return (
        defs,
        refs,
        set(),
        set(),
        visitor,
        DummyVisitor(),
        [],
        [],
        [],
        None,
        None,
        config,
        raw_imports,
    )


def _is_test_path(path: Path) -> bool:
    normalized = str(path).lower().replace("\\", "/")
    return "/test/" in normalized or normalized.endswith("test.kt")


__all__ = ["scan_kotlin_file"]
