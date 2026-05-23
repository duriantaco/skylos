from __future__ import annotations

from pathlib import Path

from .core import scan_symbols
from .danger import scan_danger


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


def scan_csharp_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
) -> tuple:
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() != ".cs":
            raise ValueError("unsupported C# path")
        source = path.read_text(  # skylos: ignore[SKY-D215] analyzer reads discovered C# source files
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return _empty_result(config)

    defs, refs, raw_imports = scan_symbols(str(path), source)
    findings = scan_danger(str(path), source) if enable_danger_rules else []

    return (
        defs,
        refs,
        set(),
        set(),
        DummyVisitor(),
        DummyVisitor(),
        [],
        findings,
        [],
        None,
        None,
        config,
        raw_imports,
    )


__all__ = ["scan_csharp_file"]
