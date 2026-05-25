from __future__ import annotations

from pathlib import Path

from .danger import scan_danger


SHELL_SOURCE_EXTS = (".sh", ".bash", ".zsh", ".ksh", ".bats")


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


def scan_shell_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
) -> tuple:
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() not in SHELL_SOURCE_EXTS:
            raise ValueError("unsupported shell path")
        source = path.read_text(  # skylos: ignore[SKY-D215] analyzer reads discovered shell source files
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return _empty_result(config)

    findings = scan_danger(str(path), source) if enable_danger_rules else []

    return (
        [],
        [],
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
        [],
    )


__all__ = ["SHELL_SOURCE_EXTS", "scan_shell_file"]
