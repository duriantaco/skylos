from __future__ import annotations

from pathlib import Path

from skylos.analysis.finding_filter import partition_inline_ignored_findings

from .danger import scan_danger
from .directives import shell_inline_ignores


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


def _analysis_result(result: tuple, source: str) -> tuple:
    ignore_lines, ignore_rules_by_line = shell_inline_ignores(source)
    findings, suppressed = partition_inline_ignored_findings(
        result[7], "security", ignore_lines, ignore_rules_by_line
    )
    return (
        *result[:7],
        findings,
        *result[8:],
        ignore_lines,
        suppressed,
        {},
        {},
        set(),
        set(),
        source.splitlines(keepends=True),
        {},
        {},
        [],
        None,
        set(),
        None,
        ignore_rules_by_line,
        False,
    )


def scan_shell_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
    _include_analysis_metadata: bool = False,
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

    result = (
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
    if not _include_analysis_metadata:
        return result
    return _analysis_result(result, source)


__all__ = ["SHELL_SOURCE_EXTS", "scan_shell_file"]
