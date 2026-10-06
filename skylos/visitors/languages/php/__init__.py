from __future__ import annotations

from pathlib import Path

from skylos.analysis.errors import analysis_error_payload
from skylos.analysis.language_errors import (
    tree_sitter_analysis_error,
    with_analysis_error,
)
from skylos.core.safe_cache_io import read_bytes_no_symlink

from .core import PhpCore
from .danger import scan_danger


class DummyVisitor:
    def __init__(
        self,
        *,
        is_test_file: bool = False,
        test_decorated_lines: set[int] | None = None,
    ) -> None:
        self.is_test_file = is_test_file
        self.test_decorated_lines = test_decorated_lines or set()
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


def scan_php_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
    project_root: str | Path | None = None,
) -> tuple:
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() != ".php":
            return _empty_result(config)
        source = read_bytes_no_symlink(
            path, max_bytes=2_000_000, project_root=project_root
        )
        if source is None:
            raise OSError("PHP source is unreadable, unsafe, or exceeds the size limit")
    except Exception as error:
        return with_analysis_error(
            _empty_result(config),
            analysis_error_payload(file_path, error, kind="source_read_error"),
        )

    core = PhpCore(str(path), source)
    core.scan()

    visitor = DummyVisitor(
        is_test_file=core.is_test_file,
        test_decorated_lines=core.test_decorated_lines,
    )
    findings = (
        scan_danger(core.root_node, str(path), source) if enable_danger_rules else []
    )

    result = (
        core.defs,
        core.refs,
        set(),
        set(),
        visitor,
        DummyVisitor(),
        [],
        findings,
        [],
        None,
        None,
        config,
        core.raw_imports,
    )
    return with_analysis_error(
        result, tree_sitter_analysis_error(str(path), core.root_node, "php")
    )


__all__ = ["scan_php_file"]
