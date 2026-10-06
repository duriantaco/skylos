from __future__ import annotations

from pathlib import Path

from skylos.analysis.errors import analysis_error_payload
from skylos.analysis.language_errors import (
    tree_sitter_analysis_error,
    with_analysis_error,
)
from skylos.core.safe_cache_io import read_bytes_no_symlink

from .core import JavaCore
from .danger import scan_danger
from .quality import scan_quality

MAX_JAVA_SOURCE_BYTES = 2_000_000


class DummyVisitor:
    """Placeholder visitor for non-Python files to satisfy the pipeline tuple format."""

    def __init__(self) -> None:
        self.is_test_file: bool = False
        self.test_decorated_lines: set[int] = set()
        self.dataclass_fields: set[str] = set()
        self.pydantic_models: set[str] = set()
        self.class_defs: dict = {}
        self.first_read_lineno: dict = {}
        self.framework_decorated_lines: set[int] = set()
        self.detected_frameworks: set[str] = set()


def _empty_java_result(config: dict, error: dict) -> tuple:
    return with_analysis_error(
        (
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
        ),
        error,
    )


def scan_java_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_quality_rules: bool = True,
    enable_danger_rules: bool = True,
    project_root: str | Path | None = None,
) -> tuple:
    if config is None:
        config = {}

    try:
        source = read_bytes_no_symlink(
            file_path, max_bytes=MAX_JAVA_SOURCE_BYTES, project_root=project_root
        )
        if source is None:
            raise OSError(
                "Java source is unreadable, unsafe, or exceeds the size limit"
            )
    except Exception as error:
        return _empty_java_result(
            config, analysis_error_payload(file_path, error, kind="source_read_error")
        )

    complexity_limit: int = config.get("complexity", 10)

    lang_overrides: dict = config.get("languages", {}).get("java", {})
    complexity_limit = lang_overrides.get("complexity", complexity_limit)

    try:
        core = JavaCore(file_path, source)
        core.scan()
    except Exception as error:
        return _empty_java_result(config, analysis_error_payload(file_path, error))
    analysis_error = tree_sitter_analysis_error(file_path, core.root_node, "java")

    d_findings: list[dict] = (
        scan_danger(core.root_node, file_path, lang=core.lang)
        if enable_danger_rules
        else []
    )
    q_findings: list[dict] = (
        scan_quality(
            core.root_node,
            source,
            file_path,
            threshold=complexity_limit,
            max_nesting=lang_overrides.get("nesting", config.get("nesting", 4)),
            max_length=lang_overrides.get("max_lines", config.get("max_lines", 50)),
            max_params=lang_overrides.get("max_args", config.get("max_args", 5)),
            lang=core.lang,
        )
        if enable_quality_rules
        else []
    )

    result = (
        core.defs,
        core.refs,
        set(),
        set(),
        DummyVisitor(),
        DummyVisitor(),
        q_findings,
        d_findings,
        [],
        None,
        None,
        config,
        core.raw_imports,
    )
    return with_analysis_error(result, analysis_error)
