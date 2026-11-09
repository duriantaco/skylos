from __future__ import annotations

from pathlib import Path

from skylos.analysis.errors import analysis_error_payload
from skylos.analysis.finding_filter import partition_inline_ignored_findings

from .core import RustCore
from .danger import scan_danger
from .quality import quality_inline_ignores, scan_quality


def _parse_error(file_path, root):
    if root is not None and not root.has_error:
        return None
    if root is None:
        return analysis_error_payload(
            file_path,
            ValueError("Rust parser unavailable; analysis is incomplete"),
            kind="parser_unavailable",
        )
    pending = [root]
    error = root
    while pending:
        node = pending.pop()
        if node.type == "ERROR" or node.is_missing:
            error = node
            break
        pending.extend(reversed([child for child in node.children if child.has_error]))
    exception = SyntaxError(
        "Rust parse error; findings for this file may be incomplete"
    )
    exception.lineno = error.start_point[0] + 1
    exception.offset = error.start_point[1] + 1
    return analysis_error_payload(file_path, exception, kind="syntax_error")


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


def _analysis_result(result, source, suppressed, error):
    # Quality-only ignores must not become dead-code/security suppressions.
    return (
        *result,
        set(),
        suppressed,
        {},
        {},
        set(),
        set(),
        source.decode("utf-8", errors="replace").splitlines(keepends=True),
        {},
        {},
        [],
        None,
        set(),
        error,
        {},
        False,
    )


def scan_rust_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
    enable_quality_rules: bool = True,
    _include_analysis_metadata: bool = False,
) -> tuple:
    if config is None:
        config = {}

    try:
        path = Path(file_path)
        if path.suffix.lower() != ".rs":
            raise ValueError("unsupported Rust path")
        source = path.read_bytes()  # skylos: ignore[SKY-D215]
    except Exception as error:
        result = _empty_result(config)
        if not _include_analysis_metadata:
            return result
        return _analysis_result(
            result,
            b"",
            [],
            analysis_error_payload(file_path, error, kind="source_read_error"),
        )

    core = RustCore(str(path), source)
    core.scan()

    visitor = DummyVisitor(
        is_test_file=core.is_test_file,
        test_decorated_lines=core.test_decorated_lines,
    )
    findings = (
        scan_danger(core.root_node, str(path), source) if enable_danger_rules else []
    )
    quality = (
        scan_quality(core.root_node, str(path), source) if enable_quality_rules else []
    )
    ignored_rules = config.get("ignore", ())
    if isinstance(ignored_rules, (list, tuple, set, frozenset)):
        quality = [
            finding for finding in quality if finding["rule_id"] not in ignored_rules
        ]
    suppressed_quality = []
    if _include_analysis_metadata:
        ignored_lines, ignored_by_rule = quality_inline_ignores(core.root_node, source)
        quality, suppressed_quality = partition_inline_ignored_findings(
            quality, "quality", ignored_lines, ignored_by_rule
        )

    result = (
        core.defs,
        core.refs,
        set(),
        set(),
        visitor,
        DummyVisitor(),
        quality,
        findings,
        [],
        None,
        None,
        config,
        core.raw_imports,
    )
    if not _include_analysis_metadata:
        return result
    return _analysis_result(
        result, source, suppressed_quality, _parse_error(str(path), core.root_node)
    )


__all__ = ["scan_rust_file"]
