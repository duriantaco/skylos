from __future__ import annotations

from pathlib import Path

from skylos.analysis.errors import analysis_error_payload
from skylos.core.inline_directives import directive_ignores
from skylos.core.safe_cache_io import read_text_no_symlink

from .core import SwiftCore, SwiftScanError, descendants

MAX_SWIFT_SOURCE_BYTES = 2_000_000


class DummyVisitor:
    def __init__(self):
        self.is_test_file = False
        self.test_decorated_lines = set()
        self.dataclass_fields = set()
        self.pydantic_models = set()
        self.class_defs = {}
        self.first_read_lineno = {}
        self.framework_decorated_lines = set()
        self.detected_frameworks = set()
        self.deadcode_coverage = {}
        self.swift_reflection_facts = None
        self.ignore_lines = set()
        self.ignore_rules_by_line = {}


def _result(config, core=None, visitor=None):
    visitor = visitor or DummyVisitor()
    return (
        core.defs if core else [],
        core.refs if core else [],
        set(),
        set(),
        visitor,
        visitor,
        [],
        [],
        [],
        None,
        None,
        config,
        core.raw_imports if core else [],
    )


def _metadata(result, source, error=None, ignored=None, rules=None):
    return (
        *result,
        ignored or set(),
        [],
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
        error,
        rules or {},
        False,
    )


def _parse_error(file_path, root):
    if root is None:
        return analysis_error_payload(
            file_path,
            ValueError("Swift grammar unavailable; analysis is incomplete"),
            kind="parser_unavailable",
        )
    if not root.has_error:
        return None
    pending = [root]
    error = root
    while pending:
        node = pending.pop()
        if node.is_error or node.is_missing:
            error = node
            break
        pending.extend(reversed([child for child in node.children if child.has_error]))
    exception = SyntaxError("Swift parse error; source analysis is incomplete")
    exception.lineno = error.start_point[0] + 1
    exception.offset = error.start_point[1] + 1
    return analysis_error_payload(file_path, exception, kind="syntax_error")


def scan_swift_file(
    file_path,
    config=None,
    *,
    enable_danger_rules=True,
    _include_analysis_metadata=False,
):
    config = {} if config is None else config
    source = ""
    try:
        path = Path(file_path)
        if path.suffix.lower() != ".swift":
            raise ValueError("unsupported Swift source path")
        source = read_text_no_symlink(
            path,
            max_bytes=MAX_SWIFT_SOURCE_BYTES,
            encoding="utf-8",
            errors="strict",
            newline="",
        )
        if source is None:
            raise ValueError(
                "Swift source is unreadable, unsafe or exceeds the source limit"
            )
    except (OSError, ValueError, UnicodeError) as error:
        result = _result(config)
        return _metadata(
            result,
            "",
            analysis_error_payload(file_path, error, kind="source_read_error"),
        )
    try:
        core = SwiftCore(str(path), source.encode("utf-8"))
        core.scan()
    except (SwiftScanError, RecursionError) as error:
        result = _result(config)
        return _metadata(
            result,
            source,
            analysis_error_payload(
                file_path, error, kind=getattr(error, "kind", "source_complexity")
            ),
        )
    visitor = DummyVisitor()
    visitor.class_defs = core.classes
    visitor.swift_reflection_facts = core.project_reflection_facts
    visitor.deadcode_coverage = {
        "status": "bounded",
        "unresolved": core.unresolved,
        "unsupported": [
            "whole_program_api_reachability",
            "compiler_macro_expansion",
            "build_configuration_evaluation",
            "general_type_inference",
            "unused_extension_imports",
        ],
    }
    comments = (
        [
            (node.start_point[0] + 1, core.text(node))
            for node in descendants(core.root_node)
            if node.type in {"comment", "multiline_comment"}
        ]
        if core.root_node is not None and not core.root_node.has_error
        else []
    )
    ignored, rules = directive_ignores(comments, source.count("\n") + 1)
    visitor.ignore_lines, visitor.ignore_rules_by_line = ignored, rules
    result = _result(config, core, visitor)
    error = _parse_error(str(path), core.root_node)
    return (
        _metadata(result, source, error, ignored, rules)
        if _include_analysis_metadata or error is not None
        else result
    )


__all__ = ["scan_swift_file"]
