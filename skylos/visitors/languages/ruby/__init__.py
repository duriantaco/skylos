from __future__ import annotations

from pathlib import Path

from skylos.analysis.errors import analysis_error_payload
from skylos.analysis.finding_filter import partition_inline_ignored_findings
from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.core.inline_directives import directive_ignores

from .core import RubyCore, descendants
from .security import scan_commands

MAX_RUBY_SOURCE_BYTES = 2_000_000


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
        self.security_coverage = {}
        self.deadcode_coverage = {}
        self.ignore_lines = set()
        self.ignore_rules_by_line = {}


def _result(config, defs=None, refs=None, visitor=None, danger=None, imports=None):
    visitor = visitor or DummyVisitor()
    return (
        defs or [],
        refs or [],
        set(),
        set(),
        visitor,
        visitor,
        [],
        danger or [],
        [],
        None,
        None,
        config,
        imports or [],
    )


def _metadata(
    result, source, error, ignored_lines=None, ignored_rules=None, suppressed=None
):
    return (
        *result,
        ignored_lines or set(),
        suppressed or [],
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
        ignored_rules or {},
        False,
    )


def _parse_error(file_path, root):
    if root is None:
        return analysis_error_payload(
            file_path,
            ValueError("Ruby grammar unavailable; analysis is incomplete"),
            kind="parser_unavailable",
        )
    if not root.has_error:
        return None
    pending = [root]
    error = root
    while pending:
        node = pending.pop()
        if node.type == "ERROR" or node.is_missing:
            error = node
            break
        pending.extend(reversed([child for child in node.children if child.has_error]))
    exception = SyntaxError("Ruby parse error; source analysis is incomplete")
    exception.lineno = error.start_point[0] + 1
    exception.offset = error.start_point[1] + 1
    return analysis_error_payload(file_path, exception, kind="syntax_error")


def scan_ruby_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_danger_rules: bool = True,
    _include_analysis_metadata: bool = False,
) -> tuple:
    config = {} if config is None else config
    try:
        path = Path(file_path)
        if path.suffix.lower() != ".rb":
            raise ValueError("unsupported Ruby path")
        source = read_text_no_symlink(
            path, max_bytes=MAX_RUBY_SOURCE_BYTES, encoding="utf-8", errors="strict"
        )
        if source is None:
            raise ValueError("unreadable Ruby source path")
    except (OSError, ValueError, UnicodeError) as error:
        result = _result(config)
        return (
            _metadata(
                result,
                "",
                analysis_error_payload(file_path, error, kind="source_read_error"),
            )
            if _include_analysis_metadata
            else result
        )
    core = RubyCore(str(path), source.encode("utf-8"))
    core.scan()
    visitor = DummyVisitor()
    visitor.class_defs = core.classes
    visitor.detected_frameworks = {"rails"} if core.rails_classes else set()
    visitor.deadcode_coverage = {
        "status": "bounded",
        "unresolved": core.dynamic_dispatch,
        "unsupported": ["runtime_route_evaluation", "cross_file_method_dispatch"],
    }
    danger, coverage = (
        scan_commands(core)
        if enable_danger_rules
        else ([], {"status": "disabled", "unresolved": []})
    )
    visitor.security_coverage = coverage
    comments = (
        [
            (node.start_point[0] + 1, core.text(node))
            for node in descendants(core.root_node)
            if node.type == "comment"
        ]
        if core.root_node and not core.root_node.has_error
        else []
    )
    ignored_lines, ignored_rules = directive_ignores(comments, source.count("\n") + 1)
    visitor.ignore_lines = ignored_lines
    visitor.ignore_rules_by_line = ignored_rules
    danger, suppressed = partition_inline_ignored_findings(
        danger, "security", ignored_lines, ignored_rules
    )
    result = _result(config, core.defs, core.refs, visitor, danger, core.raw_imports)
    if not _include_analysis_metadata:
        return result
    return _metadata(
        result,
        source,
        _parse_error(str(path), core.root_node),
        ignored_lines,
        ignored_rules,
        suppressed,
    )


__all__ = ["scan_ruby_file"]
