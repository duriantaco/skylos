from __future__ import annotations

import re

from skylos.analysis.finding_filter import partition_inline_ignored_findings

from .core import TypeScriptCore
from .danger import scan_danger
from .framework import TSFrameworkVisitor
from .quality import scan_quality
from .source_lines import split_ecmascript_lines


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
        self.ignore_lines: set[int] = set()
        self.noqa_codes_by_line: dict[int, set[str]] = {}


_MINIFIED_LINE_THRESHOLD = 3000
_UNSUPPORTED_LINE_ENDING_RE = re.compile(
    rb"\r(?!\n)|[\x0b\x0c\x1c-\x1e]|\xc2\x85|\xe2\x80[\xa8\xa9]"
)
_SKYLOS_BYTES_RE = re.compile(rb"skylos", re.IGNORECASE)
_SKYLOS_DIRECTIVE_RE = re.compile(
    r"^skylos\s*:\s*(?:"
    r"(?P<block>ignore-(?:start|end))(?=\s|$)|"
    r"ignore\s*\[(?P<rules>[^\]]*)\](?=\s|$)|"
    r"(?P<blanket>ignore)(?!\s*\[)(?=\s|$)"
    r")",
    re.IGNORECASE | re.ASCII,
)
_SKYLOS_RULE_ID_RE = re.compile(
    r"\bSKY-[A-Z][A-Z0-9-]*\b",
    re.IGNORECASE | re.ASCII,
)
_SKYLOS_IGNORE_END_RE = re.compile(
    r"\bskylos\s*:\s*ignore-end\b",
    re.IGNORECASE | re.ASCII,
)


def _iter_nodes(root_node):
    stack = [root_node] if root_node is not None else []
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _comment_body(comment_text: str) -> str | None:
    if comment_text.startswith("//"):
        return comment_text[2:]
    if not comment_text.startswith("/*") or "\n" in comment_text:
        return None
    body = comment_text[2:].rstrip()
    return body[:-2] if body.endswith("*/") else None


def _parse_typescript_directive(body: str) -> tuple[str, set[str], int] | None:
    stripped = body.lstrip()
    directive = _SKYLOS_DIRECTIVE_RE.match(stripped)
    if directive is None:
        return None

    block = directive.group("block")
    if block:
        return block.lower().removeprefix("ignore-"), set(), directive.end()

    rules = directive.group("rules")
    if rules is not None:
        rule_ids = [rule_id.strip() for rule_id in rules.split(",")]
        if not rule_ids or any(
            not _SKYLOS_RULE_ID_RE.fullmatch(rule_id) for rule_id in rule_ids
        ):
            return None
        return (
            "rules",
            {rule_id.upper() for rule_id in rule_ids},
            directive.end(),
        )

    return "blanket", set(), directive.end()


def _typescript_inline_ignores(
    root_node, source: bytes
) -> tuple[set[int], dict[int, set[str]]]:
    """Parse Skylos directives from real JS/TS comments, never string text."""
    if root_node is None or root_node.has_error:
        return set(), {}
    if not _SKYLOS_BYTES_RE.search(source):
        return set(), {}
    if _UNSUPPORTED_LINE_ENDING_RE.search(source):
        return set(), {}

    line_count = source.count(b"\n") + 1
    events_by_line: dict[int, list[tuple[str, set[str]]]] = {}
    for node in _iter_nodes(root_node):
        if node.type != "comment":
            continue
        comment_text = source[node.start_byte : node.end_byte].decode(
            "utf-8", errors="replace"
        )
        body = _comment_body(comment_text)
        if body is None:
            continue
        stripped = body.lstrip()
        parsed = _parse_typescript_directive(body)
        if parsed is None:
            continue
        kind, rules, directive_end = parsed
        line = node.start_point[0] + 1
        if line > line_count:
            continue
        events_by_line.setdefault(line, []).append((kind, rules))
        if kind == "start" and _SKYLOS_IGNORE_END_RE.search(stripped, directive_end):
            events_by_line[line].append(("end", set()))

    ignore_lines: set[int] = set()
    ignore_rules_by_line: dict[int, set[str]] = {}
    in_ignore_block = False
    for line in range(1, line_count + 1):
        if in_ignore_block:
            ignore_lines.add(line)
        for kind, rules in events_by_line.get(line, ()):
            if kind == "rules":
                ignore_rules_by_line.setdefault(line, set()).update(rules)
            else:
                ignore_lines.add(line)
            if kind == "start":
                in_ignore_block = True
            elif kind == "end":
                in_ignore_block = False

    return ignore_lines, ignore_rules_by_line


def _typescript_source_lines(source: bytes) -> list[str]:
    """Split source at ECMAScript line terminators, preserving each ending."""
    text = source.decode("utf-8", errors="replace")
    return split_ecmascript_lines(text, keepends=True)


def _analysis_scan_result(
    base_result: tuple,
    source: bytes,
    ignore_lines: set[int],
    ignore_rules_by_line: dict[int, set[str]],
    suppressed: list[dict],
) -> tuple:
    return (
        *base_result,
        ignore_lines,
        suppressed,
        {},
        {},
        set(),
        set(),
        _typescript_source_lines(source),
        {},
        {},
        [],
        None,
        set(),
        None,
        ignore_rules_by_line,
        False,
    )


def _empty_typescript_scan_result(config: dict) -> tuple:
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


def is_minified_js_source(file_path: str, source: bytes) -> bool:
    base = file_path.rsplit("/", 1)[-1]
    if ".min." in base:
        return True
    if len(source) < 5000:
        return False
    for line in source.split(b"\n", 200)[:200]:
        if len(line) > _MINIFIED_LINE_THRESHOLD:
            return True
    return False


def scan_typescript_file(
    file_path: str,
    config: dict | None = None,
    *,
    enable_quality_rules: bool = True,
    enable_danger_rules: bool = True,
    _include_analysis_metadata: bool = False,
) -> tuple:
    if config is None:
        config = {}

    try:
        with open(file_path, "rb") as f:
            source = f.read()
    except Exception:
        return _empty_typescript_scan_result(config)

    if is_minified_js_source(str(file_path), source):
        return _empty_typescript_scan_result(config)

    complexity_limit: int = config.get("complexity", 10)

    lang_overrides: dict = config.get("languages", {}).get("typescript", {})
    complexity_limit = lang_overrides.get("complexity", complexity_limit)

    core = TypeScriptCore(file_path, source)
    core.scan()

    fw = TSFrameworkVisitor()
    fw.scan(file_path, core.root_node, source, core.lang)

    d_findings: list[dict] = (
        scan_danger(core.root_node, file_path, lang=core.lang, source=source)
        if enable_danger_rules
        else []
    )
    q_findings: list[dict] = (
        scan_quality(
            core.root_node,
            source,
            file_path,
            threshold=complexity_limit,
            lang=core.lang,
        )
        if enable_quality_rules
        else []
    )
    raw_ignored_rule_ids = config.get("ignore") or []
    ignored_rule_ids = (
        {
            str(rule_id).upper()
            for rule_id in raw_ignored_rule_ids
            if isinstance(rule_id, str)
        }
        if isinstance(raw_ignored_rule_ids, (list, tuple, set, frozenset))
        else set()
    )
    if ignored_rule_ids:
        q_findings = [
            finding
            for finding in q_findings
            if str(finding.get("rule_id", "")).upper() not in ignored_rule_ids
        ]

    if _include_analysis_metadata:
        ignore_lines, ignore_rules_by_line = _typescript_inline_ignores(
            core.root_node,
            source,
        )
        q_findings, suppressed_quality = partition_inline_ignored_findings(
            q_findings,
            "quality",
            ignore_lines,
            ignore_rules_by_line,
        )
        d_findings, suppressed_danger = partition_inline_ignored_findings(
            d_findings,
            "security",
            ignore_lines,
            ignore_rules_by_line,
        )

    test_visitor = DummyVisitor()
    if _include_analysis_metadata:
        test_visitor.ignore_lines = ignore_lines

    base_result = (
        core.defs,
        core.refs,
        set(),
        set(),
        test_visitor,
        fw,
        q_findings,
        d_findings,
        [],
        None,
        None,
        config,
        core.raw_imports,
    )
    if not _include_analysis_metadata:
        return base_result
    return _analysis_scan_result(
        base_result,
        source,
        ignore_lines,
        ignore_rules_by_line,
        suppressed_quality + suppressed_danger,
    )
