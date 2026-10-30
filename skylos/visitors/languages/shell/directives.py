"""Skylos directives read from real shell comments, never quoted or heredoc text."""

from __future__ import annotations

from skylos.visitors.languages.typescript import (
    _SKYLOS_IGNORE_END_RE,
    _parse_typescript_directive,
)

from .danger import _heredoc_marker


def _split_comment(line: str, quote: str | None):
    """``(comment, code, quote)`` for one physical line.

    ``quote`` carries an open quote across lines. A ``#`` starts a comment
    only outside quotes, unescaped, at the start of a word.
    """
    escaped = False
    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (idx == 0 or line[idx - 1].isspace()):
            return line[idx + 1 :], line[:idx], quote
    return None, line, quote


def _directive_events(source: str) -> dict[int, list[tuple[str, set[str]]]]:
    events: dict[int, list[tuple[str, set[str]]]] = {}
    quote = None
    heredoc_end = None
    for line_no, raw in enumerate(source.splitlines(), 1):
        if heredoc_end is not None:
            if raw.strip() == heredoc_end:
                heredoc_end = None
            continue
        comment, code, quote = _split_comment(raw, quote)
        if quote is None:
            heredoc_end = _heredoc_marker(code)
        if comment is None:
            continue
        parsed = _parse_typescript_directive(comment)
        if parsed is None:
            continue
        kind, rules, end = parsed
        events.setdefault(line_no, []).append((kind, rules))
        if kind == "start" and _SKYLOS_IGNORE_END_RE.search(comment.lstrip(), end):
            events[line_no].append(("end", set()))
    return events


def shell_inline_ignores(source: str) -> tuple[set[int], dict[int, set[str]]]:
    """Ignored lines and per-line rule ignores, as the analyzer filter expects."""
    events = _directive_events(source)
    ignore_lines: set[int] = set()
    ignore_rules_by_line: dict[int, set[str]] = {}
    in_block = False
    for line in range(1, source.count("\n") + 2):
        if in_block:
            ignore_lines.add(line)
        for kind, rules in events.get(line, ()):
            if kind == "rules":
                ignore_rules_by_line.setdefault(line, set()).update(rules)
            else:
                ignore_lines.add(line)
            if kind == "start":
                in_block = True
            elif kind == "end":
                in_block = False
    return ignore_lines, ignore_rules_by_line
