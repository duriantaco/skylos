from __future__ import annotations

import re

_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_CONTROL_KEYWORDS = frozenset(
    {
        "case",
        "catch",
        "do",
        "else",
        "for",
        "if",
        "return",
        "switch",
        "throw",
        "try",
        "while",
    }
)
_DECLARATION_KEYWORDS = frozenset(
    {
        "const",
        "final",
        "let",
        "var",
    }
)
_MAX_CONTINUATION_LINES = 8
_MAX_EXPR_CHARS = 4096


def _assignment_index(statement: str) -> int:
    in_string: str | None = None
    escaped = False
    index = 0

    while index < len(statement):
        char = statement[index]

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_string:
                in_string = None
            index += 1
            continue

        if char in {'"', "'", "`"}:
            in_string = char
            index += 1
            continue

        if char == "=":
            prev_char = statement[index - 1] if index > 0 else ""
            next_char = statement[index + 1] if index + 1 < len(statement) else ""
            if prev_char not in {"=", "!", "<", ">"} and next_char not in {
                "=",
                ">",
            }:
                return index

        index += 1

    return -1


def _assignment_alias(lhs: str) -> str | None:
    lhs = lhs.strip()
    if not lhs:
        return None

    first = lhs.split(None, 1)[0].rstrip("(")
    if first in _CONTROL_KEYWORDS:
        return None
    if "(" in lhs or ")" in lhs or "{" in lhs or "}" in lhs:
        return None

    remainder = lhs
    for keyword in _DECLARATION_KEYWORDS:
        prefix = f"{keyword} "
        if remainder.startswith(prefix):
            remainder = remainder[len(prefix) :].strip()
            break

    if remainder.startswith(("{", "[")):
        return None
    if ":" in remainder:
        remainder = remainder.split(":", 1)[0].strip()

    names = _IDENTIFIER_RE.findall(remainder)
    if not names:
        return None

    alias = names[-1]
    if alias in _CONTROL_KEYWORDS or alias in _DECLARATION_KEYWORDS:
        return None
    return alias


def _parse_assignment_statement(statement: str) -> tuple[str, str] | None:
    stripped = statement.strip()
    if not stripped:
        return None

    index = _assignment_index(stripped)
    if index < 0:
        return None

    alias = _assignment_alias(stripped[:index])
    if not alias:
        return None

    expr = stripped[index + 1 :].strip()
    if not expr:
        return None

    return alias, expr


def _trim_expr(expr: str) -> str:
    if ";" in expr:
        return expr.split(";", 1)[0].strip()
    return expr.strip()


def _complete_expr(lines: list[str], line_index: int, expr: str) -> str:
    parts = [_trim_expr(expr)]
    if ";" in expr:
        return parts[0]

    for offset in range(1, _MAX_CONTINUATION_LINES + 1):
        next_index = line_index + offset
        if next_index >= len(lines):
            break
        next_line = lines[next_index]
        parts.append(_trim_expr(next_line))
        if ";" in next_line:
            break
        if sum(len(part) for part in parts) >= _MAX_EXPR_CHARS:
            break

    joined = " ".join(part for part in parts if part)
    if len(joined) > _MAX_EXPR_CHARS:
        return joined[:_MAX_EXPR_CHARS]
    return joined


def iter_semicolon_assignments(text: str) -> list[tuple[int, str, str]]:
    assignments: list[tuple[int, str, str]] = []
    lines = text.splitlines()

    for line_index, line in enumerate(lines):
        parsed = _parse_assignment_statement(line)
        if not parsed:
            continue
        alias, expr = parsed
        assignments.append((line_index, alias, _complete_expr(lines, line_index, expr)))

    return assignments
