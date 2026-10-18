"""A code line is a non-blank line holding a non-comment token outside docstrings."""

from __future__ import annotations

import ast
import io
import tokenize
from functools import lru_cache

_SCOPES = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
_DEFINITIONS = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
_TRIVIA = frozenset(
    {
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
    }
)


def code_lines(
    node: ast.AST,
    source: str | None = None,
    *,
    start: int | None = None,
    end: int | None = None,
) -> set[int]:
    """A code line is a non-blank line holding a token other than a comment,
    outside the docstrings of ``node`` and of the classes and functions nested
    in it. Returns those line numbers within ``start``..``end`` (default: the
    node's own span; a module spans the whole source).

    Without ``source`` (or when it does not tokenize) the lines where an AST
    node starts or ends stand in for it.
    """
    start = getattr(node, "lineno", 1) if start is None else start
    end = getattr(node, "end_lineno", None) if end is None else end
    docstrings = _docstring_spans(node)
    by_line = _code_token_spans(source) if isinstance(source, str) else None
    if by_line is None:
        return _ast_code_lines(node, docstrings, start, end)
    docstrings_by_line = _spans_by_line(docstrings)
    last = max(by_line, default=0) if end is None else end
    return {
        line
        for line in range(start, last + 1)
        if _has_code(by_line.get(line, ()), docstrings_by_line.get(line, ()))
    }


def count_statements(body: list[ast.stmt]) -> int:
    """Statements in ``body`` and its nested blocks; docstrings are not counted."""
    count = 0
    pending = list(_without_docstring(body))
    while pending:
        stmt = pending.pop()
        count += 1
        pending.extend(_nested_statements(stmt))
    return count


def _nested_statements(stmt: ast.stmt):
    body = getattr(stmt, "body", None)
    if isinstance(body, list):
        yield from (
            _without_docstring(body) if isinstance(stmt, _DEFINITIONS) else body
        )
    for field in ("orelse", "finalbody"):
        yield from getattr(stmt, field, ())
    for holder in (*getattr(stmt, "handlers", ()), *getattr(stmt, "cases", ())):
        yield from holder.body


def _is_docstring(stmt: ast.AST) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _without_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    return body[1:] if body and _is_docstring(body[0]) else body


def _docstring_spans(node: ast.AST) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    spans = []
    for scope in ast.walk(node):
        if not isinstance(scope, _SCOPES) or not scope.body:
            continue
        first = scope.body[0]
        if _is_docstring(first):
            spans.append(
                (
                    (first.lineno, first.col_offset),
                    (first.end_lineno, first.end_col_offset),
                )
            )
    return spans


def _has_code(token_spans, docstrings) -> bool:
    return any(not _inside(span, docstrings) for span in token_spans)


def _spans_by_line(spans) -> dict[int, list]:
    index: dict[int, list] = {}
    for span in spans:
        for row in range(span[0][0], span[1][0] + 1):
            index.setdefault(row, []).append(span)
    return index


def _inside(span, docstrings) -> bool:
    (row, col), (end_row, end_col) = span
    return any(
        (row, col) >= ds_start and (end_row, end_col) <= ds_end
        for ds_start, ds_end in docstrings
    )


@lru_cache(maxsize=8)
def _code_token_spans(source: str):
    """Per line, the byte spans of the code tokens that cover it."""
    lines = io.StringIO(source).readlines()
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, SyntaxError):
        return None
    by_line: dict[int, list] = {}
    for tok in tokens:
        if tok.type in _TRIVIA:
            continue
        span = (
            (tok.start[0], _byte_col(lines, tok.start)),
            (tok.end[0], _byte_col(lines, tok.end)),
        )
        for row in range(tok.start[0], tok.end[0] + 1):
            if row <= len(lines) and lines[row - 1].strip():
                by_line.setdefault(row, []).append(span)
    return by_line


def _byte_col(lines, position) -> int:
    # AST offsets count UTF-8 bytes; tokenize counts characters.
    row, col = position
    if row > len(lines) or lines[row - 1].isascii():
        return col
    return len(lines[row - 1][:col].encode("utf-8"))


def _ast_code_lines(node, docstrings, start, end) -> set[int]:
    lines = set()
    for child in ast.walk(node):
        first = getattr(child, "lineno", None)
        if not isinstance(first, int) or isinstance(child, ast.Module):
            continue
        last = getattr(child, "end_lineno", None) or first
        span = ((first, child.col_offset), (last, child.end_col_offset or 0))
        if _inside(span, docstrings):
            continue
        lines.update((first, last))
    if end is None:
        end = max(lines, default=0)
    return {line for line in lines if start <= line <= end}
