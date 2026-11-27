"""Parse standalone PostgreSQL and a limited set of literal psql scripts."""

import re

from pglast import ast, parse_sql, scan
from pglast.parser import ParseError

_CONNECT = re.compile(r"\\(?:connect|c)[ \t]+[a-zA-Z_][a-zA-Z_0-9-]*;?[ \t\r]*")
# psql accepts digits (including a leading digit) and non-ASCII characters.
_NAME = r"[a-zA-Z_0-9\x80-\U0010ffff]+"
_VARIABLE = re.compile(rf""":(?:{_NAME}|'{_NAME}'|"{_NAME}"|\{{\?{_NAME}\}})""")


class PsqlScriptError(ValueError):
    """The file requires psql behavior outside the static parser."""


def _parse_session(source, start, end):
    # Parse a complete segment. A semicolon may still belong to an unfinished
    # statement, for example inside a SQL function's BEGIN ATOMIC body.
    try:
        statements = parse_sql(source[start:end])
    except ParseError as exc:
        if start == 0 and end == len(source):
            raise
        reason, position = exc.args
        offset = end if position is None else start + position
        line = source.count("\n", 0, offset) + 1
        raise PsqlScriptError(
            f"PostgreSQL parse error on line {line}: {reason}."
        ) from exc
    if any(
        isinstance(raw.stmt, ast.CopyStmt)
        and raw.stmt.is_from
        and raw.stmt.filename is None
        for raw in statements
    ):
        raise PsqlScriptError("Inline psql COPY FROM STDIN data is unsupported.")
    return start, statements


def parse_sessions(source):
    try:
        return [_parse_session(source, 0, len(source))]
    except ParseError:
        if "\\" not in source and ":" not in source:
            raise

    # The PostgreSQL lexer keeps comments, quoted identifiers, strings, and
    # dollar-quoted function bodies intact, even when they span several lines.
    sessions = []
    start = 0
    at_boundary = True
    for token in scan(source):
        if token.start < start or token.name in {"SQL_COMMENT", "C_COMMENT"}:
            continue
        if token.name == "ASCII_58" and _VARIABLE.match(source, token.start):
            line = source.count("\n", 0, token.start) + 1
            raise PsqlScriptError(
                f"Unsupported psql variable substitution on line {line}."
            )
        if token.name != "ASCII_92":
            at_boundary = token.name == "ASCII_59"
            continue

        line_start = source.rfind("\n", 0, token.start) + 1
        line_end = source.find("\n", token.start)
        if line_end < 0:
            line_end = len(source)
        if (
            not at_boundary
            or source[line_start : token.start].strip(" \t")
            or not _CONNECT.fullmatch(source, token.start, line_end)
        ):
            line = source.count("\n", 0, token.start) + 1
            raise PsqlScriptError(
                f"Unsupported psql command or command position on line {line}."
            )

        sessions.append(_parse_session(source, start, line_start))
        start = min(len(source), line_end + 1)
        at_boundary = True

    sessions.append(_parse_session(source, start, len(source)))
    return sessions
