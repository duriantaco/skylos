"""Parse standalone PostgreSQL and limited, non-executing psql dump framing."""

import re
from bisect import bisect_left

from pglast import ast, parse_sql, scan
from pglast.parser import ParseError

from skylos.analysis.sql_files import POSTGRES_DUMP_BYTE_LIMIT

_SQL_BYTE_LIMIT = 4_000_000
_LARGE_DUMP_HEADER_LIMIT = 65_536
_SQL_LIMIT_REASON = (
    "PostgreSQL SQL exceeds the 4 MB parse limit after removing inline COPY rows."
)

_CONNECT = re.compile(r"\\(?:connect|c)[ \t]+[a-zA-Z_][a-zA-Z_0-9-]*;?[ \t\r]*")
_GUARD = re.compile(r"\\(unrestrict|restrict)[ \t]+([a-zA-Z0-9]+)[ \t\r]*")
_DESCRIBE = re.compile(
    r"\\dt?\+?(?:[ \t]+[a-zA-Z_][a-zA-Z_0-9]*(?:\.[a-zA-Z_][a-zA-Z_0-9]*)?)?[ \t\r]*"
)
# psql accepts digits (including a leading digit) and non-ASCII characters.
_NAME = r"[a-zA-Z_0-9\x80-\U0010ffff]+"
_VARIABLE = re.compile(rf""":(?:{_NAME}|'{_NAME}'|"{_NAME}"|\{{\?{_NAME}\}})""")

# Only frame COPY headers here. The server parser checks each header, then
# checks its position a second time in the AST of the complete SQL session.
_IDENT = r"[a-zA-Z_\x80-\U0010ffff]"
_IDENT_CONT = r"[a-zA-Z_0-9\x80-\U0010ffff]"
_SQL_TOKEN = re.compile(
    rf"""--[^\r\n]*|/\*|[eE]'|['";\\]|\$(?:{_IDENT}{_IDENT_CONT}*)?\$|"""
    rf"""{_IDENT}(?:{_IDENT_CONT}|\$)*"""
)
_BACKSLASH_RUN = re.compile(r"\\+")
_BLOCK_DELIMITER = re.compile(r"/\*|\*/")
_STRING_GAP = re.compile(r"(?:[ \t\f\v\r\n]|--[^\r\n]*)*")
_ESCAPED_QUOTE = re.compile(r"''|\\[\s\S]|'")
_TEXT_END = re.compile(r"^\\\.(?:\r?\n|\Z)", re.MULTILINE)
_COPY_WORD = re.compile(r"\bcopy\b", re.IGNORECASE)


class PsqlScriptError(ValueError):
    """The file requires psql behavior outside the static parser."""


def _quoted_end(source, pos, quote):
    while True:
        end = source.find(quote, pos)
        if end < 0:
            return len(source)
        pos = end + 1
        if pos == len(source) or source[pos] != quote:
            return pos
        pos += 1


def _escaped_end(source, pos):
    while True:
        close = next(
            (m for m in _ESCAPED_QUOTE.finditer(source, pos) if m[0] == "'"), None
        )
        if close is None:
            return len(source)
        # PostgreSQL continues the same escape-string mode for adjacent
        # quoted literals separated by whitespace containing a newline.
        gap = _STRING_GAP.match(source, close.end())
        if source.startswith("'", gap.end()) and ("\n" in gap[0] or "\r" in gap[0]):
            pos = gap.end() + 1
        else:
            return close.end()


def _block_end(source, pos):
    level = 1
    for match in _BLOCK_DELIMITER.finditer(source, pos):
        level += 1 if match[0] == "/*" else -1
        if level == 0:
            return match.end()
    return len(source)


def _from_stdin(stmt):
    return isinstance(stmt, ast.CopyStmt) and stmt.is_from and stmt.filename is None


def _copy_end(source, start, semicolon, compact):
    # The COPY grammar determines the input format, including the historical
    # CSV/BINARY spellings. A file/program source has no inline data section.
    if compact and (
        semicolon + 1 - start > _LARGE_DUMP_HEADER_LIMIT
        or len(source[start : semicolon + 1].encode("utf-8")) > _LARGE_DUMP_HEADER_LIMIT
    ):
        raise PsqlScriptError("COPY header in a large dump exceeds 64 KiB.")
    _, statements = _parse_session(source, start, semicolon + 1)
    stmt = statements[0].stmt
    if not _from_stdin(stmt):
        return None
    if any(
        opt.defname == "format" and getattr(opt.arg, "sval", "").lower() != "text"
        for opt in stmt.options or ()
    ):
        raise PsqlScriptError("Only text COPY FROM STDIN data is supported.")
    newline = source.find("\n", semicolon)
    if newline < 0:
        raise PsqlScriptError("Missing end marker for COPY FROM STDIN data.")
    tail = source[semicolon + 1 : newline].lstrip(" \t").removesuffix("\r")
    if tail and not tail.startswith("--"):
        raise PsqlScriptError("Unsupported text after the COPY FROM STDIN header.")
    marker = _TEXT_END.search(source, newline + 1)
    if marker is None:
        raise PsqlScriptError("Missing end marker for COPY FROM STDIN data.")
    return newline + 1, marker.end()


def _mask_copy_data(source, compact):
    if not _COPY_WORD.search(source):
        return source, set()
    pos = last = removed = 0
    copy_start = None
    boundary = True
    parts, offsets = [], set()
    while match := _SQL_TOKEN.search(source, pos):
        if compact and match.start() - removed > _SQL_BYTE_LIMIT:
            raise PsqlScriptError(_SQL_LIMIT_REASON)
        if source[pos : match.start()].strip():
            boundary = False
        token, pos = match[0], match.end()
        if token.startswith("--"):
            continue
        if token == "/*":
            pos = _block_end(source, pos)
            continue
        if token == ";":
            if copy_start is not None:
                block = _copy_end(source, copy_start, match.start(), compact)
                if block is not None:
                    first, pos = block
                    parts.append(source[last:first])
                    offsets.add(copy_start - removed)
                    if compact:
                        # Only source lines are public. Empty data lines preserve their
                        # numbers without sending a large payload to the native parser.
                        lines = source.count("\n", first, pos)
                        if first - removed + lines > _SQL_BYTE_LIMIT:
                            raise PsqlScriptError(_SQL_LIMIT_REASON)
                        parts.append("\n" * lines)
                        removed += pos - first - lines
                    else:
                        # For ordinary inputs also preserve all character offsets.
                        parts.append(
                            re.sub(
                                r"[^\n]+",
                                lambda m: " " * len(m[0]),
                                source[first:pos],
                            )
                        )
                    last = pos
            copy_start = None
            boundary = True
            continue
        if token == "\\":
            # The native token pass below validates the complete client line.
            end = source.find("\n", pos)
            pos = len(source) if end < 0 else end + 1
            copy_start = None
            boundary = True
            continue
        if boundary and token.lower() == "copy":
            copy_start = match.start()
        boundary = False
        if token in {"'", '"'}:
            pos = _quoted_end(source, pos, token)
        elif token.lower() == "e'":
            pos = _escaped_end(source, pos)
        elif token.startswith("$"):
            end = source.find(token, pos)
            pos = len(source) if end < 0 else end + len(token)
    if compact and (not offsets or len(source) - removed > _SQL_BYTE_LIMIT):
        raise PsqlScriptError(_SQL_LIMIT_REASON)
    if not offsets:
        return source, offsets
    parts.append(source[last:])
    return "".join(parts), offsets


def _line_at(source, offset):
    return (
        1
        + source.count("\n", 0, offset)
        + source.count("\r", 0, offset)
        - source.count("\r\n", 0, offset)
    )


def _located_error(source, start, end, exc):
    reason, position = exc.args
    offset = end if position is None else start + position
    line = _line_at(source, offset)
    return PsqlScriptError(f"PostgreSQL parse error on line {line}: {reason}.")


def _parse_session(source, start, end):
    try:
        return start, parse_sql(source[start:end])
    except ParseError as exc:
        raise _located_error(source, start, end, exc) from exc


def _verify_frames(sessions, copies, commands, ends):
    framed = bool(copies or commands)
    for (offset, statements), end in zip(sessions, ends, strict=True):
        for raw in statements:
            start = offset + raw.stmt_location
            stmt = raw.stmt
            if (
                framed
                and isinstance(stmt, ast.VariableSetStmt)
                and (stmt.name or "").lower() == "standard_conforming_strings"
            ):
                args = stmt.args or ()
                value = args[0].val if args else None
                enabled = (
                    isinstance(value, ast.String)
                    and value.sval.lower() in {"on", "true", "yes", "1"}
                ) or (isinstance(value, ast.Integer) and value.ival == 1)
                if not enabled:
                    raise PsqlScriptError(
                        "psql framing requires standard_conforming_strings to be on."
                    )
            if _from_stdin(stmt):
                if start not in copies:
                    raise PsqlScriptError("Unframed COPY FROM STDIN data.")
                copies.remove(start)
            # A semicolon inside a BEGIN ATOMIC body doesn't finish the SQL.
            i = bisect_left(commands, start)
            stop = start + raw.stmt_len if raw.stmt_len else end
            if i < len(commands) and commands[i] < stop:
                raise PsqlScriptError(
                    "Unsupported psql command inside a SQL statement."
                )
    if copies:
        raise PsqlScriptError("Inline COPY FROM STDIN requires a top-level statement.")
    return sessions


def parse_script(source):
    """Frame text dumps before the server's bounded lexer and parser see SQL."""
    if len(source) > POSTGRES_DUMP_BYTE_LIMIT:
        raise PsqlScriptError("PostgreSQL file exceeds the 16 MB input limit.")
    try:
        size = len(source) if source.isascii() else len(source.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise PsqlScriptError("PostgreSQL source is not valid UTF-8.") from exc
    if size > POSTGRES_DUMP_BYTE_LIMIT:
        raise PsqlScriptError("PostgreSQL file exceeds the 16 MB input limit.")
    compact = size > _SQL_BYTE_LIMIT
    if compact and (not _TEXT_END.search(source) or not _COPY_WORD.search(source)):
        raise PsqlScriptError(_SQL_LIMIT_REASON)
    source, copies = _mask_copy_data(source, compact)
    if compact and len(source.encode("utf-8")) > _SQL_BYTE_LIMIT:
        raise PsqlScriptError(_SQL_LIMIT_REASON)
    return source, _parse_sessions(source, copies)


def parse_sessions(source):
    """Return each connection's offset and statements."""
    return parse_script(source)[1]


def _parse_sessions(source, copies):
    try:
        plain = (0, parse_sql(source))
    except ParseError as exc:
        plain = None
        if "\\" not in source and ":" not in source:
            raise _located_error(source, 0, len(source), exc) from exc
    else:
        if not copies or (":" not in source and "\\'" not in source):
            return _verify_frames([plain], copies, [], [len(source)])

    starts = [0]
    ends = []
    commands = []
    parts = []
    key = None
    last = 0
    at_boundary = True
    try:
        tokens = scan(source)
    except ParseError as exc:
        raise _located_error(source, 0, len(source), exc) from exc
    for token in tokens:
        if token.start < last or token.name in {"SQL_COMMENT", "C_COMMENT"}:
            continue
        # The server (or its caller) can change standard_conforming_strings.
        # Inside an ordinary string an odd backslash run before a quote then
        # changes where SQL ends. Only frame data when both lexers agree.
        if token.name == "SCONST" and source[token.start] == "'":
            for run in _BACKSLASH_RUN.finditer(source, token.start, token.end + 1):
                if (
                    run.end() <= token.end
                    and source[run.end()] == "'"
                    and (run.end() - run.start()) % 2
                ):
                    raise PsqlScriptError(
                        f"Mode-dependent string quote on line {_line_at(source, run.end())}. "
                        "Use an explicit escape string or dollar quoting in a psql script."
                    )
        if token.name == "ASCII_58" and _VARIABLE.match(source, token.start):
            line = _line_at(source, token.start)
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
        text = source[token.start : line_end]
        guard = _GUARD.fullmatch(text)
        valid = at_boundary and not source[line_start : token.start].strip(" \t")
        if guard and valid:
            name, value = guard.groups()
            if name == "restrict" and key is None:
                key = value
            elif name == "unrestrict" and value == key:
                key = None
            else:
                valid = False
        elif key is None and valid and _CONNECT.fullmatch(text):
            ends.append(line_start)
            starts.append(min(len(source), line_end + 1))
        elif key is not None or not _DESCRIBE.fullmatch(text):
            valid = False
        if not valid:
            line = _line_at(source, token.start)
            raise PsqlScriptError(
                f"Unsupported psql command or command position on line {line}."
            )
        commands.append(token.start)
        parts.extend((source[last:line_start], " " * (line_end - line_start)))
        last = line_end
        at_boundary = True

    if plain is not None:
        return _verify_frames([plain], copies, [], [len(source)])
    if key is not None:
        raise PsqlScriptError("Unclosed psql restricted mode.")
    parts.append(source[last:])
    cleaned = "".join(parts)
    ends.append(len(cleaned))
    sessions = [
        _parse_session(cleaned, start, end)
        for start, end in zip(starts, ends, strict=True)
    ]
    return _verify_frames(sessions, copies, commands, ends)
