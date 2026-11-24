"""Locate literal password fields in bounded database connection records."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


_MAX_RECORD_CHARS = 4096
_MAX_FIELDS = 64
_SQL_SERVER_HOST = (
    r"(?:\[[0-9a-f:.]{1,64}\]|[a-z0-9][a-z0-9_.-]{0,252})"
    r"(?:\\[a-z0-9_.-]{1,128})?"
)
_SQL_ENDPOINT_RE = re.compile(
    rf"(?:tcp:)?{_SQL_SERVER_HOST}(?:[:,][0-9]{{1,5}})?", re.IGNORECASE
)
_JDBC_PREFIX_RE = re.compile(
    rf"(?<![\w+.-])jdbc:sqlserver://"
    rf"(?P<host>{_SQL_SERVER_HOST}(?::[0-9]{{1,5}})?)?[ \t]*;",
    re.IGNORECASE,
)
_ODBC_START_RE = re.compile(
    r"(?<![\w.-])"
    r"(?:driver|server|address|addr|network address|database|uid|pwd)[ \t]*=",
    re.IGNORECASE,
)
_ODBC_DRIVER_RE = re.compile(
    r"(?:SQL Server(?: Native Client(?: [0-9.]+)?)?"
    r"|ODBC Driver [0-9.]+ for SQL Server)",
    re.IGNORECASE,
)
_SEMICOLON_FIELD_RE = re.compile(
    r"[ \t]*(?P<name>[a-z][a-z0-9_ -]{0,62})[ \t]*=[ \t]*"
    r"(?:\{(?P<quoted>(?:[^}]|\}\})*)\}|(?P<plain>[^;\s\"'`<>{}()\[\]]*"
    r"(?:[ \t]+[^;\s\"'`<>{}()\[\]]+)*))[ \t]*"
    r"(?=;|[\"'`<>()}\[\]]|$)",
    re.IGNORECASE,
)
_LIBPQ_START_RE = re.compile(
    r"(?<![\w.-])(?:hostaddr|host|dbname|user|password)[ \t]*="
)
_LIBPQ_FIELD_RE = re.compile(
    r"[ \t]*(?P<name>[a-z][a-z0-9_]{0,62})[ \t]*=[ \t]*"
    r"(?:'(?P<quoted>(?:[^'\\]|\\.)*)'|(?P<plain>(?:\\.|[^\s\\'\"`;<>()[\]{}])+))"
    r"(?=[ \t\"'`;<>()[\]}]|$)"
)
_FIELD_START_RE = re.compile(r"[ \t]*[a-zA-Z][a-zA-Z0-9_ -]{0,62}[ \t]*=")
_LIBPQ_HOST_RE = re.compile(r"[a-zA-Z0-9./:_-]+(?:,[a-zA-Z0-9./:_-]+)*")
_LITERAL_USER_RE = re.compile(r"[a-zA-Z0-9._@+\\/-]{1,128}")
_LIBPQ_ESCAPE_RE = re.compile(r"\\(.)")


@dataclass(frozen=True)
class _Property:
    start: int
    end: int
    value: str = field(repr=False)


@dataclass(frozen=True)
class DatabasePassword:
    kind: str
    start: int
    end: int
    host: str = field(repr=False)
    user: str = field(repr=False)
    password: str = field(repr=False)


def _parse_record(line, start, pattern, *, semicolon):
    cursor = start
    limit = min(len(line), start + _MAX_RECORD_CHARS)
    fields = {}
    duplicate = False
    for _ in range(_MAX_FIELDS):
        match = pattern.match(line, cursor, limit)
        if match is None:
            if _FIELD_START_RE.match(line, cursor, limit):
                return None, cursor
            break
        name = match["name"].strip().lower()
        value_group = "quoted" if match["quoted"] is not None else "plain"
        value = match[value_group]
        if not semicolon:
            value = _LIBPQ_ESCAPE_RE.sub(r"\1", value)
        elif value_group == "quoted":
            value = value.replace("}}", "}")
        duplicate |= name in fields
        fields[name] = _Property(*match.span(value_group), value)
        cursor = match.end()
        if cursor == limit and limit < len(line):
            return None, cursor
        if semicolon:
            if line[cursor : cursor + 1] != ";":
                break
            cursor += 1
        elif line[cursor : cursor + 1] not in {" ", "\t"}:
            break
    else:
        return None, cursor
    return (None if duplicate else fields), cursor


def _field(fields, *names):
    matches = [fields[name] for name in names if name in fields]
    return matches[0] if len(matches) == 1 else None


def _candidate(kind, host, user, password):
    if not host or not user or not password:
        return None
    if not _LITERAL_USER_RE.fullmatch(user.value) or not 0 < len(password.value) <= 256:
        return None
    return DatabasePassword(
        kind, password.start, password.end, host, user.value, password.value
    )


def database_passwords(line: str):
    """Yield positions without interpreting independent literals as siblings."""
    semicolon_text = line.lower() if ";" in line else ""
    if "jdbc:sqlserver://" in semicolon_text:
        for prefix in _JDBC_PREFIX_RE.finditer(line):
            fields, _ = _parse_record(
                line, prefix.end(), _SEMICOLON_FIELD_RE, semicolon=True
            )
            if not fields:
                continue
            server_property = fields.get("servername")
            host = prefix["host"] or (server_property.value if server_property else "")
            if not _SQL_ENDPOINT_RE.fullmatch(host):
                continue
            result = _candidate(
                "SQL Server JDBC",
                host,
                _field(fields, "user", "username"),
                fields.get("password"),
            )
            if result:
                yield result

    if "driver" in semicolon_text:
        cursor = 0
        for marker in _ODBC_START_RE.finditer(line):
            if marker.start() < cursor:
                continue
            fields, cursor = _parse_record(
                line, marker.start(), _SEMICOLON_FIELD_RE, semicolon=True
            )
            if not fields:
                continue
            driver = fields.get("driver")
            server = _field(fields, "server", "address", "addr", "network address")
            if (
                not driver
                or not _ODBC_DRIVER_RE.fullmatch(driver.value)
                or not server
                or not _SQL_ENDPOINT_RE.fullmatch(server.value)
            ):
                continue
            result = _candidate(
                "SQL Server ODBC", server.value, fields.get("uid"), fields.get("pwd")
            )
            if result:
                yield result

    if "dbname" not in line or "password" not in line:
        return
    cursor = 0
    for marker in _LIBPQ_START_RE.finditer(line):
        if marker.start() < cursor:
            continue
        fields, cursor = _parse_record(
            line, marker.start(), _LIBPQ_FIELD_RE, semicolon=False
        )
        if not fields:
            continue
        host = fields.get("host") or fields.get("hostaddr")
        database = fields.get("dbname")
        if not host or not database or not database.value:
            continue
        if not _LIBPQ_HOST_RE.fullmatch(host.value):
            continue
        result = _candidate(
            "PostgreSQL libpq", host.value, fields.get("user"), fields.get("password")
        )
        if result:
            yield result
