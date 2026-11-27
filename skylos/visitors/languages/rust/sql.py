"""Rust SQL query text, statement creation and execution."""

from dataclasses import replace

from ._security_bindings import REQUEST_TEXT, Value, joined
from .permissions import trait_in_scope
from .sensitive import password_write

CONNECTION = "rusqlite::Connection"
STATEMENT = "rusqlite::Statement"
ROWS = "rusqlite::Rows"
MAPPED_ROWS = "rusqlite::MappedRows"
TEXT = REQUEST_TEXT
REMOTE_TEXT = "reqwest_response_text"
REMOTE_SOURCE = "remote HTTP response body (reqwest)"
REMOTE_SOURCES = frozenset({REMOTE_SOURCE})
TEXT_KINDS = {TEXT, REMOTE_TEXT}
BUILDER = "sqlx::QueryBuilder"
SQLX_EXECUTOR = "sqlx::Executor"
# A pending cursor or future carries only the sources in the SQL text. Bound
# arguments and the data returned by the database never become SQL sources.
FUTURE = "sql_query_future:"
VALUE_FUTURE = "sql_value_future"
STREAM = "sqlx_stream:"
EXECUTED = "sql_executed:"
EXECUTOR_TYPES = {"sqlx::Pool", "sqlx::pool::PoolConnection"} | {
    f"sqlx::{path}{driver}{suffix}"
    for module, driver in (
        ("postgres", "Pg"),
        ("mysql", "MySql"),
        ("sqlite", "Sqlite"),
        ("any", "Any"),
    )
    for path in ("", module + "::")
    for suffix in ("Pool", "Connection")
}
EXECUTE_ARITY = {"execute": 2, "execute_batch": 1, "query_row": 3, "query_one": 3}
OPEN_ARITY = {
    "open": 1,
    "open_in_memory": 0,
    "open_in_memory_with_flags": 1,
    "open_in_memory_with_flags_and_vfs": 2,
    "open_with_flags": 2,
    "open_with_flags_and_vfs": 3,
}
_STATEMENT_EXECUTES = {
    "execute": 1,
    "raw_execute": 0,
    "exists": 1,
    "insert": 1,
    "query_row": 2,
    "query_one": 2,
}
_QUERY_TYPES = {
    "sqlx::query": "sqlx::query::Query",
    "sqlx::query_as": "sqlx::query::QueryAs",
    "sqlx::query_scalar": "sqlx::query::QueryScalar",
    "sqlx::raw_sql": "sqlx::RawSql",
}
_QUERY_CONSTRUCTORS = {name: (1, kind) for name, kind in _QUERY_TYPES.items()} | {
    name + "_with": (2, kind)
    for name, kind in _QUERY_TYPES.items()
    if name != "sqlx::raw_sql"
}
_QUERY_KINDS = set(_QUERY_TYPES.values())
_AWAIT_METHODS = {"execute", "fetch_all", "fetch_one", "fetch_optional"}
_STREAM_METHODS = {"execute_many", "fetch", "fetch_many"}
_STREAM_TRAITS = {
    "next": (
        "futures::StreamExt",
        "futures_util::StreamExt",
        "tokio_stream::StreamExt",
    ),
    "try_next": ("futures::TryStreamExt", "futures_util::TryStreamExt"),
    "try_collect": ("futures::TryStreamExt", "futures_util::TryStreamExt"),
    "collect": (
        "futures::StreamExt",
        "futures_util::StreamExt",
        "tokio_stream::StreamExt",
    ),
}


MYSQL_TYPES = {
    "mysql::Pool",
    "mysql::Conn",
    "mysql::PooledConn",
    "mysql::Transaction",
    "mysql_async::Pool",
    "mysql_async::Conn",
    "mysql_async::Transaction",
}
MYSQL_GLOBS = {
    "mysql": ("Conn", "Pool", "PooledConn", "Transaction"),
    "mysql_async": ("Conn", "Pool", "Transaction"),
    "mysql::prelude": ("Queryable",),
    "mysql_async::prelude": ("Queryable",),
}
_MYSQL_QUERY_ARITY = {
    "query": 1,
    "query_drop": 1,
    "query_first": 1,
    "query_iter": 1,
    "query_map": 2,
    "query_fold": 3,
    "exec": 2,
    "exec_drop": 2,
    "exec_first": 2,
    "exec_iter": 2,
    "exec_map": 3,
    "exec_fold": 4,
}
_MYSQL_SYNC_ARITY = _MYSQL_QUERY_ARITY | {
    name + "_opt": arity
    for name, arity in _MYSQL_QUERY_ARITY.items()
    if name
    in {
        "query",
        "query_first",
        "query_fold",
        "query_map",
        "exec",
        "exec_first",
        "exec_fold",
        "exec_map",
    }
}
_MYSQL_ASYNC_ARITY = _MYSQL_QUERY_ARITY | {"query_stream": 1, "exec_stream": 2}
_BUILDER_CTORS = {BUILDER + "::new": 1, BUILDER + "::with_arguments": 2}


def pending_value(kind, sources=frozenset()):
    return Value(
        kind=VALUE_FUTURE, awaited=Value(kind="result_" + kind, sources=sources)
    )


def mysql_method(receiver, name, args, state):
    crate, _, ty = receiver.kind.partition("::")
    arity = len(args)
    asynchronous = crate == "mysql_async"
    if ty == "Pool" and name == "get_conn" and not args:
        return (
            pending_value("mysql_async::Conn")
            if asynchronous
            else Value(kind="result_mysql::PooledConn")
        )
    if (
        ty in {"Conn", "PooledConn", "Pool"}
        and name == "start_transaction"
        and arity == 1
    ):
        return (
            pending_value("mysql_async::Transaction")
            if asynchronous
            else Value(kind="result_mysql::Transaction")
        )
    if ty == "Pool":
        return None
    if ty == "PooledConn" and name == "unwrap" and not args:
        return Value(kind="mysql::Conn")
    trait = crate + "::prelude::Queryable"
    if not trait_in_scope(state, trait):
        return None
    if name == "prep" and arity == 1:
        sources = sql_sources(args[0])
        if asynchronous:
            return pending_value(crate + "::Statement", sources)
        return Value(kind="result_" + crate + "::Statement", sources=sources)
    arities = _MYSQL_ASYNC_ARITY if asynchronous else _MYSQL_SYNC_ARITY
    if arities.get(name) != arity:
        return None
    query = args[0]
    sources = sql_sources(query)
    if (
        name.startswith("exec")
        and not query.items
        and query.kind == crate + "::Statement"
    ):
        sources = query.real_sources
    return Value(
        kind=(FUTURE if asynchronous else EXECUTED) + trait + "::" + name,
        sources=sources,
    )


def mutable_sql_value(value):
    kind = (value.kind or "").removeprefix("result_")
    return (
        kind in TEXT_KINDS
        or kind in _QUERY_KINDS
        or kind
        in {
            BUILDER,
            STATEMENT,
            ROWS,
            MAPPED_ROWS,
            "mysql::Statement",
            "mysql_async::Statement",
        }
        or kind.startswith((FUTURE, STREAM))
        or value.password_write is not None
    )


def sql_sources(value):
    if not value.items and value.kind in TEXT_KINDS:
        return value.request_sources | (
            REMOTE_SOURCES if value.kind == REMOTE_TEXT else frozenset()
        )
    return frozenset()


def join_strings(values):
    combined = joined(values)
    if values and all(
        v.kind in TEXT_KINDS | {"string"} and not v.items for v in values
    ):
        if any(v.kind == REMOTE_TEXT for v in values):
            return replace(combined, kind=REMOTE_TEXT)
        if any(v.kind == TEXT for v in values):
            return replace(combined, kind=TEXT)
    return combined


def checked_password_write(executor, query):
    write = query.password_write
    if write is None or executor.items or executor.kind not in EXECUTOR_TYPES:
        return None
    driver = executor.kind.rsplit("::", 1)[-1]
    if driver.startswith("Pg") and write.placeholder_style == "$N":
        return write
    if driver.startswith("MySql") and write.placeholder_style == "?":
        return write
    if driver.startswith("Sqlite"):
        return write
    return None


def executor_type(api, inner, state):
    if api in {"sqlx::Pool", "sqlx::pool::PoolConnection"} and inner:
        db = state.resolve(inner)
        suffix = "Pool" if api == "sqlx::Pool" else "Connection"
        for module, name in (
            ("postgres", "Postgres"),
            ("mysql", "MySql"),
            ("sqlite", "Sqlite"),
        ):
            if db in {"sqlx::" + name, "sqlx::" + module + "::" + name}:
                return "sqlx::" + ("Pg" if module == "postgres" else name) + suffix
    return api


def sqlx_execution(owner, name, sources, write=None):
    if owner in {
        "sqlx::query::QueryAs",
        "sqlx::query::QueryScalar",
        "sqlx::query::Map",
    } and name in {"execute", "execute_many"}:
        return None
    if name in _AWAIT_METHODS:
        return Value(
            kind=FUTURE + owner + "::" + name, sources=sources, password_write=write
        )
    if name in _STREAM_METHODS:
        return Value(
            kind=STREAM + owner + "::" + name, sources=sources, password_write=write
        )
    return None


def function(api, args, state):
    if not api:
        return None
    if api.startswith("rusqlite::"):
        owner, _, name = api.rpartition("::")
        if owner == CONNECTION and OPEN_ARITY.get(name) == len(args):
            return Value(kind="result_" + CONNECTION)
        if args and owner in {CONNECTION, STATEMENT, ROWS} and args[0].kind == owner:
            return method(args[0], name, args[1:], state)
    if len(args) == 1:
        if api == "mysql::Pool::new":
            return Value(kind="result_mysql::Pool")
        if api == "mysql::Conn::new":
            return Value(kind="result_mysql::Conn")
        if api == "mysql_async::Pool::new":
            return Value(kind="mysql_async::Pool")
        if api == "mysql_async::Conn::new":
            return pending_value("mysql_async::Conn")
    if not api.startswith("sqlx::"):
        return None
    if api == "sqlx::AssertSqlSafe" and len(args) == 1:
        # This wrapper is the caller's assertion. It does not modify the text.
        return (
            args[0]
            if args[0].kind in TEXT_KINDS and not args[0].items
            else Value(kind="string")
        )
    if _BUILDER_CTORS.get(api) == len(args):
        sources = sql_sources(args[0])
        return Value(kind=BUILDER, sources=sources, sql_initial_sources=sources)
    constructor = _QUERY_CONSTRUCTORS.get(api)
    if constructor and len(args) == constructor[0]:
        write = (
            password_write(args[0])
            if len(args) == 1 and api != "sqlx::raw_sql"
            else None
        )
        return Value(
            kind=constructor[1], sources=sql_sources(args[0]), password_write=write
        )
    owner, _, name = api.rpartition("::")
    if owner in EXECUTOR_TYPES and len(args) == 1 and name == "connect":
        return pending_value(owner)
    if owner == SQLX_EXECUTOR and len(args) == 2:
        # The explicit trait method identifies the actual SQLx implementation.
        return sqlx_execution(
            owner,
            name,
            executor_sources(args[1]),
            checked_password_write(args[0], args[1]),
        )
    return None


def executor_sources(query):
    if query.kind in _QUERY_KINDS and not query.items:
        return query.real_sources
    return sql_sources(query)


def method(receiver, name, args, state):
    kind, arity = receiver.kind, len(args)
    if not kind or receiver.items:
        return None
    if kind in MYSQL_TYPES:
        return mysql_method(receiver, name, args, state)
    if (
        kind in EXECUTOR_TYPES
        and kind.endswith("Pool")
        and name == "acquire"
        and not args
    ):
        return pending_value("sqlx::pool::PoolConnection")
    if kind == "reqwest_blocking_response" and name == "text" and arity == 0:
        return Value(kind="result_" + REMOTE_TEXT)
    if kind == "reqwest_async_response" and name == "text" and arity == 0:
        return Value(kind="reqwest_text_future")
    if kind == "result_" + REMOTE_TEXT and (
        (name == "unwrap_or" and arity == 1)
        or (name == "unwrap_or_default" and arity == 0)
    ):
        return Value(kind=REMOTE_TEXT)
    if kind == BUILDER:
        if name == "push" and arity == 1:
            return replace(
                receiver, sources=receiver.real_sources | sql_sources(args[0])
            )
        if name == "push_bind" and arity == 1:
            return receiver
        if name == "reset" and arity == 0:
            return replace(receiver, sources=receiver.sql_initial_sources)
        builds = {
            "build": "sqlx::query",
            "build_query_as": "sqlx::query_as",
            "build_query_scalar": "sqlx::query_scalar",
        }
        if name in builds and arity == 0:
            return Value(kind=_QUERY_TYPES[builds[name]], sources=receiver.real_sources)
    if kind == CONNECTION:
        if name in {"prepare", "prepare_cached"} and arity == 1:
            return Value(kind="result_" + STATEMENT, sources=sql_sources(args[0]))
        if EXECUTE_ARITY.get(name) == arity:
            return Value(
                kind=EXECUTED + CONNECTION + "::" + name, sources=sql_sources(args[0])
            )
    elif kind == STATEMENT:
        if _STATEMENT_EXECUTES.get(name) == arity:
            return Value(
                kind=EXECUTED + kind + "::" + name, sources=receiver.real_sources
            )
        if name == "query" and arity == 1:
            return replace(receiver, kind="result_" + ROWS)
        if name == "raw_query" and arity == 0:
            return replace(receiver, kind=ROWS)
        if name in {"query_map", "query_and_then"} and arity == 2:
            return replace(receiver, kind="result_" + MAPPED_ROWS)
    elif kind == ROWS and name == "next" and arity == 0:
        return replace(receiver, kind=EXECUTED + ROWS + "::next")
    elif (
        kind == MAPPED_ROWS
        and name in {"next", "collect", "count", "last"}
        and arity == 0
    ):
        return replace(receiver, kind=EXECUTED + MAPPED_ROWS + "::" + name)
    elif kind in _QUERY_KINDS | {"sqlx::query::Map"} and arity == 1:
        if name in {"map", "try_map"} and kind in {
            "sqlx::query::Query",
            "sqlx::query::Map",
        }:
            return replace(receiver, kind="sqlx::query::Map")
        if kind not in {"sqlx::RawSql", "sqlx::query::Map"} and name in {
            "bind",
            "persistent",
        }:
            if name == "bind" and receiver.password_write is not None:
                return replace(
                    receiver, password_write=receiver.password_write.bind(args[0])
                )
            return receiver
        return sqlx_execution(
            kind, name, receiver.real_sources, checked_password_write(args[0], receiver)
        )
    elif (
        kind in EXECUTOR_TYPES
        and arity == 1
        and name in _AWAIT_METHODS | _STREAM_METHODS
    ):
        if trait_in_scope(state, SQLX_EXECUTOR):
            return sqlx_execution(
                SQLX_EXECUTOR,
                name,
                executor_sources(args[0]),
                checked_password_write(receiver, args[0]),
            )
    elif (
        kind.startswith(STREAM)
        and arity == 0
        and any(trait_in_scope(state, trait) for trait in _STREAM_TRAITS.get(name, ()))
    ):
        return replace(receiver, kind=FUTURE + kind[len(STREAM) :])
    return None


def format_argument(value, tokens):
    """A macro's flat token tree cannot prove what an arbitrary call returns."""
    if value.kind in TEXT_KINDS:
        if len(tokens) == 1 and tokens[0].type == "identifier":
            return value
        return replace(value, kind=None)
    return value


def formatted_kind(parts, inserted):
    if any(value.kind == REMOTE_TEXT and not value.items for _, value in parts):
        return REMOTE_TEXT
    sources = {
        source
        for _, value in parts
        if value.kind == TEXT
        for source in value.request_sources
    }
    return TEXT if sources and sources == inserted.request_sources else "string"
