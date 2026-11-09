"""OWASP's handling for identifiers that cannot be bound: check the value against a
fixed set first. Each guard form sits beside one that proves nothing."""

from __future__ import annotations

import ast

import pytest

from skylos.rules.danger.danger_sql.sql_flow import scan


def _lines(source: str) -> list[int]:
    findings: list[dict] = []
    scan(ast.parse(source), "db.py", findings)
    return [f["line"] for f in findings if f["rule_id"] == "SKY-D211"]


GUARDED = [
    "def rows(conn, sort):\n"
    "    if sort not in COLUMNS:\n"
    "        raise ValueError(sort)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "def rows(conn, sort):\n"
    "    if sort not in ('id', 'qty'):\n"
    "        return []\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "def rows(conn, sort, direction):\n"
    "    if sort not in COLUMNS or direction not in ('asc', 'desc'):\n"
    "        raise ValueError(sort)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort} {direction}")\n',
    "@bp.get('/items')\n"
    "def rows():\n"
    "    sort = request.args.get('sort')\n"
    "    if sort not in COLUMNS:\n"
    "        abort(400)\n"
    '    return db.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "async def rows(conn, sort):\n"
    "    if sort not in COLUMNS:\n"
    "        raise ValueError(sort)\n"
    '    return await conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
]

STILL_REPORTED = [
    'def rows(conn, sort):\n    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "def rows(conn, sort):\n"
    "    if sort not in COLUMNS:\n"
    "        print(sort)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "def rows(conn, sort, other):\n"
    "    if other not in COLUMNS:\n"
    "        raise ValueError(other)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "def rows(conn, sort, flag):\n"
    "    if flag:\n"
    "        if sort not in COLUMNS:\n"
    "            raise ValueError(sort)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "def rows(conn, sort, allowed):\n"
    "    if sort not in allowed:\n"
    "        raise ValueError(sort)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "def rows(conn, sort):\n"
    '    conn.execute(f"SELECT 1 ORDER BY {sort}")\n'
    "    if sort not in COLUMNS:\n"
    "        raise ValueError(sort)\n",
    "def rows(conn, sort):\n"
    "    if sort in COLUMNS:\n"
    "        raise ValueError(sort)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
    "def rows(conn, sort):\n"
    "    if sort not in COLUMNS:\n"
    "        raise ValueError(sort)\n"
    "    sort = sort + request_suffix(conn)\n"
    '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n',
]


@pytest.mark.parametrize("source", GUARDED)
def test_a_value_proved_to_be_in_a_fixed_set_is_not_injection(source):
    assert _lines(source) == []


@pytest.mark.parametrize("source", STILL_REPORTED)
def test_a_guard_that_proves_nothing_is_still_injection(source):
    assert _lines(source) != []


def test_the_guard_covers_only_the_function_it_is_in():
    source = (
        "def first(conn, sort):\n"
        "    if sort not in COLUMNS:\n"
        "        raise ValueError(sort)\n"
        '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n'
        "def second(conn, sort):\n"
        '    return conn.execute(f"SELECT 1 ORDER BY {sort}")\n'
    )
    assert _lines(source) == [6]


STATIC_MAP = (
    "QUERIES = {\n"
    "    ('id', 'asc'): 'SELECT 1 ORDER BY id ASC',\n"
    "    ('id', 'desc'): 'SELECT 1 ORDER BY id DESC',\n"
    "}\n"
)


@pytest.mark.parametrize(
    "body",
    [
        "def rows(conn, sort, direction):\n"
        "    query = QUERIES[(sort, direction)]\n"
        "    return conn.execute(query)\n",
        "def rows(conn, sort, direction):\n"
        "    query = QUERIES.get((sort, direction))\n"
        "    if query is None:\n"
        "        raise ValueError(sort)\n"
        "    return conn.execute(query)\n",
        "def rows(conn, sort, direction):\n"
        "    return conn.execute(QUERIES[(sort, direction)])\n",
    ],
)
def test_a_lookup_in_a_map_of_static_queries_is_not_injection(body):
    assert _lines(STATIC_MAP + body) == []


@pytest.mark.parametrize(
    "source",
    [
        "QUERIES = {'a': f'SELECT {TABLE}'}\n"
        "def rows(conn, key):\n"
        "    query = QUERIES[key]\n"
        "    return conn.execute(query)\n",
        "def rows(conn, key, queries):\n"
        "    query = queries[key]\n"
        "    return conn.execute(query)\n",
        "QUERIES = {'a': 'SELECT 1'}\n"
        "def rows(conn, key, QUERIES):\n"
        "    query = QUERIES[key]\n"
        "    return conn.execute(query)\n",
        "QUERIES = {'a': 'SELECT 1'}\n"
        "QUERIES['b'] = load_query()\n"
        "def rows(conn, key):\n"
        "    query = QUERIES[key]\n"
        "    return conn.execute(query)\n",
        "QUERIES = {'a': 'SELECT 1'}\n"
        "def rows(conn, key):\n"
        "    query = QUERIES[key] + key\n"
        "    return conn.execute(query)\n",
    ],
)
def test_a_map_that_is_not_proved_static_is_still_reported(source):
    assert _lines(source) != []
