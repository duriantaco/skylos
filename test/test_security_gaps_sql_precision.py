import ast
from pathlib import Path

import pytest

from skylos.rules.danger.danger_sql.sql_flow import scan


def _findings(tmp_path: Path, source: str):
    path = tmp_path / "queries.py"
    path.write_text(source)
    findings = []
    scan(ast.parse(source), path, findings)
    return [row for row in findings if row["rule_id"] == "SKY-D211"]


@pytest.mark.parametrize(
    "expression",
    [
        "select(User).join(Address).distinct()",
        "select(User).outerjoin(Address).options(option)",
        "select(User).execution_options(stream_results=True)",
        "select(User).where(User.id.in_(ids))",
        "select(User).where(User.name.ilike(f'%{name}%'))",
        "select(User).params(name=name)",
    ],
)
def test_proven_sqlalchemy_builders_bind_values(tmp_path, expression):
    source = (
        "from sqlalchemy import select\n"
        "def lookup(session, ids, name):\n"
        f"    query = {expression}\n"
        "    session.execute(query)\n"
    )
    assert _findings(tmp_path, source) == []


@pytest.mark.parametrize(
    "otherwise", ["", "    else:\n        query = query.offset(offset)\n"]
)
def test_both_branches_preserve_the_statement_proof(tmp_path, otherwise):
    source = (
        "from sqlalchemy import select\n"
        "def lookup(session, limit, offset):\n"
        "    query = select(User)\n"
        "    if limit:\n"
        "        query = query.limit(limit)\n"
        + otherwise
        + "    session.execute(query)\n"
    )
    assert _findings(tmp_path, source) == []


@pytest.mark.parametrize(
    "body",
    [
        "query = select(User).order_by(name)",
        "query = select(User).where(f'name = {name}')",
        "query = select(User).prefix_with(name)",
        "query = select(User).where(name.in_(ids))",
        "query = select(User)\n    if name:\n        query = name",
        "query = name\n    if name:\n        query = select(User)",
    ],
)
def test_sqlalchemy_lookalikes_and_raw_clauses_remain_reported(tmp_path, body):
    source = (
        "from sqlalchemy import select\n"
        "def lookup(session, ids, name):\n"
        f"    {body}\n"
        "    session.execute(query)\n"
    )
    assert _findings(tmp_path, source)


@pytest.mark.parametrize(
    "imports, digest",
    [
        ("import hashlib", "hashlib.sha256(value).hexdigest()"),
        ("from hashlib import sha256 as make_digest", "make_digest(value).hexdigest()"),
        ("import hashlib as h", "h.new('sha256', value).hexdigest()"),
        ("import secrets", "secrets.token_hex(32)"),
    ],
)
def test_generated_hex_values_cannot_inject_sql(tmp_path, imports, digest):
    source = (
        f"{imports}\n"
        "def lookup(cursor, value):\n"
        f"    digest = {digest}\n"
        "    cursor.execute(f\"SELECT * FROM cache WHERE digest = '{digest}'\")\n"
    )
    assert _findings(tmp_path, source) == []


@pytest.mark.parametrize(
    "prefix, expression",
    [
        ("", "value.hexdigest()"),
        (
            "import hashlib\nhashlib.sha256 = identity\n",
            "hashlib.sha256(value).hexdigest()",
        ),
        ("import hashlib\n", "hashlib.sha256(value).digest()"),
        ("import hashlib\n", "hashlib.new(value).hexdigest()"),
        ("import hashlib\n", "hashlib.sha256(value).hexdigest() + value"),
    ],
)
def test_hex_lookalikes_and_reintroduced_input_remain_reported(
    tmp_path, prefix, expression
):
    source = (
        prefix
        + "def lookup(cursor, value):\n"
        + f"    digest = {expression}\n"
        + "    cursor.execute(f\"SELECT * FROM cache WHERE digest = '{digest}'\")\n"
    )
    assert _findings(tmp_path, source)


def test_unresolved_helper_sql_remains_an_explicit_raw_review(tmp_path):
    rows = _findings(
        tmp_path, "def lookup(cursor, query):\n    cursor.execute(query)\n"
    )
    assert len(rows) == 1
    assert rows[0]["severity"] == "CRITICAL"
    assert rows[0]["metadata"]["source_status"] == "unresolved"
    assert rows[0]["metadata"]["audit_only"] is True
    assert "attacker control has not been established" in rows[0]["message"]


def test_actual_sql_input_keeps_its_attack_evidence(tmp_path):
    rows = _findings(tmp_path, "cursor.execute('SELECT ' + input())\n")
    assert len(rows) == 1
    assert rows[0]["metadata"]["source_status"] == "untrusted"
    assert rows[0]["metadata"]["security_evidence"]["source"]
    assert not rows[0]["metadata"].get("audit_only")
