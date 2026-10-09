from pathlib import Path
from skylos.rules.danger.danger import scan_ctx


SQLALCHEMY_TEXT_RULE_IDS = {"SKY-D211", "SKY-D217"}


def _write(tmp_path: Path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return p


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def _scan_one(tmp_path: Path, name, code):
    file_path = _write(tmp_path, name, code)
    return scan_ctx(tmp_path, [file_path])


def test_sqlalchemy_text_tainted_flags(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip):\n"
        "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
    )
    out = _scan_one(tmp_path, "raw_sa.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_sqlalchemy_text_import_aliases_remain_sql_sinks(tmp_path):
    cases = {
        "direct": (
            "from sqlalchemy import text as draw_text\n"
            "def direct(ip):\n"
            "    draw_text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "qualified": (
            "import sqlalchemy as plt\n"
            "def qualified(ip):\n"
            "    plt.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
    }
    for symbol, code in cases.items():
        out = _scan_one(tmp_path, f"raw_sa_{symbol}.py", code)
        ids = {finding["rule_id"] for finding in out}
        assert SQLALCHEMY_TEXT_RULE_IDS <= ids


def test_sqlalchemy_text_requires_unshadowed_absolute_import(tmp_path):
    safe_cases = {
        "unbound_global": (
            "def f(ip):\n    sqlalchemy.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "bare_parameter": (
            "def f(sqlalchemy, ip):\n"
            "    sqlalchemy.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "relative_import": (
            "from .sqlalchemy import text as draw_text\n"
            "def f(ip):\n"
            "    draw_text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "shadowed_alias": (
            "import sqlalchemy as sa\n"
            "def f(sa, ip):\n"
            "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "assigned_local": (
            "import sqlalchemy as sa\n"
            "def f(plot, ip):\n"
            "    sa = plot\n"
            "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "unrelated_module_alias": (
            "import matplotlib.pyplot as sqlalchemy\n"
            "def f(ip):\n"
            "    sqlalchemy.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "unrelated_text_import": (
            "from matplotlib.pyplot import text\n"
            "def f(ip):\n"
            "    text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
        "reassigned_alias": (
            "import sqlalchemy as sa\n"
            "sa = object()\n"
            "def f(ip):\n"
            "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
        ),
    }
    for name, code in safe_cases.items():
        out = _scan_one(tmp_path, f"safe_sa_{name}.py", code)
        assert not (SQLALCHEMY_TEXT_RULE_IDS & _rule_ids(out))


def test_sqlalchemy_text_module_import_is_visible_before_ast_visit(tmp_path):
    code = (
        "def f(ip):\n"
        "    sa.text('DELETE FROM logs WHERE ip=' + ip)\n"
        "import sqlalchemy as sa\n"
    )
    out = _scan_one(tmp_path, "late_module_sa_import.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_sqlalchemy_text_local_absolute_import_before_call_flags(tmp_path):
    code = (
        "def f(ip):\n"
        "    from sqlalchemy import text\n"
        "    text('DELETE FROM logs WHERE ip=' + ip)\n"
    )
    out = _scan_one(tmp_path, "local_sa_import.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_comprehension_target_does_not_shadow_enclosing_sqlalchemy_alias(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip, rows):\n"
        "    [x for sa in rows for x in (sa,)]\n"
        "    sa.text('SELECT ' + ip)\n"
    )
    out = _scan_one(tmp_path, "sa_after_comprehension.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_comprehension_target_shadows_sqlalchemy_alias_inside_scope(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip, rows):\n"
        "    return [sa.text('SELECT ' + ip) for sa in rows]\n"
    )
    out = _scan_one(tmp_path, "sa_inside_comprehension.py", code)
    assert not (SQLALCHEMY_TEXT_RULE_IDS & _rule_ids(out))


def test_final_unconditional_module_import_provides_sqlalchemy_provenance(tmp_path):
    vulnerable_cases = {
        "after_assignment": (
            "sa = None\n"
            "import sqlalchemy as sa\n"
            "def f(ip):\n"
            "    sa.text('SELECT ' + ip)\n"
        ),
        "after_unrelated_import": (
            "import matplotlib.pyplot as sa\n"
            "import sqlalchemy as sa\n"
            "def f(ip):\n"
            "    sa.text('SELECT ' + ip)\n"
        ),
    }
    for name, code in vulnerable_cases.items():
        out = _scan_one(tmp_path, f"sa_final_import_{name}.py", code)
        assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_final_unrelated_module_binding_removes_sqlalchemy_provenance(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "import matplotlib.pyplot as sa\n"
        "def f(ip):\n"
        "    sa.text('SELECT ' + ip)\n"
    )
    out = _scan_one(tmp_path, "sa_final_unrelated_import.py", code)
    assert not (SQLALCHEMY_TEXT_RULE_IDS & _rule_ids(out))


def test_lambda_parameter_shadows_sqlalchemy_alias(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip):\n"
        "    return lambda sa: sa.text('SELECT ' + ip)\n"
    )
    out = _scan_one(tmp_path, "sa_shadowed_in_lambda.py", code)
    assert not (SQLALCHEMY_TEXT_RULE_IDS & _rule_ids(out))


def test_lambda_with_unshadowed_sqlalchemy_alias_flags(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def f(ip):\n"
        "    return lambda plot: sa.text('SELECT ' + ip)\n"
    )
    out = _scan_one(tmp_path, "sa_used_in_lambda.py", code)
    assert SQLALCHEMY_TEXT_RULE_IDS <= _rule_ids(out)


def test_non_sqlalchemy_text_receiver_is_not_a_sql_sink(tmp_path):
    code = (
        "import matplotlib.pyplot as plt\n"
        "import pandas as pd\n"
        "def render(df: pd.DataFrame, read_col: str, labels: list[str]) -> None:\n"
        "    fig, ax = plt.subplots()\n"
        "    for i, (_, row) in enumerate(df.iterrows()):\n"
        "        value = row[read_col]\n"
        "        if value:\n"
        "            ax.text(i - 0.17, value / 2, labels[i], ha='center')\n"
    )
    out = _scan_one(tmp_path, "matplotlib_text.py", code)
    assert not ({"SKY-D211", "SKY-D217"} & _rule_ids(out))


def test_non_sqlalchemy_text_receiver_stays_safe_when_sqlalchemy_is_imported(tmp_path):
    code = (
        "import sqlalchemy as sa\n"
        "def render(ax, value, label):\n"
        "    ax.text(0, value / 2, label)\n"
    )
    out = _scan_one(tmp_path, "mixed_text_receivers.py", code)
    assert not ({"SKY-D211", "SKY-D217"} & _rule_ids(out))


def test_pandas_read_sql_tainted_flags(tmp_path):
    code = (
        "import pandas as pd\n"
        "def f(conn, name):\n"
        "    pd.read_sql(f\"SELECT * FROM users WHERE name='{name}'\", conn)\n"
    )
    out = _scan_one(tmp_path, "raw_pd.py", code)
    assert "SKY-D217" in _rule_ids(out)


def test_django_objects_raw_tainted_flags(tmp_path):
    code = (
        "class _O:\n"
        "    def raw(self, *a, **k):\n"
        "        return []\n"
        "class User:\n"
        "    objects = _O()\n"
        "def f(u):\n"
        "    User.objects.raw('SELECT * FROM auth_user WHERE username=' + u)\n"
    )
    out = _scan_one(tmp_path, "raw_dj.py", code)
    assert "SKY-D217" in _rule_ids(out)


def test_raw_constant_ok(tmp_path):
    code = "import pandas as pd\ndef f(conn):\n    pd.read_sql('SELECT 1 AS x', conn)\n"
    out = _scan_one(tmp_path, "raw_ok.py", code)
    assert "SKY-D217" not in _rule_ids(out)


# SQLAlchemy Core / ORM statement builders bind every value as a parameter.
# Table-method suppressions need a locally proven constructor; a method name
# or an import from an application module does not establish the receiver type.
TABLE_PROOF = (
    "from sqlalchemy import Table, Column, Integer, String, MetaData\n"
    "notes = Table('notes', MetaData(), Column('id', Integer), Column('title', String))\n"
)
SQL_BUILDER_SAFE = {
    "table_insert_values": (
        TABLE_PROOF + "async def post(payload):\n"
        "    query = notes.insert().values(title=payload.title, description=payload.description)\n"
        "    return await database.execute(query=query)\n"
    ),
    "table_delete_where": (
        TABLE_PROOF + "async def delete(id: int):\n"
        "    query = notes.delete().where(id == notes.c.id)\n"
        "    return await database.execute(query=query)\n"
    ),
    "table_update_chain": (
        TABLE_PROOF + "async def put(id: int, payload):\n"
        "    query = (\n"
        "        notes\n"
        "        .update()\n"
        "        .where(id == notes.c.id)\n"
        "        .values(title=payload.title, description=payload.description)\n"
        "        .returning(notes.c.id)\n"
        "    )\n"
        "    return await database.execute(query=query)\n"
    ),
    "table_select_inline": (
        TABLE_PROOF + "def find(conn, name):\n"
        "    return conn.execute(notes.select().where(notes.c.title == name))\n"
    ),
    "table_constructor_alias": (
        "import sqlalchemy as sa\n"
        "notes = sa.Table('notes', sa.MetaData(), sa.Column('title', sa.String))\n"
        "def post(conn, title):\n"
        "    conn.execute(notes.insert().values(title=title))\n"
    ),
    "table_bound_formatted_value": (
        TABLE_PROOF + "def post(conn, title):\n"
        "    conn.execute(notes.insert().values(title=f'label: {title}'))\n"
    ),
    "imported_insert_variable": (
        "from sqlalchemy import insert\n"
        "def add(session, data):\n"
        "    stmt = insert(User).values(**data)\n"
        "    session.execute(stmt)\n"
    ),
    "statement_extended_later": (
        "from sqlalchemy import select\n"
        "def find(session, name):\n"
        "    stmt = select(User)\n"
        "    stmt = stmt.where(User.name == name)\n"
        "    session.execute(stmt)\n"
    ),
    "limit_offset_params": (
        "from sqlalchemy import select\n"
        "def page(session, skip: int, limit: int):\n"
        "    return session.execute(select(User).offset(skip).limit(limit))\n"
    ),
    "text_bindparams": (
        "from sqlalchemy import text\n"
        "def find(session, uid):\n"
        "    q = text('SELECT * FROM t WHERE id = :id').bindparams(id=uid)\n"
        "    session.execute(q)\n"
    ),
    "text_bindparams_inline": (
        "from sqlalchemy import text\n"
        "def find(session, uid):\n"
        "    session.execute(text('SELECT * FROM t WHERE id = :id').bindparams(id=uid))\n"
    ),
    "text_with_params": (
        "from sqlalchemy import text\n"
        "def find(session, uid):\n"
        "    session.execute(text('SELECT * FROM t WHERE id = :id'), {'id': uid})\n"
    ),
}


def test_sql_statement_builders_are_not_sql_injection(tmp_path):
    for name, code in SQL_BUILDER_SAFE.items():
        out = _scan_one(tmp_path, f"{name}.py", code)
        hits = [f for f in out if f["rule_id"] in SQLALCHEMY_TEXT_RULE_IDS]
        assert hits == [], name


SQL_STRING_BUILT = {
    "fstring_variable": (
        "def find(cur, name):\n"
        "    q = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
        "    cur.execute(q)\n"
    ),
    "concatenation": (
        "def find(cur, name):\n"
        '    cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
    ),
    "percent_format": (
        "def find(cur, name):\n"
        "    cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"
    ),
    "str_format": (
        "def find(cur, name):\n"
        "    cur.execute(\"SELECT * FROM users WHERE name = '{}'\".format(name))\n"
    ),
    "text_fstring": (
        "from sqlalchemy import text\n"
        "def find(session, name):\n"
        "    session.execute(text(f\"SELECT * FROM users WHERE name = '{name}'\"))\n"
    ),
    "table_where_fstring": (
        "def find(conn, users, name):\n"
        "    conn.execute(users.select().where(f\"name = '{name}'\"))\n"
    ),
    "imported_select_where_fstring": (
        "from sqlalchemy import select\n"
        "def find(session, name):\n"
        "    session.execute(select(User).where(f\"name = '{name}'\"))\n"
    ),
    "table_order_by_request_value": (
        "from flask import request\n"
        "def listing(conn, users):\n"
        "    conn.execute(users.select().order_by(request.args['sort']))\n"
    ),
    "builder_replaced_by_string": (
        "def find(conn, users, name):\n"
        "    q = users.select()\n"
        '    q = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
        "    conn.execute(q)\n"
    ),
    "helper_select_without_builder_evidence": (
        "def find(cur, dao):\n    cur.execute(dao.select())\n"
    ),
    "helper_with_unrelated_sqlalchemy_import": (
        "from sqlalchemy import text\n"
        "def find(conn, builder, name):\n"
        "    conn.execute(builder.select(name))\n"
    ),
    "helper_with_builder_shaped_chain": (
        "def find(conn, builder, clause):\n"
        "    conn.execute(builder.select().where(clause))\n"
    ),
    "unresolved_imported_table": (
        "from app.db import notes\n"
        "def post(conn, title):\n"
        "    conn.execute(notes.insert().values(title=title))\n"
    ),
    "mapped_parameter_has_no_table_proof": (
        "def find(conn, User, name):\n"
        "    conn.execute(User.__table__.select().where(User.name == name))\n"
    ),
    "table_constructor_parameter_shadow": (
        "from sqlalchemy import Table\n"
        "def find(conn, Table, name):\n"
        "    notes = Table(name)\n"
        "    conn.execute(notes.select().where(name))\n"
    ),
    "table_constructor_local_rebinding": (
        "from sqlalchemy import Table as MakeTable\n"
        "def find(conn, factory, name):\n"
        "    MakeTable = factory\n"
        "    notes = MakeTable(name)\n"
        "    conn.execute(notes.insert().values(title=name))\n"
    ),
    "select_constructor_parameter_shadow": (
        "from sqlalchemy import select\n"
        "def find(conn, select, name):\n"
        "    stmt = select(name)\n"
        "    conn.execute(stmt)\n"
    ),
    "update_constructor_local_rebinding": (
        "from sqlalchemy import update as build_update\n"
        "def find(conn, helper, name):\n"
        "    build_update = helper\n"
        "    stmt = build_update(name)\n"
        "    conn.execute(stmt)\n"
    ),
    "request_alias_clause": (
        "from sqlalchemy import select\n"
        "from flask import request\n"
        "def find(conn):\n"
        "    clause = request.args['sort']\n"
        "    stmt = select(User).order_by(clause)\n"
        "    conn.execute(stmt)\n"
    ),
    "request_keyword_clause": (
        "from sqlalchemy import select\n"
        "from flask import request\n"
        "def find(conn):\n"
        "    stmt = select(User).with_statement_hint(text=request.args['hint'])\n"
        "    conn.execute(stmt)\n"
    ),
    "statement_unknown_extension": (
        "from sqlalchemy import select\n"
        "def find(conn, prefix):\n"
        "    stmt = select(User)\n"
        "    stmt = stmt.prefix_with(prefix)\n"
        "    conn.execute(stmt)\n"
    ),
    "statement_loop_binding": (
        "from sqlalchemy import select\n"
        "def find(conn, clauses):\n"
        "    stmt = select(User)\n"
        "    for stmt in clauses:\n"
        "        conn.execute(stmt)\n"
    ),
    "table_rebound_after_function_definition": (
        TABLE_PROOF + "def find(conn, name):\n"
        "    conn.execute(notes.select().where(notes.c.title == name))\n"
        "notes = request.args['builder']\n"
    ),
    "conditional_statement_assignment": (
        "from sqlalchemy import select\n"
        "def find(conn, clause, condition):\n"
        "    stmt = clause\n"
        "    if condition:\n"
        "        stmt = clause\n"
        "    else:\n"
        "        stmt = select(User)\n"
        "    conn.execute(stmt)\n"
    ),
    "table_method_rebound": (
        "from sqlalchemy import Table\n"
        "def find(conn, helper, title):\n"
        "    notes = Table('notes', metadata)\n"
        "    notes.insert = helper\n"
        "    conn.execute(notes.insert().values(title=title))\n"
    ),
    "statement_method_rebound": (
        "from sqlalchemy import select\n"
        "def find(conn, helper, title):\n"
        "    stmt = select(User)\n"
        "    stmt.values = helper\n"
        "    conn.execute(stmt.values(title=title))\n"
    ),
    "statement_exception_handler": (
        "from sqlalchemy import select\n"
        "def find(conn, raw):\n"
        "    stmt = raw\n"
        "    try:\n"
        "        stmt = select(User)\n"
        "    except Exception:\n"
        "        conn.execute(stmt)\n"
    ),
    "loop_can_execute_zero_times": (
        "from sqlalchemy import select\n"
        "def find(conn, raw, rows):\n"
        "    stmt = raw\n"
        "    for row in rows:\n"
        "        stmt = select(User)\n"
        "    else:\n"
        "        conn.execute(stmt)\n"
    ),
    "parameter_shadows_module_statement": (
        "from app.db import notes\n"
        "query = notes.delete().where(notes.c.id == 1)\n"
        "def run(cur, query):\n"
        "    cur.execute(query)\n"
    ),
}


def test_string_built_sql_still_flags(tmp_path):
    for name, code in SQL_STRING_BUILT.items():
        out = _scan_one(tmp_path, f"{name}.py", code)
        assert "SKY-D211" in _rule_ids(out), name


def test_text_inside_execute_is_reported_once_per_line(tmp_path):
    # kennethreitz/records: the caller's SQL reaches text() inside execute().
    code = (
        "from sqlalchemy import text\n"
        "class Connection:\n"
        "    def query(self, query, **params):\n"
        "        return self._conn.execute(text(query).bindparams(**params))\n"
        "    def bulk_query(self, query, *multiparams):\n"
        "        self._conn.execute(text(query), *multiparams)\n"
    )
    out = _scan_one(tmp_path, "records_like.py", code)
    d211 = sorted(f["line"] for f in out if f["rule_id"] == "SKY-D211")
    assert d211 == [4, 6]


def test_text_variable_is_reported_at_text_call_only(tmp_path):
    code = (
        "from sqlalchemy import text\n"
        "def find(session, name):\n"
        '    q = text("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
        "    session.execute(q)\n"
    )
    out = _scan_one(tmp_path, "text_variable.py", code)
    assert sorted(f["line"] for f in out if f["rule_id"] == "SKY-D211") == [3]
