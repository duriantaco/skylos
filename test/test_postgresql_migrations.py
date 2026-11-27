import pytest

pglast = pytest.importorskip("pglast")

from skylos.visitors.languages.postgresql_migrations import scan_migrations


def findings(sql):
    rows = []

    def report(position, rule, severity, message):
        assert severity == "MEDIUM"
        assert 0 <= position < len(sql)
        assert message
        rows.append((rule, 1 + sql.count("\n", 0, position)))

    scan_migrations(pglast.parse_sql(sql), report)
    return rows


@pytest.mark.parametrize("begin", ["BEGIN", "START TRANSACTION", "BEGIN WORK"])
def test_concurrent_index_commands_inside_an_explicit_block(begin):
    sql = f"""{begin};
    -- migration 🦋
    CREATE UNIQUE INDEX CONCURRENTLY
      app_idx ON app.orders(id);
    SAVEPOINT s;
    ROLLBACK TO SAVEPOINT s;
    RELEASE SAVEPOINT s;
    DROP INDEX CONCURRENTLY
      app.app_idx;
    COMMIT;
    CREATE INDEX CONCURRENTLY outside_idx ON t(id);
    """
    assert findings(sql) == [("SKY-Q506", 3), ("SKY-Q506", 8)]


@pytest.mark.parametrize("end", ["COMMIT", "END", "ROLLBACK", "ABORT"])
def test_chain_and_no_chain_keep_the_transaction_boundaries(end):
    sql = f"""BEGIN;
    {end} AND CHAIN;
    CREATE INDEX CONCURRENTLY i ON t(n);
    {end} AND NO CHAIN;
    DROP INDEX CONCURRENTLY i;
    """
    assert findings(sql) == [("SKY-Q506", 3)]


def test_no_session_or_prepared_transaction_leaks():
    assert (
        findings("BEGIN;\nPREPARE TRANSACTION 'batch';\nDROP INDEX CONCURRENTLY i;")
        == []
    )
    assert findings("COMMIT PREPARED 'batch';\nDROP INDEX CONCURRENTLY i;") == []
    assert findings("COMMIT AND CHAIN;\nCREATE INDEX CONCURRENTLY i ON t(n);") == []
    assert findings("BEGIN;") == []
    assert findings("CREATE INDEX CONCURRENTLY i ON t(n);") == []


@pytest.mark.parametrize(
    "command",
    [
        "DROP INDEX CONCURRENTLY a, b",
        "DROP INDEX CONCURRENTLY IF EXISTS first.idx, second.idx",
        "DROP INDEX CONCURRENTLY a CASCADE",
        "DROP INDEX CONCURRENTLY a, b CASCADE",
    ],
)
def test_invalid_concurrent_drop_emits_one_finding(command):
    assert findings("SELECT 1;\n/* 猫 */\n" + command) == [("SKY-Q507", 3)]


@pytest.mark.parametrize(
    "sql",
    [
        "DROP INDEX CONCURRENTLY IF EXISTS app.idx RESTRICT",
        'DROP INDEX CONCURRENTLY "one,index"',
        "DROP INDEX a,b CASCADE",
        "BEGIN; CREATE INDEX i ON t(c); DROP INDEX i CASCADE; COMMIT;",
        "SELECT 'DROP INDEX CONCURRENTLY a, b';",
        "DO $$ BEGIN EXECUTE 'DROP INDEX CONCURRENTLY a,b'; END $$;",
    ],
)
def test_regular_ddl_and_sql_text_stay_quiet(sql):
    assert findings(sql) == []


@pytest.mark.parametrize(
    ("sql", "line"),
    [
        ("CREATE TABLE t (\n x int REFERENCES a (x,y)\n)", 2),
        ("CREATE TABLE t (a int, b int,\n FOREIGN KEY(a,b) REFERENCES p(id))", 2),
        (
            "CREATE TABLE t (a int, b int,\n CONSTRAINT named FOREIGN KEY(a,b) REFERENCES p(id))",
            2,
        ),
        (
            "ALTER TABLE t\n ADD CONSTRAINT fk FOREIGN KEY(a,b) REFERENCES p(id) NOT VALID",
            2,
        ),
        ("ALTER TABLE ONLY t\n ADD COLUMN x int\n REFERENCES p(a,b)", 3),
        ("CREATE SCHEMA app\n CREATE TABLE t (a int\n REFERENCES p(a,b))", 3),
    ],
)
def test_mismatched_foreign_key_column_counts(sql, line):
    assert findings(sql) == [("SKY-Q508", line)]


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE TABLE t (a int REFERENCES p(id))",
        "CREATE TABLE t (a int REFERENCES p)",
        "CREATE TABLE t (a int,b int,FOREIGN KEY(a,b) REFERENCES p(id1,id2))",
        "CREATE TABLE t (a int,b int,FOREIGN KEY(a,b) REFERENCES p)",
        "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY(a) REFERENCES p(id) NOT VALID",
        "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY(a, PERIOD r) REFERENCES p(id, PERIOD r)",
        "CREATE TABLE t (a int UNIQUE, b int, PRIMARY KEY(a,b))",
        "CREATE TABLE t (a int CHECK (a > 0))",
        "CREATE VIEW v AS SELECT 'FOREIGN KEY(a,b) REFERENCES p(id)'",
    ],
)
def test_valid_or_catalog_dependent_constraints_stay_quiet(sql):
    assert findings(sql) == []


def test_multiple_column_and_table_constraints_at_their_original_lines():
    sql = """ALTER TABLE t
    ADD COLUMN k int REFERENCES p (a,b),
    ADD CONSTRAINT valid FOREIGN KEY (a,b) REFERENCES p (a,b),
    ADD CONSTRAINT wrong FOREIGN KEY (a) REFERENCES p (a,b);"""
    assert findings(sql) == [("SKY-Q508", 2), ("SKY-Q508", 4)]
