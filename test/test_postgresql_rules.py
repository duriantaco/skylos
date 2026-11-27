import pytest

from skylos.visitors.languages import postgresql

requires_parser = pytest.mark.skipif(
    postgresql.ast is None, reason="requires the postgres extra"
)


def check(source):
    findings, error = postgresql.scan_postgresql(source, "schema.sql")
    assert error is None
    assert all(row["file"] == "schema.sql" for row in findings)
    return [(row["rule_id"], row["line"]) for row in findings]


def test_missing_parser_is_reported(monkeypatch):
    monkeypatch.setattr(postgresql, "ast", None)
    findings, error = postgresql.scan_postgresql("SELECT 1", "example.sql")
    assert not findings
    assert "skylos[postgres]" in error


@requires_parser
@pytest.mark.parametrize("source", ["SELECT from", "SELECT 1;\x00 SELECT 2", "\udc80"])
def test_unparsed_input_has_no_optimistic_results(source):
    findings, error = postgresql.scan_postgresql(source, "example.sql")
    assert error
    assert findings == []


@requires_parser
def test_locations_follow_unicode_source():
    sql = """-- 門 ééé
WITH
  left_over AS (SELECT 1)
SELECT '🐍' FROM example
WHERE value
  <> NULL;
CREATE FUNCTION current_count() RETURNS integer
LANGUAGE SQL SECURITY DEFINER AS 'SELECT 1';"""
    assert check(sql) == [("SKY-Q503", 3), ("SKY-Q504", 6), ("SKY-D417", 8)]


@requires_parser
@pytest.mark.parametrize(
    ("sql", "unused"),
    [
        ("WITH x AS (SELECT 1) SELECT * FROM x", False),
        ("WITH x AS (SELECT 1) TABLE public.x", True),
        ("WITH x AS (SELECT 1) SELECT * FROM (WITH x AS (SELECT 2) TABLE x) q", True),
        ("WITH x AS (SELECT 1), y AS (TABLE x) TABLE y", False),
        ('WITH "Case" AS (SELECT 1) SELECT * FROM "Case"', False),
        ("WITH x AS (UPDATE data SET n=2 RETURNING n) SELECT 1", False),
        ("WITH x AS (SELECT thing() FROM data) SELECT 1", False),
        ("WITH x AS (SELECT * FROM data FOR UPDATE) SELECT 1", False),
        ("WITH x AS (SELECT 1) DELETE FROM x", True),
        (
            "WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<4) SELECT 1",
            True,
        ),
        (
            "WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<4) TABLE x",
            False,
        ),
    ],
)
def test_cte_read_and_scope(sql, unused):
    assert check(sql) == ([("SKY-Q503", 1)] if unused else [])


@requires_parser
def test_null_filters_and_assignments():
    sql = """UPDATE t SET a=NULL WHERE a IS NULL;
SELECT 1 FROM t JOIN s ON s.id = NULL
WHERE x>0 AND NOT (y<>NULL)
GROUP BY t.n HAVING t.n = NULL;
SELECT 1 FROM t WHERE EXISTS(SELECT z=NULL FROM u);
SELECT count(*) FILTER (WHERE deleted_at != NULL) FROM t;
SET transform_null_equals TO on;
SELECT 1 WHERE x = NULL;
SELECT 1 WHERE x <> NULL;
"""
    assert check(sql) == [("SKY-Q504", n) for n in (2, 3, 4, 6, 9)]


@requires_parser
def test_transaction_can_restore_nonstandard_null_equality():
    sql = """SET transform_null_equals TO on;
BEGIN;
SET LOCAL transform_null_equals TO off;
COMMIT;
SELECT 1 WHERE x = NULL;"""
    assert check(sql) == []


@requires_parser
@pytest.mark.parametrize(
    ("option", "flag"),
    [
        ("SECURITY DEFINER", True),
        ("SECURITY INVOKER", False),
        ("", False),
        ("SECURITY DEFINER SET search_path = pg_catalog, pg_temp", False),
        ("SECURITY DEFINER SET search_path = ''", False),
        ("SECURITY DEFINER SET search_path FROM CURRENT", False),
        ("SECURITY DEFINER SET work_mem = '4MB'", True),
    ],
)
def test_definer_scopes(option, flag):
    sql = f"CREATE FUNCTION f() RETURNS integer\n{option}\nLANGUAGE sql AS 'SELECT 1';"
    assert check(sql) == ([("SKY-D417", 2)] if flag else [])
