import pytest

from skylos.visitors.languages import postgresql

pytestmark = pytest.mark.skipif(
    postgresql.ast is None, reason="requires the postgres extra"
)


@pytest.mark.parametrize(
    "query",
    [
        "SELECT * FROM t WHERE active AND t.id NOT IN (0, NULL)",
        "SELECT * FROM t JOIN u ON t.id NOT IN (NULL)",
        "SELECT id FROM t GROUP BY id HAVING id NOT IN (-1, NULL, 1)",
        "SELECT count(*) FILTER (WHERE id NOT IN (NULL, 1)) FROM t",
        "DELETE FROM t WHERE 7 NOT IN (2, NULL)",
        "UPDATE t SET id = 7 WHERE id NOT IN (NULL)",
        "MERGE INTO t USING u ON u.id NOT IN (NULL) WHEN MATCHED THEN DO NOTHING",
        "MERGE INTO t USING u ON true WHEN MATCHED AND u.id NOT IN (NULL) THEN DO NOTHING",
        "SELECT 1 WHERE EXISTS (SELECT 1 FROM t WHERE id NOT IN (0, NULL))",
    ],
)
def test_required_filter_with_a_literal_null(query):
    rows, error = postgresql.scan_postgresql(query, "example.sql")
    assert error is None
    assert [(row["rule_id"], row["line"]) for row in rows] == [("SKY-Q505", 1)]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id NOT IN (1, NULL) FROM t",
        "SELECT * FROM t WHERE id IN (1, NULL)",
        "SELECT * FROM t WHERE id NOT IN (1, 2)",
        "SELECT * FROM t WHERE id NOT IN ('NULL', 'ok')",
        "SELECT * FROM t WHERE id NOT IN (NULL, other_id)",
        "SELECT * FROM t WHERE id NOT IN (SELECT value FROM omitted)",
        "SELECT * FROM t WHERE id NOT IN (VALUES (NULL), (1))",
        "SELECT * FROM t WHERE id NOT IN (1, NULL) OR active",
        "SELECT * FROM t WHERE NOT (id NOT IN (1, NULL))",
        "SELECT * FROM t WHERE (id NOT IN (1, NULL)) IS UNKNOWN",
        "SELECT * FROM t WHERE id::custom_id NOT IN (NULL)",
        "SELECT * FROM t WHERE id NOT IN (1::custom_id, NULL)",
        "SELECT * FROM t WHERE (id, name) NOT IN ((1, NULL))",
        "SELECT * FROM t WHERE f(id) NOT IN (1, NULL)",
        "SELECT * FROM t WHERE NULL NOT IN (1, NULL)",
        "ALTER TABLE t ADD CHECK (id NOT IN (1, NULL))",
    ],
)
def test_null_lists_with_different_or_unknown_semantics_stay_quiet(sql):
    assert postgresql.scan_postgresql(sql, "example.sql") == ([], None)


def test_distinct_filter_rules_keep_their_operator_lines():
    sql = """-- 門
SELECT 1 FROM t
WHERE x
   NOT IN (NULL, 10)
 AND y
   <> NULL;
"""
    rows, error = postgresql.scan_postgresql(sql, "example.sql")
    assert error is None
    assert [(row["rule_id"], row["line"]) for row in rows] == [
        ("SKY-Q505", 4),
        ("SKY-Q504", 6),
    ]
