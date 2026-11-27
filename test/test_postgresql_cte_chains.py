import pytest

from skylos.visitors.languages.postgresql import scan_postgresql

pytest.importorskip("pglast")


@pytest.mark.parametrize(
    ("query", "unused"),
    [
        (
            "WITH a AS (SELECT 1), b AS (TABLE a), c AS (TABLE b) SELECT 0",
            ["a", "b", "c"],
        ),
        ("WITH a AS (SELECT 1), b AS (TABLE a), c AS (TABLE b) TABLE c", []),
        ("WITH a AS (SELECT 1), b AS (TABLE a), c AS (TABLE b) TABLE a", ["b", "c"]),
        ("WITH a AS (SELECT 1), b AS (SELECT count(*) FROM a) SELECT 0", []),
        ("WITH a AS (SELECT 1), w AS (INSERT INTO t SELECT * FROM a) SELECT 0", []),
        ("WITH a AS (SELECT 1), b AS (WITH a AS (SELECT 2) TABLE a) TABLE b", ["a"]),
    ],
)
def test_orphaned_chains_and_effectful_roots(query, unused):
    rows, error = scan_postgresql(query, "chain.sql")
    assert error is None
    assert [row["message"].split("'")[1] for row in rows] == unused


@pytest.mark.parametrize(
    ("clause", "unused"),
    [
        ("SELECT * FROM jobs AS batch FOR UPDATE OF batch", ["batch"]),
        ("SELECT * FROM jobs AS batch FOR KEY SHARE OF batch", ["batch"]),
        ("SELECT * FROM batch AS b JOIN jobs j ON true FOR UPDATE OF j", []),
        ("SELECT id INTO TEMP batch FROM jobs", ["batch"]),
        ("SELECT id INTO TEMP staged FROM batch", []),
    ],
)
def test_lock_names_and_select_destinations_are_not_cte_inputs(clause, unused):
    rows, error = scan_postgresql(
        "WITH batch AS (SELECT id FROM pending_jobs) " + clause, "queue.sql"
    )
    assert error is None
    assert [row["message"].split("'")[1] for row in rows] == unused


def test_cte_containing_a_lock_keeps_its_real_dependencies():
    query = """WITH source_rows AS (SELECT id FROM pending_jobs),
  alias_only AS (SELECT 1),
  locked AS (
    SELECT j.id FROM jobs AS alias_only
    JOIN source_rows AS j ON j.id = alias_only.id
    FOR UPDATE OF alias_only
  )
SELECT 1;"""
    rows, error = scan_postgresql(query, "locks.sql")
    assert error is None
    assert [(r["rule_id"], r["line"]) for r in rows] == [("SKY-Q503", 2)]
