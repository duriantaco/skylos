import pytest

from skylos.visitors.languages import postgresql

pytestmark = pytest.mark.skipif(
    postgresql.ast is None, reason="requires the postgres extra"
)


def findings(sql):
    rows, error = postgresql.scan_postgresql(sql, "reports.sql")
    assert error is None
    return [(row["rule_id"], row["line"]) for row in rows]


def test_only_subsequent_searched_case_arms_are_unreachable():
    sql = """-- café
SELECT CASE
    WHEN ready THEN 1
    WHEN (TRUE) THEN 2
    WHEN expired THEN 3
    WHEN cancelled THEN 4
    ELSE 5
END FROM orders;"""
    assert findings(sql) == [("SKY-Q509", 5), ("SKY-Q509", 6)]


def test_searched_case_repeated_column_null_test():
    sql = """SELECT CASE
      WHEN "State" IS NULL THEN 1
      WHEN "State" IS NOT NULL THEN 2
      WHEN state IS NULL THEN 3
      WHEN "State" ISNULL THEN 4
      ELSE 5 END FROM t"""
    assert findings(sql) == [("SKY-Q509", 5)]


def test_qualified_name_can_be_a_volatile_computed_field():
    sql = """CREATE TABLE readings (id integer);
CREATE FUNCTION sample_flag(readings) RETURNS integer VOLATILE
LANGUAGE SQL AS $$ SELECT CASE WHEN random() > 0.5 THEN 1 END $$;
SELECT CASE
  WHEN t.sample_flag IS NULL THEN 1
  WHEN t.sample_flag IS NULL THEN 2
  ELSE 3 END FROM readings AS t;"""
    assert findings(sql) == []


def test_repeated_null_test_with_lateral_projection():
    sql = """SELECT CASE
  WHEN sampled IS NULL THEN 1
  WHEN sampled IS NULL THEN 2
  END FROM orders,
  LATERAL (SELECT CASE WHEN random() > 0.5 THEN orders.id END AS sampled) s;"""
    assert findings(sql) == [("SKY-Q509", 3)]


@pytest.mark.parametrize(
    ("selector", "first", "other"),
    [
        ("i::integer", "-2", "3"),
        ("i::pg_catalog.int2", "7", "8"),
        ("CAST(i AS BIGINT)", "1", "2"),
        ("1", "42", "99"),
        ("flag::boolean", "true", "false"),
        ("false", "false", "true"),
    ],
)
def test_simple_case_duplicate_builtin_literals(selector, first, other):
    sql = f"""SELECT CASE {selector}
        WHEN {first} THEN 'a'
        WHEN {other} THEN 'b'
        WHEN {first} THEN 'c'
        END FROM t"""
    assert findings(sql) == [("SKY-Q509", 4)]


@pytest.mark.parametrize(
    "case",
    [
        "CASE flag WHEN true THEN 1 WHEN false THEN 2 END",
        "CASE i WHEN 1 THEN 1 WHEN 1 THEN 2 END",
        "CASE i::custom_id WHEN 1 THEN 1 WHEN 1 THEN 2 END",
        "CASE i::custom.int4 WHEN 1 THEN 1 WHEN 1 THEN 2 END",
        "CASE i::int4 WHEN 1 THEN 1 WHEN 1 THEN 2 END",
        "CASE i::integer[] WHEN 1 THEN 1 WHEN 1 THEN 2 END",
        "CASE i::integer WHEN 1::mytype THEN 1 WHEN 1::mytype THEN 2 END",
        "CASE i COLLATE \"C\" WHEN 'a' THEN 1 WHEN 'a' THEN 2 END",
        "CASE when f() IS NULL THEN 1 WHEN f() IS NULL THEN 2 END",
        "CASE WHEN x.a IS NULL THEN 1 WHEN y.a IS NULL THEN 2 END",
        "CASE WHEN true::myboolean THEN 1 WHEN foo THEN 2 END",
        "CASE WHEN ready THEN 1 WHEN ready THEN 2 END",
        "CASE WHEN ready THEN 1 WHEN false THEN 2 END",
        "CASE WHEN a IS NULL THEN CASE WHEN a IS NULL THEN 1 END ELSE 3 END",
    ],
)
def test_unresolved_or_different_case_comparisons_stay_quiet(case):
    assert findings(f"SELECT {case} FROM t") == []


@pytest.mark.parametrize(
    "expression",
    [
        "COUNT(CASE WHEN paid THEN 1 ELSE 0 END)",
        "pg_catalog.count(CASE status WHEN 'ready' THEN 1 WHEN 'paid' THEN 2 ELSE 0 END)",
        "count(CASE WHEN a THEN true ELSE false END) FILTER (WHERE included)",
        "count(CASE WHEN b THEN 'yes' ELSE 'no' END) OVER (PARTITION BY id)",
        "count(CASE WHEN b THEN 0.25 ELSE -1.50 END)",
    ],
)
def test_count_with_non_null_case_results(expression):
    assert findings(f"SELECT\n  {expression} FROM t") == [("SKY-Q510", 2)]


@pytest.mark.parametrize(
    "expression",
    [
        "count(CASE WHEN paid THEN 1 END)",
        "count(CASE WHEN paid THEN NULL ELSE 0 END)",
        "count(CASE WHEN a THEN 2 WHEN b THEN NULL ELSE 0 END)",
        "count(CASE WHEN paid THEN id ELSE 0 END)",
        "count(CASE WHEN paid THEN 1 ELSE 'unknown' END)",
        "count(CASE WHEN paid THEN 1::order_id ELSE 0::order_id END)",
        "count(DISTINCT CASE WHEN paid THEN 1 ELSE 0 END)",
        "count(CASE WHEN paid THEN 1 ELSE 0 END ORDER BY id)",
        "count(1) WITHIN GROUP (ORDER BY CASE WHEN paid THEN 1 ELSE 0 END)",
        "count(VARIADIC CASE WHEN paid THEN 1 ELSE 0 END)",
        "custom.count(CASE WHEN paid THEN 1 ELSE 0 END)",
        '"Count"(CASE WHEN paid THEN 1 ELSE 0 END)',
        "sum(CASE WHEN paid THEN 1 ELSE 0 END)",
        "count(*) FILTER (WHERE paid)",
    ],
)
def test_counts_with_other_semantics_stay_quiet(expression):
    assert findings(f"SELECT {expression} FROM t") == []


def test_nested_case_and_count_have_independent_locations():
    sql = """SELECT
  count(CASE WHEN (CASE
             WHEN c IS NULL THEN true
             WHEN c IS NULL THEN false
             ELSE enabled END)
       THEN 1 ELSE 0 END)
FROM t;"""
    assert findings(sql) == [("SKY-Q510", 2), ("SKY-Q509", 4)]
