import pytest

from skylos.visitors.languages import postgresql

pytestmark = pytest.mark.skipif(
    postgresql.ast is None, reason="requires the postgres extra"
)


def reported_lines(sql):
    findings, error = postgresql.scan_postgresql(sql, "routines.sql")
    assert error is None
    return [row["line"] for row in findings if row["rule_id"] == "SKY-D417"]


@pytest.mark.parametrize(
    ("declaration", "options", "reported"),
    [
        ("CREATE PROCEDURE p()", "SECURITY DEFINER", True),
        ("CREATE OR REPLACE PROCEDURE p()", "EXTERNAL SECURITY DEFINER", True),
        ("CREATE PROCEDURE p()", "SECURITY DEFINER SET work_mem TO '4MB'", True),
        ("CREATE PROCEDURE p()", "SECURITY DEFINER SET search_path = ''", False),
        (
            "CREATE PROCEDURE p()",
            "SET search_path FROM CURRENT SECURITY DEFINER",
            False,
        ),
        ("CREATE PROCEDURE p()", "SET SCHEMA 'pg_catalog' SECURITY DEFINER", False),
        ("CREATE PROCEDURE p()", 'SECURITY DEFINER SET "SEARCH_PATH" = app', False),
        ("CREATE PROCEDURE p()", "SECURITY INVOKER", False),
        ("CREATE PROCEDURE p()", "", False),
    ],
)
def test_procedure_declaration(declaration, options, reported):
    sql = f"{declaration}\n{options}\nLANGUAGE SQL AS 'SELECT 1';"
    assert reported_lines(sql) == ([2] if reported else [])


@pytest.mark.parametrize("object_type", ["FUNCTION", "PROCEDURE", "ROUTINE"])
def test_alter_reports_the_security_clause_when_path_is_cleared(object_type):
    sql = f"ALTER {object_type} app.refresh(integer)\nRESET search_path\nSECURITY DEFINER;"
    assert reported_lines(sql) == [3]


@pytest.mark.parametrize(
    ("settings", "reported"),
    [
        ("RESET ALL", True),
        ("SET search_path TO DEFAULT", True),
        ("SET search_path FROM CURRENT RESET search_path", True),
        ("SET search_path TO app RESET ALL SET work_mem TO '4MB'", True),
        ("RESET ALL SET search_path FROM CURRENT", False),
        ("RESET search_path SET search_path TO app", False),
        ("RESET work_mem", False),
        ("SET work_mem TO '4MB'", False),
        ("", False),
    ],
)
def test_alter_uses_the_last_path_change(settings, reported):
    sql = f"ALTER ROUTINE app.refresh(integer)\nSECURITY DEFINER {settings};"
    assert reported_lines(sql) == ([2] if reported else [])


def test_settings_do_not_transfer_across_statements_or_overloads():
    sql = """CREATE FUNCTION app.f(integer) RETURNS int
      SECURITY DEFINER SET search_path TO pg_catalog LANGUAGE SQL AS 'SELECT 1';
    ALTER FUNCTION app.f(text) RESET ALL;
    ALTER FUNCTION other.f(integer) SECURITY DEFINER;
    ALTER FUNCTION app.f(integer) SECURITY DEFINER;
    ALTER ROUTINE app.f(integer) SECURITY INVOKER RESET ALL;
    """
    assert reported_lines(sql) == []


def test_conflicting_security_options_cannot_change_a_routine():
    assert (
        reported_lines("ALTER ROUTINE f() SECURITY DEFINER SECURITY INVOKER RESET ALL")
        == []
    )
