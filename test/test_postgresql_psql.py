import pytest

from skylos.visitors.languages import postgresql

pytestmark = pytest.mark.skipif(
    postgresql.ast is None, reason="requires the postgres extra"
)


def scan(sql):
    return postgresql.scan_postgresql(sql, "migration.sql")


def test_literal_connections_preserve_lines_and_start_new_sessions():
    sql = (
        "-- é\r\n"
        "SET transform_null_equals = on;\r\n"
        "SELECT * FROM t WHERE a = NULL; -- before reconnect\r\n"
        "  \\c chinook;\r\n"
        "\\connect next_db-2\r\n"
        "SELECT '🐟' FROM t WHERE a = NULL;\r\n"
        "\\c last_db"
    )
    findings, error = scan(sql)
    assert error is None
    assert [(x["rule_id"], x["line"]) for x in findings] == [("SKY-Q504", 6)]


def test_client_looking_text_in_multiline_sql_stays_in_its_session():
    sql = r"""\c one
SET transform_null_equals = on;
SELECT 'regular
\i filename
:foo', E'escaped\' quote
\c in_string', "quoted
\connect in_identifier", $body$
\c in_dollar_quote
:variable
$body$;
/* outer /* nested */
\c in_comment
*/
-- \i path
SELECT * FROM t WHERE a = NULL;
\connect two
SELECT * FROM t WHERE a = NULL;
"""
    findings, error = scan(sql)
    assert error is None
    assert [(x["rule_id"], x["line"]) for x in findings] == [("SKY-Q504", 17)]


@pytest.mark.parametrize(
    "command",
    [
        r"\i local.sql",
        r"\set db other",
        r"\!",
        r"\gexec",
        r"\c :db",
        r"\connect `database_name`",
        r"\c db user",
        r"\c db \i also.sql",
        r"\c db; SELECT 1",
        r"SELECT 1; \c db",
        "SELECT 1\n\\c db",
        "/* comment */ \\c db",
    ],
)
def test_unsupported_commands_invalidate_the_entire_file(command):
    findings, error = scan("SELECT * FROM t WHERE a = NULL;\n" + command)
    assert not findings
    assert "Unsupported psql command" in error
    assert "line" in error


@pytest.mark.parametrize("variable", [":db", ":'name'", ':"name"', ":{?var}"])
def test_psql_substitutions_are_explicit(variable):
    findings, error = scan(f"\\c db\nSELECT {variable};")
    assert not findings
    assert "psql variable substitution on line 2" in error


def test_postgres_casts_slices_and_json_survive_normal_sql():
    findings, error = scan("SELECT (ARRAY[1,2,3])[1:2]::int[], json_object('a':1);")
    assert not findings
    assert error is None


def test_unambiguous_postgres_slices_and_json_in_a_psql_script():
    findings, error = scan(
        "\\c db\nSELECT (ARRAY[1,2,3])[1: 2]::int[], "
        "json_object('a': 1, 'b':'a value with spaces');"
    )
    assert not findings
    assert error is None


@pytest.mark.parametrize("expr", ["(ARRAY[1,2,3])[1:2]", "json_object('k':v)"])
def test_psql_can_interpolate_a_numeric_slice_or_json_value(expr):
    findings, error = scan(f"\\c db\nSELECT {expr};")
    assert not findings
    assert "psql variable substitution on line 2" in error


def test_semicolon_inside_atomic_body_is_not_a_connection_boundary():
    sql = r"""CREATE FUNCTION f() RETURNS int LANGUAGE SQL BEGIN ATOMIC
SELECT 1;
\c db
END;
"""
    findings, error = scan(sql)
    assert not findings
    assert "parse error" in error


def test_later_session_syntax_error_points_to_original_line():
    findings, error = scan("SELECT 1;\n\\c db\nSELECT '🐠';\nBROKEN;")
    assert not findings
    assert "parse error on line 4" in error


@pytest.mark.parametrize(
    "sql",
    [
        "COPY t FROM STDIN;\n\\c inside_data\nSELECT 1;",
        "\\c before_copy\nCOPY t FROM STDIN;\nSELECT 1;",
        "COPY t FROM STDIN;\nSELECT 1 WHERE 42 NOT IN (1, NULL);\n",
    ],
)
def test_copy_input_is_never_treated_as_a_client_command_or_sql(sql):
    findings, error = scan(sql)
    assert not findings
    assert "COPY FROM STDIN" in error
