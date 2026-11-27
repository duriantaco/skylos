import pytest

from skylos.visitors.languages.postgresql import scan_postgresql

pytest.importorskip("pglast")


@pytest.mark.parametrize(
    ("sql", "rule", "line"),
    [
        ("GRANT CREATE ON SCHEMA app\n TO PUBLIC;", "SKY-D418", 2),
        ("GRANT ALL ON SCHEMA app TO readers, PUBLIC;", "SKY-D418", 1),
        ("ALTER DEFAULT PRIVILEGES GRANT CREATE ON SCHEMAS TO PUBLIC;", "SKY-D418", 1),
        ("CREATE SCHEMA app GRANT CREATE ON SCHEMA app TO PUBLIC;", "SKY-D418", 1),
        ("CREATE USER job\n BYPASSRLS;", "SKY-D419", 2),
        ("CREATE ROLE job WITH LOGIN BYPASSRLS;", "SKY-D419", 1),
        ("ALTER USER job WITH BYPASSRLS LOGIN;", "SKY-D419", 1),
        ("GRANT UPDATE (title) ON app.books TO PUBLIC;", "SKY-D420", 1),
        ("GRANT ALL (title) ON app.books TO PUBLIC;", "SKY-D420", 1),
        ("GRANT ALL ON ALL TABLES IN SCHEMA app TO PUBLIC;", "SKY-D420", 1),
        (
            "ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT INSERT ON TABLES\n TO PUBLIC;",
            "SKY-D420",
            2,
        ),
    ],
)
def test_reports_the_explicit_privilege_once(sql, rule, line):
    rows, error = scan_postgresql(sql, "roles.sql")
    assert error is None
    assert [(row["rule_id"], row["line"]) for row in rows] == [(rule, line)]


@pytest.mark.parametrize(
    "sql",
    [
        "REVOKE CREATE ON SCHEMA app FROM PUBLIC",
        "GRANT USAGE ON SCHEMA app TO PUBLIC",
        "GRANT SELECT, REFERENCES ON app.books TO PUBLIC",
        "GRANT ALL ON SEQUENCE app.seq TO PUBLIC",
        'GRANT CREATE ON SCHEMA app TO "PUBLIC"',
        "GRANT UPDATE ON app.books TO readers",
        "GRANT INSERT ON app.books TO PUBLIC WITH GRANT OPTION",
        "ALTER DEFAULT PRIVILEGES REVOKE DELETE ON TABLES FROM PUBLIC",
        "CREATE ROLE job BYPASSRLS",
        "CREATE USER job NOLOGIN BYPASSRLS",
        "CREATE USER job NOBYPASSRLS",
        "ALTER ROLE job BYPASSRLS",
        "ALTER USER job LOGIN",
        "ALTER USER job WITH LOGIN NOLOGIN BYPASSRLS",
    ],
)
def test_other_roles_objects_and_unknown_settings_stay_quiet(sql):
    assert scan_postgresql(sql, "roles.sql") == ([], None)
