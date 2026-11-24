"""Literal SQL Server and PostgreSQL credentials keep one record boundary."""

import json

import pytest

from skylos.rules.secrets import scan_ctx


PASSWORD = "rQ8" + "xK4!w2"


def _scan(path, line):
    return scan_ctx({"relpath": path, "lines": line.splitlines(keepends=True)})


@pytest.mark.parametrize(
    "path,record,expected,kind",
    [
        (
            "src/Config.java",
            f'"jdbc:sqlserver://db.internal:1433;databaseName=main;user=svc;password={PASSWORD};"',
            PASSWORD,
            "SQL Server JDBC",
        ),
        (
            "notes.md",
            "`jdbc:sqlserver://;serverName=db.internal;username=svc;password={rQ8;xK}} z};`",
            "rQ8;xK}} z",
            "SQL Server JDBC",
        ),
        (
            "incident.csv",
            f'"UID=svc;Server=tcp:db.internal,1433;PWD={PASSWORD};Driver={{ODBC Driver 18 for SQL Server}};"',
            PASSWORD,
            "SQL Server ODBC",
        ),
        (
            "incident.log",
            "`Driver={SQL Server Native Client 11.0};Server=db.internal;UID=svc;PWD={rQ8; xK4!};`",
            "rQ8; xK4!",
            "SQL Server ODBC",
        ),
        (
            "config.yaml",
            f'conn: "user = svc dbname = main hostaddr = 192.0.2.3 password = {PASSWORD}"',
            PASSWORD,
            "PostgreSQL libpq",
        ),
        (
            "notes.txt",
            r"`dbname=main user=svc host=db.internal password='rQ8 xK\'4!w2'`",
            r"rQ8 xK\'4!w2",
            "PostgreSQL libpq",
        ),
    ],
)
def test_literal_database_records_report_only_the_password(path, record, expected, kind):
    [finding] = [item for item in _scan(path, record) if item["provider"] == "database_credentials"]

    assert finding["rule_id"] == "SKY-S101"
    assert finding["line"] == 1
    assert record[finding["col"] : finding["end_col"]] == expected
    assert kind in finding["message"]
    assert finding["preview"] == "********"
    assert expected not in json.dumps(finding)


@pytest.mark.parametrize(
    "record",
    [
        f"jdbc:sqlserver://;user=svc;password={PASSWORD}",
        f"jdbc:sqlserver://host:1433;user=svc;password={PASSWORD}",
        "jdbc:sqlserver://db.internal;user=svc;password=",
        "jdbc:sqlserver://db.internal;user=svc;password=prefix${PASSWORD}",
        "jdbc:sqlserver://db.internal;user=svc;password={unclosed",
        f"jdbc:sqlserver://db.internal;user=svc;password={PASSWORD};password=",
        f"jdbc:sqlserver://db.internal;user=svc;username=other;password={PASSWORD};",
        f'Server=db.internal;UID=svc;PWD={PASSWORD};Driver={{SQLite3 ODBC Driver}};',
        f"Server=db.internal;UID=svc;PWD={PASSWORD};",
        "Driver={SQL Server};Server=db.internal;Trusted_Connection=yes;",
        f'Driver={{SQL Server}};Server=db.internal;UID=svc; "PWD={PASSWORD}"',
        f"host=db.internal user=svc password={PASSWORD}",
        "host=db.internal dbname=main user=svc password='your_password_here'",
        "host=db.internal dbname=main user=svc password=prefix${DB_PASSWORD}",
        f"host=db.internal dbname=main user=svc password={PASSWORD} password=''",
        f'"host=db.internal dbname=main" + "user=svc password={PASSWORD}"',
        f"host=db.internal dbname=main user=svc\npassword={PASSWORD}",
        f"password={PASSWORD}; user=svc; product=server;",
    ],
)
def test_text_property_scanner_requires_one_complete_database_record(record):
    assert _scan("incident.txt", record) == []


@pytest.mark.parametrize("path", ["tests/fixtures/connection.txt", "db.pem", "test/db.py"])
def test_property_record_scan_preserves_provider_only_fixture_and_key_rules(path):
    record = f"host=db.internal dbname=main user=svc password={PASSWORD}"
    assert _scan(path, record) == []


def test_postgres_jdbc_query_recognition_reaches_regular_source():
    line = f'"jdbc:postgresql://db.internal/main?user=svc&password={PASSWORD}"'
    [finding] = _scan("src/Config.java", line)

    assert finding["provider"] == "url_credentials"
    assert line[finding["col"] : finding["end_col"]] == PASSWORD
