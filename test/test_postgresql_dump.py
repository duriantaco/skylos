import pytest

from skylos.visitors.languages import postgresql

pytestmark = pytest.mark.skipif(
    postgresql.ast is None, reason="requires the postgres extra"
)


def scan(sql):
    return postgresql.scan_postgresql(sql, "dump.sql")


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_dump_data_is_opaque_and_positions_survive(newline):
    lines = [
        "-- PostgreSQL database dump",
        r"\restrict key12A",
        'COPY public."mixed Name" ("é") FROM stdin;',
        "data\t门",
        "",
        "SELECT 1 WHERE 42 NOT IN (1, NULL);",
        r"\i unavailable.sql",
        "/* unclosed comment and '",
        r"\.",
        "SELECT 1 WHERE 1 = NULL;",
        r"\unrestrict key12A",
        r"\d+ public.orders",
        "SELECT 1 WHERE 2 NOT IN (1,NULL);",
    ]
    rows, error = scan(newline.join(lines))
    assert error is None
    assert [(r["rule_id"], r["line"]) for r in rows] == [
        ("SKY-Q504", 10),
        ("SKY-Q505", 13),
    ]


def test_multiline_copy_text_and_an_empty_block():
    sql = """COPY public.t
      (id, name)
      FROM STDIN WITH (FORMAT text);
\\.
COPY t FROM STDIN;
\\.
SELECT 1 WHERE n = NULL;"""
    rows, error = scan(sql)
    assert error is None
    assert [r["line"] for r in rows] == [7]


@pytest.mark.parametrize(
    "opts",
    ["WITH (FORMAT csv)", "CSV HEADER", "WITH (FORMAT binary)"],
)
def test_unsupported_copy_data_format_is_unparsed(opts):
    rows, error = scan(f"COPY t FROM STDIN {opts};\n1\n\\.\nSELECT 1 WHERE n = NULL;")
    assert not rows
    assert "COPY" in error


@pytest.mark.parametrize(
    "tail",
    ["", "sql-looking content\n", " \\.\n", "\\. \n", "\\\\.\n"],
)
def test_missing_or_inexact_terminator_is_unparsed(tail):
    rows, error = scan("SELECT 1 WHERE a = NULL;\nCOPY t FROM STDIN;\n" + tail)
    assert not rows
    assert "COPY FROM STDIN" in error


@pytest.mark.parametrize(
    "directive",
    [
        r"\unrestrict Wrong",
        r"\restrict Two",
        r"\d",
        r"\connect other",
        r"\i file",
    ],
)
def test_restriction_key_and_command_policy(directive):
    rows, error = scan("\\restrict One\nSELECT 1 WHERE n = NULL;\n" + directive)
    assert not rows and error


@pytest.mark.parametrize(
    "directive",
    [
        r"\restrict",
        r"\restrict bad-key",
        r"\unrestrict extra",
        r"\restrict unclosed",
        r"\d :table",
        r"\d public.t \g",
        r"\dt `name`",
    ],
)
def test_incomplete_or_dynamic_meta_commands_stay_unparsed(directive):
    rows, error = scan("SELECT 1 WHERE n = NULL;\n" + directive)
    assert not rows and error


def test_framing_does_not_reset_the_session():
    from pglast import ast

    from skylos.visitors.languages.postgresql_script import parse_sessions

    sql = r"""\restrict k
BEGIN;
COPY t FROM STDIN;
\c not_a_session
\.
\unrestrict k
\dt
CREATE INDEX CONCURRENTLY i ON t (id);
COMMIT;"""
    sessions = parse_sessions(sql)
    assert len(sessions) == 1
    assert [type(r.stmt) for r in sessions[0][1]] == [
        ast.TransactionStmt,
        ast.CopyStmt,
        ast.IndexStmt,
        ast.TransactionStmt,
    ]
    assert sql[sessions[0][1][2].stmt_location :].startswith("CREATE INDEX")


def test_sql_lexical_context_shields_literal_headers_and_markers():
    sql = r"""\d
SELECT $body$
COPY t FROM STDIN;
\.
\restrict fake
$body$;
SELECT E'escaped\' COPY t FROM STDIN;'
        'continues';
/* outer /* COPY t FROM STDIN; */ inner \. */
SELECT "COPY t FROM STDIN;" FROM t;
SELECT 1 WHERE a = NULL;
"""
    rows, error = scan(sql)
    assert error is None
    assert [row["line"] for row in rows] == [11]


def test_metadata_within_atomic_body_is_unparsed():
    rows, error = scan(
        "CREATE FUNCTION f() RETURNS int LANGUAGE SQL BEGIN ATOMIC\n"
        "SELECT 1;\n\\d\nEND;"
    )
    assert not rows and error


def test_external_copy_is_ordinary_sql_and_keeps_following_queries():
    sql = "COPY t FROM '/fixture';\nCOPY t TO STDOUT;\nSELECT 1 WHERE a = NULL;"
    rows, error = scan(sql)
    assert error is None
    assert [row["line"] for row in rows] == [3]


def test_continued_postgres_escape_string_keeps_its_quote_mode():
    sql = r"""\d
SELECT E'start,'
    'escaped quote\';
COPY t FROM STDIN;
\.
joined';
SELECT 1 WHERE n = NULL;
"""
    rows, error = scan(sql)
    assert error is None
    assert [row["line"] for row in rows] == [7]


@pytest.mark.parametrize("suffix", [";", ""])
def test_metadata_cannot_be_inserted_in_an_unterminated_atomic_statement(suffix):
    sql = (
        "CREATE FUNCTION f() RETURNS int LANGUAGE SQL BEGIN ATOMIC\nSELECT 1;\n\\d\nEND"
        + suffix
    )
    rows, error = scan(sql)
    assert not rows and error


@pytest.mark.parametrize("setting", ["off", "DEFAULT"])
def test_special_string_mode_in_dump_is_unparsed(setting):
    rows, error = scan(
        f"SET standard_conforming_strings = {setting};\n"
        "COPY t FROM STDIN;\n1\n\\.\nSELECT 1 WHERE a = NULL;"
    )
    assert not rows
    assert "standard_conforming_strings" in error


def test_copy_scripts_apply_psql_variable_rules_outside_data():
    sql = "COPY t FROM stdin;\n:row\n\\.\nSELECT (ARRAY[1,2])[1:2];"
    rows, error = scan(sql)
    assert not rows
    assert "variable substitution on line 4" in error
    assert scan(sql.replace("[1:2]", "[1: 2]")) == ([], None)


def test_large_pg_dump_compacts_only_data_and_preserves_lines(tmp_path, monkeypatch):
    from skylos.analysis.sql_files import analyze_sql_file
    from skylos.visitors.languages import postgresql_script

    calls = []
    parse = postgresql_script.parse_sql

    def checked_parse(source):
        size = len(source.encode())
        assert size <= 4_000_000
        assert "OPAQUE_PAYLOAD" not in source
        calls.append(size)
        return parse(source)

    monkeypatch.setattr(postgresql_script, "parse_sql", checked_parse)
    payload = ("OPAQUE_PAYLOAD 门" + "x" * 90 + "\n") * 40000
    sql = (
        r"\restrict pg123"
        + "\nCOPY t FROM STDIN;\n"
        + payload
        + "\\.\nSELECT '🍊';\nCOPY t FROM STDIN;\n"
        + "SELECT 1 WHERE hidden = NULL;\n\\.\nSELECT 1 WHERE visible = NULL;\n"
        + r"\unrestrict pg123"
    )
    path = tmp_path / "data.sql"
    path.write_text(sql, encoding="utf-8")
    assert path.stat().st_size > 4_000_000
    rows, coverage = analyze_sql_file(
        path, {"sql": {"dialect": "postgresql"}}, tmp_path
    )
    assert coverage["status"] == "checked"
    assert [(r["rule_id"], r["line"]) for r in rows] == [("SKY-Q504", 40008)]
    assert calls and min(calls) < 256


def test_large_dump_error_reports_original_line_after_data():
    rows, error = scan(
        "COPY t FROM STDIN;\n"
        + ("x" * 100 + "\n") * 40_000
        + "\\.\nSELECT 1;\nSELEC broken;"
    )
    assert not rows and "parse error on line 40004" in error


@pytest.mark.parametrize(
    "tail",
    [
        "SELECT 1;",
        "SELECT $text$\nCOPY t FROM STDIN;\nrow\n\\.\n$text$;",
        "COPY t FROM STDIN;\nno terminator\n",
    ],
)
def test_large_non_dump_or_unterminated_block_returns_no_findings(tail, monkeypatch):
    from skylos.visitors.languages import postgresql_script

    def unexpected_parse(*args):
        pytest.fail("oversized SQL reached the native parser")

    monkeypatch.setattr(postgresql_script, "parse_sql", unexpected_parse)
    monkeypatch.setattr(postgresql_script, "scan", unexpected_parse)
    rows, error = scan("-- " + "x" * 4_000_001 + "\n" + tail)
    assert not rows and "4 MB" in error


def test_large_dump_with_excessive_residual_sql_or_header_is_unparsed(monkeypatch):
    from skylos.visitors.languages import postgresql_script

    parse = postgresql_script.parse_sql

    def checked_parse(sql):
        assert len(sql.encode()) <= 65_536
        return parse(sql)

    monkeypatch.setattr(postgresql_script, "parse_sql", checked_parse)
    rows, error = scan("COPY t FROM STDIN;\nrow\n\\.\n-- " + "x" * 4_000_001)
    assert not rows and "4 MB" in error
    rows, error = scan(
        'COPY "' + "x" * 65_536 + '" FROM STDIN;\n' + "x" * 4_000_001 + "\n\\.\n"
    )
    assert not rows and "header" in error


def test_dump_above_raw_byte_limit_is_unchecked():
    rows, error = scan("COPY t FROM STDIN;\n" + "x" * 16_000_000 + "\n\\.\n")
    assert not rows and "16 MB" in error


def test_large_dump_budget_counts_retained_utf8_bytes(monkeypatch):
    from skylos.visitors.languages import postgresql_script

    parse = postgresql_script.parse_sql
    calls = []

    def checked_parse(sql):
        calls.append(len(sql.encode()))
        assert calls[-1] <= 65_536
        return parse(sql)

    monkeypatch.setattr(postgresql_script, "parse_sql", checked_parse)
    sql = "COPY t FROM STDIN;\nvalue\n\\.\nSELECT '" + "𓀀" * 1_000_001 + "';"
    rows, error = scan(sql)
    assert not rows and "4 MB" in error
    assert len(calls) == 1


def test_large_copy_must_be_in_the_final_top_level_ast():
    sql = (
        "CREATE FUNCTION f() RETURNS int LANGUAGE SQL BEGIN ATOMIC\nSELECT 1;\n"
        "COPY t FROM STDIN;\n" + "row" * 1_500_000 + "\n\\.\nEND;"
    )
    rows, error = scan(sql)
    assert not rows
    assert "top-level" in error or "parse error" in error


@pytest.mark.parametrize("bom", [b"", b"\xef\xbb\xbf"])
def test_file_reader_accepts_exact_raw_byte_budget(tmp_path, monkeypatch, bom):
    from skylos.analysis import sql_files

    # Exercise the exact boundary cheaply for files with and without a UTF-8 BOM.
    cap = 256
    monkeypatch.setattr(sql_files, "POSTGRES_DUMP_BYTE_LIMIT", cap)
    path = tmp_path / "dump.sql"
    start = bom + b"COPY t FROM STDIN;\n"
    end = b"\n\\.\nSELECT 1 WHERE n = NULL;"
    cfg = {"sql": {"dialect": "postgresql"}}
    path.write_bytes(start + b"x" * (cap - len(start) - len(end)) + end)
    rows, coverage = sql_files.analyze_sql_file(path, cfg, tmp_path)
    assert coverage["status"] == "checked"
    assert [(r["rule_id"], r["line"]) for r in rows] == [("SKY-Q504", 4)]
    with path.open("ab") as output:
        output.write(b"\n")
    assert sql_files.analyze_sql_file(path, cfg, tmp_path)[1]["status"] == "unparsed"


@pytest.mark.parametrize("padding", [4, 4_000_001])
def test_file_loader_does_not_synthesize_a_copy_terminator(tmp_path, padding):
    from skylos.analysis.sql_files import analyze_sql_file

    path = tmp_path / "dump.sql"
    path.write_bytes(
        b"COPY t FROM stdin;\n" + b"x" * padding + b"\r\\.\rSELECT 1 WHERE a = NULL;\n"
    )
    rows, coverage = analyze_sql_file(
        path, {"sql": {"dialect": "postgresql"}}, tmp_path
    )
    assert rows == []
    assert coverage["status"] == "unparsed"


def test_file_loader_keeps_plain_cr_only_line_numbers(tmp_path):
    from skylos.analysis.sql_files import analyze_sql_file

    path = tmp_path / "plain.sql"
    path.write_bytes(b"-- heading\rSELECT 1;\rSELECT 2 WHERE a = NULL;")
    rows, coverage = analyze_sql_file(
        path, {"sql": {"dialect": "postgresql"}}, tmp_path
    )
    assert coverage["status"] == "checked"
    assert [(row["rule_id"], row["line"]) for row in rows] == [("SKY-Q504", 3)]


def test_cr_in_copy_data_does_not_shift_following_sql(tmp_path):
    from skylos.analysis.sql_files import analyze_sql_file

    path = tmp_path / "dump.sql"
    path.write_bytes(
        b"COPY t FROM stdin;\r\nrow\rwith\rembedded CR\r\n\\.\r\nSELECT 1 WHERE a = NULL;"
    )
    rows, coverage = analyze_sql_file(
        path, {"sql": {"dialect": "postgresql"}}, tmp_path
    )
    assert coverage["status"] == "checked"
    assert [(row["rule_id"], row["line"]) for row in rows] == [("SKY-Q504", 4)]


@pytest.mark.parametrize("client", ["\\dt\n", "COPY t FROM stdin;\nrow\n\\.\n"])
def test_framed_sql_with_a_mode_dependent_quote_is_unchecked(client):
    sql = (
        "SELECT set_config('standard_conforming_strings', 'off', false);\n"
        + client
        + "SELECT 'tail\\';"
    )
    rows, error = scan(sql)
    assert not rows and "quote" in error


def test_explicit_escape_strings_and_opaque_rows_have_unambiguous_boundaries():
    sql = r"""\dt
SELECT E'it\'s ok', $$tail\'$$, 'two slashes\\'; -- tail\'
COPY t FROM stdin;
tail\'
\.
SELECT 1 WHERE a = NULL;
"""
    rows, error = scan(sql)
    assert error is None
    assert [(row["rule_id"], row["line"]) for row in rows] == [("SKY-Q504", 6)]
