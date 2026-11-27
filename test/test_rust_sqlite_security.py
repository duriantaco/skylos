from textwrap import dedent

import pytest

from skylos.reporting.listing import is_listed
from skylos.visitors.languages.rust import scan_rust_file


def sql_findings(tmp_path, code, relative="src/lib.rs"):
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text(dedent(code), encoding="utf-8")
    return [
        row
        for row in scan_rust_file(str(path), {})[7]
        if row["rule_id"] == "SKY-D211" and is_listed(row, "danger")
    ]


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ('let _ = db.execute(&format!("UPDATE items SET value = {input}"), []);', True),
        (
            'let sql = format!("SELECT {}", input); let _ = db.execute_batch(&sql);',
            True,
        ),
        ("let _ = db.query_row(&input, [], |row| row.get::<_, i64>(0));", True),
        (
            'let _ = db.execute(&format!("UPDATE items SET value = ?1 WHERE key = {key}", key = input), [1]);',
            True,
        ),
        ('let _ = db.execute("UPDATE items SET value = ?1", [&input]);', False),
        (
            'let _ = db.query_row("SELECT ?1", [&input], |row| row.get::<_, String>(0));',
            False,
        ),
        (
            'let sql = format!("SELECT {}", input.len()); let _ = db.execute_batch(&sql);',
            False,
        ),
        ("let sql = opaque(input); let _ = db.execute_batch(&sql);", False),
        (
            'let sql = format!("SELECT {}", opaque(input)); let _ = db.execute_batch(&sql);',
            False,
        ),
        ('let sql = "SELECT 1"; let _ = db.execute_batch(sql);', False),
        ("let _ = db.prepare(&input);", False),
        ("let mut sql = input; sql.clear(); let _ = db.execute_batch(&sql);", False),
        (
            "let mut sql = input; rewrite(&mut sql); let _ = db.execute_batch(&sql);",
            False,
        ),
    ],
)
def test_query_text_and_bound_values(tmp_path, statement, expected):
    code = """
        use axum::extract::Path;
        use rusqlite::Connection as Database;
        fn opaque(_text: String) -> String { String::from("SELECT 1") }
        fn rewrite(text: &mut String) { text.clear(); }
        fn run(Path(input): Path<String>, db: &Database) {
            STATEMENT
        }
    """.replace("STATEMENT", statement)
    rows = sql_findings(tmp_path, code)
    assert len(rows) == int(expected)
    if expected:
        assert all(row["line"] == 7 and row["severity"] == "CRITICAL" for row in rows)


def test_constructor_alias_and_associated_method(tmp_path):
    rows = sql_findings(
        tmp_path,
        """
        use axum::extract::Path;
        use rusqlite::Connection as Db;
        fn run(Path(input): Path<String>) -> rusqlite::Result<()> {
            let db = Db::open_in_memory()?;
            Db::execute_batch(&db, &input)
        }
    """,
    )
    assert [row["line"] for row in rows] == [6]


def test_local_connection_and_fixed_numeric_input_are_quiet(tmp_path):
    assert not sql_findings(
        tmp_path,
        """
        use axum::extract::Path;
        struct Recorder;
        impl Recorder { fn execute_batch(&self, _sql: &str) {} }
        fn run(Path(input): Path<String>, capture: Recorder) { capture.execute_batch(&input); }
        fn number(Path(id): Path<i64>, db: &rusqlite::Connection) {
            let _ = db.execute_batch(&format!("SELECT {id}"));
        }
    """,
    )


def test_test_only_query_and_operator_input_are_quiet(tmp_path):
    code = """
        use axum::extract::Path;
        fn run(Path(input): Path<String>, db: &rusqlite::Connection) {
            #[cfg(test)]
            db.execute_batch(&input).unwrap();
            let operator = std::env::var("QUERY").unwrap(); db.execute_batch(&operator).unwrap();
        }
    """
    assert not sql_findings(tmp_path, code)
    assert not sql_findings(tmp_path, code.replace("#[cfg(test)]", ""), "tests/demo.rs")


def test_actix_request_text_and_fixed_user_data_are_distinct(tmp_path):
    rows = sql_findings(
        tmp_path,
        """
        use actix_web::HttpRequest;
        use rusqlite::Connection;
        fn run(req: HttpRequest, db: &Connection) {
            let _ = db.execute_batch(req.query_string());
            let _ = db.execute("UPDATE items SET value=?1", [req.query_string()]);
        }
    """,
    )
    assert [row["line"] for row in rows] == [5]


def test_inert_closures_or_async_blocks_do_not_execute_queries(tmp_path):
    assert not sql_findings(
        tmp_path,
        """
        use axum::extract::Path;
        fn run(Path(input): Path<String>, db: &rusqlite::Connection) {
            let _unused = || db.execute_batch(&input);
            let _unused_future = async { db.execute_batch(&input) };
        }
    """,
    )


def test_local_module_named_rusqlite_is_quiet(tmp_path):
    assert not sql_findings(
        tmp_path,
        """
        use axum::extract::Path;
        mod rusqlite {
            pub struct Connection;
            impl Connection { pub fn execute_batch(&self, text: &str) {} }
        }
        fn run(Path(input): Path<String>, db: &rusqlite::Connection) {
            db.execute_batch(&input);
        }
    """,
    )


def test_absolute_connection_and_interleaved_comments(tmp_path):
    rows = sql_findings(
        tmp_path,
        """
        use axum::extract::Path;
        fn run(Path(input): Path<String>, db: &::rusqlite::Connection) {
            let _ = db.execute(/* SQL text */ &input, /* parameters */ []);
            let _ = db.execute(/* SQL text */ "SELECT ?1", /* parameters */ [&input]);
        }
    """,
    )
    assert [row["line"] for row in rows] == [4]


def test_numeric_rendering_after_local_conversion_is_quiet(tmp_path):
    assert not sql_findings(
        tmp_path,
        """
        use axum::extract::Path;
        fn run(Path(input): Path<String>, db: &rusqlite::Connection) {
            let id = input.parse::<i64>().unwrap_or_default();
            let sql = format!("SELECT {id}");
            let _ = db.execute_batch(&sql);
        }
    """,
    )


def test_collection_of_connections_is_not_itself_a_connection(tmp_path):
    # An extension trait may expose the same method on an array.
    assert not sql_findings(
        tmp_path,
        """
        use axum::extract::Path;
        use rusqlite::Connection;
        use audit_log::AuditBatch;
        fn run(Path(input): Path<String>, db: Connection) {
            let audit = [db];
            audit.execute_batch(&input);
        }
        """,
    )
