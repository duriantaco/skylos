"""SQL execution controls. All SQL stays inside static Rust source fixtures."""

from textwrap import dedent

import pytest

from skylos.reporting.listing import is_listed
from skylos.visitors.languages.rust import scan_rust_file


def findings(tmp_path, source):
    file = tmp_path / "src/handler.rs"
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(dedent(source))
    return [
        (row["line"], row["severity"])
        for row in scan_rust_file(str(file), {})[7]
        if row["rule_id"] == "SKY-D211" and is_listed(row, "danger")
    ]


@pytest.mark.parametrize(
    ("statement", "report"),
    [
        ("let mut q = conn.prepare(&input)?; q.execute([])?;", True),
        (
            "let mut q = conn.prepare_cached(&input)?; q.query_row([], |r| r.get::<_, i32>(0))?;",
            True,
        ),
        ("conn.prepare(&input)?.query([])?.next()?;", True),
        (
            "let mut q = conn.prepare(&input)?; let rows = q.query_map([], |r| r.get::<_, String>(0))?; for row in rows { let _ = row?; }",
            True,
        ),
        (
            "let mut q = conn.prepare(&input)?; let mut rows = q.raw_query(); rows.next()?;",
            True,
        ),
        (
            'let mut q = conn.prepare("SELECT ?1")?; q.query_row([input], |r| r.get::<_, String>(0))?;',
            False,
        ),
        ("let mut q = conn.prepare(&input)?; let _ = q.query([])?;", False),
        (
            "let mut q = conn.prepare(&input)?; let _ = q.query_map([], |r| r.get::<_, String>(0))?;",
            False,
        ),
        ("let q = conn.prepare(&input)?; let _ = q.column_count();", False),
        (
            'let mut q = conn.prepare(&input)?; q = conn.prepare("SELECT 1")?; q.exists([])?;',
            False,
        ),
    ],
)
def test_prepared_sqlite_statements(tmp_path, statement, report):
    source = f"""
        use actix_web::HttpRequest;
        use rusqlite::Connection;
        fn run(req: HttpRequest, conn: &Connection) -> rusqlite::Result<()> {{
            let input = req.query_string().to_owned();
            {statement}
            Ok(())
        }}
    """
    assert findings(tmp_path, source) == ([(6, "CRITICAL")] if report else [])


@pytest.mark.parametrize(
    ("statement", "report"),
    [
        ("sqlx::query(&input).fetch_all(pool).await?;", True),
        (
            "let q = make_query(&input).bind(3); let f = q.execute(pool); f.await?;",
            True,
        ),
        ("sqlx::query_as::<_, (i32,)>(&input).fetch_one(pool).await?;", True),
        ("sqlx::query_scalar::<_, i32>(&input).fetch_optional(pool).await?;", True),
        ("sqlx::raw_sql(sqlx::AssertSqlSafe(input)).execute(pool).await?;", True),
        ("pool.execute(input.as_str()).await?;", True),
        ("sqlx::Executor::execute(pool, input.as_str()).await?;", True),
        (
            "let mut rows = make_query(&input).fetch(pool); rows.try_next().await?;",
            True,
        ),
        ('sqlx::query("SELECT $1").bind(input).fetch_all(pool).await?;', False),
        ("let _future = make_query(&input).fetch_all(pool);", False),
        ("let _stream = make_query(&input).fetch(pool);", False),
        ("let _ = make_query(&input);", False),
        ("let _unused = async { make_query(&input).fetch_all(pool).await };", False),
        ("let _unused = || make_query(&input).fetch_all(pool);", False),
        (
            'let fixed = format!("SELECT {}", input.len()); sqlx::query(&fixed).fetch_all(pool).await?;',
            False,
        ),
    ],
)
def test_sqlx_dispatch(tmp_path, statement, report):
    source = f"""
        use axum::extract::Path;
        use sqlx::{{PgPool, Executor, query as make_query}};
        use futures_util::TryStreamExt;
        async fn run(Path(input): Path<String>, pool: &PgPool) -> Result<(), sqlx::Error> {{
            {statement}
            Ok(())
        }}
    """
    assert findings(tmp_path, source) == ([(6, "CRITICAL")] if report else [])


def test_local_sqlx_name_and_extension_method_are_quiet(tmp_path):
    assert not findings(
        tmp_path,
        """
        use axum::extract::Path;
        mod sqlx { pub use audit_log::query; }
        use audit_log::Check as _;
        async fn run(Path(input): Path<String>, capture: &audit_log::Log) {
            sqlx::query(&input).fetch_all(capture).await;
            capture.execute(input.as_str()).await;
        }
    """,
    )


@pytest.mark.parametrize(
    ("statement", "report"),
    [
        (
            'let mut q = Builder::<sqlx::Postgres>::new("SELECT "); q.push(input); q.build().fetch_all(pool).await?;',
            True,
        ),
        (
            "let mut q = Builder::<sqlx::Postgres>::new(input); q.reset(); q.build_query_scalar::<i32>().fetch_one(pool).await?;",
            True,
        ),
        (
            'let mut q = Builder::<sqlx::Postgres>::new("SELECT "); q.push_bind(input); q.build().fetch_all(pool).await?;',
            False,
        ),
        (
            'let mut q = Builder::<sqlx::Postgres>::new("SELECT 1 "); q.push(&input); q.reset(); q.build().fetch_all(pool).await?;',
            False,
        ),
        (
            'let mut q = Builder::<sqlx::Postgres>::new("SELECT 1 "); let a = q.push(&input); a.reset(); q.build().fetch_all(pool).await?;',
            False,
        ),
        (
            "let mut q = Builder::<sqlx::Postgres>::new(input); let _ = q.build();",
            False,
        ),
        (
            "let mut q = Builder::<sqlx::Postgres>::new(input); replace_sql(&mut q); q.build().fetch_all(pool).await?;",
            False,
        ),
    ],
)
def test_sqlx_builder_sql_and_bound_values(tmp_path, statement, report):
    source = f"""
        use axum::extract::Path;
        use sqlx::{{QueryBuilder as Builder, PgPool}};
        fn replace_sql(q: &mut Builder<sqlx::Postgres>) {{ *q = Builder::new("SELECT 1"); }}
        async fn run(Path(input): Path<String>, pool: &PgPool) -> Result<(), sqlx::Error> {{
            {statement}
            Ok(())
        }}
    """
    assert findings(tmp_path, source) == ([(6, "CRITICAL")] if report else [])


def test_sqlx_other_traits_cannot_turn_query_as_into_executor(tmp_path):
    assert not findings(
        tmp_path,
        """
        use axum::extract::Path;
        use auditing::Inspect;
        async fn run(Path(input): Path<String>, audit: &auditing::Log) {
            let q = sqlx::query_as::<_, (i32,)>(&input);
            q.execute(audit).await;
        }
    """,
    )


@pytest.mark.parametrize(
    ("body", "report"),
    [
        (
            'let s = reqwest::blocking::get(url)?.text()?; let q = String::from("SELECT ") + &s; db.execute_batch(&q)?;',
            True,
        ),
        (
            'let s = reqwest::get(url).await?.text().await?; let q = format!("SELECT {s}"); db.execute_batch(&q)?;',
            True,
        ),
        (
            'let s = reqwest::blocking::get(url)?.text().unwrap_or_default(); db.execute("SELECT ?1", [s])?;',
            False,
        ),
        (
            'let s = reqwest::blocking::get(url)?.text()?; let n = s.parse::<i64>()?; db.execute_batch(&format!("SELECT {n}"))?;',
            False,
        ),
        (
            "let s = std::env::args().nth(1).unwrap_or_default(); db.execute_batch(&s)?;",
            False,
        ),
    ],
)
def test_response_body_sql_flow(tmp_path, body, report):
    source = f"""
        async fn execute(url: &str, db: &rusqlite::Connection) -> Result<(), Box<dyn std::error::Error>> {{
            {body}
            Ok(())
        }}
    """
    assert findings(tmp_path, source) == ([(3, "CRITICAL")] if report else [])


@pytest.mark.parametrize(
    ("db", "statement", "report"),
    [
        ("mysql", "conn.query_drop(&text)?;", True),
        ("mysql", 'conn.exec_drop("SELECT ?", (&text,))?;', False),
        ("mysql", "let stmt = conn.prep(&text)?; conn.exec_drop(&stmt, ())?;", True),
        ("mysql", "let _stmt = conn.prep(&text)?;", False),
        ("mysql_async", "conn.query_drop(&text).await?;", True),
        ("mysql_async", "let _future = conn.query_drop(&text);", False),
        ("mysql_async", 'conn.exec_drop("SELECT ?", (&text,)).await?;', False),
        (
            "mysql_async",
            "let stmt = conn.prep(&text).await?; conn.exec_drop(&stmt, ()).await?;",
            True,
        ),
    ],
)
def test_mysql_queryable_execution(tmp_path, db, statement, report):
    source = f"""
        use actix_web::HttpRequest;
        use {db}::prelude::Queryable;
        async fn run(req: HttpRequest, conn: &mut {db}::Conn) -> {db}::Result<()> {{
            let text = req.query_string().to_owned();
            {statement}
            Ok(())
        }}
    """
    assert findings(tmp_path, source) == ([(6, "CRITICAL")] if report else [])


def test_local_mysql_and_unrelated_queryable_stay_quiet(tmp_path):
    assert not findings(
        tmp_path,
        """
        use axum::extract::Path;
        use audit::Queryable;
        fn log(Path(input): Path<String>, conn: &mut mysql::Conn) { conn.query_drop(&input); }
        mod demo {
            use axum::extract::Path;
            mod mysql { pub use audit::Conn; }
            fn log(Path(input): Path<String>, conn: &mut mysql::Conn) { conn.query_drop(&input); }
        }
    """,
    )


def test_statement_replaced_through_mutable_borrow_is_quiet(tmp_path):
    assert not findings(
        tmp_path,
        """
        use axum::extract::Path;
        fn run(Path(input): Path<String>, db: &rusqlite::Connection) -> rusqlite::Result<()> {
            let mut stmt = db.prepare(&input)?;
            let mut fixed = db.prepare("SELECT 1")?;
            std::mem::swap(&mut stmt, &mut fixed);
            let _ = stmt.query_row([], |r| r.get::<_, i32>(0))?;
            Ok(())
        }
    """,
    )


@pytest.mark.parametrize(
    ("call", "report"),
    [
        (
            'sqlx::query("INSERT INTO users (name, password) VALUES ($1, $2)").bind("guest").bind(raw).execute(pool).await;',
            True,
        ),
        (
            'let q = sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1").bind(31).bind(raw); let fut = q.execute(pool); fut.await;',
            True,
        ),
        (
            'sqlx::query("INSERT INTO users (password_hash, note) VALUES (?, ?)").bind(derive_hash(raw)).bind(raw).execute(pool).await;',
            False,
        ),
        (
            'sqlx::query("INSERT INTO users (name, password) VALUES ($1, $2)").bind(raw).bind(derive_hash(raw)).execute(pool).await;',
            False,
        ),
        (
            'let _unpolled = sqlx::query("UPDATE users SET password = $1").bind(raw).execute(pool);',
            False,
        ),
        (
            'let _ = sqlx::query("INSERT INTO users (password, account) VALUES ($1, $2)").bind(raw).execute(pool).await;',
            False,
        ),
        (
            'let _ = sqlx::query("SELECT id FROM users WHERE password = $1").bind(raw).fetch_all(pool).await;',
            False,
        ),
        (
            'let _ = sqlx::query("INSERT INTO users (password) VALUES (hash($1))").bind(raw).execute(pool).await;',
            False,
        ),
        (
            'let _ = sqlx::query("UPDATE users SET display_name = $1 WHERE password = $2").bind("guest").bind(raw).execute(pool).await;',
            False,
        ),
        (
            'let pending = async { sqlx::query("UPDATE users SET password = $1").bind(raw).execute(pool).await };',
            False,
        ),
    ],
)
def test_exposed_password_requires_its_bound_slot_and_execution(tmp_path, call, report):
    source = f"""
        use secrecy::{{SecretString, ExposeSecret}};
        fn derive_hash(_: &str) -> String {{ todo!() }}
        async fn save(password: &SecretString, pool: &sqlx::PgPool) {{
            let raw = password.expose_secret();
            {call}
        }}
    """
    file = tmp_path / "src/account.rs"
    file.parent.mkdir(parents=True)
    file.write_text(dedent(source))
    rows = [
        r
        for r in scan_rust_file(str(file), {})[7]
        if r["rule_id"] == "SKY-D387" and is_listed(r, "danger")
    ]
    assert [r["line"] for r in rows] == ([6] if report else [])


@pytest.mark.parametrize(
    ("driver", "placeholder", "expected"),
    [
        ("sqlx::PgPool", "?", False),
        ("sqlx::PgPool", "$1", True),
        ("sqlx::MySqlPool", "?", True),
        ("sqlx::MySqlPool", "$1", False),
    ],
)
def test_password_placeholder_matches_sqlx_backend(
    tmp_path, driver, placeholder, expected
):
    source = f"""
        use secrecy::{{SecretString, ExposeSecret}};
        async fn run(pass: &SecretString, pool: &{driver}) {{
            sqlx::query("UPDATE users SET password = {placeholder}").bind(pass.expose_secret()).execute(pool).await;
        }}
    """
    file = tmp_path / "src/save.rs"
    file.parent.mkdir()
    file.write_text(dedent(source))
    rows = [r for r in scan_rust_file(str(file), {})[7] if r["rule_id"] == "SKY-D387"]
    assert len(rows) == int(expected)
