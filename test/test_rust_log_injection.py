from textwrap import dedent

import pytest

from skylos.visitors.languages.rust import scan_rust_file


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ('log::warn!("Lookup failed for {name}");', True),
        ('tracing::info!("Request arg = {0}", name);', True),
        ('log::error!("{} {alias}", 42, alias = name);', True),
        ('tracing::info!(user = %name, "visited");', False),
        ('log::info!("Value: {name:?}");', False),
        ('log::info!("{{name}}");', False),
        ('log::info!("Value: {}", name.escape_debug());', False),
        (
            "let safe = name.replace(['\\r', '\\n'], \" \"); log::info!(\"Value: {safe}\");",
            False,
        ),
        ('let count = name.len(); log::info!("Value: {count}");', False),
        ('let unused = || log::warn!("Value: {name}");', False),
        ('#[cfg(test)] log::warn!("Value: {name}");', False),
    ],
)
def test_plain_request_text_in_log_message(tmp_path, statement, expected):
    code = f"""
        use axum::extract::Path;
        fn handler(Path(name): Path<String>) {{
            {statement}
        }}
    """
    path = tmp_path / "src" / "lib.rs"
    path.parent.mkdir()
    path.write_text(dedent(code))
    rows = [r for r in scan_rust_file(str(path), {})[7] if r["rule_id"] == "SKY-D392"]
    assert len(rows) == int(expected)
    if expected:
        assert rows[0]["severity"] == "MEDIUM"


def test_undecoded_query_and_unrelated_logger_are_quiet(tmp_path):
    code = """
        use actix_web::HttpRequest;
        use axum::extract::Path;
        fn raw(r: HttpRequest) {
            let encoded = r.query_string();
            log::info!("Item: {encoded}");
        }
        mod custom {
            macro_rules! info { ($message:literal) => { () }; }
            use axum::extract::Path;
            pub fn run(Path(name): Path<String>) { info!("Item: {name}"); }
        }
    """
    path = tmp_path / "lib.rs"
    path.write_text(dedent(code))
    assert not [
        r for r in scan_rust_file(str(path), {})[7] if r["rule_id"] == "SKY-D392"
    ]
