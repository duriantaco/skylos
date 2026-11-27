from textwrap import dedent

import pytest

from skylos.visitors.languages.rust import scan_rust_file


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('let html = format!("<p>{}</p>", name.len());', False),
        ('let html = format!("<p>{v:?}</p>", v = name.len());', False),
        (
            'let n = name.len(); let s = format!("{n}"); let html = format!("<p>{s}</p>");',
            False,
        ),
        ('let html = format!("<p>{name}</p>");', True),
        ('let html = format!("<p>{}: {name}</p>", name.len());', True),
        ('let html = format!("<p>{}</p>", name.len().to_string() + &name);', True),
    ],
)
def test_rendering_length_of_a_known_string(tmp_path, body, expected):
    path = tmp_path / "src" / "lib.rs"
    path.parent.mkdir()
    path.write_text(
        dedent(f"""
        use axum::extract::Path;
        fn show(Path(name): Path<String>) -> axum::response::Html<String> {{
            {body}
            axum::response::Html(html)
        }}
    """)
    )
    findings = [
        r for r in scan_rust_file(str(path), {})[7] if r["rule_id"] == "SKY-D228"
    ]
    assert len(findings) == int(expected)


def test_custom_len_method_has_no_standard_length_guarantee(tmp_path):
    path = tmp_path / "lib.rs"
    path.write_text(
        dedent("""
        use axum::extract::Path;
        struct Label(String);
        impl Label { fn len(&self) -> &str { &self.0 } }
        fn show(Path(name): Path<Label>) -> axum::response::Html<String> {
            axum::response::Html(format!("<p>{}</p>", name.len()))
        }
    """)
    )
    assert any(r["rule_id"] == "SKY-D228" for r in scan_rust_file(str(path), {})[7])
