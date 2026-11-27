import pytest

from skylos.visitors.languages.rust import scan_rust_file


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('let pat = format!("^{name}$"); let _ = regex::Regex::new(&pat);', "SKY-D389"),
        (
            'use regex::bytes::Regex as Matcher; let _ = Matcher::new(&format!("^user/{}$", name));',
            "SKY-D389",
        ),
        (
            'let fixed = regex::escape(&name); let _ = regex::Regex::new(&format!("^{fixed}$"));',
            None,
        ),
        ("let _ = regex::Regex::new(&name);", None),
        ('let _ = regex::Regex::new("^[a-z]+$");', None),
        (
            'struct Regex; impl Regex { fn new(_: &str) {} } Regex::new(&format!("^{name}$"));',
            None,
        ),
        ("let buf = String::with_capacity(n);", "SKY-D390"),
        ("let copy = n; let _ = std::vec::Vec::<u8>::with_capacity(copy);", "SKY-D390"),
        ("let _ = String::with_capacity(n.min(2048));", None),
        ("if n > 2048 { return; } let _ = String::with_capacity(n);", None),
        ("assert!(n < 16000); let _ = String::with_capacity(n);", None),
        ("let _ = std::vec::Vec::<()>::with_capacity(n);", None),
        ("let _ = String::with_capacity(name.len());", None),
        ("let _ = String::with_capacity(4096);", None),
    ],
)
def test_request_pattern(tmp_path, body, expected):
    source = (
        "use axum::extract::Path;\nfn run(Path(name): Path<String>, Path(n): Path<usize>) {\n"
        + body
        + "\n}"
    )
    path = tmp_path / "app.rs"
    path.write_text(source)
    findings = [
        f["rule_id"]
        for f in scan_rust_file(str(path), {})[7]
        if f["rule_id"] in {"SKY-D389", "SKY-D390"}
    ]
    assert findings == ([expected] if expected else [])


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("let _: Vec<String> = serde_json::from_reader(stream)?;", True),
        (
            "let mut buf=Vec::new(); stream.read_to_end(&mut buf)?; let _: Vec<String> = serde_json::from_slice(&buf)?;",
            True,
        ),
        ("let _: Vec<String> = serde_json::from_reader(stream.take(1024))?;", False),
        (
            "let mut buf=Vec::new(); stream.take(1024).read_to_end(&mut buf)?; let _: Vec<String> = serde_json::from_slice(&buf)?;",
            False,
        ),
        (
            "let mut buf=Vec::new(); stream.read_to_end(&mut buf)?; if buf.len()>1024 {return Ok(());} let _: Vec<String> = serde_json::from_slice(&buf)?;",
            False,
        ),
        ("let _: u32 = serde_json::from_reader(stream)?;", False),
        (
            'let _: Vec<String> = serde_json::from_reader(std::io::Cursor::new(b"[]"))?;',
            False,
        ),
        (
            "let mut text=String::new(); stream.read_to_string(&mut text)?; let _: Vec<String> = serde_json::from_str(&text)?;",
            True,
        ),
        (
            "let mut text=String::new(); stream.take(4096).read_to_string(&mut text)?; let _: Vec<String> = serde_json::from_str(&text)?;",
            False,
        ),
        (
            "let mut text=String::new(); stream.read_to_string(&mut text)?; if text.len()>256 {return Ok(());} let _: Vec<String> = serde_json::from_str(&text)?;",
            False,
        ),
    ],
)
def test_socket_deserialization(tmp_path, body, expected):
    path = tmp_path / "server.rs"
    path.write_text(
        "use std::io::Read;\nfn read(mut stream: std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {\n"
        + body
        + "\nOk(())\n}"
    )
    findings = [
        f for f in scan_rust_file(str(path), {})[7] if f["rule_id"] == "SKY-D233"
    ]
    assert len(findings) == int(expected)


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ("let mut buf: Vec<i16> = Vec::new(); buf.reserve_exact(n);", "SKY-D390"),
        ("let mut buf: Vec<()> = Vec::new(); buf.reserve(n);", None),
        ("let mut buf: Vec<u8> = Vec::new(); if n < 1024 {buf.reserve(n);}", None),
        ('let _ = regex::Regex::new(&format!("tag/{name}/release"));', "SKY-D389"),
        ('let _ = regex::Regex::new(&format!("{name}"));', None),
    ],
)
def test_capacity_and_regex_variants(tmp_path, body, rule):
    path = tmp_path / "app.rs"
    path.write_text(
        "use axum::extract::Path;\nfn run(Path(n): Path<usize>, Path(name): Path<String>) {\n"
        + body
        + "\n}"
    )
    assert [
        f["rule_id"]
        for f in scan_rust_file(str(path), {})[7]
        if f["rule_id"] in {"SKY-D389", "SKY-D390"}
    ] == ([rule] if rule else [])


def test_inline_capacity_guard_and_zero_sized_element(tmp_path):
    path = tmp_path / "src.rs"
    path.write_text("""
        use axum::extract::Path;
        type u8 = ();
        fn allocate(Path(n): Path<usize>) {
            let _checked = String::with_capacity({ assert!(n <= 256); n });
        }
        fn reserve(Path(n): Path<usize>) {
            let mut no_storage: Vec<u8> = Vec::new();
            no_storage.reserve(n);
        }
        fn qualified(Path(n): Path<usize>) {
            let _ = Vec::<u8>::with_capacity(n);
        }
    """)
    assert not [
        r for r in scan_rust_file(str(path), {})[7] if r["rule_id"] == "SKY-D390"
    ]


def test_short_circuit_read_does_not_mark_the_destination_as_network_data(tmp_path):
    path = tmp_path / "src.rs"
    path.write_text("""
        use std::io::Read;
        fn read(mut socket: std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
            let mut buffer = Vec::new();
            let _unused = false && socket.read_to_end(&mut buffer)? > 0;
            let _: Vec<u32> = serde_json::from_slice(&buffer)?;
            Ok(())
        }
    """)
    assert not [
        r for r in scan_rust_file(str(path), {})[7] if r["rule_id"] == "SKY-D233"
    ]
