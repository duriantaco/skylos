"""Regression cases for session cookie and authenticated transport settings."""

from textwrap import dedent

import pytest

from skylos.visitors.languages.rust import scan_rust_file


def findings(tmp_path, code, rule):
    path = tmp_path / "src/lib.rs"
    path.parent.mkdir(exist_ok=True)
    path.write_text(dedent(code).strip(), encoding="utf-8")
    return [f for f in scan_rust_file(str(path), {})[7] if f["rule_id"] == rule]


@pytest.mark.parametrize(
    ("statements", "count"),
    [
        ('jar.add(C::new("session", token));', 1),
        (
            'let c = C::build(("session_id", token)).http_only(true).build(); jar.add(c.clone());',
            1,
        ),
        ('jar.add(C::build(("auth_token", token)).secure(false).build());', 1),
        ('let mut c = C::new("session", token); c.set_secure(false); jar.add(c);', 1),
        ('jar.add(C::build(("session", token)).secure(true).build());', 0),
        ('let mut c = C::new("session", token); c.set_secure(true); jar.add(c);', 0),
        ('let mut c = C::new("session", token); configure(&mut c); jar.add(c);', 0),
        (
            'let mut c = C::new("session", token); if enabled { c.set_secure(true); } jar.add(c);',
            0,
        ),
        ('jar.add(C::build(("session", token)).secure(enabled).build());', 0),
        (
            'jar.add(C::build(("session", token)).same_site(cookie::SameSite::None).build());',
            0,
        ),
        ('jar.add(C::build(("session", token)).partitioned(true).build());', 0),
        ('jar.add(C::new("theme", token));', 0),
        ('jar.add(C::new("session", ""));', 0),
        ('jar.add_original(C::new("session", token));', 0),
        ('let _ = C::new("session", token);', 0),
        ('let c = C::new("session", token); jar.remove(c);', 0),
    ],
)
def test_session_cookie_jar(tmp_path, statements, count):
    rows = findings(
        tmp_path,
        f"""
        use cookie::{{Cookie as C, CookieJar}};
        fn run(token: String, enabled: bool) {{
            let mut jar = CookieJar::new();
            {statements}
        }}
    """,
        "SKY-D252",
    )
    assert len(rows) == count
    if rows:
        assert rows[0]["line"] == 4


@pytest.mark.parametrize(
    ("statement", "count"),
    [
        ('client.get("http://api.example.org/").bearer_auth(token).send().await;', 1),
        (
            'client.get("http://api.example.org/").basic_auth("service", Some(token)).send().await;',
            1,
        ),
        (
            'let f = client.get("http://api.example.org").header("Authorization", token).send(); f.await;',
            1,
        ),
        ('client.get("https://api.example.org").bearer_auth(token).send().await;', 0),
        ('client.get("http://localhost:8080").bearer_auth(token).send().await;', 0),
        ('client.get("http://127.1.2.3").bearer_auth(token).send().await;', 0),
        ('client.get("http://[::1]").bearer_auth(token).send().await;', 0),
        ('client.get("http://api.example.org").send().await;', 0),
        (
            'client.get("http://api.example.org").header("Accept", "text/plain").send().await;',
            0,
        ),
        (
            'let _unpolled = client.get("http://api.example.org").bearer_auth(token).send();',
            0,
        ),
        (
            'let _unused = async { client.get("http://api.example.org").bearer_auth(token).send().await; };',
            0,
        ),
        ("let _ = client.get(url).bearer_auth(token).send().await;", 0),
        (
            'let c = reqwest::Client::builder().https_only(true).build().unwrap(); c.get("http://api.example.org").bearer_auth(token).send().await;',
            0,
        ),
    ],
)
def test_auth_http_dispatch(tmp_path, statement, count):
    rows = findings(
        tmp_path,
        f"""
        async fn run(token: &str, url: &str) {{
            let client = reqwest::Client::new();
            {statement}
        }}
    """,
        "SKY-D356",
    )
    assert len(rows) == count
    if rows:
        assert rows[0]["line"] == 3


def test_blocking_send_and_built_request_exec(tmp_path):
    rows = findings(
        tmp_path,
        """
        use reqwest::blocking::Client as Http;
        pub fn run(token: &str) {
            let c = Http::new();
            c.post("http://api.example.org").bearer_auth(token).send();
            let req = c.get("http://api.example.org").bearer_auth(token).build().unwrap();
            c.execute(req);
        }
    """,
        "SKY-D356",
    )
    assert [r["line"] for r in rows] == [4, 6]


def test_shadowed_api_names_and_test_code_stay_quiet(tmp_path):
    code = """
        mod cookie { pub struct Cookie; pub struct CookieJar; }
        fn config(token: &str) {
            let mut jar = cookie::CookieJar::new();
            jar.add(cookie::Cookie::new("session", token));
        }
        #[test] fn fixture() {
            reqwest::blocking::Client::new().get("http://api.example.org").bearer_auth("demo").send();
        }
    """
    assert findings(tmp_path, code, "SKY-D252") == []
    assert findings(tmp_path, code, "SKY-D356") == []


@pytest.mark.parametrize(
    ("operation", "rule", "count"),
    [
        (
            'client.get("http://api.example.org").basic_auth("user", Some(raw)).send().await;',
            "SKY-D356",
            1,
        ),
        (
            'client.get("https://api.example.org").query(&[("code", raw)]).send().await;',
            "SKY-D391",
            1,
        ),
        (
            'client.get("https://api.example.org").query(&[("code", private.expose_secret())]).send().await;',
            "SKY-D391",
            1,
        ),
        (
            'reqwest::get(format!("https://api.example.org/profile/{raw}")).await;',
            "SKY-D391",
            1,
        ),
        (
            'let u = format!("https://api.example.org/path?q={}", raw); client.get(&u).send().await;',
            "SKY-D391",
            1,
        ),
        (
            'client.get("https://api.example.org").bearer_auth(raw).send().await;',
            "SKY-D391",
            0,
        ),
        (
            'client.get("https://api.example.org").query(&[("public", "value")]).send().await;',
            "SKY-D391",
            0,
        ),
        (
            'client.get("https://api.example.org").query(&[("code", raw.len())]).send().await;',
            "SKY-D391",
            0,
        ),
        (
            'client.get(format!("https://api.example.org/#{}", raw)).send().await;',
            "SKY-D391",
            0,
        ),
        (
            'client.get(format!("https://api.example.org/?n={}", raw.len())).send().await;',
            "SKY-D391",
            0,
        ),
        (
            'client.get(format!("https://api.example.org/?n={:.0}", raw)).send().await;',
            "SKY-D391",
            0,
        ),
        (
            'client.get("https://api.example.org").query(&[("code", raw)]).send();',
            "SKY-D391",
            0,
        ),
    ],
)
def test_secret_url_inputs(tmp_path, operation, rule, count):
    code = f"""
        use secrecy::{{SecretString, ExposeSecret}};
        async fn run(client: &reqwest::Client, private: SecretString) {{
            let raw = private.expose_secret();
            {operation}
        }}
    """
    rows = findings(tmp_path, code, rule)
    assert len(rows) == count
    if rows:
        assert rows[0]["line"] == 4


@pytest.mark.parametrize(
    ("addition", "count"),
    [
        ('HttpResponse::Ok().cookie(Cookie::new("session", token)).finish()', 1),
        (
            'HttpResponse::Ok().cookie(Cookie::build("session", token).secure(true).finish()).finish()',
            0,
        ),
        ('HttpResponse::Ok().cookie(Cookie::new("theme", token)).finish()', 0),
        (
            '{ let mut b = HttpResponse::Ok(); b.cookie(Cookie::new("session", token)); HttpResponse::Ok().finish() }',
            0,
        ),
    ],
)
def test_actix_response_cookie(tmp_path, addition, count):
    rows = findings(
        tmp_path,
        f"""
        use actix_web::{{cookie::Cookie, HttpResponse}};
        fn reply(token: String) -> HttpResponse {{
            {addition}
        }}
    """,
        "SKY-D252",
    )
    assert len(rows) == count


@pytest.mark.parametrize(
    ("addition", "count"),
    [
        ('jar.add(Cookie::new("session", token))', 1),
        ('{ let _ = jar.add(Cookie::new("session", token)); CookieJar::new() }', 0),
        ('jar.add(Cookie::new("theme", token))', 0),
    ],
)
def test_axum_returned_jar(tmp_path, addition, count):
    rows = findings(
        tmp_path,
        f"""
        use axum_extra::extract::cookie::{{CookieJar, Cookie}};
        fn response(jar: CookieJar, token: String) -> CookieJar {{
            {addition}
        }}
    """,
        "SKY-D252",
    )
    assert len(rows) == count


def test_request_replacing_url_or_headers_forgets_outgoing_evidence(tmp_path):
    code = """
        use secrecy::{ExposeSecret, SecretString};
        fn send(client: &reqwest::blocking::Client, secret: &SecretString) {
            let raw = secret.expose_secret();
            let mut req = client.get("http://api.example.org").bearer_auth(raw).build().unwrap();
            req.headers_mut().clear();
            let _ = client.execute(req);
            let mut other = client.get(format!("https://api.example.org/?a={raw}")).build().unwrap();
            *other.url_mut() = "https://api.example.org".parse().unwrap();
            let _ = client.execute(other);
        }
    """
    assert not findings(tmp_path, code, "SKY-D356")
    assert not findings(tmp_path, code, "SKY-D391")


@pytest.mark.parametrize(
    ("preamble", "body", "expected"),
    [
        ('use cookie::Cookie;', 'let cookie = Cookie::new("session", token); let mut jar = cookie::CookieJar::new(); jar.add(cookie);', 1),
        ('use cookie as baked;', 'let baked = 5; let mut jar = baked::CookieJar::new(); jar.add(baked::Cookie::new("session", token));', 1),
        ('use cookie::CookieJar as Store; use cookie::Cookie;', 'let Store = 5; let mut jar = Store::new(); jar.add(Cookie::new("session", token));', 1),
        ('mod cookie { pub struct CookieJar; }', 'let cookie = 5; let mut jar = cookie::CookieJar::new(); jar.add(cookie::Cookie::new("session", token));', 0),
        ('mod local { pub struct CookieJar; } use local as baked;', 'let baked = 5; let mut jar = baked::CookieJar::new(); jar.add(cookie::Cookie::new("session", token));', 0),
    ],
)
def test_local_values_preserve_cookie_type_namespace(tmp_path, preamble, body, expected):
    rows = findings(tmp_path, f"{preamble}\nfn set(token: String) {{ {body} }}", "SKY-D252")
    assert len(rows) == expected
