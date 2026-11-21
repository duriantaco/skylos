"""Rust security source model: only request data is listed.

Environment variables, command-line arguments and library parameters are
operator or calling-code input: D212/D215 sinks they reach stay in the report
as unlisted review items. Request extractors, Rocket route parameters and
request objects are request data. SSRF (D216) and XSS (D228) need request
data; TLS verification off (D210) is structural.
"""

from __future__ import annotations

from pathlib import Path

from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.listing import is_listed, is_unproven_source_review
from skylos.visitors.languages.rust import scan_rust_file


def _scan(tmp_path: Path, code: str, name: str = "lib.rs") -> list[dict]:
    file_path = tmp_path / name
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(code, encoding="utf-8")
    return scan_rust_file(str(file_path), {})[7]


def _rows(findings, rule):
    return [
        (f["line"], is_unproven_source_review(f))
        for f in findings
        if f["rule_id"] == rule
    ]


# --- operator and library input: review, not listed -------------------------


def test_env_var_path_is_an_unlisted_review_item(tmp_path):
    findings = _scan(
        tmp_path,
        """use std::{env, fs};
fn load() {
    let path = env::var("APP_CONFIG").unwrap();
    fs::read_to_string(path).unwrap();
}
""",
    )
    [finding] = [f for f in findings if f["rule_id"] == "SKY-D215"]
    assert is_unproven_source_review(finding)
    assert finding["metadata"]["rust_source"] == "operator_input"
    assert finding["message"].startswith("Review (not listed, not blocking)")
    view = apply_advice_policy({"danger": [finding]})
    assert not is_listed(view["danger"][0], "danger")


def test_cli_argument_command_and_library_parameter_are_review_items(tmp_path):
    findings = _scan(
        tmp_path,
        """use std::{env, fs, process::Command};
pub fn run() {
    let program = env::args().nth(1).unwrap();
    Command::new(program).spawn().unwrap();
}
pub fn search_path(path: &str) {
    fs::read(path).unwrap();
}
""",
    )
    assert _rows(findings, "SKY-D212") == [(4, True)]
    assert _rows(findings, "SKY-D215") == [(7, True)]


def test_request_source_never_counts_as_unproven(tmp_path):
    findings = _scan(
        tmp_path,
        """use actix_web::web::Query;
use std::fs;
async fn download(Query(params): Query<Params>) {
    fs::read(params.name).unwrap();
}
""",
    )
    [finding] = [f for f in findings if f["rule_id"] == "SKY-D215"]
    assert not is_unproven_source_review(finding)
    assert "review_item" not in finding
    forged = {
        **finding,
        "metadata": {**finding["metadata"], "rust_source": "operator_input"},
    }
    assert not is_unproven_source_review(forged)


# --- request sources --------------------------------------------------------


def test_axum_path_extractor_reaching_a_command_is_listed(tmp_path):
    findings = _scan(
        tmp_path,
        """use axum::extract::Path;
use std::process::Command;
async fn run(Path(tool): Path<String>) {
    Command::new(tool).output().unwrap();
}
""",
    )
    assert _rows(findings, "SKY-D212") == [(4, False)]


def test_numeric_extractor_is_not_request_text(tmp_path):
    findings = _scan(
        tmp_path,
        """use actix_web::web::Path;
async fn show(id: Path<i64>, client: &reqwest::Client) {
    client.get(format!("{}", id)).send();
}
""",
    )
    assert _rows(findings, "SKY-D216") == []


def test_rocket_route_parameter_text_is_request_data(tmp_path):
    findings = _scan(
        tmp_path,
        """use std::fs;
#[get("/files/<name>?<page>")]
fn file(name: &str, page: i32, id: CipherId) {
    fs::read(name).unwrap();
    fs::read(format!("{page}")).unwrap();
    fs::read(id.to_string()).unwrap();
}
""",
    )
    assert _rows(findings, "SKY-D215") == [(4, False)]


def test_actix_glob_import_provides_extractors(tmp_path):
    findings = _scan(
        tmp_path,
        """use actix_web::{web::*, HttpRequest};
async fn proxy(Query(params): Query<Params>, client: Data<reqwest::Client>) {
    client.get(params.url).send().await;
}
""",
    )
    assert _rows(findings, "SKY-D216") == [(3, False)]


def test_request_object_data_but_not_server_state(tmp_path):
    findings = _scan(
        tmp_path,
        """use actix_web::HttpRequest;
use reqwest::Client;
async fn hop(req: HttpRequest) {
    let client = Client::new();
    client.get(req.query_string()).send().await;
    client.get(req.app_data::<String>().unwrap()).send().await;
}
""",
    )
    assert _rows(findings, "SKY-D216") == [(5, False)]


# --- SSRF -------------------------------------------------------------------


def test_fixed_host_and_encoded_values_are_not_ssrf(tmp_path):
    findings = _scan(
        tmp_path,
        """use axum::extract::Query;
use reqwest::Client;
use urlencoding::encode;
async fn f(Query(q): Query<Params>, base: &str) {
    let client = Client::new();
    client.get(format!("https://api.example.com/users/{}", q.name)).send().await;
    client.get(format!("{}/users/{}", base, q.name)).send().await;
    client.get(format!("{}?u={}", base, encode(&q.name))).send().await;
    client.get(format!("{}{}", base, q.path)).send().await;
    client.get(format!("https://{}/x", q.host)).send().await;
}
""",
    )
    assert _rows(findings, "SKY-D216") == [(9, False), (10, False)]


def test_ssrf_through_local_helpers_is_reported_at_the_handler_call(tmp_path):
    findings = _scan(
        tmp_path,
        """use actix_web::web::{Data, Query};
use reqwest_middleware::ClientWithMiddleware;
fn send(client: &ClientWithMiddleware, url: String) {
    client.request(reqwest::Method::GET, url);
}
async fn fetch(url: String, client: &ClientWithMiddleware) {
    send(client, url);
}
async fn handler(Query(params): Query<Params>, client: Data<ClientWithMiddleware>) {
    let target = params.target_url();
    fetch(target, &client).await;
}
async fn internal(client: Data<ClientWithMiddleware>) {
    fetch(String::from("http://localhost/x"), &client).await;
}
""",
    )
    [finding] = [f for f in findings if f["rule_id"] == "SKY-D216"]
    assert finding["line"] == 11
    assert "fetch() -> send() -> client.request()" in finding["message"]
    assert (
        finding["metadata"]["rust_flow"]["via"]
        == "fetch() -> send() -> client.request()"
    )


def test_env_url_is_not_ssrf(tmp_path):
    findings = _scan(
        tmp_path,
        """use reqwest::Client;
async fn f() {
    let url = std::env::var("API").unwrap();
    Client::new().get(url).send().await;
}
""",
    )
    assert _rows(findings, "SKY-D216") == []


def test_stored_rows_are_not_request_data_but_written_rows_are(tmp_path):
    findings = _scan(
        tmp_path,
        """use actix_web::web::Json;
use webmention::Webmention;
async fn create(data: Json<CreatePost>, context: Data<Ctx>) {
    let post = Post::read(&mut context.pool(), data.id).await.unwrap();
    Webmention::new(post.ap_id.clone(), post.url.clone());
    let form = PostForm { url: data.url.clone() };
    let inserted = Post::create(&mut context.pool(), &form).await.unwrap();
    if let Some(url) = inserted.url.clone() {
        Webmention::new::<Url>(inserted.ap_id.clone(), url);
    }
}
""",
    )
    assert _rows(findings, "SKY-D216") == [(9, False)]


def test_validator_guard_and_index_selection_stop_request_data(tmp_path):
    findings = _scan(
        tmp_path,
        """use std::{fs, process::Command};
fn is_valid_domain(domain: &str) -> bool {
    domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
}
#[get("/<domain>/icon.png")]
fn icon(domain: &str) {
    if !is_valid_domain(domain) {
        return;
    }
    fs::read(format!("/cache/{domain}.png")).unwrap();
}
#[get("/run/<tool>")]
fn run(tool: &str) {
    let tools = ["gzip", "xz"];
    let index = tool.len() % 2;
    Command::new(tools[index]).spawn().unwrap();
}
""",
    )
    assert _rows(findings, "SKY-D215") == []
    assert _rows(findings, "SKY-D212") == []


# --- XSS --------------------------------------------------------------------


def test_route_parameter_in_html_markup_is_xss(tmp_path):
    findings = _scan(
        tmp_path,
        """use html_escape::encode_text;
#[get("/breach?<username>")]
async fn breach(username: &str) -> JsonResult {
    Ok(Json(json!({
        "description": format!("Go to <a href=\\"https://x.example/{username}\\">{username}</a>"),
    })))
}
#[get("/safe?<username>")]
async fn safe(username: &str) -> String {
    let encoded: String = url::form_urlencoded::byte_serialize(username.as_bytes()).collect();
    let a = format!("<a href=\\"/u/{encoded}\\">x</a>");
    let b = format!("<b>{}</b>", encode_text(username));
    let c = format!("user {username} not found");
    let d = format!("expected Option<String>, got {username}");
    a + &b + &c + &d
}
fn render(name: &str) -> String {
    format!("<p>{name}</p>")
}
""",
    )
    assert _rows(findings, "SKY-D228") == [(5, False)]


def test_html_built_by_a_helper_is_reported_at_the_call(tmp_path):
    findings = _scan(
        tmp_path,
        """use axum::extract::Query;
fn page(title: &str) -> String {
    format!("<h1>{}</h1>", title)
}
async fn show(Query(q): Query<Params>) -> String {
    page(&q.title)
}
""",
    )
    assert _rows(findings, "SKY-D228") == [(6, False)]


def test_request_ssrf_and_xss_in_test_code_are_not_reported(tmp_path):
    findings = _scan(
        tmp_path,
        """#[cfg(test)]
mod tests {
    use axum::extract::Query;
    async fn f(Query(q): Query<Params>) -> String {
        reqwest::get(q.url).await;
        format!("<p>{}</p>", q.name)
    }
}
""",
    )
    assert _rows(findings, "SKY-D216") == [] and _rows(findings, "SKY-D228") == []


# --- TLS verification off ---------------------------------------------------


_VERIFIER = """use rustls::client::danger::{{ServerCertVerified, ServerCertVerifier}};
#[derive(Debug)]
struct NoCertVerifier {{}}
impl ServerCertVerifier for NoCertVerifier {{
    fn verify_server_cert(&self, _e: &CertificateDer, _i: &[CertificateDer], _n: &ServerName, _o: &[u8], _t: UnixTime) -> Result<ServerCertVerified, rustls::Error> {{
        {body}
    }}
}}
"""


def test_accept_all_certificate_verifier_is_reported(tmp_path):
    body = "// accept everything\n        Ok(ServerCertVerified::assertion())"
    findings = _scan(tmp_path, _VERIFIER.format(body=body))
    [finding] = [f for f in findings if f["rule_id"] == "SKY-D210"]
    assert finding["line"] == 5
    assert "NoCertVerifier" in finding["message"]


def test_checking_verifier_and_test_verifier_are_not_reported(tmp_path):
    body = (
        "if pinned(_e) { return Ok(ServerCertVerified::assertion()); }\n"
        "        Err(rustls::Error::General(String::new()))"
    )
    assert not _rows(_scan(tmp_path, _VERIFIER.format(body=body)), "SKY-D210")
    accept = "Ok(ServerCertVerified::assertion())"
    findings = _scan(
        tmp_path, "#[cfg(test)]\nmod tests {\n" + _VERIFIER.format(body=accept) + "}\n"
    )
    assert not _rows(findings, "SKY-D210")
    findings = _scan(tmp_path, _VERIFIER.format(body=accept), name="tests/tls.rs")
    assert not _rows(findings, "SKY-D210")


def test_dangerous_client_switches(tmp_path):
    findings = _scan(
        tmp_path,
        """use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
fn clients(strict: bool) {
    reqwest::Client::builder().danger_accept_invalid_certs(true).build();
    reqwest::Client::builder().danger_accept_invalid_hostnames(true).build();
    reqwest::Client::builder().danger_accept_invalid_certs(strict).build();
    reqwest::Client::builder().danger_accept_invalid_certs(false).build();
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_verify(SslVerifyMode::PEER);
}
""",
    )
    assert [line for line, _ in _rows(findings, "SKY-D210")] == [3, 4, 8]
