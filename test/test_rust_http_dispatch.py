from textwrap import dedent

from skylos.reporting.listing import is_listed
from skylos.visitors.languages.rust import scan_rust_file


def reported_lines(tmp_path, source):
    path = tmp_path / "lib.rs"
    code = dedent(source).strip()
    path.write_text(code, encoding="utf-8")
    findings = scan_rust_file(str(path), {})[7]
    lines = code.splitlines()
    return [
        lines[finding["line"] - 1].strip()
        for finding in findings
        if finding["rule_id"] == "SKY-D216" and is_listed(finding, "danger")
    ]


def test_caller_sends_or_discards_returned_builder(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use reqwest::{Client, RequestBuilder};

        fn prepare(client: &Client, destination: String) -> RequestBuilder {
            client.get(destination)
        }
        async fn handler(Path(input): Path<String>, client: Client) {
            let unused = prepare(&client, input.clone());
            drop(unused);
            let pending = prepare(&client, input);
            let _ = pending.send().await;
        }
        """,
    ) == ["let _ = pending.send().await;"]


def test_built_request_and_execute_future_must_be_used(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use reqwest::Client;

        async fn handler(Path(input): Path<String>, client: Client) {
            let unsent = client.post(input.clone()).build().unwrap();
            drop(unsent);
            let first = client.get(input.clone()).build().unwrap();
            let pending = client.execute(first);
            drop(pending);
            let second = client.get(input).build().unwrap();
            let _ = client.execute(second).await;
        }
        """,
    ) == ["let _ = client.execute(second).await;"]


def test_fixed_service_query_headers_and_body_keep_destination_fixed(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use reqwest::Client;

        async fn handler(Path(input): Path<String>, client: Client) {
            let fixed = client.post("https://service.example/lookup")
                .header("x-input", input.clone())
                .query(&[("name", input.clone())])
                .body(input.clone());
            let _ = fixed.send().await;
            let external = client.post(input).body("payload");
            let _ = external.send().await;
        }
        """,
    ) == ["let _ = external.send().await;"]


def test_blocking_request_is_sent_synchronously(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use reqwest::blocking::Client;

        fn handler(Path(input): Path<String>, client: Client) {
            let unused = client.get(input.clone());
            drop(unused);
            let _ = client.get(input.clone()).send();
            let _ = reqwest::blocking::get(input);
        }
        """,
    ) == [
        "let _ = client.get(input.clone()).send();",
        "let _ = reqwest::blocking::get(input);",
    ]


def test_async_free_function_future_requires_a_real_executor(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use std::future::Future;

        fn spawn<F: Future>(_ignored: F) {}
        async fn handler(Path(input): Path<String>) {
            spawn(reqwest::get(input.clone()));
            let _ignored = reqwest::get(input.clone());
            let _ = tokio::spawn(reqwest::get(input.clone()));
            let _ = reqwest::get(input).await;
        }
        """,
    ) == [
        "let _ = tokio::spawn(reqwest::get(input.clone()));",
        "let _ = reqwest::get(input).await;",
    ]


def test_async_helper_only_dispatches_when_its_caller_runs_it(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use reqwest::Client;

        async fn dispatch(client: &Client, destination: String) {
            let _ = client.get(destination).send().await;
        }
        async fn handler(Path(input): Path<String>, client: Client) {
            drop(dispatch(&client, input.clone()));
            let pending = dispatch(&client, input);
            pending.await;
        }
        """,
    ) == ["pending.await;"]


def test_async_block_only_dispatches_when_polled(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use reqwest::Client;

        async fn handler(Path(input): Path<String>, client: Client) {
            let unused = async {
                let _ = client.get(input.clone()).send().await;
            };
            drop(unused);
            let pending = async move {
                let _ = client.get(input).send().await;
            };
            pending.await;
        }
        """,
    ) == ["pending.await;"]


def test_captured_request_in_called_and_discarded_closures(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        async fn handler(Path(input): Path<String>) {
            let sync_task = || { let _ = reqwest::blocking::get(input.clone()); };
            let unused = async || { let _ = ::reqwest::get(input.clone()).await; };
            drop(unused);
            sync_task();
            let make_task = async || { let _ = reqwest::get(input.clone()).await; };
            drop(make_task());
            make_task().await;
        }
        """,
    ) == ["sync_task();", "make_task().await;"]


def test_execute_uses_current_request_url(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use reqwest::Client;
        use url::Url;

        fn configure(url: &mut Url) {
            *url = Url::parse("https://service.example/").unwrap();
        }
        async fn handler(Path(input): Path<String>, client: Client) {
            let mut replaced = client.get(&input).build().unwrap();
            *replaced.url_mut() = Url::parse("https://service.example/").unwrap();
            let _ = client.execute(replaced).await;
            let mut changed = client.get("https://service.example/").build().unwrap();
            *changed.url_mut() = Url::parse(&input).unwrap();
            let _ = client.execute(changed).await;
            let mut configured = client.get(&input).build().unwrap();
            let url = configured.url_mut();
            configure(url);
            let _ = client.execute(configured).await;
        }
        """,
    ) == ["let _ = client.execute(changed).await;"]


def test_other_clients_keep_findings_in_project_task_wrappers(tmp_path):
    assert reported_lines(
        tmp_path,
        """
        use axum::extract::Path;
        use std::future::Future;

        fn run_task<F: Future<Output = ()> + Send + 'static>(task: F) {
            tokio::spawn(task);
        }
        async fn send(destination: String) {
            let _ = ureq::get(&destination).call();
        }
        async fn handler(Path(input): Path<String>) {
            run_task(async move {
                let _ = ureq::get(&input).call();
                send(input).await;
            });
        }
        """,
    ) == [
        "let _ = ureq::get(&input).call();",
        "send(input).await;",
    ]
