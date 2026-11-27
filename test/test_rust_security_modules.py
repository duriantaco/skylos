import json
from pathlib import Path

import pytest

from skylos import analyze
from skylos.visitors.languages.rust.project_model import build_project
from skylos.visitors.languages.rust.project_security import sibling_http_findings

HELPER = """use reqwest::Client;
pub(super) async fn deliver(client: &Client, destination: String) {
    let _ = client.get(destination).send().await;
}
"""


def project(root, caller, helper=HELPER):
    source = root / "src"
    source.mkdir()
    (root / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.1.0"\nedition="2021"\n'
    )
    (source / "transport.rs").write_text(helper)
    (source / "lib.rs").write_text(caller)
    return source


def findings(root, files=None):
    files = list(files if files is not None else (root / "src").glob("*.rs"))
    return sibling_http_findings(build_project(root, files), set(map(str, files)))


@pytest.mark.parametrize(
    ("imports", "callee"),
    [
        ("use transport::deliver as forward;", "forward"),
        ("use crate::transport as outbound;", "outbound::deliver"),
        ("", "crate::transport::deliver"),
    ],
)
def test_awaited_sibling_helper(tmp_path, imports, callee):
    project(
        tmp_path,
        f"""mod transport;
{imports}
use axum::extract::Query;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {{
    {callee}(&client, url).await;
}}
""",
    )
    [row] = findings(tmp_path)
    assert row["rule_id"] == "SKY-D216"
    assert (Path(row["file"]).name, row["line"]) == ("lib.rs", 5)
    assert "transport::deliver" in row["message"]


@pytest.mark.parametrize(
    "body",
    [
        "let _ = deliver(&client, url);",
        'deliver(&client, "https://example.org".into()).await;',
        "let deliver = |_, _| async {}; deliver(&client, url).await;",
    ],
)
def test_unused_fixed_or_shadowed_sibling_helper(tmp_path, body):
    project(
        tmp_path,
        f"""mod transport;
use transport::deliver;
use axum::extract::Query;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {{
    {body}
}}
""",
    )
    assert not findings(tmp_path)


@pytest.mark.parametrize(
    "declaration",
    [
        '#[cfg(feature = "extra")] mod transport;',
        '#[cfg_attr(feature = "extra", path = "alternate.rs")] mod transport;',
        '#[path = "transport.rs"] mod transport;',
        "",
    ],
)
def test_only_unconditional_declared_modules_supply_evidence(tmp_path, declaration):
    project(
        tmp_path,
        f"""{declaration}
use axum::extract::Query;
use transport::deliver;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {{
    deliver(&client, url).await;
}}
""",
    )
    assert not findings(tmp_path)


def test_unselected_helper_and_ambiguous_module_stay_quiet(tmp_path):
    src = project(
        tmp_path,
        """mod transport;
use axum::extract::Query;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {
    transport::deliver(&client, url).await;
}
""",
    )
    assert not findings(tmp_path, [src / "lib.rs"])
    (src / "transport").mkdir()
    (src / "transport/mod.rs").write_text(HELPER)
    assert not findings(tmp_path, src.rglob("*.rs"))


def test_returned_sibling_builder_is_reported_only_when_sent(tmp_path):
    project(
        tmp_path,
        """mod transport;
use axum::extract::Query;
use transport::prepare;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {
    drop(prepare(&client, url.clone()));
    let _ = prepare(&client, url).send().await;
}
""",
        helper="""use reqwest::{Client, RequestBuilder};
pub(super) fn prepare(client: &Client, destination: String) -> RequestBuilder {
    client.get(destination)
}
""",
    )
    [row] = findings(tmp_path)
    assert row["line"] == 6


def test_handlers_in_sibling_module_resolve_super_paths(tmp_path):
    src = project(tmp_path, "mod handlers; mod transport;")
    (src / "handlers.rs").write_text("""use axum::extract::Query;
use super::transport::deliver;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {
    deliver(&client, url).await;
}
""")
    [row] = findings(tmp_path)
    assert Path(row["file"]).name == "handlers.rs"


def test_other_clients_do_not_gain_reqwest_dispatch_evidence(tmp_path):
    project(
        tmp_path,
        """mod transport;
use axum::extract::Query;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {
    transport::deliver(&client, url).await;
}
""",
        helper="""use reqwest::Client;
pub(super) async fn deliver(_client: &Client, destination: String) {
    ureq::get(&destination);
}
""",
    )
    assert not findings(tmp_path)


def test_test_only_dispatch_does_not_reach_production_caller(tmp_path):
    project(
        tmp_path,
        """mod transport;
use axum::extract::Query;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {
    transport::deliver(&client, url).await;
}
""",
        helper=HELPER.replace("    let _", "    #[cfg(test)]\n    let _"),
    )
    assert not findings(tmp_path)


def test_project_entrypoint_honors_rule_and_file_selection(tmp_path):
    src = project(
        tmp_path,
        """mod transport;
use axum::extract::Query;
async fn handler(Query(url): Query<String>, client: reqwest::Client) {
    transport::deliver(&client, url).await;
}
""",
    )

    def rows(path, **options):
        report = json.loads(
            analyze(str(path), grep_cache=False, enable_danger=True, **options)
        )
        return [
            (Path(row["file"]).name, row["line"])
            for row in report.get("danger", ())
            if row["rule_id"] == "SKY-D216"
        ]

    assert rows(tmp_path) == [("lib.rs", 4)]
    assert rows(src / "lib.rs") == []
    assert rows(tmp_path, project_config_overrides={"ignore": ["SKY-D216"]}) == []
