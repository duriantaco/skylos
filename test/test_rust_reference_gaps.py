import json
from textwrap import dedent

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.rust import scan_rust_file
from test.fixture_paths import write_fixture


def write(tmp_path, name, source):
    return write_fixture(
        tmp_path, f"src/{name}", dedent(source).lstrip(), overwrite=True
    )


@pytest.mark.parametrize("alias", ["Error", "Error as _", "Error as StdError"])
def test_standard_error_trait_method_keeps_import_live(tmp_path, alias):
    path = write(
        tmp_path,
        "lib.rs",
        f"""
        use std::error::{alias};
        pub fn inspect(error: &external::Error) {{ error.source(); }}
        """,
    )
    local = alias.split(" as ")[-1]
    refs = {name for name, _ in scan_rust_file(str(path), {})[1]}
    assert local in refs
    report = json.loads(analyze(str(tmp_path), conf=40, grep_verify=False))
    assert local not in {item["name"] for item in report["unused_imports"]}


@pytest.mark.parametrize(
    "source",
    [
        "use std::error::Error; pub fn inspect() {}",
        'use std::error::Error; pub fn inspect() { let _ = "error.source()"; }',
        "use crate::custom::Error; pub fn inspect(error: Other) { error.source(); }",
        "use std::error::custom::Error; pub fn inspect(error: Other) { error.source(); }",
    ],
)
def test_error_trait_spelling_without_standard_method_use_stays_unused(
    tmp_path, source
):
    path = write(tmp_path, "lib.rs", source)
    refs = {name for name, _ in scan_rust_file(str(path), {})[1]}
    assert "Error" not in refs


def test_error_trait_method_in_other_function_does_not_rescue_local_import(tmp_path):
    path = write(
        tmp_path,
        "lib.rs",
        """
        pub fn inspect(error: External) {
            use std::error::Error as Needed;
            error.source();
        }
        pub fn other() { use std::error::Error as Unused; }
        """,
    )
    refs = {name for name, _ in scan_rust_file(str(path), {})[1]}
    assert "Needed" in refs
    assert "Unused" not in refs


@pytest.mark.parametrize("alias", ["Error as _", "Error as Unused"])
def test_inherent_source_method_does_not_rescue_unused_error_trait(tmp_path, alias):
    path = write(
        tmp_path,
        "lib.rs",
        f"""
        use std::error::{alias};
        struct Local;
        impl Local {{ fn source(&self) {{}} }}
        pub fn inspect(error: Local) {{ error.source(); }}
        """,
    )
    refs = {name for name, _ in scan_rust_file(str(path), {})[1]}
    assert alias.split(" as ")[-1] not in refs


@pytest.mark.parametrize("reference", ["crate::error::upgrade", "error::upgrade"])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_qualified_callback_reaches_only_its_module(tmp_path, reference, grep_verify):
    write(
        tmp_path,
        "lib.rs",
        f"""
        mod error;
        mod unused;
        pub fn run() {{ external().map_err({reference}); }}
        """,
    )
    write(
        tmp_path,
        "error.rs",
        "pub(crate) fn upgrade(error: External) {}\nfn abandoned() {}",
    )
    write(tmp_path, "unused.rs", "pub(crate) fn upgrade(error: External) {}")
    report = json.loads(analyze(str(tmp_path), conf=40, grep_verify=grep_verify))
    unused = {item["full_name"] for item in report["unused_functions"]}
    assert "error.upgrade" not in unused
    assert {"unused.upgrade", "error.abandoned"} <= unused


def test_qualified_callback_in_dead_caller_does_not_become_an_entry(tmp_path):
    write(
        tmp_path,
        "lib.rs",
        "mod error { pub(crate) fn upgrade(error: External) {} } fn abandoned() { external().map_err(crate::error::upgrade); }",
    )
    report = json.loads(analyze(str(tmp_path), conf=40, grep_verify=False))
    assert {"abandoned", "error.upgrade"} <= {
        item["full_name"] for item in report["unused_functions"]
    }


def danger(tmp_path, source):
    path = write(tmp_path, "lib.rs", source)
    return {
        (item["rule_id"], item["line"]) for item in scan_rust_file(str(path), {})[7]
    }


@pytest.mark.parametrize("provider", ["std", "tokio", "async_std"])
@pytest.mark.parametrize("site", ["function", "block"])
def test_matching_cfg_provider_retains_filesystem_audit(tmp_path, provider, site):
    call = "File::open(input);"
    if site == "function":
        body = f'#[cfg(feature="stream")] fn read(input: String) {{ {call} }}'
    elif site == "block":
        body = f'fn read(input: String) {{ #[cfg(feature = "stream")] {{ {call} }} }}'
    findings = danger(
        tmp_path,
        f'#[cfg(feature="stream")] use {provider}::fs::File;\n{body}',
    )
    assert findings == {("SKY-D215", 2)}


@pytest.mark.parametrize(
    "declaration,body",
    [
        (
            '#[cfg(feature="stream")] use tokio::fs::File;',
            "fn read(input: String) { File::open(input); }",
        ),
        (
            '#[cfg(feature="stream")] use tokio::fs::File;',
            '#[cfg(feature="other")] fn read(input: String) { File::open(input); }',
        ),
        (
            '#[cfg(feature="stream")] use custom::File;',
            '#[cfg(feature="stream")] fn read(input: String) { File::open(input); }',
        ),
        (
            '#[cfg(feature="stream")] use tokio::fs::File;',
            '#[cfg(feature="stream")] fn read(input: String) { struct File; File::open(input); }',
        ),
        (
            '#[cfg(feature="stream")] use tokio::fs::File;\nuse custom::File;',
            '#[cfg(feature="stream")] fn read(input: String) { File::open(input); }',
        ),
        (
            '#[cfg(feature="stream")] use tokio::fs::File;',
            '#[cfg(feature="stream")] fn read(input: String) { File::open("fixed"); }',
        ),
    ],
)
def test_unproven_cfg_provider_and_lookalikes_stay_quiet(tmp_path, declaration, body):
    assert danger(tmp_path, f"{declaration}\n{body}") == set()


def test_cfg_function_with_docs_attribute_keeps_known_feature(tmp_path):
    assert danger(
        tmp_path,
        """#[cfg(feature="stream")] use tokio::fs::File;
#[cfg(feature = "stream")]
#[cfg_attr(docsrs, doc(cfg(feature="stream")))]
async fn read(input: String) { File::open(input).await; }
""",
    ) == {("SKY-D215", 4)}


def test_cfg_module_conditions_reach_its_functions(tmp_path):
    assert danger(
        tmp_path,
        """#[cfg(feature="stream")] mod reads {
    #[cfg(feature="stream")] use tokio::fs::File;
    fn read(input: String) { File::open(input); }
}
""",
    ) == {("SKY-D215", 3)}


def test_cfg_attr_import_does_not_claim_unconditional_provider(tmp_path):
    assert (
        danger(
            tmp_path,
            """#[cfg(feature="stream")]
#[cfg_attr(feature="other", cfg(unix))]
use tokio::fs::File;
#[cfg(feature="stream")] fn read(input: String) { File::open(input); }
""",
        )
        == set()
    )


def test_cfg_scope_does_not_leak_to_later_statement(tmp_path):
    assert danger(
        tmp_path,
        """#[cfg(feature="stream")] use tokio::fs::File;
fn read(input: String) {
    #[cfg(feature="stream")] { File::open(input); }
    File::open(input);
}
""",
    ) == {("SKY-D215", 3)}
