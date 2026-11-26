import json
import subprocess
import sys

import pytest

from skylos.visitors.languages.rust.effective_visibility import complete_target_set
from skylos.visitors.languages.rust.project_model import build_project
from test.test_rust_dead_code_precision import CARGO, _names, _report


def test_private_parent_does_not_export_every_pub_function(tmp_path):
    report = _report(
        tmp_path,
        {
            "src/lib.rs": """
            mod implementation;
            pub use implementation::published as api;
            pub mod surface { pub fn downstream() { super::implementation::invoked(); } }
        """,
            "src/implementation.rs": """
            pub fn published() {}
            pub fn invoked() {}
            pub fn abandoned() {}
            mod nested { pub fn retired() {} }
        """,
        },
    )
    assert _names(report, "unused_functions") == {"abandoned", "retired"}


def test_reexported_module_and_glob_preserve_public_surface(tmp_path):
    report = _report(
        tmp_path,
        {
            "src/lib.rs": """
            mod hidden {
                pub mod subset { pub fn renamed_api() {} }
                pub fn glob_api() {}
                mod nested { pub fn unused() {} }
            }
            mod bridge { pub use crate::hidden::subset as renamed; }
            pub use bridge::renamed as published;
            pub use hidden::*;
        """,
        },
    )
    assert _names(report, "unused_functions") == {"unused"}


@pytest.mark.parametrize(
    "addition",
    [
        "generate_public_api!();",
        '#[cfg(feature = "api")] pub use hidden::possible as exposed;',
        '#[cfg_attr(feature = "other", path = "alternate.rs")] mod routes;',
        "mod missing;",
        "pub use unknown::*;",
    ],
)
def test_incomplete_export_proof_keeps_public_spelling(tmp_path, addition):
    report = _report(
        tmp_path,
        {
            "src/lib.rs": "mod hidden { pub fn possible() {} }\n" + addition,
        },
    )
    assert "possible" not in _names(report, "unused_functions")


def test_shared_file_can_be_public_through_another_cargo_target(tmp_path):
    report = _report(
        tmp_path,
        {
            "src/lib.rs": "mod common;",
            "src/common.rs": "pub fn shared() {}",
            "src/main.rs": "pub mod common; fn main() {}",
        },
    )
    assert "shared" not in _names(report, "unused_functions")


def test_include_in_another_cargo_target_can_expose_private_module_file(tmp_path):
    report = _report(
        tmp_path,
        {
            "src/lib.rs": 'include!("common.rs");',
            "src/common.rs": "pub fn exposed() {}",
            "src/main.rs": "mod common; fn main() {}",
        },
    )
    assert "exposed" not in _names(report, "unused_functions")


def test_missing_declared_cargo_target_abstains(tmp_path):
    report = _report(
        tmp_path,
        {
            "Cargo.toml": CARGO.format(edition="2021")
            + '[[bin]]\nname = "other"\npath = "generated.rs"\n',
            "src/lib.rs": "mod common { pub fn possible() {} }",
        },
    )
    assert "possible" not in _names(report, "unused_functions")


def test_literal_path_and_doc_attributes_preserve_complete_module_tree(tmp_path):
    report = _report(
        tmp_path,
        {
            "src/lib.rs": '#![doc = "crate docs"]\n#[path = "alternate.rs"] mod hidden;\npub use hidden::child::public_api;',
            "src/alternate.rs": "pub mod child;",
            "src/child.rs": '#[doc = r#"published"#]\npub fn public_api() {}\npub fn retired() {}',
        },
    )
    assert _names(report, "unused_functions") == {"retired"}
    # Simulate an exclusion: the declared file exists, but discovery omitted it.
    model = build_project(tmp_path, [tmp_path / "src/lib.rs"])
    assert not complete_target_set(model)


def test_cli_lists_only_hidden_unused_function_at_experimental_threshold(tmp_path):
    root = tmp_path / "demo"
    source = root / "src"
    source.mkdir(parents=True)
    (root / "Cargo.toml").write_text(CARGO.format(edition="2021"))
    (source / "lib.rs").write_text("mod hidden;\npub use hidden::exported as api;\n")
    (source / "hidden.rs").write_text("pub fn exported() {}\npub fn retired() {}\n")
    output = tmp_path / "report.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "skylos.cli",
            str(root),
            "--confidence",
            "40",
            "--no-upload",
            "--format",
            "json",
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
    )
    report = json.loads(output.read_text())
    assert [(f["name"], f["confidence"]) for f in report["unused_functions"]] == [
        ("retired", 40)
    ]
