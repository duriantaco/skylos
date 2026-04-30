from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.rust import scan_rust_file


def _scan_rust(tmp_path: Path, code: str, filename: str = "lib.rs") -> tuple:
    file_path = tmp_path / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(code, encoding="utf-8")
    return scan_rust_file(str(file_path), {})


def test_rust_scanner_collects_defs_refs_and_raw_imports(tmp_path):
    defs, refs, _, _, visitor, _, quality, danger, _, _, _, _, raw_imports = _scan_rust(
        tmp_path,
        """
use crate::util::{helper as h, Config};
use std::process::Command;

pub struct User {
    name: String,
}

impl User {
    pub fn new(name: String) -> Self { Self { name } }
    fn private_helper(&self) { h(); }
    pub fn run(&self) { self.private_helper(); }
}

fn stale() {}
""",
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}
    exported = {d.name for d in defs if d.is_exported}

    assert "h" in def_names
    assert "Config" in def_names
    assert "Command" in def_names
    assert "User" in def_names
    assert "User.new" in def_names
    assert "User.private_helper" in def_names
    assert "User.run" in def_names
    assert "stale" in def_names

    assert "h" in ref_names
    assert "private_helper" in ref_names

    assert "User" in exported
    assert "User.new" in exported
    assert "User.run" in exported
    assert "User.private_helper" not in exported
    assert "stale" not in exported

    assert visitor.is_test_file is False
    assert quality == []
    assert danger == []
    assert raw_imports == [
        {
            "source": "crate::util::{helper as h, Config}",
            "names": ["h", "Config"],
            "line": 2,
        },
        {"source": "std::process::Command", "names": ["Command"], "line": 3},
    ]


def test_rust_test_attribute_marks_function_as_test_related(tmp_path):
    defs, _, _, _, visitor, _, _, _, _, _, _, _, _ = _scan_rust(
        tmp_path,
        """
#[test]
fn test_it_works() {}
""",
        filename="tests/user_test.rs",
    )

    test_def = next(d for d in defs if d.name == "test_it_works")

    assert test_def.is_exported is True
    assert visitor.is_test_file is True
    assert visitor.test_decorated_lines


def test_rust_trait_impl_methods_are_exported(tmp_path):
    defs, refs, *_ = _scan_rust(
        tmp_path,
        """
trait Service { fn handle(&self); }
struct User;
impl Service for User {
    fn handle(&self) {}
}
""",
    )

    impl_method = next(d for d in defs if d.name == "User.handle")
    ref_names = {r[0] for r in refs}

    assert impl_method.is_exported is True
    assert {"Service", "User"} <= ref_names


def test_rust_nested_modules_qualify_definitions_and_calls(tmp_path):
    defs, refs, *_ = _scan_rust(
        tmp_path,
        """
pub mod api {
    pub fn route() {
        private();
    }

    fn private() {}
}
""",
    )

    def_names = {d.name for d in defs}
    exported = {d.name for d in defs if d.is_exported}
    ref_names = {r[0] for r in refs}

    assert {"api", "api.route", "api.private"} <= def_names
    assert {"api", "api.route"} <= exported
    assert "api.private" not in exported
    assert "private" in ref_names


def test_rust_external_mod_declaration_is_raw_import(tmp_path):
    defs, _, _, _, _, _, _, _, _, _, _, _, raw_imports = _scan_rust(
        tmp_path,
        """
mod handlers;
""",
    )

    handlers = next(d for d in defs if d.name == "handlers")

    assert handlers.type == "import"
    assert handlers.is_exported is False
    assert raw_imports == [
        {
            "source": "handlers.rs",
            "names": ["handlers"],
            "line": 2,
            "candidates": ["handlers.rs", "handlers/mod.rs"],
        }
    ]


def test_rust_external_mod_declaration_prefers_existing_mod_rs(tmp_path):
    (tmp_path / "src" / "handlers").mkdir(parents=True)
    (tmp_path / "src" / "handlers" / "mod.rs").write_text(
        "pub fn run() {}\n",
        encoding="utf-8",
    )
    file_path = tmp_path / "src" / "lib.rs"
    file_path.write_text(
        """
pub mod handlers;
""",
        encoding="utf-8",
    )

    defs, _, _, _, _, _, _, _, _, _, _, _, raw_imports = scan_rust_file(
        str(file_path), {}
    )
    handlers = next(d for d in defs if d.name == "handlers")

    assert handlers.is_exported is True
    assert raw_imports == [
        {
            "source": "handlers/mod.rs",
            "names": ["handlers"],
            "line": 2,
            "candidates": ["handlers/mod.rs"],
        }
    ]


def test_rust_grouped_use_imports_collect_leaf_names(tmp_path):
    defs, _, _, _, _, _, _, _, _, _, _, _, raw_imports = _scan_rust(
        tmp_path,
        """
use std::{fs, path::PathBuf};
use crate::http::{Client as HttpClient, Response};
""",
    )

    def_names = {d.name for d in defs}

    assert {"fs", "PathBuf", "HttpClient", "Response"} <= def_names
    assert raw_imports == [
        {
            "source": "std::{fs, path::PathBuf}",
            "names": ["fs", "PathBuf"],
            "line": 2,
        },
        {
            "source": "crate::http::{Client as HttpClient, Response}",
            "names": ["HttpClient", "Response"],
            "line": 3,
        },
    ]


def test_rust_src_module_files_use_module_namespace(tmp_path):
    file_path = tmp_path / "src" / "handlers.rs"
    file_path.parent.mkdir(parents=True)
    file_path.write_text(
        """
pub fn run() {
    helper();
}

fn helper() {}
""",
        encoding="utf-8",
    )

    defs, refs, *_ = scan_rust_file(str(file_path), {})

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}

    assert {"handlers.run", "handlers.helper"} <= def_names
    assert "helper" in ref_names


def test_rust_scoped_calls_add_qualified_refs(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
mod api {
    pub fn route() {}
}

fn main() {
    api::route();
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert "api.route" in ref_names
    assert {"api", "route"} <= ref_names
