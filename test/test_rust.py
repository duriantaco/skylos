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

    assert handlers.type == "module"
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


def test_rust_use_imports_emit_project_qualified_refs(tmp_path):
    file_path = tmp_path / "src" / "drivers" / "mysql" / "query.rs"
    file_path.parent.mkdir(parents=True)
    file_path.write_text(
        """
use super::helpers::{escape_identifier as escape, is_wkt_geometry};

fn run() {
    escape("table");
    is_wkt_geometry("point");
}
""",
        encoding="utf-8",
    )

    _, refs, *_ = scan_rust_file(str(file_path), {})
    ref_names = {r[0] for r in refs}

    assert "drivers.mysql.helpers.escape_identifier" in ref_names
    assert "drivers.mysql.helpers.is_wkt_geometry" in ref_names


def test_rust_function_signatures_scan_type_parameters_and_return_types(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
use tauri::{AppHandle, Runtime};
use crate::models::RoutineInfo;

pub async fn get_routines<R: Runtime>(
    app: AppHandle<R>,
) -> Result<Vec<RoutineInfo>, String> {
    todo!()
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert {"Runtime", "AppHandle", "RoutineInfo"} <= ref_names


def test_rust_trait_signatures_and_attribute_macros_are_refs(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
use async_trait::async_trait;
use crate::models::{ConnectionParams, RoutineInfo};

#[async_trait]
pub trait DatabaseDriver {
    async fn get_routines(
        &self,
        params: &ConnectionParams,
    ) -> Result<Vec<RoutineInfo>, String>;
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert {"async_trait", "ConnectionParams", "RoutineInfo"} <= ref_names


def test_rust_impl_attribute_macros_are_refs(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
use async_trait::async_trait;

trait Service {
    fn run(&self);
}

struct Driver;

#[async_trait]
impl Service for Driver {
    fn run(&self) {}
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert "async_trait" in ref_names


def test_rust_external_trait_import_method_usage_marks_import_live(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
use futures::StreamExt;
use sqlx::{Column, Row, ValueRef};
use std::io::{Read, Write};
use tauri::{Emitter, Manager};

fn run(stream: &mut Stream, row: RowLike, column: ColumnLike, value: ValueLike) {
    stream.next();
    row.try_get_raw(0);
    column.type_info();
    value.is_null();
    file.read_to_end(&mut bytes);
    out.write_all(&bytes);
    app.emit("event", ());
    app.path();
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert {"StreamExt", "Row", "Column", "ValueRef", "Read", "Write"} <= ref_names
    assert {"Emitter", "Manager"} <= ref_names


def test_rust_generic_trait_method_calls_mark_trait_import_live(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
use sqlx::Row;

fn run(row: RowLike, index: usize) {
    row.try_get::<Vec<u8>, _>(index);
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert "Row" in ref_names


def test_rust_type_alias_rhs_is_scanned_for_trait_objects(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
use tokio_postgres::types::ToSql;

type PgParam = Box<dyn ToSql + Send + Sync>;
""",
    )

    ref_names = {r[0] for r in refs}

    assert "ToSql" in ref_names


def test_rust_local_extension_trait_import_not_rescued_by_method_name(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
use crate::traits::WidgetExt;

fn run(widget: Widget) {
    widget.next();
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert "next" in ref_names
    assert "WidgetExt" not in ref_names


def test_rust_inline_module_calls_emit_sibling_refs(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
mod tls_tests {
    fn params_with_ssl() {}

    #[test]
    fn test_tls_connector_disable() {
        params_with_ssl();
    }
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert "tls_tests.params_with_ssl" in ref_names


def test_rust_restricted_visibility_is_not_exported(tmp_path):
    defs, *_ = _scan_rust(
        tmp_path,
        """
pub(crate) fn crate_only() {}
pub(super) fn parent_only() {}
pub(in crate::api) fn scoped_only() {}
pub fn external() {}
""",
    )

    exported = {d.name for d in defs if d.is_exported}

    assert "external" in exported
    assert "crate_only" not in exported
    assert "parent_only" not in exported
    assert "scoped_only" not in exported


def test_rust_generic_impl_methods_are_collected(tmp_path):
    defs, refs, *_ = _scan_rust(
        tmp_path,
        """
struct Boxed<T>(T);

impl<T> Boxed<T> {
    pub fn new(value: T) -> Self { Self(value) }
    fn helper(&self) {}
}
""",
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}
    exported = {d.name for d in defs if d.is_exported}

    assert {"Boxed.new", "Boxed.helper"} <= def_names
    assert "Boxed" in ref_names
    assert "Boxed.new" in exported
    assert "Boxed.helper" not in exported


def test_rust_generic_trait_impl_methods_are_exported(tmp_path):
    defs, refs, *_ = _scan_rust(
        tmp_path,
        """
trait Service<T> { fn handle(&self, value: T); }
struct Boxed<T>(T);

impl<'a, T> Service<T> for Boxed<T> where T: Clone {
    fn handle(&self, value: T) {
        self.helper();
    }
}

impl<T> Boxed<T> {
    fn helper(&self) {}
}
""",
    )

    impl_method = next(d for d in defs if d.name == "Boxed.handle")
    ref_names = {r[0] for r in refs}

    assert impl_method.is_exported is True
    assert {"Service", "Boxed", "helper"} <= ref_names


def test_rust_trait_default_methods_are_collected_and_scanned(tmp_path):
    defs, refs, *_ = _scan_rust(
        tmp_path,
        """
trait Service {
    fn defaulted(&self) {
        helper();
    }
    fn required(&self);
}

fn helper() {}
""",
    )

    def_names = {d.name for d in defs}
    ref_names = {r[0] for r in refs}
    exported = {d.name for d in defs if d.is_exported}

    assert {"Service.defaulted", "Service.required"} <= def_names
    assert {"Service.defaulted", "Service.required"} <= exported
    assert "helper" in ref_names


def test_rust_glob_import_is_raw_import_without_import_def(tmp_path):
    defs, _, _, _, _, _, _, _, _, _, _, _, raw_imports = _scan_rust(
        tmp_path,
        """
use crate::handlers::*;
""",
    )

    assert {d.type for d in defs} == set()
    assert raw_imports == [{"source": "crate::handlers::*", "names": ["*"], "line": 2}]


def test_rust_serde_attrs_and_field_types_are_references(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct ModelList {
    models: Vec<Model>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Deserialize)]
struct Model {
    id: String,
}

fn default_true() -> bool { true }
""",
    )

    ref_names = {r[0] for r in refs}

    assert {"Serialize", "Deserialize", "Model", "default_true"} <= ref_names


def test_rust_callback_methods_and_registration_macros_are_references(tmp_path):
    _, refs, *_ = _scan_rust(
        tmp_path,
        """
struct StatementStream;

impl StatementStream {
    fn next_statement(&mut self) -> Option<String> { None }
}

fn parse_json_number(_: &serde_json::Value) -> Option<f64> { None }
fn refresh_and_collect_system_stats() {}
fn is_debug_mode() -> bool { true }
fn close_devtools() {}

fn run(value: Option<&serde_json::Value>, stream: &mut StatementStream) {
    value.and_then(parse_json_number);
    tokio::task::spawn_blocking(refresh_and_collect_system_stats);
    stream.next_statement();
    tauri::generate_handler![is_debug_mode, close_devtools];
}
""",
    )

    ref_names = {r[0] for r in refs}

    assert {
        "parse_json_number",
        "refresh_and_collect_system_stats",
        "next_statement",
        "is_debug_mode",
        "close_devtools",
    } <= ref_names
