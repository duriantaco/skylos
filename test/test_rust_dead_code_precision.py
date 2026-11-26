"""Rust dead-code precision changes, each with what it removes and what stays.

1. trait imports abstain unless provably not a trait;
2. `use` trees resolved leaf by leaf, through re-exports and aliases;
3. test/bench harness attributes are entry points;
4. associated types, patterns, format strings, attribute calls, tuple fields,
   alias right-hand sides and local macro bodies are read;
5. a crate cannot capture another crate's bare-named definition;
6. methods on receivers typed by a re-exported type are credited;
7. `#[allow(dead_code)]` / `#[allow(unused_imports)]` and cfg alternatives.
"""

import json
from textwrap import dedent

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.rust.core import is_harness_attribute, use_tree_leaves
from skylos.visitors.languages.rust.project_model import build_project

CARGO = '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "{edition}"\n'


def _report(tmp_path, files, *, edition="2021", manifest=True):
    if manifest:
        files = {"Cargo.toml": CARGO.format(edition=edition), **files}
    for relative, text in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text).lstrip())
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=40,
            grep_verify=False,
            grep_cache=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return result


def _names(result, category):
    return {item.get("simple_name", item["name"]) for item in result.get(category, [])}


def _abstained(result):
    return {item["name"] for item in result.get("dead_code_abstentions", [])}


def _whitelisted(result):
    return {(item["name"], item["reason"]) for item in result.get("whitelisted", [])}


# 1. Trait imports ---------------------------------------------------------


def test_external_trait_used_through_methods_abstains(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            use bstr::ByteSlice;
            fn main() { let text = b"abc"; let _ = text.find_byte(b'a'); }
            """
        },
    )
    assert "ByteSlice" not in _names(result, "unused_imports")
    assert "ByteSlice" in _abstained(result)


def test_underscore_trait_import_is_never_a_finding(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            use std::fmt::Write as _;
            fn main() { let mut text = String::new(); write!(text, "x").unwrap(); }
            """
        },
    )
    assert _names(result, "unused_imports") == set()
    assert "_" not in _abstained(result)


def test_project_trait_used_only_through_methods_abstains(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod traits;
            use crate::traits::{Crud, Post};
            fn main() { let _ = Post.create(); }
            """,
            "src/traits.rs": """
            pub(crate) trait Crud { fn create(&self) -> u8; }
            pub(crate) struct Post;
            impl Crud for Post { fn create(&self) -> u8 { 1 } }
            """,
        },
    )
    assert "Crud" not in _names(result, "unused_imports")
    assert "Crud" in _abstained(result)


def test_trait_used_through_an_associated_path_abstains(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            use std::str::FromStr;
            fn main() { let _ = url::Url::from_str("https://example.com"); }
            """
        },
    )
    assert "FromStr" not in _names(result, "unused_imports")


def test_imports_that_cannot_be_traits_are_still_reported(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod model;
            use std::collections::HashMap;
            use std::fs;
            use crate::model::Thing;
            use serde_json::Value;
            fn main() {}
            """,
            "src/model.rs": "pub(crate) struct Thing;\n",
        },
    )
    # A std type, a module, a project struct, and an unknown external item
    # whose scope calls no method and names no associated item.
    assert {"HashMap", "fs", "Thing", "Value"} <= _names(result, "unused_imports")


def test_std_trait_with_no_member_reached_is_reported(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            use std::io::Read;
            use serde_json::Value;
            fn main() { let text = String::new(); let _ = text.len(); }
            """
        },
    )
    unused = _names(result, "unused_imports")
    # `len` is not a member of io::Read, so Read is provably unused; any
    # method call could reach an unknown external trait, so Value abstains.
    assert "Read" in unused
    assert "Value" not in unused
    assert "Value" in _abstained(result)


def test_project_trait_whose_members_are_never_reached_is_reported(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod traits { pub trait Stamp { fn stamp(&self) -> u8; } }
            use traits::Stamp;
            fn main() { let value = 1; let _ = value.to_string(); }
            """
        },
    )
    assert "Stamp" in _names(result, "unused_imports")


@pytest.mark.parametrize("edition,reported", [("2021", True), ("2018", False)])
def test_redundant_prelude_trait_import_is_reported_by_edition(
    tmp_path, edition, reported
):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            use std::convert::TryInto;
            fn main() { let value: u32 = 1; let _: u8 = value.try_into().unwrap(); }
            """
        },
        edition=edition,
    )
    assert ("TryInto" in _names(result, "unused_imports")) is reported


@pytest.mark.parametrize(
    "attribute, redundant",
    [
        ("#![no_std]", False),
        ('#![cfg_attr(not(feature = "std"), no_std)]', False),
        ("#![cfg_attr(unix, cfg_attr(debug_assertions, no_std))]", False),
        ('#![cfg_attr(no_std, doc = "no_std")]', True),
        ("", True),
    ],
)
def test_alloc_trait_import_uses_the_crate_prelude(tmp_path, attribute, redundant):
    result = _report(
        tmp_path,
        {
            "src/lib.rs": f"{attribute}\nextern crate alloc;\nmod labels;",
            "src/labels.rs": """
            use alloc::string::ToString;
            use alloc::borrow::ToOwned;
            pub fn label(value: u8) -> alloc::string::String { value.to_string() }
            """,
        },
    )
    unused = _names(result, "unused_imports")
    assert ("ToString" in unused) is redundant
    assert "ToOwned" in unused


def test_shared_source_keeps_traits_needed_by_a_no_std_target(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/lib.rs": "#![no_std]\nextern crate alloc;\nmod labels;",
            "src/main.rs": "extern crate alloc;\nmod labels;\nfn main() {}",
            "src/labels.rs": """
            use alloc::borrow::ToOwned;
            pub fn label(value: &str) -> alloc::string::String { value.to_owned() }
            """,
        },
    )
    assert "ToOwned" not in _names(result, "unused_imports")


# 2. Use trees, re-exports and aliases -------------------------------------


def test_use_tree_leaves_keep_every_segment():
    leaves = use_tree_leaves(
        "crate::{pathutil::{self, is_hidden_entry, strip as cut}, walk::DirEntry, x::*}"
    )
    assert ("pathutil", "pathutil", ("crate", "pathutil")) in leaves
    assert (
        "is_hidden_entry",
        "is_hidden_entry",
        ("crate", "pathutil", "is_hidden_entry"),
    ) in leaves
    assert ("cut", "strip", ("crate", "pathutil", "strip")) in leaves
    assert ("DirEntry", "DirEntry", ("crate", "walk", "DirEntry")) in leaves
    assert len(leaves) == 4


def test_nested_use_group_credits_the_imported_functions(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/lib.rs": """
            mod dir;
            mod pathutil;
            mod walk;
            pub use crate::dir::Ignore;
            """,
            "src/dir.rs": """
            use crate::{
                pathutil::{is_hidden_entry, strip_prefix},
                walk::DirEntry,
            };
            pub struct Ignore;
            impl Ignore {
                pub fn matched(&self, entry: &DirEntry) -> bool {
                    is_hidden_entry(entry) && strip_prefix(1) == 1
                }
            }
            """,
            "src/pathutil.rs": """
            use crate::walk::DirEntry;
            pub(crate) fn is_hidden_entry(entry: &DirEntry) -> bool { entry.hidden }
            pub(crate) fn strip_prefix(x: u8) -> u8 { x }
            pub(crate) fn never_called() -> u8 { 0 }
            """,
            "src/walk.rs": "pub struct DirEntry { pub hidden: bool }\n",
        },
    )
    functions = _names(result, "unused_functions")
    assert {"is_hidden_entry", "strip_prefix"}.isdisjoint(functions)
    assert "never_called" in functions


def test_reexports_and_aliases_credit_their_targets(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod flags;
            fn main() {
                let _ = flags::generate_fish();
                let _ = flags::Mode::Search;
            }
            """,
            "src/flags/mod.rs": """
            mod complete;
            mod lowargs;
            pub(crate) use crate::flags::{
                complete::fish::generate as generate_fish,
                lowargs::Mode,
            };
            pub(crate) use lowargs::Unconsumed;
            """,
            "src/flags/complete/mod.rs": "pub(crate) mod fish;\n",
            "src/flags/complete/fish.rs": """
            pub(crate) fn generate() -> String { helper() }
            fn helper() -> String { String::new() }
            """,
            "src/flags/lowargs.rs": """
            pub(crate) enum Mode { Search }
            pub(crate) struct Unconsumed;
            """,
        },
    )
    assert {"generate", "helper"}.isdisjoint(_names(result, "unused_functions"))
    assert "Mode" not in _names(result, "unused_classes")
    imports = _names(result, "unused_imports")
    assert {"generate_fish", "Mode"}.isdisjoint(imports)
    # A re-export nobody reads is still reported, and so is its target.
    assert "Unconsumed" in imports
    assert "Unconsumed" in _names(result, "unused_classes")


def test_alias_path_call_credits_the_aliased_type_method(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod lowargs;
            mod defs;
            fn main() { defs::parse(); }
            """,
            "src/lowargs.rs": """
            pub(crate) struct ContextSeparator(u8);
            impl ContextSeparator {
                pub(crate) fn new(value: u8) -> ContextSeparator { ContextSeparator(value) }
                pub(crate) fn unused(&self) -> u8 { self.0 }
            }
            """,
            "src/defs.rs": """
            pub(crate) fn parse() {
                use crate::lowargs::ContextSeparator as Separator;
                let _ = Separator::new(1);
            }
            """,
        },
    )
    functions = _names(result, "unused_functions")
    assert "new" not in functions
    assert "unused" in functions


def test_project_model_resolves_reexport_chains(tmp_path):
    files = {
        "Cargo.toml": CARGO.format(edition="2021"),
        "src/lib.rs": "mod util;\npub fn run() -> bool { util::str_to_bool() }\n",
        "src/util/mod.rs": "mod str_to_bool;\npub(crate) use self::str_to_bool::str_to_bool;\n",
        "src/util/str_to_bool.rs": "pub(crate) fn str_to_bool() -> bool { true }\n",
    }
    for relative, text in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    project = build_project(
        tmp_path, [tmp_path / name for name in files if name.endswith(".rs")]
    )
    (lib,) = project.modules_of(tmp_path / "src" / "lib.rs")
    targets = project.resolve(lib, ("crate", "util", "str_to_bool"))
    # The value namespace reaches the function through the re-export; the
    # type namespace reaches the module of the same name.
    items = [target[1] for target in targets if target[0] == "item"]
    assert [(item.kind, item.name, item.file.name) for item in items] == [
        ("fn", "str_to_bool", "str_to_bool.rs")
    ]


# 3. Harness entry points --------------------------------------------------


@pytest.mark.parametrize(
    "attribute,expected",
    [
        ("#[test]", True),
        ("#[bench]", True),
        ('#[tokio::test(flavor = "multi_thread")]', True),
        ("#[divan::bench(args = [1, 2])]", True),
        ("#[sqlx::test]", True),
        ("#[rstest]", True),
        ("#[inline]", False),
        ("#[cfg(test)]", False),
        ("#[cfg_attr(test, test)]", False),
        ("#[testing]", False),
        ("#[test_helper]", False),
    ],
)
def test_harness_attribute_is_the_last_path_segment(attribute, expected):
    assert is_harness_attribute(attribute) is expected


def test_bench_and_test_functions_are_entry_points(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/lib.rs": "pub fn run() {}\n",
            "benches/bench.rs": """
            #![feature(test)]
            extern crate test;

            fn helper() -> u32 { 3 }

            #[bench]
            fn bench_one(b: &mut test::Bencher) { b.iter(|| helper()); }

            #[divan::bench(args = [1, 2])]
            fn bench_two(n: u32) -> u32 { n }

            #[tokio::test(flavor = "multi_thread")]
            /// A doc comment between the attribute and the function.
            async fn documented() {}

            fn orphan_helper() -> u32 { 4 }
            """,
        },
    )
    functions = _names(result, "unused_functions")
    assert {"helper", "bench_one", "bench_two", "documented"}.isdisjoint(functions)
    assert "orphan_helper" in functions


def test_harness_false_bench_registers_functions_through_its_macros(tmp_path):
    result = _report(
        tmp_path,
        {
            "Cargo.toml": CARGO.format(edition="2021")
            + '\n[[bench]]\nname = "speed"\nharness = false\n',
            "src/lib.rs": "pub fn run() {}\n",
            "benches/speed.rs": """
            use criterion::{criterion_group, criterion_main, Criterion};
            fn parse_bench(c: &mut Criterion) { c.bench_function("parse", |b| b.iter(|| 1)); }
            fn not_registered(_: &mut Criterion) {}
            criterion_group!(benches, parse_bench);
            criterion_main!(benches);
            """,
        },
        manifest=False,
    )
    functions = _names(result, "unused_functions")
    assert "parse_bench" not in functions
    assert "not_registered" in functions


# 4. Syntactic positions ---------------------------------------------------


def test_imported_variant_in_a_match_pattern_is_read(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod casing { pub(crate) enum CasingStyle { Camel, Kebab } }
            use casing::CasingStyle;
            fn pick(style: CasingStyle) -> &'static str {
                use casing::CasingStyle::{Camel, Kebab};
                match style { Camel => "c", Kebab => "k" }
            }
            fn main() { pick(CasingStyle::Camel); }
            """
        },
    )
    assert {"Camel", "Kebab"}.isdisjoint(_names(result, "unused_imports"))


def test_associated_type_and_alias_rhs_and_tuple_field_are_read(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod forms;
            use std::path::PathBuf;
            use crate::forms::{InsertForm, Match};
            trait Crud { type Form; }
            struct Post;
            impl Crud for Post { type Form = InsertForm; }
            type Range = Match;
            struct TempDir(PathBuf);
            fn make() -> Option<(Post, TempDir, Range)> { None }
            fn main() { let _ = make(); }
            """,
            "src/forms.rs": "pub(crate) struct InsertForm;\npub(crate) struct Match;\n",
        },
    )
    assert {"InsertForm", "Match", "PathBuf"}.isdisjoint(
        _names(result, "unused_imports")
    )


def test_inline_format_argument_reads_constants_not_locals(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            use std::env::consts::EXE_SUFFIX;
            fn name() -> u8 { 1 }
            fn main() {
                let name = 2;
                let _ = format!("sendmail{EXE_SUFFIX} {name}");
            }
            """
        },
    )
    assert "EXE_SUFFIX" not in _names(result, "unused_imports")
    # `{name}` reads the local, not the function.
    assert "name" in _names(result, "unused_functions")


def test_attribute_calls_and_serde_paths_through_imports_are_read(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod helpers;
            use helpers::{can_mod, placeholder, LtreeDef};
            struct View {
                #[diesel(select_expression = can_mod())]
                allowed: bool,
                #[serde(skip, default = "placeholder")]
                url: String,
                #[cfg_attr(feature = "full", serde(with = "LtreeDef"))]
                path: String,
            }
            fn main() { let _ = View { allowed: true, url: String::new(), path: String::new() }; }
            """,
            "src/helpers.rs": """
            pub(crate) fn can_mod() -> bool { true }
            pub(crate) fn placeholder() -> String { String::new() }
            pub(crate) struct LtreeDef;
            """,
        },
    )
    assert {"can_mod", "placeholder", "LtreeDef"}.isdisjoint(
        _names(result, "unused_imports")
    )
    assert {"can_mod", "placeholder"}.isdisjoint(_names(result, "unused_functions"))


def test_enum_used_through_a_variant_glob_is_read(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            #[derive(Clone, Copy)]
            enum State { Escape, Literal }
            enum Unused { Never }
            fn unescape(text: &str) -> usize {
                use self::State::*;
                let mut state = Literal;
                for _ in text.chars() {
                    state = match state { Escape => Literal, Literal => Escape };
                }
                matches!(state, Escape) as usize
            }
            fn main() { let _ = unescape("x"); }
            """
        },
    )
    classes = _names(result, "unused_classes")
    assert "State" not in classes
    assert "Unused" in classes


def test_local_macro_body_reads_imports_where_it_is_invoked(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            macro_rules! create_app { () => { Command::new() } }
            pub struct Command;
            impl Command { pub fn new() -> Self { Command } }
            mod startup {
                use super::Command;
                pub fn run() { let _ = create_app!(); }
            }
            fn main() { startup::run(); }
            """
        },
    )
    assert "Command" not in _names(result, "unused_imports")


# 5. Crate identity --------------------------------------------------------


def test_bare_named_definition_of_another_crate_does_not_capture(tmp_path):
    result = _report(
        tmp_path,
        {
            "Cargo.toml": '[workspace]\nmembers = ["app", "printer"]\n',
            "app/Cargo.toml": CARGO.format(edition="2021").replace("demo", "app"),
            "app/src/main.rs": "struct Config;\nfn main() { let _ = Config; }\n",
            "printer/Cargo.toml": CARGO.format(edition="2021").replace(
                "demo", "printer"
            ),
            "printer/src/lib.rs": "mod path;\npub fn run() { path::show(); }\n",
            "printer/src/path.rs": """
            struct Config { x: u8 }
            pub(crate) fn show() { let config = Config { x: 1 }; let _ = config.x; }
            struct Spare;
            """,
        },
        manifest=False,
    )
    classes = _names(result, "unused_classes")
    assert "Config" not in classes
    assert "Spare" in classes


# 6. Receiver types across files ------------------------------------------


def test_method_on_a_reexported_receiver_type_is_credited(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            mod flags;
            use crate::flags::HiArgs;
            fn run(args: &HiArgs) -> bool { args.quit_after_match() }
            fn main() { let args = flags::make(); run(&args); }
            """,
            "src/flags/mod.rs": """
            mod hiargs;
            pub(crate) use self::hiargs::HiArgs;
            pub(crate) fn make() -> HiArgs { HiArgs { quit: false } }
            """,
            "src/flags/hiargs.rs": """
            pub(crate) struct HiArgs { pub(crate) quit: bool }
            impl HiArgs {
                pub(crate) fn quit_after_match(&self) -> bool { self.quit }
                pub(crate) fn never_called(&self) -> bool { !self.quit }
            }
            """,
        },
    )
    functions = _names(result, "unused_functions")
    assert "quit_after_match" not in functions
    assert "never_called" in functions


# 7. Lint levels and cfg alternatives --------------------------------------


def test_allowed_dead_code_is_whitelisted_not_reported(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/lib.rs": "mod literal;\nmod flat;\nmod docs;\npub fn run() {}\n",
            "src/literal.rs": """
            pub(crate) struct TSeq;
            #[allow(dead_code)]
            impl TSeq {
                fn new() -> TSeq { TSeq }
            }
            fn plain_dead() {}
            #[allow(clippy::too_many_arguments)]
            fn lint_unrelated_dead() {}
            """,
            "src/flat.rs": "#![allow(dead_code)]\nfn or_insert_with() {}\n",
            "src/docs.rs": "#![allow(unused_imports)]\nuse std::collections::HashMap;\n",
        },
    )
    functions = _names(result, "unused_functions")
    assert {"new", "or_insert_with"}.isdisjoint(functions)
    assert {"plain_dead", "lint_unrelated_dead"} <= functions
    whitelisted = _whitelisted(result)
    assert ("new", "#[allow(dead_code)] in scope") in whitelisted
    assert ("or_insert_with", "#[allow(dead_code)] in scope") in whitelisted
    assert ("HashMap", "#[allow(unused_imports)] in scope") in whitelisted
    assert "HashMap" not in _names(result, "unused_imports")


def test_crate_level_allow_reaches_child_modules(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/lib.rs": "#![allow(dead_code)]\nmod child;\npub fn run() {}\n",
            "src/child.rs": "fn unused() {}\n",
        },
    )
    assert "unused" not in _names(result, "unused_functions")


def test_cfg_alternatives_share_liveness(tmp_path):
    result = _report(
        tmp_path,
        {
            "src/main.rs": """
            struct PrinterPath;
            impl PrinterPath {
                fn as_path(&self) -> u8 {
                    #[cfg(unix)]
                    fn imp(_: &PrinterPath) -> u8 { 1 }
                    #[cfg(not(unix))]
                    fn imp(_: &PrinterPath) -> u8 { 2 }
                    imp(self)
                }
            }
            fn main() { let _ = PrinterPath.as_path(); }
            """
        },
    )
    assert "imp" not in _names(result, "unused_functions")
