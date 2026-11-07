"""Source-owned import use, distilled from compiler-verified real projects."""

import json
from textwrap import dedent

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.rust import scan_rust_file


def scan(tmp_path, source, *, grep_verify=False):
    path = tmp_path / "src" / "main.rs"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(source).lstrip())
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=40,
            grep_verify=grep_verify,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return path, result


def unused_imports(result):
    return {finding["name"] for finding in result.get("unused_imports", [])}


@pytest.mark.parametrize("alias", ["fs", "fs as files"])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_module_import_used_in_a_qualified_type_path(tmp_path, alias, grep_verify):
    local = alias.split(" as ")[-1]
    _, result = scan(
        tmp_path,
        f"""
        use std::{alias};
        use std::collections::HashMap;
        enum Input {{ File({local}::File) }}
        fn main() {{ let _: Option<Input> = None; }}
        """,
        grep_verify=grep_verify,
    )
    assert unused_imports(result) == {"HashMap"}


@pytest.mark.parametrize(
    "attributes",
    [
        '#[arg(action(Mode::SetTrue), default_value(format_value!("ready")))]',
        '#[arg(action = Mode::SetTrue, value = format_value!("ready"))]',
    ],
)
def test_attribute_expressions_and_macros_reference_actual_imports(
    tmp_path, attributes
):
    _, result = scan(
        tmp_path,
        f"""
        use external::{{Mode, UnusedMode, format_value, unused_format}};
        {attributes}
        struct Options {{ value: bool }}
        fn main() {{}}
        """,
    )
    assert unused_imports(result) == {"UnusedMode", "unused_format"}


@pytest.mark.parametrize(
    "attribute",
    [
        '#[arg(help = "Mode::SetTrue format_value!(true)")]',
        '#[arg(Mode = "unused", format_value = "unused")]',
        '#[doc = "Mode and format_value are only documentation"]',
    ],
)
def test_attribute_strings_and_metadata_keys_do_not_reference_imports(
    tmp_path, attribute
):
    _, result = scan(
        tmp_path,
        f"""
        use external::{{Mode, format_value}};
        {attribute}
        struct Options {{ value: bool }}
        fn main() {{}}
        """,
    )
    assert unused_imports(result) == {"Mode", "format_value"}


def test_bare_attribute_options_are_not_imported_values(tmp_path):
    _, result = scan(
        tmp_path,
        """
        use external::{short, long};
        #[arg(short, long)]
        struct Options { value: bool }
        fn main() {}
        """,
    )
    assert unused_imports(result) == {"short", "long"}


def test_enum_variant_names_do_not_rescue_an_unrelated_import(tmp_path):
    _, result = scan(
        tmp_path,
        """
        use external::{UnusedMode, DISCRIMINANT};
        enum Options { UnusedMode = DISCRIMINANT }
        fn main() {}
        """,
    )
    assert unused_imports(result) == {"UnusedMode"}


TRAIT_USES = [
    ("anyhow", "Context", 'value.context("details");'),
    ("clap", "CommandFactory", "Arguments::command();"),
    ("rand", "Rng", "value.gen::<u64>();"),
    ("owo_colors", "OwoColorize", "value.color(color);"),
    ("owo_colors", "Color", "let _ = colors::Default::ANSI_FG;"),
]


@pytest.mark.parametrize("provider,trait,body", TRAIT_USES)
@pytest.mark.parametrize("renaming", ["", " as _", " as Extension"])
def test_external_trait_api_use_keeps_its_import(
    tmp_path, provider, trait, body, renaming
):
    _, result = scan(
        tmp_path,
        f"""
        use {provider}::{trait}{renaming};
        use std::collections::HashSet;
        pub fn inspect(value: External) {{ {body} }}
        fn main() {{}}
        """,
    )
    assert unused_imports(result) == {"HashSet"}


@pytest.mark.parametrize("provider,trait,body", TRAIT_USES)
def test_same_trait_spelling_from_an_unproven_provider_is_not_a_use(
    tmp_path, provider, trait, body
):
    _, result = scan(
        tmp_path,
        f"""
        use crate::custom::{trait};
        pub fn inspect(value: External) {{ {body} }}
        fn main() {{}}
        """,
    )
    assert trait in unused_imports(result)


@pytest.mark.parametrize("provider,trait,body", TRAIT_USES)
def test_trait_api_use_in_another_function_does_not_rescue_local_import(
    tmp_path, provider, trait, body
):
    _, result = scan(
        tmp_path,
        f"""
        pub fn inspect(value: External) {{
            use {provider}::{trait} as Needed;
            {body}
        }}
        pub fn other() {{ use {provider}::{trait} as Unused; }}
        fn main() {{}}
        """,
    )
    assert "Needed" not in unused_imports(result)
    assert "Unused" in unused_imports(result)


@pytest.mark.parametrize(
    "import_path,implementation,call",
    [
        (
            "anyhow::Context",
            "fn context(&self, _: &str) {}",
            'value.context("details");',
        ),
        ("rand::Rng", "fn gen<T>(&self) {}", "value.gen::<u64>();"),
        ("owo_colors::OwoColorize", "fn color(&self, _: u8) {}", "value.color(1);"),
        ("clap::CommandFactory", "fn command() {}", "Local::command();"),
    ],
)
def test_known_inherent_method_does_not_rescue_external_trait(
    tmp_path, import_path, implementation, call
):
    local = import_path.rsplit("::", 1)[-1]
    path, result = scan(
        tmp_path,
        f"""
        use {import_path};
        struct Local;
        impl Local {{ {implementation} }}
        pub fn inspect(value: Local) {{ {call} }}
        fn main() {{}}
        """,
    )
    assert local in unused_imports(result)
    refs = {name for name, _ in scan_rust_file(str(path), {})[1]}
    assert local not in refs


def test_known_inherent_constant_does_not_rescue_color_trait(tmp_path):
    _, result = scan(
        tmp_path,
        """
        use owo_colors::Color;
        struct Local;
        impl Local { const ANSI_FG: u8 = 1; }
        pub fn inspect() { let _ = Local::ANSI_FG; }
        fn main() {}
        """,
    )
    assert unused_imports(result) == {"Color"}


def test_nested_lookalike_provider_does_not_get_trait_api_proof(tmp_path):
    _, result = scan(
        tmp_path,
        """
        use anyhow::custom::Context;
        pub fn inspect(value: External) { value.context("details"); }
        fn main() {}
        """,
    )
    assert unused_imports(result) == {"Context"}


@pytest.mark.parametrize(
    "provider,trait,body",
    [
        ("owo_colors", "OwoColorize", 'format!("{}", "|".color(color));'),
        ("rand", "Rng", "assert_eq!(value.gen::<u64>(), 0);"),
        ("anyhow", "Context", 'println!("{:?}", value.context("details"));'),
    ],
)
def test_trait_method_expression_inside_macro_arguments_is_a_use(
    tmp_path, provider, trait, body
):
    _, result = scan(
        tmp_path,
        f"""
        use {provider}::{trait};
        use std::collections::HashSet;
        pub fn inspect(value: External) {{ {body} }}
        fn main() {{}}
    """,
    )
    assert unused_imports(result) == {"HashSet"}


def test_macro_method_text_and_known_inherent_receiver_do_not_keep_trait(tmp_path):
    _, result = scan(
        tmp_path,
        """
        use owo_colors::OwoColorize;
        struct Local;
        impl Local { fn color(&self, _: u8) {} }
        pub fn inspect(value: Local) {
            println!("value.color(1)");
            println!("{:?}", value.color(1));
        }
        fn main() {}
    """,
    )
    assert unused_imports(result) == {"OwoColorize"}


@pytest.mark.parametrize("provider,trait,body", TRAIT_USES)
def test_local_module_with_provider_name_is_not_external_api_proof(
    tmp_path, provider, trait, body
):
    _, result = scan(
        tmp_path,
        f"""
        mod {provider} {{ pub trait {trait} {{}} }}
        use {provider}::{trait};
        pub fn inspect(value: External) {{ {body} }}
        fn main() {{}}
    """,
    )
    assert trait in unused_imports(result)


@pytest.mark.parametrize("provider,trait,body", TRAIT_USES)
@pytest.mark.parametrize("alias", ["InnerTrait", "_"])
def test_nearer_same_trait_import_does_not_rescue_redundant_outer_alias(
    tmp_path, provider, trait, body, alias
):
    _, result = scan(
        tmp_path,
        f"""
        use {provider}::{trait} as OuterTrait;
        pub fn inspect(value: External) {{
            use {provider}::{trait} as {alias};
            {body}
        }}
        fn main() {{}}
    """,
    )
    assert unused_imports(result) == {"OuterTrait"}


@pytest.mark.parametrize("provider,trait,body", TRAIT_USES)
def test_independent_outer_trait_use_survives_inner_reimport(
    tmp_path, provider, trait, body
):
    _, result = scan(
        tmp_path,
        f"""
        use {provider}::{trait} as OuterTrait;
        pub fn inspect(value: External) {{
            use {provider}::{trait} as InnerTrait;
            {body}
        }}
        pub fn separate(value: External) {{ {body} }}
        fn main() {{}}
    """,
    )
    assert not unused_imports(result)
