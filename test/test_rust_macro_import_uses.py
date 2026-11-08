"""Source-typed writer macros and conditional attribute import identities."""

import json

import pytest

from skylos.analyzer import analyze


def _imports(tmp_path, source, *, with_lines=False):
    (tmp_path / "main.rs").write_text(source)
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
    return {
        (item.get("simple_name", item["name"]), item["line"])
        if with_lines
        else item.get("simple_name", item["name"])
        for item in result.get("unused_imports", [])
    }


@pytest.mark.parametrize("macro", ["write", "writeln"])
@pytest.mark.parametrize(
    "constructor", ["Vec::new()", "Vec::with_capacity(20)", "Vec::<u8>::new()"]
)
def test_io_writer_macro_reads_its_aliased_trait(tmp_path, macro, constructor):
    source = (
        "use std::io::Write as Output;\nuse std::io::Read as Spare;\n"
        + f'fn main() {{ let mut buffer = {constructor}; {macro}!(&mut buffer, "text").unwrap(); }}\n'
    )
    assert _imports(tmp_path, source) == {"Spare"}


def test_captured_writer_buffer_keeps_io_trait(tmp_path):
    source = 'use std::io::Write;\nfn main() { let mut buffer = Vec::with_capacity(20); let mut callback = || { buffer.clear(); write!(&mut buffer, "text").unwrap(); }; callback(); }\n'
    assert _imports(tmp_path, source) == set()


def test_fmt_and_io_writer_traits_have_distinct_receiver_types(tmp_path):
    source = 'use std::fmt::Write as TextOutput;\nuse std::io::Write as ByteOutput;\nfn main() { let mut buffer = String::new(); writeln!(&mut buffer, "text").unwrap(); }\n'
    assert _imports(tmp_path, source) == {"ByteOutput"}


def test_vec_writer_does_not_credit_fmt_write(tmp_path):
    source = 'use std::fmt::Write as Spare;\nuse std::io::Write as Output;\nfn main() { let mut buffer = Vec::new(); write!(&mut buffer, "text").unwrap(); }\n'
    assert _imports(tmp_path, source) == {"Spare"}


@pytest.mark.parametrize("custom_name", ["Sink", "Vec"])
def test_inherent_write_fmt_does_not_credit_io_trait(tmp_path, custom_name):
    source = (
        "use std::io::Write as Spare;\n"
        + f"struct {custom_name} {{}}\nimpl {custom_name} {{ fn new() -> Self {{ Self {{}} }} fn write_fmt(&mut self, _: std::fmt::Arguments<'_>) -> std::fmt::Result {{ Ok(()) }} }}\n"
        + f'fn main() {{ let mut buffer = {custom_name}::new(); write!(&mut buffer, "text").unwrap(); }}\n'
    )
    assert _imports(tmp_path, source) == {"Spare"}


def test_shadowed_writer_macro_does_not_credit_trait(tmp_path):
    source = 'use std::io::Write as Spare;\nmacro_rules! write { ($writer:expr, $message:expr) => { $writer.clear() }; }\nfn main() { let mut buffer = Vec::<u8>::new(); write!(&mut buffer, "text"); }\n'
    assert _imports(tmp_path, source) == {"Spare"}


def test_qualified_standard_macro_ignores_local_macro_shadow(tmp_path):
    source = 'use std::io::Write as Output;\nmacro_rules! write { ($writer:expr, $message:expr) => { $writer.clear() }; }\nfn main() { let mut buffer = Vec::<u8>::new(); std::write!(&mut buffer, "text").unwrap(); }\n'
    assert _imports(tmp_path, source) == set()


def test_writer_text_and_nonbyte_vectors_supply_no_evidence(tmp_path):
    source = 'use std::io::Write as Spare;\nfn main() { let _ = "write!(&mut buffer, text)"; let mut buffer = Vec::<u32>::new(); let _ = &mut buffer; }\n'
    assert _imports(tmp_path, source) == {"Spare"}


@pytest.mark.parametrize("guard", ['feature = "checked"', "all()"])
def test_cfg_attr_wrapped_alias_reads_matching_import(tmp_path, guard):
    source = f"#[cfg({guard})]\nuse attributes::stamp as Applied;\n#[cfg({guard})]\nuse attributes::stamp as Spare;\n#[cfg_attr({guard}, Applied)]\nfn main() {{}}\n"
    assert _imports(tmp_path, source) == {"Spare"}


def test_nested_cfg_attr_matches_combined_import_guards(tmp_path):
    source = '#[cfg(all(feature = "outer", feature = "inner"))]\nuse attributes::stamp as Applied;\n#[cfg_attr(feature = "outer", cfg_attr(feature = "inner", Applied))]\nfn main() {}\n'
    assert _imports(tmp_path, source) == set()


@pytest.mark.parametrize(
    "attributes",
    [
        "#[cfg_attr(any(), Applied)]",
        '#[cfg_attr(feature = "checked", doc = "Applied")]',
        "#[cfg_attr(Applied, allow(dead_code))]",
        '#[cfg(any())]\n#[cfg_attr(feature = "checked", Applied)]',
    ],
)
def test_false_predicate_and_prose_do_not_read_attribute_import(tmp_path, attributes):
    source = (
        "use attributes::stamp as Applied;\n"
        + attributes
        + "\nfn target() {}\nfn main() {}\n"
    )
    assert _imports(tmp_path, source) == {"Applied"}


def test_mismatched_feature_guard_does_not_prove_attribute_import_used(tmp_path):
    source = '#[cfg(feature = "one")]\nuse attributes::stamp as Applied;\n#[cfg_attr(feature = "two", Applied)]\nfn main() {}\n'
    assert _imports(tmp_path, source) == {"Applied"}


@pytest.mark.parametrize(
    "attributes",
    [
        "#[cfg_attr(all(), Applied)]\n#[cfg(any())]",
        "#[cfg_attr(all(), cfg(any()))]\n#[cfg_attr(all(), Applied)]",
    ],
)
def test_inactive_item_never_reads_its_wrapped_attribute(tmp_path, attributes):
    source = (
        "use attributes::stamp as Applied;\n"
        + attributes
        + "\nfn target() {}\nfn main() {}\n"
    )
    assert _imports(tmp_path, source) == {"Applied"}


def test_inner_attribute_import_does_not_credit_outer_binding(tmp_path):
    source = "use attributes::stamp as Applied;\nfn main() { use attributes::stamp as Applied; #[cfg_attr(all(), Applied)] fn target() {} target(); }\n"
    assert _imports(tmp_path, source, with_lines=True) == {("Applied", 1)}


def test_unknown_glob_cannot_prove_a_prelude_vec_writer(tmp_path):
    source = 'use foreign::*;\nuse std::io::Write as Spare;\nfn main() { let mut buffer = Vec::new(); write!(&mut buffer, "text").unwrap(); }\n'
    assert "Spare" in _imports(tmp_path, source)


def test_local_shared_write_fmt_trait_can_outrank_io_write(tmp_path):
    source = (
        "use std::io::Write as Inactive;\n"
        "trait Formatter { fn write_fmt(&self, args: std::fmt::Arguments<'_>) -> std::fmt::Result; }\n"
        "impl Formatter for Vec<u8> { fn write_fmt(&self, _: std::fmt::Arguments<'_>) -> std::fmt::Result { Ok(()) } }\n"
        'fn main() { let buffer: Vec<u8> = Vec::with_capacity(8); write!(buffer, "{}", 1).unwrap(); }\n'
    )
    assert _imports(tmp_path, source) == {"Inactive"}
