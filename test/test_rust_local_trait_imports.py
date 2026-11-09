"""Import use derived from local trait declarations and receiver identities."""

import json

import pytest

from skylos.analyzer import analyze


DECLARATIONS = """
struct Card {}
struct Badge {}
mod traits {
    pub trait Stamp { fn stamp(&self) -> u8; }
    pub trait Other { fn stamp(&self) -> u8; }
    pub trait Retired { fn retired(&self) -> u8; }
    impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } }
    impl Other for super::Badge { fn stamp(&self) -> u8 { 2 } }
    impl Retired for super::Card { fn retired(&self) -> u8 { 3 } }
}
"""


def _scan(tmp_path, source, *, grep_verify=False):
    (tmp_path / "main.rs").write_text(source)
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=40,
            grep_verify=grep_verify,
            grep_cache=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return {
        item.get("simple_name", item["name"])
        for item in result.get("unused_imports", [])
    }


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "expression",
    [
        "let value = Card {}; let _ = value.stamp();",
        "let value: Card = Card {}; let _ = value.stamp();",
        "let value = &Card {}; let _ = value.stamp();",
        "let _ = (Card {}).stamp();",
        'let value = Card {}; println!("{}", value.stamp());',
    ],
)
def test_local_trait_method_keeps_its_alias_import(tmp_path, expression, grep_verify):
    source = (
        DECLARATIONS
        + "use crate::traits::Stamp as Active;\n"
        + "use crate::traits::Retired as Inactive;\n"
        + f"fn main() {{ {expression} }}\n"
    )
    assert _scan(tmp_path, source, grep_verify=grep_verify) == {"Inactive"}


def test_local_trait_uses_follow_the_receiver_type(tmp_path):
    source = (
        DECLARATIONS
        + "use crate::traits::Stamp as Active;\n"
        + "use crate::traits::Other as Inactive;\n"
        + "fn main() { let value = Card {}; let _ = value.stamp(); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


@pytest.mark.parametrize("inner_path", ["crate::traits", "traits"])
def test_inner_trait_alias_owns_the_method_use(tmp_path, inner_path):
    source = (
        DECLARATIONS
        + "use crate::traits::Stamp as Outer;\n"
        + f"fn main() {{ use {inner_path}::Stamp as Inner; "
        + "let value = Card {}; let _ = value.stamp(); }\n"
    )
    assert _scan(tmp_path, source) == {"Outer"}


def test_independent_outer_use_keeps_both_trait_aliases(tmp_path):
    source = (
        DECLARATIONS
        + "use crate::traits::Stamp as Outer;\n"
        + "fn nested() { use traits::Stamp as Inner; "
        + "let value = Card {}; let _ = value.stamp(); }\n"
        + "fn main() { let value = Card {}; let _ = value.stamp(); nested(); }\n"
    )
    assert _scan(tmp_path, source) == set()


def test_inherent_method_does_not_credit_a_trait_import(tmp_path):
    source = (
        DECLARATIONS
        + "impl Card { fn stamp(&self) -> u8 { 4 } }\n"
        + "use crate::traits::Stamp as Inactive;\n"
        + "fn main() { let value = Card {}; let _ = value.stamp(); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


def test_child_module_call_does_not_credit_parent_import(tmp_path):
    source = (
        DECLARATIONS
        + "use crate::traits::Stamp as Outer;\n"
        + "mod worker { use crate::traits::Stamp as Inner; "
        + "pub fn run() { let value = super::Card {}; let _ = value.stamp(); } }\n"
        + "fn main() { worker::run(); }\n"
    )
    assert _scan(tmp_path, source) == {"Outer"}


def test_source_trait_type_alias_keeps_required_import(tmp_path):
    source = (
        DECLARATIONS
        + "type Voucher = Card;\n"
        + "use crate::traits::Stamp as Active;\n"
        + "fn main() { let value: Voucher = Card {}; let _ = value.stamp(); }\n"
    )
    assert _scan(tmp_path, source) == set()


def test_method_name_in_prose_does_not_credit_trait_import(tmp_path):
    source = (
        DECLARATIONS
        + "use crate::traits::Stamp as Inactive;\n"
        + 'fn main() { println!("value.stamp()"); }\n'
    )
    assert _scan(tmp_path, source) == {"Inactive"}


@pytest.mark.parametrize("blanket", [False, True])
@pytest.mark.parametrize("by_value", [False, True])
def test_reference_impl_keeps_the_imports_selected_by_rust(tmp_path, blanket, by_value):
    other_impl = (
        "impl<T> Other for &T { fn stamp(&self) -> u8 { 2 } }"
        if blanket
        else "impl Other for &super::Card { fn stamp(&self) -> u8 { 2 } }"
    )
    source = (
        "struct Card {}\nmod traits {\n"
        "pub trait Stamp { fn stamp(&self) -> u8; }\n"
        "pub trait Other { fn stamp(&self) -> u8; }\n"
        "impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } }\n"
        + other_impl
        + "\n}\nuse crate::traits::Stamp as Inactive;\n"
        + "use crate::traits::Other as Active;\n"
        + "fn main() { let value = &Card {}; let _ = value.stamp(); "
        + "let _ = Active::stamp(&value); }\n"
    )
    if by_value:
        source = source.replace(
            "trait Stamp { fn stamp(&self)", "trait Stamp { fn stamp(self)"
        )
        source = source.replace(
            "impl Stamp for super::Card { fn stamp(&self)",
            "impl Stamp for super::Card { fn stamp(self)",
        )
    # With &self, the Stamp import supplies value.stamp(). The explicit Other
    # call uses Active too. A by-value Stamp receiver loses to Other's borrow.
    assert _scan(tmp_path, source) == ({"Inactive"} if by_value else set())


@pytest.mark.parametrize(
    "by_value",
    [False, True],
)
def test_reference_trait_in_another_file_has_distinct_receiver_uses(tmp_path, by_value):
    (tmp_path / "external.rs").write_text(
        "pub trait Other { fn stamp(&self) -> u8; }\n"
        "impl Other for &crate::Card { fn stamp(&self) -> u8 { 2 } }\n"
    )
    source = (
        DECLARATIONS
        + "mod external;\nuse crate::traits::Stamp as Inactive;\n"
        + "use external::Other as Active;\n"
        + "fn main() { let value = &Card {}; let _ = value.stamp(); "
        + "let _ = Active::stamp(&value); }\n"
    )
    if by_value:
        source = source.replace(
            "trait Stamp { fn stamp(&self)", "trait Stamp { fn stamp(self)"
        )
        source = source.replace(
            "impl Stamp for super::Card { fn stamp(&self)",
            "impl Stamp for super::Card { fn stamp(self)",
        )
    assert _scan(tmp_path, source) == ({"Inactive"} if by_value else set())


def test_macro_generated_inherent_method_does_not_credit_trait_import(tmp_path):
    source = (
        DECLARATIONS
        + "macro_rules! install { () => { impl Card { fn stamp(&self) -> u8 { 4 } } } }\n"
        + "install!();\nuse crate::traits::Stamp as Inactive;\n"
        + "fn main() { let value = Card {}; let _ = value.stamp(); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


def test_inherent_method_in_another_module_keeps_trait_import_unused(tmp_path):
    (tmp_path / "external.rs").write_text(
        "impl crate::Card { pub fn stamp(&self) -> u8 { 4 } }\n"
    )
    source = (
        DECLARATIONS
        + "mod external;\nuse crate::traits::Stamp as Inactive;\n"
        + "fn main() { let value = Card {}; let _ = value.stamp(); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


@pytest.mark.parametrize("fallible", [False, True])
def test_prelude_conversion_does_not_credit_a_local_trait(tmp_path, fallible):
    if fallible:
        member, return_type, body, result_type = (
            "try_into",
            "Result<u8, ()>",
            "Ok(1)",
            "Result<Card, std::convert::Infallible>",
        )
    else:
        member, return_type, body, result_type = "into", "u8", "1", "Card"
    source = (
        "struct Card {}\nmod traits {\n"
        + f"pub trait Stamp {{ fn {member}(&self) -> {return_type}; }}\n"
        + f"impl Stamp for super::Card {{ fn {member}(&self) -> {return_type} {{ {body} }} }}\n"
        + "}\nuse crate::traits::Stamp as Inactive;\n"
        + f"fn main() {{ let value = Card {{}}; let _: {result_type} = value.{member}(); }}\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


@pytest.mark.parametrize("generic", [False, True])
def test_more_specific_double_reference_selects_its_own_trait(tmp_path, generic):
    implementation = (
        "impl<T> Other for &&T { fn stamp(self) -> u8 { 2 } }"
        if generic
        else "impl Other for &&super::Card { fn stamp(self) -> u8 { 2 } }"
    )
    source = (
        "struct Card {}\nmod traits {\n"
        "pub trait Stamp { fn stamp(&self) -> u8; }\n"
        "pub trait Other { fn stamp(self) -> u8; }\n"
        "impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } }\n"
        + implementation
        + "\n}\nuse crate::traits::Stamp as Inactive;\n"
        + "use crate::traits::Other as Active;\n"
        + "fn main() { let value = &&Card {}; let _ = value.stamp(); "
        + "let _ = Active::stamp(value); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


@pytest.mark.parametrize("generic", [False, True])
def test_mutable_reference_selects_its_own_trait(tmp_path, generic):
    implementation = (
        "impl<T> Other for &mut T { fn stamp(self) -> u8 { 2 } }"
        if generic
        else "impl Other for &mut super::Card { fn stamp(self) -> u8 { 2 } }"
    )
    source = (
        "struct Card {}\nmod traits {\n"
        "pub trait Stamp { fn stamp(&self) -> u8; }\n"
        "pub trait Other { fn stamp(self) -> u8; }\n"
        "impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } }\n"
        + implementation
        + "\n}\nuse crate::traits::Stamp as Inactive;\n"
        + "use crate::traits::Other as Active;\n"
        + "fn main() { let _ = Active::stamp(&mut Card {}); "
        + "let value = &mut Card {}; let _ = value.stamp(); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


def test_annotated_parameter_preserves_its_reference_type(tmp_path):
    source = (
        DECLARATIONS
        + "use crate::traits::Stamp as Active;\n"
        + "fn run(value: &Card) { let _ = value.stamp(); }\n"
        + "fn main() { run(&Card {}); }\n"
    )
    assert _scan(tmp_path, source) == set()


def test_unknown_external_blanket_trait_does_not_credit_local_import(tmp_path):
    source = (
        DECLARATIONS
        + "use crate::traits::Stamp as Inactive;\n"
        + "use foreign::Alternate as Active;\n"
        + "fn main() { let value = Card {}; let _ = value.stamp(); "
        + "let _ = Active::stamp(Card {}); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


def test_reference_type_alias_keeps_receiver_depth(tmp_path):
    source = (
        "struct Card {}\nmod traits {\n"
        "pub trait Stamp { fn stamp(&self) -> u8; }\n"
        "pub trait Other { fn stamp(self) -> u8; }\n"
        "impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } }\n"
        "impl Other for &&super::Card { fn stamp(self) -> u8 { 2 } }\n"
        "}\ntype Double = &'static &'static Card;\n"
        "use crate::traits::Stamp as Inactive;\n"
        "use crate::traits::Other as Active;\n"
        "fn main() { let value: Double = &&Card {}; let _ = value.stamp(); "
        "let _ = Active::stamp(value); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}


def test_unmodeled_generic_trait_cannot_credit_a_competing_import(tmp_path):
    source = (
        "struct Card {}\nmod traits {\n"
        "pub trait Stamp { fn stamp(&self) -> u8; }\n"
        "pub trait Other<T> { fn stamp(self) -> u8; }\n"
        "impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } }\n"
        "impl Other<i32> for &&super::Card { fn stamp(self) -> u8 { 2 } }\n"
        "}\nuse crate::traits::Stamp as Inactive;\n"
        "use crate::traits::Other as Active;\n"
        "fn main() { let value = &&Card {}; let _ = value.stamp(); "
        "let _ = <&&Card as Active<i32>>::stamp(value); }\n"
    )
    assert _scan(tmp_path, source) == {"Inactive"}
