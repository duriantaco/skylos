"""Selected source module closures preserve receiver and import ownership."""

import json

import pytest

from skylos.analyzer import analyze


DECLARATIONS = """struct Card {}
mod traits {
    pub trait Stamp { fn stamp(&self) -> u8; }
    impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } }
}
"""


def _scan(root, **options):
    result = json.loads(
        analyze(
            str(root),
            conf=40,
            grep_verify=False,
            grep_cache=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
            **options,
        )
    )
    assert not result.get("analysis_errors")
    return {
        (item.get("simple_name", item["name"]).removeprefix("r#"), item["line"])
        for item in result.get("unused_imports", [])
    }


@pytest.mark.parametrize("layout", ["external.rs", "external/mod.rs"])
@pytest.mark.parametrize("source_root", [".", "src"])
def test_out_of_line_reference_trait_uses_are_proven(tmp_path, layout, source_root):
    root = tmp_path / source_root
    root.mkdir(exist_ok=True)
    main = (
        DECLARATIONS
        + """mod external;
use crate::traits::Stamp as Inactive;
use external::Other as Active;
fn main() { let value = &Card {}; let _ = value.stamp(); let _ = Active::stamp(&value); }
"""
    )
    (root / "main.rs").write_text(main)
    external = root / layout
    external.parent.mkdir(exist_ok=True)
    external.write_text(
        "pub trait Other { fn stamp(&self) -> u8; }\nimpl Other for &crate::Card { fn stamp(&self) -> u8 { 2 } }\n"
    )
    assert _scan(tmp_path) == set()


@pytest.mark.parametrize(
    "implementation",
    [
        "impl crate::Card { pub fn stamp(&self) -> u8 { 3 } }",
        "pub trait Other { fn stamp(&self) -> u8; } impl Other for &crate::Card { fn stamp(&self) -> u8 { 2 } }",
    ],
)
def test_external_inherent_and_byvalue_precedence_leave_unused_trait(
    tmp_path, implementation
):
    main = DECLARATIONS.replace("stamp(&self)", "stamp(self)")
    main += "mod external;\nuse crate::traits::Stamp as Inactive;\n"
    if "trait Other" in implementation:
        main += "use external::Other as Active;\n"
    main += "fn main() { let value = &Card {}; let _ = value.stamp(); }\n"
    (tmp_path / "main.rs").write_text(main)
    (tmp_path / "external.rs").write_text(implementation)
    assert ("Inactive", 7) in _scan(tmp_path)


def test_ordinary_module_file_children_are_relative_to_its_name(tmp_path):
    (tmp_path / "main.rs").write_text("mod model;\nfn main() { model::run(); }\n")
    (tmp_path / "model.rs").write_text(
        DECLARATIONS
        + """mod external;
use self::traits::Stamp as Active;
pub fn run() { let value = Card {}; let _ = value.stamp(); }
"""
    )
    (tmp_path / "model").mkdir()
    (tmp_path / "model" / "external.rs").write_text("pub fn spare() {}\n")
    assert not {name for name, _ in _scan(tmp_path)}


def test_inline_module_child_path_is_not_relative_to_crate_root(tmp_path):
    (tmp_path / "main.rs").write_text(
        "mod model {\n"
        + DECLARATIONS
        + """mod external;
use self::traits::Stamp as Active;
pub fn run() { let value = Card {}; let _ = value.stamp(); }
}
fn main() { model::run(); }
"""
    )
    (tmp_path / "model").mkdir()
    (tmp_path / "model" / "external.rs").write_text("pub fn spare() {}\n")
    assert not {name for name, _ in _scan(tmp_path)}


def test_missing_module_supplies_no_project_trait_proof(tmp_path):
    (tmp_path / "main.rs").write_text(
        DECLARATIONS
        + "mod absent;\nuse traits::Stamp as Active;\nfn main() { let _ = Card {}.stamp(); }\n"
    )
    assert _scan(tmp_path) == {("Active", 7)}


def test_ambiguous_module_supplies_no_project_trait_proof(tmp_path):
    (tmp_path / "main.rs").write_text(
        DECLARATIONS
        + "mod external;\nuse traits::Stamp as Active;\nfn main() { let _ = Card {}.stamp(); }\n"
    )
    (tmp_path / "external.rs").write_text("")
    (tmp_path / "external").mkdir()
    (tmp_path / "external" / "mod.rs").write_text("")
    assert _scan(tmp_path) == {("Active", 7)}


def test_attributed_module_identity_supplies_no_project_trait_proof(tmp_path):
    (tmp_path / "main.rs").write_text(
        DECLARATIONS
        + '#[path = "other.rs"]\nmod external;\nuse traits::Stamp as Active;\nfn main() { let _ = Card {}.stamp(); }\n'
    )
    (tmp_path / "external.rs").write_text("")
    (tmp_path / "other.rs").write_text("")
    assert _scan(tmp_path) == {("Active", 8)}


def test_excluded_module_supplies_no_project_trait_proof(tmp_path):
    (tmp_path / "main.rs").write_text(
        DECLARATIONS
        + "mod external;\nuse traits::Stamp as Active;\nfn main() { let _ = Card {}.stamp(); }\n"
    )
    (tmp_path / "hidden").mkdir()
    # Direct helper invocation tests admission separately from CLI path policy.
    from skylos.visitors.languages.rust.core import RustCore
    from skylos.visitors.languages.rust.project_traits import (
        apply_project_trait_imports,
    )

    core = RustCore(str(tmp_path / "main.rs"), (tmp_path / "main.rs").read_bytes())
    core.scan()
    (tmp_path / "external.rs").write_text("")
    definitions = {str(index): definition for index, definition in enumerate(core.defs)}
    apply_project_trait_imports(
        definitions,
        [tmp_path / "main.rs"],
        scan_root=tmp_path,
        analysis_scope={"complete_repository": True},
        analysis_errors=[],
    )
    assert (
        next(
            definition for definition in core.defs if definition.type == "import"
        ).references
        == 0
    )


@pytest.mark.parametrize(
    "source",
    [
        "use std::mem::drop as Release;\nfn main() {\nuse std::mem::drop as Release;\nRelease(String::new());\n}\n",
        "use std::mem::drop as Release; fn main() { use std::mem::drop as Release; Release(String::new()); }\n",
        "use std::mem::drop as r#Release;\nfn main() {\nuse std::mem::drop as r#Release;\nr#Release(String::new());\n}\n",
    ],
)
def test_duplicate_function_alias_retains_unread_outer_import(tmp_path, source):
    (tmp_path / "main.rs").write_text(source)
    assert _scan(tmp_path) == {("Release", 1)}


def test_duplicate_aliases_used_in_separate_modules_keep_both(tmp_path):
    source = "mod first { use std::mem::drop as Release; pub fn run() { Release(String::new()); } }\nmod second { use std::mem::drop as Release; pub fn run() { Release(String::new()); } }\nfn main() { first::run(); second::run(); }\n"
    (tmp_path / "main.rs").write_text(source)
    assert _scan(tmp_path) == set()


def test_unused_sibling_module_import_is_not_read_by_same_alias(tmp_path):
    source = "mod first { use std::mem::drop as Release; pub fn run() { Release(String::new()); } }\nmod second { use std::mem::drop as Release; }\nfn main() { first::run(); }\n"
    (tmp_path / "main.rs").write_text(source)
    assert _scan(tmp_path) == {("Release", 2)}


def test_duplicate_module_reimport_reads_its_outer_provider(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use std::mem as memory;\nmod child { use crate::memory as memory; pub fn run() { memory::drop(String::new()); } }\nfn main() { child::run(); }\n"
    )
    assert _scan(tmp_path) == set()


def test_duplicate_type_alias_retains_unused_outer_binding(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use std::string::String as Text;\nfn main() { use std::string::String as Text; let _: Text = Text::new(); }\n"
    )
    assert _scan(tmp_path) == {("Text", 1)}


def test_local_value_shadow_does_not_read_either_import(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use std::mem::drop as Release;\nfn main() { use std::mem::drop as Release; { let Release = |_| (); Release(String::new()); } }\n"
    )
    assert _scan(tmp_path) == {("Release", 1), ("Release", 2)}


def test_inactive_conditional_alias_cannot_replace_used_outer_binding(tmp_path):
    (tmp_path / "main.rs").write_text(
        "use std::mem::drop as Release;\nfn main() { #[cfg(any())] use std::mem::drop as Release; Release(String::new()); }\n"
    )
    assert _scan(tmp_path) == set()
