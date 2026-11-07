"""Opaque closer bindings cannot inherit a same-named outer receiver's type."""

import json

import pytest

from skylos.analyzer import analyze


_KINDS = (
    "tuple",
    "closure",
    "for",
    "match",
    "if-let",
    "while-let",
    "const",
    "static",
    "raw-tuple",
    "parameter",
)


def _body(kind, name, owner, use):
    if kind in {"tuple", "raw-tuple"}:
        binding = "r#" + name if kind == "raw-tuple" else name
        return f"{{ let ({binding}, _) = ({owner} {{}}, ()); {use} }}"
    if kind == "closure":
        return (
            f"let call = |({name}, _): ({owner}, ())| {{ {use} }}; call(({owner} {{}}, ())));"[
                :-2
            ]
            + ";"
        )
    if kind == "for":
        return f"for {name} in [{owner} {{}}] {{ {use} }}"
    if kind == "match":
        return f"match ({owner} {{}}, ()) {{ ({name}, _) => {{ {use} }} }};"
    if kind == "if-let":
        return f"if let Some({name}) = Some({owner} {{}}) {{ {use} }}"
    if kind == "while-let":
        return f"let mut source = Some({owner} {{}}); while let Some({name}) = source.take() {{ {use} }}"
    if kind in {"const", "static"}:
        return f"{{ {kind} {name}: {owner} = {owner} {{}}; {use} }}"
    if kind == "parameter":
        return (
            f"fn call(({name}, _): ({owner}, ())) {{ {use} }} call(({owner} {{}}, ())));"[
                :-2
            ]
            + ";"
        )
    raise AssertionError(kind)


def _source(family, kind):
    if family == "trait":
        declarations = "struct Card {}\nstruct Other {}\nmod traits { pub trait Stamp { fn stamp(&self) -> u8; } impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } } }\nimpl Other { fn stamp(&self) -> u8 { 2 } }\nuse crate::traits::Stamp as Inactive;\n"
        body = _body(kind, "value", "Other", "let _ = value.stamp();")
        return (
            declarations
            + f"fn main() {{ let value = Card {{}}; {body} let _ = value; }}\n"
        )
    declarations = "use std::io::Write as Inactive;\nstruct Writer {}\nimpl Writer { fn write_fmt(&self, _: std::fmt::Arguments<'_>) -> std::fmt::Result { Ok(()) } }\n"
    body = _body(kind, "buffer", "Writer", 'write!(buffer, "{}", 1).unwrap();')
    return (
        declarations
        + f"fn main() {{ let buffer: Vec<u8> = Vec::with_capacity(8); {body} let _ = buffer; }}\n"
    )


def _unused(tmp_path, source):
    (tmp_path / "main.rs").write_text(source)
    report = json.loads(
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
    assert not report.get("analysis_errors")
    return {
        entry.get("simple_name", entry["name"])
        for entry in report.get("unused_imports", [])
    }


@pytest.mark.parametrize("family", ["trait", "io"])
@pytest.mark.parametrize("kind", _KINDS)
def test_unsupported_closer_binding_stops_outer_receiver_lookup(tmp_path, family, kind):
    assert "Inactive" in _unused(tmp_path, _source(family, kind))


def test_module_alias_writer_import_belongs_to_nearest_trait_binding(tmp_path):
    source = 'use std::io::Write as Outer;\nuse std::io as io;\nfn main() { use io::Write as Inner; let mut buffer: Vec<u8> = Vec::with_capacity(8); write!(buffer, "{}", 1).unwrap(); }\n'
    unused = _unused(tmp_path, source)
    assert "Outer" in unused
    assert "Inner" not in unused


def test_function_local_type_does_not_inherit_module_type_identity(tmp_path):
    source = "struct Card {}\nmod traits { pub trait Stamp { fn stamp(&self) -> u8; } pub trait Other { fn stamp(&self) -> u8; } impl Stamp for super::Card { fn stamp(&self) -> u8 { 1 } } }\nuse traits::Stamp as Inactive;\nfn main() { use crate::traits::Other as Active; struct Card {} impl Active for Card { fn stamp(&self) -> u8 { 2 } } let value = Card {}; let _ = value.stamp(); }\n"
    assert "Inactive" in _unused(tmp_path, source)
