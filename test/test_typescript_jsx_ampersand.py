"""Raw JSX text must not make an otherwise valid TSX scan incomplete."""

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.core import TypeScriptCore


@pytest.mark.parametrize(
    "markup",
    [
        "<p>Save & Enable</p>",
        "<p>A & B & C</p>",
        "<p>&</p>",
        "<>A & B</>",
        "<p>A && B</p>",
        "<p>A & B <span>Q & R</span></p>",
        "<p>A & B {value & other}</p>",
    ],
)
def test_raw_ampersands_in_jsx_text_parse_without_changing_source(markup):
    source = f"export const View = () => {markup};\n".encode("utf-8")
    core = TypeScriptCore("view.tsx", source)

    assert core.root_node is not None
    assert core.root_node.has_error is False
    assert core.source == source
    assert any(
        "&" in core._get_text(node)
        for node in core._iter_nodes(core.root_node)
        if node.type == "jsx_text"
    )


def test_raw_jsx_ampersands_preserve_unicode_offsets_and_scan_metadata(tmp_path):
    source = (
        "export function View() {\n"
        "  return <p>Résumé · Free & open source · A & B</p>;\n"
        "}\n"
        "export const after = 1;\n"
    )
    path = tmp_path / "view.tsx"
    path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        source, encoding="utf-8"
    )

    result = scan_typescript_file(str(path), _include_analysis_metadata=True)
    definitions = {definition.name: definition.line for definition in result[0]}
    assert result[25] is None
    assert definitions["View"] == 1
    assert definitions["after"] == 4

    core = TypeScriptCore(str(path), source.encode("utf-8"))
    jsx_text = next(
        node
        for node in core._iter_nodes(core.root_node)
        if node.type == "jsx_text"
        and b"Free &" in core.source[node.start_byte : node.end_byte]
    )
    assert core._get_text(jsx_text) == "Résumé · Free & open source · A & B"
    assert jsx_text.start_point[0] == 1


@pytest.mark.parametrize(
    "source",
    [
        "const View = () => <p>A & B {value & }</p>;",
        "const View = () => <p>A & B</p>; const broken = ;",
        "const View = () => <p>Save & Enable</p>; const broken = 1 & ;",
        "const View = () => <p>&amp;</p>; const broken = ;",
        "const View = () => <p & bad>text</p>;",
        "const View = () => <T & U>text</T>;",
        "const broken = 1 & ;",
    ],
)
def test_raw_jsx_ampersand_recovery_keeps_other_syntax_errors(source):
    core = TypeScriptCore("view.tsx", source.encode("utf-8"))
    assert core.root_node is not None
    assert core.root_node.has_error is True
