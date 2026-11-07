"""Native-valid syntax gaps must preserve source names, offsets and real errors."""

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.core import TypeScriptCore


@pytest.mark.parametrize("filename", ["sample.ts", "sample.js", "sample.tsx"])
@pytest.mark.parametrize("tag", ["String.raw", "raw", "object.raw"])
@pytest.mark.parametrize(
    "literal", [r"`\undefined`", r"`\\unc-server\unc-path`", r"`\xG1`", r"`\u{wrong}`"]
)
def test_tagged_template_invalid_cooked_escape_is_valid_syntax(filename, tag, literal):
    source = f"const value = {tag}{literal};\n".encode()
    core = TypeScriptCore(filename, source)
    assert not core.root_node.has_error
    assert core.source == source
    assert core.root_node.end_byte == len(source)


@pytest.mark.parametrize(
    "expression",
    [
        'load<typeof import("./module")>()',
        'await load<typeof import("./module")>()',
        'load<typeof import("./module")["Config"]>()',
        'load<string, typeof import("./module")>()',
        'load<typeof import("./module")>(actualInput)',
    ],
)
def test_import_type_query_in_call_type_arguments_is_not_runtime_code(expression):
    source = f"const value = {expression};\n".encode()
    core = TypeScriptCore("sample.ts", source)
    assert not core.root_node.has_error
    assert core.source == source
    assert core.root_node.end_byte == len(source)
    core.scan()
    assert any(item["source"] == "./module" for item in core.raw_imports)


@pytest.mark.parametrize(
    "source",
    [
        r"const value = `\undefined`;",
        r"const value = String.raw`\undefined ${broken(}`;",
        r"const value = String.raw`\undefined`;" + "\nconst broken = ;",
        'const value = load<typeof import("./module")>();\nconst broken = ;',
        "const value = load<typeof import(variable)>();",
        'const value = load<typeof import("./module", wrong)>();',
        'const value = load<typeof import("./module")>(;',
    ],
)
def test_genuine_errors_around_new_repairs_stay_incomplete(tmp_path, source):
    filename = tmp_path / "sample.ts"
    filename.write_text(source, encoding="utf-8")
    result = scan_typescript_file(str(filename), _include_analysis_metadata=True)
    assert result[25] is not None


def test_runtime_call_and_following_danger_keep_their_source_positions(tmp_path):
    source = (
        r"const path = String.raw`\undefined`;" + "\n"
        'const actual = load<typeof import("./module")>(request.query);\n'
        "export function run(value: string) {\n"
        "  return eval(value);\n"
        "}\n"
    )
    filename = tmp_path / "sample.ts"
    filename.write_text(source, encoding="utf-8")
    result = scan_typescript_file(str(filename), _include_analysis_metadata=True)
    assert result[25] is None
    assert any(d.name == "run" and d.line == 3 for d in result[0])
    assert any(f["rule_id"] == "SKY-D201" and f["line"] == 4 for f in result[7])


def test_repaired_type_query_keeps_runtime_argument_references_and_original_names():
    source = b'const result = load<typeof import("./module")>(actualInput);'
    core = TypeScriptCore("sample.ts", source)
    core.scan()
    assert not core.root_node.has_error
    names = {name for name, _ in core.refs}
    assert "load" in names
    assert "actualInput" in names
    assert not any("impor_" in name for name in names)
    imports = [item for item in core.raw_imports if item["source"] == "./module"]
    assert len(imports) == 1
    assert imports[0].get("type_only") is True


def test_relational_runtime_import_is_not_reclassified_as_a_type_query():
    source = b'const result = value < typeof import("./module");\nconst broken = ;'
    core = TypeScriptCore("sample.ts", source)
    core.scan()
    assert core.root_node.has_error
    imports = [item for item in core.raw_imports if item["source"] == "./module"]
    assert len(imports) == 1
    assert not imports[0].get("type_only")


def test_parenthesized_comparisons_keep_actual_runtime_imports():
    source = b'const result = (value < typeof import("./module")) > (actualInput);'
    core = TypeScriptCore("sample.ts", source)
    core.scan()
    assert not core.root_node.has_error
    imports = [item for item in core.raw_imports if item["source"] == "./module"]
    assert len(imports) == 1
    assert not imports[0].get("type_only")
