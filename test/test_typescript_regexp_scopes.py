"""RegExp scope regressions using inert, in-memory TypeScript sources."""

import pytest
from tree_sitter import Parser

from skylos.visitors.languages.typescript import danger as danger_module


def _scan_exec_findings(source: str, expected_exec_lines: list[int]) -> list[tuple]:
    source_bytes = source.encode("utf-8")
    lang = danger_module.TS_LANG
    assert lang is not None
    root = Parser(lang).parse(source_bytes).root_node
    assert not root.has_error

    captures = danger_module._run_batch(
        root, lang, "danger_complex", danger_module._COMPLEX_PATTERN
    )
    assert (
        sorted(node.start_point[0] + 1 for node in captures.get("exec_prop", []))
        == expected_exec_lines
    )

    findings = danger_module.scan_danger(
        root, "src/labels.ts", lang=lang, source=source_bytes
    )
    assert not [
        finding
        for finding in findings
        if finding["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    ]
    return [
        (finding["rule_id"], finding["file"], finding["line"])
        for finding in findings
        if finding["rule_id"] == "SKY-D212"
    ]


def test_code_block_regex_exec_is_not_command_execution():
    source = (
        "const codeBlockRegex = /```([\\s\\S]*?)```/g;\n"
        'const content = "```label```";\n'
        "let match;\n"
        "while ((match = codeBlockRegex.exec(content)) !== null) {\n"
        "  const block = match[1];\n"
        "}\n"
    )

    assert _scan_exec_findings(source, [4]) == []


@pytest.mark.parametrize(
    "inner_scope",
    [
        pytest.param(
            "function describe(codeBlockRegex) {\n  return codeBlockRegex.length;\n}\n",
            id="function-parameter",
        ),
        pytest.param(
            "function describe<T>(codeBlockRegex: T): T {\n"
            "  return codeBlockRegex;\n"
            "}\n",
            id="typed-generic-parameter",
        ),
        pytest.param(
            "const describe = (codeBlockRegex: string) => codeBlockRegex.length;\n",
            id="typed-arrow-parameter",
        ),
        pytest.param(
            "function describe() {\n"
            '  const codeBlockRegex = "label";\n'
            "  return codeBlockRegex.length;\n"
            "}\n",
            id="function-const-local",
        ),
        pytest.param(
            "function describe() {\n"
            '  var codeBlockRegex = "label";\n'
            "  return codeBlockRegex.length;\n"
            "}\n",
            id="function-var-local",
        ),
        pytest.param(
            "{\n"
            '  let codeBlockRegex = "label";\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="block-let-local",
        ),
        pytest.param(
            "try {\n"
            '  throw "label";\n'
            "} catch (codeBlockRegex) {\n"
            "  const label = codeBlockRegex;\n"
            "}\n",
            id="catch-binding",
        ),
        pytest.param(
            "function describe({ codeBlockRegex }: { codeBlockRegex: string }) {\n"
            "  return codeBlockRegex.length;\n"
            "}\n",
            id="typed-destructured-parameter",
        ),
        pytest.param(
            'for (const codeBlockRegex of ["label"]) {\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="for-of-lexical-binding",
        ),
        pytest.param(
            "for (let codeBlockRegex = 0; codeBlockRegex < 1; codeBlockRegex++) {\n"
            "  const index = codeBlockRegex;\n"
            "}\n",
            id="for-initializer-lexical-binding",
        ),
        pytest.param(
            "{\n"
            '  const { codeBlockRegex } = { codeBlockRegex: "label" };\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="object-destructured-local",
        ),
        pytest.param(
            "{\n"
            '  const { label: codeBlockRegex } = { label: "label" };\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="renamed-destructured-local",
        ),
        pytest.param(
            "{\n"
            '  const { codeBlockRegex = "label" } = {};\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="object-destructuring-literal-default",
        ),
        pytest.param(
            "{\n"
            '  const [codeBlockRegex = "label"] = [];\n'
            "  const size = codeBlockRegex.length;\n"
            "}\n",
            id="array-destructuring-literal-default",
        ),
        pytest.param(
            "const describe = function codeBlockRegex() {\n"
            "  return codeBlockRegex.name;\n"
            "};\n",
            id="named-function-expression",
        ),
        pytest.param(
            "const Label = class codeBlockRegex {\n"
            "  describe() { return codeBlockRegex.name; }\n"
            "};\n",
            id="named-class-expression",
        ),
        pytest.param(
            "const labels = {\n"
            "  describe(codeBlockRegex: string) { return codeBlockRegex.length; }\n"
            "};\n",
            id="object-method-parameter",
        ),
        pytest.param(
            "class Label {\n"
            "  describe(codeBlockRegex: string) { return codeBlockRegex.length; }\n"
            "}\n",
            id="class-method-parameter",
        ),
    ],
)
def test_inner_shadow_does_not_invalidate_outer_regexp(inner_scope):
    source = (
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
        + inner_scope
        + 'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, len(source.splitlines())]) == []


def test_sibling_function_binding_does_not_affect_local_regexp():
    source = (
        "function matchLabel() {\n"
        "  const codeBlockRegex = /label/g;\n"
        '  return codeBlockRegex.exec("label");\n'
        "}\n"
        "function describe(codeBlockRegex: string) {\n"
        "  return codeBlockRegex.length;\n"
        "}\n"
    )

    assert _scan_exec_findings(source, [3]) == []


def test_nested_regexp_bindings_keep_their_own_calls():
    source = (
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
        "function matchOtherLabel() {\n"
        "  const codeBlockRegex = /other/g;\n"
        '  return codeBlockRegex.exec("other");\n'
        "}\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, 5, 7]) == []


def test_closure_preserves_outer_literal_regexp():
    source = (
        "const codeBlockRegex = /label/g;\n"
        "function matchLabel(text: string) {\n"
        "  return codeBlockRegex.exec(text);\n"
        "}\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [3, 5]) == []


def test_nested_var_is_body_scoped_without_shadowing_parameter_default():
    source = (
        "const codeBlockRegex = /label/g;\n"
        'function describe(match = codeBlockRegex.exec("label")) {\n'
        "  if (true) {\n"
        '    var codeBlockRegex = "label";\n'
        "  }\n"
        "  const label = codeBlockRegex;\n"
        "  return match;\n"
        "}\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, 9]) == []


@pytest.mark.parametrize(
    "declaration",
    ["const labels = {", "class Label {"],
    ids=["object-method", "class-method"],
)
def test_computed_method_name_uses_outer_regexp_before_parameter_scope(declaration):
    source = (
        "const codeBlockRegex = /label/g;\n"
        f"{declaration}\n"
        '  [codeBlockRegex.exec("label")![0]](codeBlockRegex: string) {\n'
        "    return codeBlockRegex.length;\n"
        "  }\n"
        "};\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [3, 7]) == []


@pytest.mark.parametrize(
    "import_statement",
    [
        pytest.param(
            'import { codeBlockRegex as label } from "./labels";',
            id="aliased-remote-spelling",
        ),
        pytest.param(
            'import type { codeBlockRegex } from "./labels";',
            id="type-only-import",
        ),
        pytest.param(
            'import { type codeBlockRegex } from "./labels";',
            id="type-only-specifier",
        ),
    ],
)
def test_static_import_names_do_not_contaminate_runtime_regexp(import_statement):
    source = (
        f"{import_statement}\n"
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [3]) == []


@pytest.mark.parametrize(
    "function_body",
    [
        pytest.param("  return arguments.length;\n", id="ordinary-function"),
        pytest.param(
            "  const count = () => arguments.length;\n  return count;\n",
            id="arrow-inherits-function-arguments",
        ),
    ],
)
def test_implicit_arguments_is_independent_of_outer_regexp(function_body):
    source = (
        "const arguments = /label/g;\n"
        'arguments.exec("label");\n'
        "function describe() {\n"
        f"{function_body}"
        "}\n"
        'arguments.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, len(source.splitlines())]) == []


def test_arrow_retains_outer_regexp_named_arguments():
    source = (
        "const arguments = /label/g;\n"
        "const matchLabel = (text: string) => arguments.exec(text);\n"
        'arguments.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, 3]) == []


def test_opaque_same_named_parameter_does_not_inherit_outer_regexp_proof():
    source = (
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
        "function describe(codeBlockRegex: { exec(text: string): string }) {\n"
        '  return codeBlockRegex.exec("label");\n'
        "}\n"
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, 4, 6]) == [("SKY-D212", "src/labels.ts", 4)]


def test_unknown_exec_receiver_is_not_exempted_by_nearby_regexp():
    source = (
        "const codeBlockRegex = /label/g;\n"
        'codeBlockRegex.exec("label");\n'
        "declare const receiver: { exec(text: string): string };\n"
        'receiver.exec("label");\n'
        'codeBlockRegex.exec("label");\n'
    )

    assert _scan_exec_findings(source, [2, 4, 5]) == [("SKY-D212", "src/labels.ts", 4)]
