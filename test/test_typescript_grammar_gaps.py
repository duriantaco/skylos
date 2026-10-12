"""Valid TS/JS the tree-sitter grammar rejects must not make a scan incomplete.

tree-sitter-typescript 0.23.2 fails on these constructs; Skylos repairs them
in a scratch copy of the source without moving any byte, so findings keep
their lines and genuine syntax errors are still reported.
"""

import json

import pytest
from tree_sitter import Parser

from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.core import TS_LANG, TSX_LANG, TypeScriptCore

GRAMMAR_GAPS = {
    # TypeScript 4.7 variance annotations (zod, effect).
    "variance_interface": (
        "gap.ts",
        (
            "export interface Box<in out T, out U = unknown> {\n"
            "  value: T\n"
            "  other: U\n"
            "}\n"
        ),
    ),
    "variance_multiline": (
        "gap.ts",
        (
            "export interface ZodType<\n"
            "  out Output = unknown,\n"
            "  out Input = unknown,\n"
            "> extends Base {\n"
            "  parse(input: Input): Output\n"
            "}\n"
        ),
    ),
    "variance_type_alias_and_class": (
        "gap.ts",
        (
            "export type Equivalence<in A> = (self: A, that: A) => boolean\n"
            "export class Cell<out T> {\n"
            "  constructor(readonly value: T) {}\n"
            "}\n"
        ),
    ),
    # Generic call signature after a member without a separator (redux-saga
    # effects.d.ts, effect's dual APIs).
    "generic_call_signature_interface": (
        "gap.d.ts",
        (
            "interface ThunkDispatch<S, A extends Action> {\n"
            "  <R>(thunk: Thunk<R, S>): R\n"
            "  <B extends A>(action: B): B\n"
            "  <R, B extends A>(\n"
            "    action: B | Thunk<R, S>,\n"
            "  ): B | R\n"
            "}\n"
        ),
    ),
    "generic_call_signature_object_type": (
        "gap.ts",
        (
            "export const get: {\n"
            "  <S extends object, const K extends keyof S>(key: K): (self: S) => S[K]\n"
            "  <S extends object, const K extends keyof S>(self: S, key: K): S[K]\n"
            "} = dual(2, (self: any, key: any) => self[key])\n"
        ),
    ),
    "member_named_in": (
        "gap.ts",
        (
            "export interface Parameter {\n"
            "  name: string\n"
            '  in: "query" | "header"\n'
            "  required?: boolean\n"
            "}\n"
        ),
    ),
    # TypeScript 5.0 (vitest, trpc, TanStack Query).
    "export_type_star": (
        "gap.ts",
        (
            "export type * from './types'\n"
            "export type * as Vite from 'vite'\n"
            "export const after = 1\n"
        ),
    ),
    # Escapes in template literal types (effect Schema.ts, drizzle-orm).
    "template_literal_type_escape": (
        "gap.ts",
        (
            "export type ImportTypeError<P extends string> =\n"
            "  `Please install \\`${P}\\` to use \\`class X extends ${P}<X>()\\``\n"
            "export const after = 1\n"
        ),
    ),
    # ``using`` as a plain identifier (drizzle-orm).
    "using_identifier": (
        "gap.ts",
        (
            "export function index(name: string, using?: string) {\n"
            "  if (using) return `${name} USING ${using}`\n"
            "  const [a, using2] = [using, 1]\n"
            "  return a\n"
            "}\n"
        ),
    ),
    "using_identifier_js": (
        "gap.js",
        "function index(using) {\n  if (using) return using\n  return null\n}\n",
    ),
    # A query string in a JSX attribute (trpc's site).
    "jsx_attribute_ampersand": (
        "gap.tsx",
        (
            "export const Fonts = () => (\n"
            '  <link href="https://fonts.example/css2?family=Inter&display=swap" />\n'
            ")\n"
        ),
    ),
}


def _raw_parse_has_error(file_name: str, source: str) -> bool:
    lang = TSX_LANG if file_name.endswith((".tsx", ".jsx", ".js")) else TS_LANG
    return Parser(lang).parse(source.encode("utf-8")).root_node.has_error


@pytest.mark.parametrize("name", sorted(GRAMMAR_GAPS))
def test_grammar_gap_is_still_a_raw_parse_error(name):
    """When a grammar release parses this, the repair for it can go."""
    file_name, source = GRAMMAR_GAPS[name]
    assert _raw_parse_has_error(file_name, source)


@pytest.mark.parametrize("name", sorted(GRAMMAR_GAPS))
def test_grammar_gap_parses_without_errors_and_keeps_source(name):
    file_name, source = GRAMMAR_GAPS[name]
    source_bytes = source.encode("utf-8")
    core = TypeScriptCore(file_name, source_bytes)

    assert core.root_node is not None
    assert core.root_node.has_error is False
    assert core.source == source_bytes
    assert core.root_node.end_byte == len(source_bytes)


@pytest.mark.parametrize("name", sorted(GRAMMAR_GAPS))
def test_grammar_gap_scan_reports_no_analysis_error(tmp_path, name):
    file_name, source = GRAMMAR_GAPS[name]
    (tmp_path / file_name).write_text(source, encoding="utf-8")

    result = scan_typescript_file(
        str(tmp_path / file_name), _include_analysis_metadata=True
    )

    assert result[25] is None


def test_variance_repair_names_the_real_type_parameters():
    source = b"interface Box<in out T, out U = unknown> { value: T }\n"
    core = TypeScriptCore("box.ts", source)

    names = [
        core._get_text(node.child_by_field_name("name"))
        for node in core._iter_nodes(core.root_node)
        if node.type == "type_parameter"
    ]
    parameters = next(
        node
        for node in core._iter_nodes(core.root_node)
        if node.type == "type_parameters"
    )

    assert names == ["T", "U"]
    # Text comes from the original source, modifiers included.
    assert core._get_text(parameters) == "<in out T, out U = unknown>"


def test_findings_after_repaired_spans_keep_their_lines(tmp_path):
    source = (
        "export interface Box<in out T> {\n"  # 1
        "  value: T\n"  # 2
        "}\n"  # 3
        "export const call: {\n"  # 4
        "  (a: string): string\n"  # 5
        "  <T>(a: T): T\n"  # 6
        "} = (a: any) => a\n"  # 7
        "export type * from './types'\n"  # 8
        "export type Message<P extends string> = `use \\`${P}\\``\n"  # 9
        "export function run(input: string, using?: string) {\n"  # 10
        "  return eval(input + using)\n"  # 11
        "}\n"  # 12
    )
    (tmp_path / "gaps.ts").write_text(source, encoding="utf-8")

    result = scan_typescript_file(
        str(tmp_path / "gaps.ts"), _include_analysis_metadata=True
    )
    definitions = {definition.name: definition.line for definition in result[0]}
    danger = result[7]

    assert result[25] is None
    assert definitions["Box"] == 1
    assert definitions["call"] == 4
    assert definitions["Message"] == 9
    assert definitions["run"] == 10
    assert [
        finding["line"] for finding in danger if finding["rule_id"] == "SKY-D201"
    ] == [11]


@pytest.mark.parametrize(
    ("file_name", "source", "line"),
    [
        # A genuine error after a repaired construct.
        ("bad.ts", "interface Box<in T> { value: T }\n\nconst broken = ;\n", 3),
        # A genuine error before a repaired construct.
        ("bad.ts", "const broken = ;\n\ninterface Box<in T> { value: T }\n", 1),
        ("bad.ts", "export type * from './a'\nexport const = 1\n", 2),
        ("bad.d.ts", "interface D {\n  x(): X\n  <A>(a: A): A\n  y: \n}\n", 4),
        # TypeScript rejects variance annotations on functions.
        ("bad.ts", "export function f<in T>(value: T) {}\n", 1),
        # An invalid escape is an error in a template literal type.
        ("bad.ts", "type T = `use \\`x\\` \\1`\n", 1),
        # Neither construct is JavaScript.
        ("bad.js", "class Box<in T> {}\n", 1),
        ("bad.js", "export type * from './a'\n", 1),
    ],
)
def test_genuine_syntax_errors_are_still_reported_with_their_line(
    tmp_path, file_name, source, line
):
    (tmp_path / file_name).write_text(source, encoding="utf-8")

    result = scan_typescript_file(
        str(tmp_path / file_name), _include_analysis_metadata=True
    )

    analysis_error = result[25]
    assert analysis_error is not None
    assert analysis_error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert analysis_error["error_type"] == "TypeScriptParseError"
    assert analysis_error["line"] == line


def test_full_scan_reports_only_genuine_typescript_syntax_errors(tmp_path):
    from skylos.analyzer import analyze

    for index, (file_name, source) in enumerate(GRAMMAR_GAPS.values()):
        (tmp_path / f"gap{index}_{file_name}").write_text(source, encoding="utf-8")
    (tmp_path / "bad.ts").write_text(
        "export interface Box<in T> { value: T }\n\nconst x = ;\n",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path)))

    errors = [
        (error["file"].rsplit("/", 1)[-1], error["line"])
        for error in result["analysis_errors"]
    ]
    assert errors == [("bad.ts", 3)]
