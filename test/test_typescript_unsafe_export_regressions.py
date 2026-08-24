import pytest
import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser

from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.quality_signals import _api_value_contract


def _t106(tmp_path, source, *, filename="unsafe-export.ts"):
    path = tmp_path / filename
    path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        source,
        encoding="utf-8",
    )
    findings = scan_typescript_file(str(path), enable_quality_rules=True)[6]
    return [finding for finding in findings if finding["rule_id"] == "SKY-T106"]


def test_deep_exported_type_does_not_recurse_or_flag_nested_any(tmp_path):
    source = "export type Deep = " + "Promise<" * 700 + "any" + ">" * 700 + ";"

    assert _t106(tmp_path, source) == []


@pytest.mark.parametrize(
    "source",
    [
        "export const result = factory((value: any): any => value);",
        (
            "export const handler: (value: unknown) => unknown = "
            "(value: any): any => value;"
        ),
        (
            "function parse(value: any): any { return value; }"
            "const alias: (value: unknown) => unknown = parse;"
            "export { alias };"
        ),
        ("export const result = { value: factory((item: any): any => item) };"),
        (
            "export function run(): unknown { "
            "return factory((value: any): any => value); }"
        ),
        "export default factory((value: any): any => value);",
    ],
)
def test_runtime_callbacks_are_not_treated_as_exported_api_slots(tmp_path, source):
    assert _t106(tmp_path, source) == []


@pytest.mark.parametrize(
    "source",
    [
        (
            "export default class extends Base {"
            " private hidden(value: any): any { return value; }"
            " protected guarded(value: any): any { return value; }"
            " override inherited(value: any): any { return value; }"
            " #secret: any;"
            " }"
        ),
        (
            "const Client = class extends Base {"
            " private hidden(value: any): any { return value; }"
            " protected guarded: any;"
            " override inherited(value: any): any { return value; }"
            " #secret: any;"
            " }; export { Client };"
        ),
    ],
)
def test_class_expression_private_and_override_members_stay_private(tmp_path, source):
    assert _t106(tmp_path, source) == []


@pytest.mark.parametrize(
    ("source", "expected_name"),
    [
        (
            "export default class { public send(value: any): unknown {} }",
            "default.send",
        ),
        (
            (
                "const Client = class { send(value: any): unknown {} }; "
                "export { Client };"
            ),
            "Client.send",
        ),
        (
            "export default { run(value: any): unknown { return value; } };",
            "default.run",
        ),
    ],
)
def test_public_members_of_direct_exported_values_are_checked(
    tmp_path, source, expected_name
):
    findings = _t106(tmp_path, source)

    assert [finding["name"] for finding in findings] == [expected_name]


def test_exported_overload_signatures_are_not_overwritten(tmp_path):
    findings = _t106(
        tmp_path,
        "function parse(value: any): void;"
        "function parse(value: string): void {}"
        "export { parse };",
    )

    assert len(findings) == 1
    assert findings[0]["name"] == "parse"


@pytest.mark.parametrize(
    "source",
    [
        (
            "function parse(value: unknown): unknown;"
            "function parse(value: any): any { return value; }"
            "export { parse };"
        ),
        (
            "export function parse(value: unknown): unknown;"
            "export function parse(value: any): any { return value; }"
        ),
        (
            "export class Client {"
            "parse(value: unknown): unknown;"
            "parse(value: any): any { return value; }"
            "}"
        ),
        (
            "declare const method: unique symbol;"
            "export class Client {"
            "[method](value: unknown): unknown;"
            "[ method ](value: any): any { return value; }"
            "}"
        ),
        (
            "export class Client {"
            '["parse"](value: unknown): unknown;'
            "['parse'](value: any): any { return value; }"
            "}"
        ),
        (
            "export class Client {"
            "handler: (value: unknown) => unknown = "
            "(value: any): any => value;"
            "}"
        ),
    ],
)
def test_explicit_public_contracts_hide_implementation_types(tmp_path, source):
    assert _t106(tmp_path, source) == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("export const value = source as any;", 1),
        ("export default source as Record<string, any>;", 1),
        ("export const value = <any>source;", 1),
        ("export const value = await (source as any);", 1),
        ("export default await (source as Record<string, any>);", 1),
        ("export const handler = source as (value: any) => any;", 2),
        (
            "export default source as {value: any; records: Record<string, any>};",
            2,
        ),
        ("export const value = source as Promise<any>;", 0),
        (
            (
                "export const handler = ((value: any): any => value) "
                "satisfies (value: unknown) => unknown;"
            ),
            2,
        ),
        ("export const value = (source as any) as unknown;", 0),
    ],
)
def test_exported_assertions_and_satisfies_keep_typescript_semantics(
    tmp_path, source, expected
):
    assert len(_t106(tmp_path, source)) == expected


@pytest.mark.parametrize(
    "export_expression",
    ["(parse)", "parse!", "parse satisfies (value: unknown) => unknown"],
)
def test_default_export_wrappers_preserve_local_function_contract(
    tmp_path, export_expression
):
    findings = _t106(
        tmp_path,
        "function parse(value: any): any { return value; }"
        f"export default {export_expression};",
    )

    assert len(findings) == 2


def test_default_export_assertion_replaces_local_function_contract(tmp_path):
    findings = _t106(
        tmp_path,
        "function parse(value: any): any { return value; }"
        "export default parse as (value: unknown) => unknown;",
    )

    assert findings == []


def test_awaited_thenable_does_not_expose_the_raw_object_contract(tmp_path):
    findings = _t106(
        tmp_path,
        "declare const source: unknown;"
        "export const value = await (source as {"
        "then(onfulfilled: (value: unknown) => unknown): unknown;"
        "internal: any"
        "});",
    )

    assert findings == []


def test_deep_await_wrappers_fail_closed_without_recursion():
    source = ("export const value = " + "await\n" * 1_100 + "(source as any);").encode()
    parser = Parser(Language(tsts.language_typescript()))
    root = parser.parse(source).root_node
    declaration = root.named_children[0].child_by_field_name("declaration")
    declarator = next(
        child
        for child in declaration.named_children
        if child.type == "variable_declarator"
    )
    value = declarator.child_by_field_name("value")

    annotation, preserved = _api_value_contract(value, source)

    assert root.has_error is False
    assert annotation is None
    assert preserved.id == value.id


@pytest.mark.parametrize(
    "source",
    [
        "export const parse = () => source as any;",
        "export const parse = () => source as Record<string, any>;",
        "export function parse() { return source as any; }",
        'export function parse() { "use strict"; return source as any; }',
    ],
)
def test_direct_inferred_return_contracts_are_checked(tmp_path, source):
    assert len(_t106(tmp_path, source)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "export const parse = async () => source as any;",
        "export async function parse() { return source as any; }",
    ],
)
def test_async_inferred_returns_remain_nested_in_promise(tmp_path, source):
    assert _t106(tmp_path, source) == []


@pytest.mark.parametrize(
    ("source", "expected_names"),
    [
        (
            (
                "export namespace API {"
                "export function parse(value: any): any { return value; }"
                "}"
            ),
            ["API.parse", "API.parse"],
        ),
        (
            "export namespace API { export interface Payload { value: any } }",
            ["API.Payload"],
        ),
        (
            (
                "namespace API { export type Payload = Record<string, any>; }"
                "export { API };"
            ),
            ["API.Payload"],
        ),
        (
            (
                "export namespace Outer {"
                "export namespace Inner { export const value: any = source; }"
                "}"
            ),
            ["Outer.Inner.value"],
        ),
    ],
)
def test_exported_namespace_contracts_are_checked(tmp_path, source, expected_names):
    assert [finding["name"] for finding in _t106(tmp_path, source)] == expected_names


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('declare module "pkg" { export function parse(value: any): any; }', 2),
        ('declare module "pkg" { function parse(value: any): any; }', 2),
        ("declare namespace API { function parse(value: any): any; }", 2),
        (
            "declare global { interface Window { payload: any } } export {};",
            1,
        ),
    ],
)
def test_ambient_module_and_global_contracts_are_checked(tmp_path, source, expected):
    assert len(_t106(tmp_path, source, filename="public.d.ts")) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("declare function parse(value: any): any;", 2),
        ("interface Window { payload: any }", 1),
        ("declare const config: Record<string, any>;", 1),
    ],
)
def test_declaration_script_globals_are_public(tmp_path, source, expected):
    assert len(_t106(tmp_path, source, filename="public.d.ts")) == expected


def test_module_local_ambient_namespace_is_not_exported(tmp_path):
    findings = _t106(
        tmp_path,
        "export {};declare namespace Internal { function parse(value: any): any; }",
        filename="public.d.ts",
    )

    assert findings == []


@pytest.mark.parametrize("filename", ["public.d.mts", "public.d.cts"])
def test_declaration_module_extensions_do_not_create_script_globals(tmp_path, filename):
    findings = _t106(
        tmp_path,
        "declare namespace Internal { function parse(value: any): any; }",
        filename=filename,
    )

    assert findings == []


@pytest.mark.parametrize(
    "source",
    [
        "export const { value }: any = source;",
        "export const [value]: any = source;",
        "const { value }: { value: any } = source; export { value };",
        "const { value } = source as any; export { value };",
    ],
)
def test_exported_destructured_exact_contracts_are_checked(tmp_path, source):
    assert len(_t106(tmp_path, source)) == 1


def test_destructured_exports_only_check_the_selected_property(tmp_path):
    source = (
        "const { safe, hidden }: { safe: unknown; hidden: any } = source;"
        "export { safe };"
    )

    assert _t106(tmp_path, source) == []


def test_each_destructured_export_uses_its_own_property_contract(tmp_path):
    source = (
        "const { safe, hidden }: { safe: unknown; hidden: any } = source;"
        "export { safe, hidden };"
    )

    findings = _t106(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["name"] == "hidden"


@pytest.mark.parametrize(
    ("binding", "expected"),
    [("safe", 0), ("hidden", 1)],
)
def test_const_alias_preserves_destructured_contract_selector(
    tmp_path, binding, expected
):
    source = (
        "const { safe, hidden }: { safe: unknown; hidden: any } = source;"
        f"const alias = {binding}; export {{ alias }};"
    )

    findings = _t106(tmp_path, source)
    assert len(findings) == expected
    if findings:
        assert findings[0]["name"] == "alias"


def test_exported_declaration_namespace_members_are_implicitly_public(tmp_path):
    source = "export namespace API {function parse(value: any): any;}"

    assert len(_t106(tmp_path, source, filename="api.d.ts")) == 2


def test_merged_exported_type_declarations_are_all_checked(tmp_path):
    findings = _t106(
        tmp_path,
        "interface Payload { unsafe: any }"
        "interface Payload { safe: unknown }"
        "export type { Payload };",
    )

    assert len(findings) == 1
    assert findings[0]["name"] == "Payload"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            (
                "type Shared = unknown; const Shared: any = source; "
                "export type { Shared };"
            ),
            0,
        ),
        (
            "type Shared = unknown; const Shared: any = source; export { Shared };",
            1,
        ),
        (
            "type Shared = any; const Shared: unknown = source; export { Shared };",
            1,
        ),
    ],
)
def test_type_and_value_export_namespaces_are_kept_separate(tmp_path, source, expected):
    assert len(_t106(tmp_path, source)) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            (
                "function helper() { type Record<K, V> = V; }"
                "export type Payload = Record<string, any>;"
            ),
            1,
        ),
        (
            (
                "import { Record as Renamed } from './types';"
                "export type Payload = Record<string, any>;"
            ),
            1,
        ),
        (
            (
                "import { Other as Record } from './types';"
                "export type Payload = Record<string, any>;"
            ),
            0,
        ),
        (
            ("import Record = Types.Record;export type Payload = Record<string, any>;"),
            0,
        ),
        (
            "module Record {} export type Payload = Record<string, any>;",
            0,
        ),
        (
            ("type Record<K, V> = V;export type Payload = Record<string, any>;"),
            0,
        ),
    ],
)
def test_record_shadowing_uses_the_reference_scope(tmp_path, source, expected):
    assert len(_t106(tmp_path, source)) == expected


@pytest.mark.parametrize(
    "source",
    [
        "export type Handler = () => any;",
        "export const handler: () => any = () => value;",
        "export type Payload = Record<string, /* documented */ any>;",
    ],
)
def test_function_returns_and_commented_record_types_are_detected(tmp_path, source):
    assert len(_t106(tmp_path, source)) == 1


def test_multiple_export_aliases_do_not_duplicate_the_same_slot(tmp_path):
    findings = _t106(
        tmp_path,
        "function parse(value: any): void; export { parse as one, parse as two };",
    )

    assert len(findings) == 1


@pytest.mark.parametrize(
    ("source", "expected_names"),
    [
        (
            "export = { parse(value: any): any { return value; } };",
            ["default.parse", "default.parse"],
        ),
        (
            "function parse(value: any): any { return value; } export = parse;",
            ["parse", "parse"],
        ),
    ],
)
def test_export_assignment_contracts_are_checked(tmp_path, source, expected_names):
    assert [finding["name"] for finding in _t106(tmp_path, source)] == expected_names


@pytest.mark.parametrize(
    "source",
    [
        (
            "class Client { static parse(value: any): any { return value; } }"
            "export type { Client };"
        ),
        ("class Client { constructor(value: any) {} }export type { Client };"),
    ],
)
def test_type_only_class_exports_skip_static_and_constructor_contracts(
    tmp_path, source
):
    assert _t106(tmp_path, source) == []


def test_type_only_class_exports_still_check_instance_contracts(tmp_path):
    findings = _t106(
        tmp_path,
        "class Client { send(value: any): any { return value; } }"
        "export type { Client };",
    )

    assert [finding["name"] for finding in findings] == [
        "Client.send",
        "Client.send",
    ]


@pytest.mark.parametrize("modifier", ["public", "readonly", "public readonly"])
def test_type_only_class_exports_check_public_parameter_properties(tmp_path, modifier):
    findings = _t106(
        tmp_path,
        f"class Client {{ constructor({modifier} value: any) {{}} }}"
        "export type { Client };",
    )

    assert [finding["name"] for finding in findings] == ["Client.value"]


def test_type_only_class_exports_check_override_parameter_properties(tmp_path):
    findings = _t106(
        tmp_path,
        "class Base { value: unknown }"
        "class Client extends Base {"
        "constructor(override value: any) { super(); }"
        "} export type { Client };",
    )

    assert [finding["name"] for finding in findings] == ["Client.value"]


@pytest.mark.parametrize(
    "modifier", ["private", "protected", "protected readonly", "protected override"]
)
def test_type_only_class_exports_skip_private_parameter_properties(tmp_path, modifier):
    findings = _t106(
        tmp_path,
        f"class Client {{ constructor({modifier} value: any) {{}} }}"
        "export type { Client };",
    )

    assert findings == []


def test_type_only_namespace_exports_skip_value_members(tmp_path):
    findings = _t106(
        tmp_path,
        "namespace API {"
        "export const value: any = source;"
        "export type Payload = unknown;"
        "} export type { API };",
    )

    assert findings == []


def test_type_only_namespace_exports_keep_nested_instance_contracts(tmp_path):
    findings = _t106(
        tmp_path,
        "namespace API { export class Client {"
        "static parse(value: any): any { return value; }"
        "send(value: any): any { return value; }"
        "} } export type { API };",
    )

    assert [finding["name"] for finding in findings] == [
        "API.Client.send",
        "API.Client.send",
    ]


def test_array_rest_destructuring_keeps_the_remaining_tuple_shape(tmp_path):
    findings = _t106(
        tmp_path,
        "const [safe, ...rest]: [unknown, any] = value; export { rest };",
    )

    assert findings == []


@pytest.mark.parametrize(
    ("source", "expected_names"),
    [
        (
            (
                "function parse(value: any): any { return value; }"
                "export default { parse };"
            ),
            ["default.parse", "default.parse"],
        ),
        (
            (
                "function parse(value: any): any { return value; }"
                "export default { run: parse };"
            ),
            ["default.run", "default.run"],
        ),
    ],
)
def test_exported_object_identifier_properties_resolve_local_contracts(
    tmp_path, source, expected_names
):
    assert [finding["name"] for finding in _t106(tmp_path, source)] == expected_names


def test_default_parameter_assertion_is_an_inferred_public_contract(tmp_path):
    findings = _t106(
        tmp_path,
        "export function parse(value = source as any): unknown { return value; }",
    )

    assert [finding["name"] for finding in findings] == ["parse"]


def test_explicit_parameter_type_wins_over_asserted_default(tmp_path):
    findings = _t106(
        tmp_path,
        "export function parse(value: unknown = source as any): unknown { "
        "return value; }",
    )

    assert findings == []


@pytest.mark.parametrize(
    "source",
    [
        "export class Box<T = any> {}",
        "export function get<T = any>(): T;",
        "export interface Box<T = any> { value: T }",
        "export type Box<T = any> = { value: T };",
    ],
)
def test_exported_generic_defaults_are_checked(tmp_path, source):
    assert len(_t106(tmp_path, source)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "export interface API { get<T = any>(): T }",
        "export type API = <T = any>() => T;",
        "export type API = { get<T = any>(): T };",
        "export interface API { get: <T = any>() => T }",
    ],
)
def test_nested_exported_generic_defaults_are_checked(tmp_path, source):
    assert len(_t106(tmp_path, source)) == 1


def test_nested_or_union_generic_defaults_stay_out_of_exact_any_rule(tmp_path):
    assert _t106(tmp_path, "export type Box<T = any | null> = { value: T };") == []


def test_unlabelled_tuple_slots_are_checked(tmp_path):
    findings = _t106(tmp_path, "export type Pair = [any, string];")

    assert [finding["name"] for finding in findings] == ["Pair"]


@pytest.mark.parametrize(
    "source",
    [
        "export type Values = any[];",
        "export type Values = [any | null];",
        "export type Values = [...any[]];",
    ],
)
def test_nested_tuple_any_stays_out_of_exact_any_rule(tmp_path, source):
    assert _t106(tmp_path, source) == []


def test_exported_inferred_object_does_not_resolve_shadowed_identifier(tmp_path):
    findings = _t106(
        tmp_path,
        "function parse(value: any): any { return value; }"
        "export function wrapper(parse: unknown) { return { parse }; }",
    )

    assert findings == []


def test_nested_record_contract_scan_stays_bounded(tmp_path):
    contract = "leaf: unknown"
    for index in range(400):
        contract = f"field{index}: Record<string, any>;\nnext: {{\n{contract}\n}}"
    source = f"export interface Payload {{\n{contract}\n}}"

    findings = _t106(tmp_path, source)

    assert len(findings) == 400


def test_deep_exact_any_contract_scan_stays_bounded(tmp_path):
    contract = "leaf: unknown"
    for index in range(800):
        contract = f"field{index}: any;\nnext: {{\n{contract}\n}}"
    source = f"export interface Payload {{\n{contract}\n}}"

    findings = _t106(tmp_path, source)

    assert len(findings) == 800


def test_deep_exported_object_identifier_resolution_stays_bounded(tmp_path):
    value = "{ parse }"
    for _ in range(400):
        value = "{\nparse,\nnext:\n" + value + "\n}"
    source = (
        f"function parse(value: any): any {{ return value; }}\nexport default {value};"
    )

    findings = _t106(tmp_path, source)

    assert [finding["name"] for finding in findings] == [
        "default.parse",
        "default.parse",
    ]
