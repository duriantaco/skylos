import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript import scan_typescript_file


def _scan(
    tmp_path,
    source,
    *,
    filename="app.ts",
    config=None,
    enable_quality_rules=True,
):
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        source,
        encoding="utf-8",
    )
    result = scan_typescript_file(
        str(path),
        config=config,
        enable_quality_rules=enable_quality_rules,
    )
    return result[6]


def _rule(findings, rule_id):
    return [finding for finding in findings if finding["rule_id"] == rule_id]


@pytest.mark.parametrize(
    "source",
    [
        "new Promise(async (resolve) => resolve(await work()));",
        "new Promise<void>(async (resolve) => resolve(await work()));",
        "new Promise((async (resolve) => resolve(await work())));",
        "new Promise((/* reason */ async (resolve) => resolve(await work())));",
        "new Promise(<Executor>(async (resolve) => resolve(await work())));",
        "new Promise(async function (resolve) { resolve(await work()); });",
        "new Promise(async function* (resolve) { resolve(await work()); });",
    ],
)
def test_q405_flags_async_promise_executors(tmp_path, source):
    findings = _scan(tmp_path, source)

    async_executors = _rule(findings, "SKY-Q405")

    assert len(async_executors) == 1
    assert async_executors[0]["severity"] == "HIGH"
    assert async_executors[0]["name"] == "Promise"


@pytest.mark.parametrize(
    "source",
    [
        "new Promise((resolve) => resolve(work()));",
        "class Promise<T> { constructor(callback: unknown) {} }\nnew Promise(async () => work());",
        "function run(Promise: any) { new Promise(async () => work()); }",
        "globalThis.Promise = CustomPromise;\nnew Promise(async () => work());",
        "const text = 'new Promise(async () => work())';",
    ],
)
def test_q405_skips_safe_or_unproven_promise_constructors(tmp_path, source):
    assert _rule(_scan(tmp_path, source), "SKY-Q405") == []


def test_q405_skips_promise_mutated_from_another_scope(tmp_path):
    source = (
        "function poison() { Promise = CustomPromise; } poison();\n"
        "new Promise(async resolve => resolve(await work()));"
    )

    assert _rule(_scan(tmp_path, source), "SKY-Q405") == []


def test_q405_ignores_shadowed_nested_promise_mutation(tmp_path):
    source = (
        "function harmless(Promise) { Promise = CustomPromise; }\n"
        "new Promise(async resolve => resolve(await work()));"
    )

    assert len(_rule(_scan(tmp_path, source), "SKY-Q405")) == 1


@pytest.mark.parametrize(
    "source",
    [
        "[1, 2].forEach(async (value) => work(value));",
        "const values = [1, 2];\nvalues.forEach(async (value) => work(value));",
        "const values = Array.from(source);\nvalues.forEach(async (value) => work(value));",
        "const values = [1, 2];\nvalues.filter(Boolean).forEach(async (value) => work(value));",
        "const values = [1, 2];\nvalues.forEach(/* callback */ async (value) => work(value));",
        "[1, 2].forEach((/* reason */ async (value) => work(value)));",
        "const callback = async (value) => work(value); [1, 2].forEach(callback);",
        "async function callback(value) { await work(value); } [1, 2].forEach(callback);",
        "[1, 2].forEach(callback); async function callback(value) { await work(value); }",
        "async function callback(value) { await work(value); } callback(0); [1].forEach(callback);",
        '[1]["forEach"](async value => work(value));',
        "[3, 1].sort().forEach(async (value) => work(value));",
        "[1, 2].reverse().forEach(async (value) => work(value));",
        "const values = [1, 2]; consume(values); values.forEach(async value => work(value));",
    ],
)
def test_q406_flags_async_callbacks_on_proven_arrays(tmp_path, source):
    findings = _scan(tmp_path, source)

    callbacks = _rule(findings, "SKY-Q406")

    assert len(callbacks) == 1
    assert callbacks[0]["severity"] == "HIGH"
    assert callbacks[0]["name"] == "forEach"


@pytest.mark.parametrize(
    "source",
    [
        "[1, 2].forEach((value) => work(value));",
        "const custom = { forEach(callback: any) { callback(1); } };\ncustom.forEach(async (value) => work(value));",
        "let values = [1, 2];\nvalues.forEach(async (value) => work(value));",
        "const values = [1, 2];\nvalues.forEach = custom;\nvalues.forEach(async (value) => work(value));",
        "const source = [1];\nconst alias = source;\nsource.forEach = custom;\nalias.forEach(async value => work(value));",
        "const source = [1];\nconst alias = source;\nObject.setPrototypeOf(source, customPrototype);\nalias.forEach(async value => work(value));",
        "Array.prototype.forEach = custom;\n[1, 2].forEach(async (value) => work(value));",
        "const text = '.forEach(async value => work(value))';",
        "[1].forEach(async function* (value) { yield work(value); });",
        "async function callback(value) { await work(value); } callback = sync; [1].forEach(callback);",
        "callback = sync; async function callback(value) { await work(value); } [1].forEach(callback);",
    ],
)
def test_q406_skips_safe_or_unproven_foreach_calls(tmp_path, source):
    assert _rule(_scan(tmp_path, source), "SKY-Q406") == []


@pytest.mark.parametrize(
    ("method", "rule_id"),
    [("forEach", "SKY-Q406"), ("map", "SKY-Q407")],
)
@pytest.mark.parametrize(
    "mutation",
    [
        "function make() { callback = sync; return function run() { USE } } make()();",
        "function poison() { callback = sync; } poison(); USE",
    ],
)
def test_named_async_callbacks_skip_writes_from_other_visible_scopes(
    tmp_path, method, rule_id, mutation
):
    use = f"[1].{method}(callback);"
    source = (
        "async function callback(value) { await work(value); }\n"
        + mutation.replace("USE", use)
    )

    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    ("method", "rule_id"),
    [("forEach", "SKY-Q406"), ("map", "SKY-Q407")],
)
def test_const_async_callback_proof_fails_closed_on_assignment(
    tmp_path, method, rule_id
):
    source = (
        "const callback = async value => work(value);\n"
        "function poison() { callback = sync; } poison();\n"
        f"[1].{method}(callback);"
    )

    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    ("method", "rule_id"),
    [("forEach", "SKY-Q406"), ("map", "SKY-Q407")],
)
@pytest.mark.parametrize(
    "source_template",
    [
        (
            "async function callback(value) { await work(value); }\n"
            "function make() { return function run() { USE } } make()();"
        ),
        (
            "function make() {\n"
            "  async function callback(value) { await work(value); }\n"
            "  return function run() { USE };\n"
            "}\nmake()();"
        ),
        (
            "async function callback(value) { await work(value); }\n"
            "function shadow(callback) { callback = sync; } shadow(other); USE"
        ),
        ("async function callback(value) { await work(value); }\nUSE callback = sync;"),
    ],
)
def test_named_async_callbacks_keep_proof_across_safe_scope_cases(
    tmp_path, method, rule_id, source_template
):
    source = source_template.replace("USE", f"[1].{method}(callback);")

    assert len(_rule(_scan(tmp_path, source), rule_id)) == 1


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "async function callback(value) { await work(value); }\n"
                "for (callback of [sync]) {} [1].forEach(callback);"
            ),
            "SKY-Q406",
        ),
        (
            (
                "async function callback(value) { await work(value); }\n"
                "for (callback in source) {} [1].map(callback);"
            ),
            "SKY-Q407",
        ),
        (
            (
                "const values = [1]; for (values.forEach of [custom]) {}\n"
                "values.forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1]; for (values.map in source) {}\n"
                "values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
        (
            (
                "for (Array.prototype.forEach of [custom]) {}\n"
                "[1].forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "for (Array.prototype.map in source) {}\n"
                "[1].map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_async_array_rules_skip_for_in_and_for_of_mutations(tmp_path, source, rule_id):
    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            "for (Promise of [CustomPromise]) new Promise(async resolve => resolve());",
            "SKY-Q405",
        ),
        (
            (
                "async function callback(value) { await work(value); }\n"
                "for (callback of [sync]) [1].forEach(callback);"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1];\n"
                "for (values.map in source) values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
        (
            (
                "for (Array.prototype.map of [custom]) "
                "[1].map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_async_rules_apply_loop_target_write_before_braceless_body(
    tmp_path, source, rule_id
):
    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "for (Promise of (new Promise(async resolve => resolve()), "
                "[CustomPromise])) {}"
            ),
            "SKY-Q405",
        ),
        (
            (
                "async function callback(value) { await work(value); }\n"
                "for (callback of ([1].map(callback), [sync])) {}"
            ),
            "SKY-Q407",
        ),
        (
            (
                "const values = [1];\n"
                "for (values.forEach of "
                "(values.forEach(async value => work(value)), [custom])) {}"
            ),
            "SKY-Q406",
        ),
        (
            (
                "for (Array.prototype.map of "
                "([1].map(async value => work(value)), [custom])) {}"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_async_rules_apply_loop_target_write_after_iterable(tmp_path, source, rule_id):
    assert len(_rule(_scan(tmp_path, source), rule_id)) == 1


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "const values = [1];\n"
                'globalThis.Object.defineProperty(values, "forEach", {value: custom});\n'
                "values.forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1];\n"
                "globalThis.Object.setPrototypeOf(values, customPrototype);\n"
                "values.forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1];\n"
                'window.Reflect.set(values, "map", custom);\n'
                "values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_async_array_rules_skip_global_qualified_builtin_mutators(
    tmp_path, source, rule_id
):
    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "const values = [1];\n"
                "const mutate = Object.defineProperty;\n"
                'mutate(values, "forEach", {value: custom});\n'
                "values.forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1];\n"
                "const mutate = Object.defineProperty;\n"
                "const applyMutation = mutate;\n"
                'applyMutation(values, "map", {value: custom});\n'
                "values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
        (
            (
                "const values = [1];\n"
                "const {set: mutate} = Reflect;\n"
                'mutate(values, "map", custom);\n'
                "values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_async_array_rules_skip_resolvable_builtin_mutator_aliases(
    tmp_path, source, rule_id
):
    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "function poison() { Array.prototype.forEach = custom; } poison();\n"
                "[1].forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "function poison() { const proto = Array.prototype; proto.map = custom; } poison();\n"
                "[1].map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
        (
            (
                "const values = [1];\n"
                "function poison() { values.forEach = custom; } poison();\n"
                "values.forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1];\n"
                "function poison() { const alias = values; alias.map = custom; } poison();\n"
                "values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_async_array_rules_skip_mutations_captured_by_other_scopes(
    tmp_path, source, rule_id
):
    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "function harmless(Array) { Array.prototype.forEach = custom; }\n"
                "[1].forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1];\n"
                "function harmless(values) { values.map = custom; }\n"
                "values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_shadowed_nested_mutations_do_not_poison_async_array_proofs(
    tmp_path, source, rule_id
):
    assert len(_rule(_scan(tmp_path, source), rule_id)) == 1


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "async function callback(value) { await work(value); }\n"
                "function poison() { callback = sync; { const callback = other; } }\n"
                "poison(); [1].map(callback);"
            ),
            "SKY-Q407",
        ),
        (
            (
                "const values = [1];\n"
                "function poison() {\n"
                "  const alias = values; { const values = []; } alias.map = custom;\n"
                "}\npoison(); values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
        (
            (
                "function poison() {\n"
                "  Array.prototype.forEach = custom; { const Array = Other; }\n"
                "}\npoison(); [1].forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "function poison() { Boolean = custom; { const Boolean = other; } }\n"
                "poison(); [1].map(async value => work(value)).filter(Boolean);"
            ),
            "SKY-Q407",
        ),
        (
            (
                "const values = [1]; const alias = values;\n"
                "function poison() { alias.map = custom; }\n"
                "poison(); values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_async_array_rules_skip_outer_mutations_around_block_shadows(
    tmp_path, source, rule_id
):
    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "async function callback(value) { await work(value); }\n"
                "function harmless() { { const callback = sync; callback = other; } }\n"
                "harmless(); [1].forEach(callback);"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1];\n"
                "function harmless() { { const values = []; values.map = custom; } }\n"
                "harmless(); values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
        (
            (
                "function harmless() {\n"
                "  { const Array = Other; Array.prototype.map = custom; }\n"
                "}\nharmless(); [1].map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_block_local_mutations_do_not_poison_outer_proofs(tmp_path, source, rule_id):
    assert len(_rule(_scan(tmp_path, source), rule_id)) == 1


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        (
            (
                "const values = [1];\n"
                "Object.getPrototypeOf(values).forEach = custom;\n"
                "values.forEach(async value => work(value));"
            ),
            "SKY-Q406",
        ),
        (
            (
                "const values = [1];\n"
                "Reflect.getPrototypeOf(values).map = custom;\n"
                "values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
        (
            (
                "const values = [1];\n"
                'Object.defineProperty(Object.getPrototypeOf(values), "map", '
                "{value: custom});\n"
                "values.map(async value => work(value));"
            ),
            "SKY-Q407",
        ),
    ],
)
def test_async_array_rules_skip_call_derived_member_mutations(
    tmp_path, source, rule_id
):
    assert _rule(_scan(tmp_path, source), rule_id) == []


@pytest.mark.parametrize(
    "source",
    [
        "[1, 2].map(async (value) => work(value));",
        "const values = [1, 2];\nvalues.map(async (value) => work(value));",
        "const values = Array.of(1, 2);\nvoid values.map(async (value) => work(value));",
        "async function run() { await [1, 2].map(async (value) => work(value)); }",
        "[1, 2].map((/* reason */ async (value) => work(value)));",
        "[1, 2].map(<Callback>(async (value) => work(value)));",
        "const callback = async (value) => work(value); [1, 2].map(callback);",
        "async function callback(value) { await work(value); } [1, 2].map(callback);",
        "[1, 2].map(callback); async function callback(value) { await work(value); }",
        "async function callback(value) { await work(value); } callback(0); [1].map(callback);",
        '[1]["map"](async value => work(value));',
        "[3, 1].sort().map(async (value) => work(value));",
        "[1, 2].reverse().map(async (value) => work(value));",
        "const values = [1, 2]; consume(values); values.map(async value => work(value));",
        "const values=[1]; const alias=values; console.log(alias.length); values.map(async v=>work(v));",
        "const values=[1]; values.map(async v=>work(v)); values.map=custom;",
        "const values=[1]; consume(values); values.map(async v=>work(v)); function other(){ const values:any={}; values.map=custom; }",
        "ready && [1].map(async (value) => work(value));",
        "ready ? [1].map(async (value) => work(value)) : null;",
        "([1].map(async (value) => work(value)), done());",
    ],
)
def test_q407_flags_discarded_async_map_results(tmp_path, source):
    findings = _scan(tmp_path, source)

    discarded = _rule(findings, "SKY-Q407")

    assert len(discarded) == 1
    assert discarded[0]["severity"] == "HIGH"
    assert discarded[0]["name"] == "map"


@pytest.mark.parametrize(
    "source",
    [
        "const jobs = [1, 2].map(async (value) => work(value));",
        "returnValue([1, 2].map(async (value) => work(value)));",
        "async function run() { return [1, 2].map(async (value) => work(value)); }",
        "async function run() { await Promise.all([1, 2].map(async (value) => work(value))); }",
        "[1, 2].map((value) => work(value));",
        "const custom = { map(callback: any) { return callback(1); } };\ncustom.map(async (value) => work(value));",
        "const source = [1];\nconst alias = source;\nsource.map = custom;\nalias.map(async value => work(value));",
        "const result = (done(), [1].map(async value => work(value)));",
        "[1].map(async function* (value) { yield work(value); });",
        "async function callback(value) { await work(value); } callback = sync; [1].map(callback);",
        "callback = sync; async function callback(value) { await work(value); } [1].map(callback);",
        'const values=[1]; Object["defineProperty"](values, "map", {value: custom}); values.map(async v=>work(v));',
    ],
)
def test_q407_skips_consumed_sync_or_unproven_map_results(tmp_path, source):
    assert _rule(_scan(tmp_path, source), "SKY-Q407") == []


@pytest.mark.parametrize(
    "source",
    [
        "[1].map(async value => work(value)).filter(Boolean);",
        "[1].map(async value => work(value)).filter((Boolean));",
        "void [1].map(async value => work(value)).filter(Boolean);",
        "[1].map(async value => work(value)).filter(Boolean).length;",
        "const count = [1].map(async value => work(value)).length;",
    ],
)
def test_q407_flags_discarded_nonconsuming_map_chains(tmp_path, source):
    assert len(_rule(_scan(tmp_path, source), "SKY-Q407")) == 1


@pytest.mark.parametrize(
    "source",
    [
        "const jobs = [1].map(async value => work(value)).filter(Boolean);",
        "function run() { return [1].map(async value => work(value)).filter(Boolean); }",
        "consume([1].map(async value => work(value)).filter(Boolean));",
        "[1].map(async value => work(value)).forEach(consume);",
        "[1].map(async value => work(value)).filter(handle);",
        (
            "const Boolean = consume;\n"
            "[1].map(async value => work(value)).filter(Boolean);"
        ),
        (
            "Array.prototype.filter = custom;\n"
            "[1].map(async value => work(value)).filter(Boolean);"
        ),
    ],
)
def test_q407_skips_consumed_or_unproven_outer_map_chains(tmp_path, source):
    assert _rule(_scan(tmp_path, source), "SKY-Q407") == []


def test_q407_skips_boolean_filter_chain_when_global_is_mutated_in_closure(tmp_path):
    source = (
        "function poison() { Boolean = customBoolean; } poison();\n"
        "[1].map(async value => work(value)).filter(Boolean);"
    )

    assert _rule(_scan(tmp_path, source), "SKY-Q407") == []


@pytest.mark.parametrize("filename", ["app.js", "app.jsx", "app.ts", "app.tsx"])
def test_async_quality_rules_support_javascript_and_typescript(tmp_path, filename):
    findings = _scan(
        tmp_path,
        "[1].forEach(async (value) => work(value));",
        filename=filename,
    )

    assert len(_rule(findings, "SKY-Q406")) == 1


@pytest.mark.parametrize(
    ("source", "expected_name"),
    [
        (
            "export function parse(value: any): string { return String(value); }",
            "parse",
        ),
        (
            "function parse(value: any): string { return String(value); }\nexport { parse as parseValue };",
            "parse",
        ),
        (
            "export default (value: any): string => String(value);",
            "default",
        ),
        (
            "export default function (value: any): string { return String(value); }",
            "default",
        ),
        ("export const value: any = source;", "value"),
        ("export type Payload = any;", "Payload"),
        ("export interface Payload { value: any }", "Payload"),
        (
            "export class Client { send(value: any): string { return String(value); } }",
            "Client.send",
        ),
        (
            "export abstract class Client { abstract send(value: any): string; }",
            "Client.send",
        ),
        (
            "function parse(value: any): string { return String(value); }\nconst alias = parse;\nexport { alias };",
            "alias",
        ),
    ],
)
def test_t106_flags_exact_any_on_exported_api_slots(tmp_path, source, expected_name):
    findings = _scan(tmp_path, source)

    unsafe_types = _rule(findings, "SKY-T106")

    assert len(unsafe_types) == 1
    assert unsafe_types[0]["severity"] == "MEDIUM"
    assert unsafe_types[0]["name"] == expected_name
    assert "exact type 'any'" in unsafe_types[0]["message"]


@pytest.mark.parametrize(
    "source",
    [
        "export function parse(): Record<string, any> { return {}; }",
        "export const values: Record<string, any> = {};",
        "export interface Payload { values: Record<string, any> }",
    ],
)
def test_t106_flags_builtin_record_string_any(tmp_path, source):
    unsafe_types = _rule(_scan(tmp_path, source), "SKY-T106")

    assert len(unsafe_types) == 1
    assert "Record<string, any>" in unsafe_types[0]["message"]


def test_t106_flags_any_valued_index_signatures(tmp_path):
    findings = _scan(
        tmp_path,
        "export interface Payload { [key: string]: any; safe: unknown }",
    )

    unsafe_types = _rule(findings, "SKY-T106")

    assert len(unsafe_types) == 1
    assert "any-valued index signature" in unsafe_types[0]["message"]


def test_t106_reports_each_unsafe_exported_slot_once(tmp_path):
    findings = _scan(
        tmp_path,
        "export function parse(value: any): Record<string, any> { return value; }\nexport { parse };",
    )

    unsafe_types = _rule(findings, "SKY-T106")

    assert len(unsafe_types) == 2
    assert {finding["name"] for finding in unsafe_types} == {"parse"}


def test_t106_scans_handwritten_declaration_files(tmp_path):
    findings = _scan(
        tmp_path,
        "export declare function parse(value: any): unknown;",
        filename="public.d.ts",
    )

    assert len(_rule(findings, "SKY-T106")) == 1


@pytest.mark.parametrize(
    "source",
    [
        "function hidden(value: any): any { return value; }",
        "export function safe(value: Promise<any>): any[] { return []; }",
        "export function safe(value: any | null): Array<any> { return []; }",
        "export function safe(): Record<string, unknown> { return {}; }",
        "export function safe(): Record<number, any> { return {}; }",
        "type Record<K, V> = { value: V };\nexport function safe(): Record<string, any> { return { value: 1 }; }",
        "import type { Record } from './types';\nexport function safe(): Record<string, any> { return {}; }",
        "function local(value: any): any { return value; }\nexport { local } from './other';",
        "export class Client { private send(value: any): any { return value; } }",
        "export class Client { protected send(value: any): any { return value; } }",
        "export class Client extends Base { override send(value: any): any { return value; } }",
    ],
)
def test_t106_skips_nonpublic_nested_or_ambiguous_types(tmp_path, source):
    assert _rule(_scan(tmp_path, source), "SKY-T106") == []


def test_t106_ignores_typescript_syntax_in_javascript(tmp_path):
    findings = _scan(
        tmp_path,
        "export function parse(value: any): any { return value; }",
        filename="app.js",
    )

    assert _rule(findings, "SKY-T106") == []


@pytest.mark.parametrize(
    "source",
    [
        "function later() { throw new Error('Not implemented'); }",
        "const later = async () => { throw new Error(`Unimplemented`); };",
        "class Service { later() { throw Error('TODO: add implementation'); } }",
        "function later() { throw new NotImplementedError(); }",
        "function later() { 'use strict'; throw new Error('Not implemented'); }",
        "async function later() { 'use server'; throw new Error('Not implemented'); }",
        "function later() { throw (new Error('Not implemented')); }",
    ],
)
def test_l026_flags_not_implemented_runtime_stubs(tmp_path, source):
    unfinished = _rule(_scan(tmp_path, source), "SKY-L026")

    assert len(unfinished) == 1
    assert unfinished[0]["severity"] == "MEDIUM"


@pytest.mark.parametrize(
    "source",
    [
        "declare function later(): void;",
        "function later() { throw new Error('Unsupported input'); }",
        "function later() { audit(); throw new Error('Not implemented'); }",
        "function later() { return 'Not implemented'; }",
        "function validate() { throw new Error('TODO item must have a title'); }",
        "const text = \"function later() { throw new Error('Not implemented'); }\";",
    ],
)
def test_l026_skips_declarations_and_non_stub_functions(tmp_path, source):
    assert _rule(_scan(tmp_path, source), "SKY-L026") == []


@pytest.mark.parametrize(
    "filename",
    [
        "client.test.ts",
        "client.spec.js",
        "__tests__/client.ts",
        "tests/helpers/fakes.ts",
        "test/helpers/fakes.ts",
        "fixtures/fake.ts",
        "mocks/client.ts",
        "__mocks__/client.ts",
        "component.stories.tsx",
        "test_client.ts",
    ],
)
def test_l026_skips_test_fixture_stubs(tmp_path, filename):
    findings = _scan(
        tmp_path,
        "class FakeClient { send() { throw new Error('Not implemented'); } }",
        filename=filename,
    )

    assert _rule(findings, "SKY-L026") == []


@pytest.mark.parametrize(
    "source",
    [
        "try { work(); } catch (error) {}",
        "try { work(); } catch { /* TODO */ }",
        "try { work(); } catch { /* do not ignore failures */ }",
        "try { work(); } catch { /* do not skip failures */ }",
        "try { work(); } catch { /* should not ignore failures */ }",
        "try { work(); } catch { /* not intentionally ignored */ }",
        "try { work(); } catch { /* error happens in production */ }",
        "try { work(); } catch { ; }",
    ],
)
def test_l007_flags_empty_typescript_catch_blocks(tmp_path, source):
    empty = _rule(_scan(tmp_path, source), "SKY-L007")

    assert len(empty) == 1
    assert empty[0]["severity"] == "MEDIUM"


@pytest.mark.parametrize(
    "source",
    [
        "try { work(); } catch (error) { report(error); }",
        "try { work(); } catch { /* intentionally ignored */ }",
        "try { work(); } catch { /* optional cleanup */ }",
        "try { JSON.parse(chunk); } catch { /* Not valid JSON yet, skip */ }",
        "try { work(); } catch { /* Do nothing. A later check reports errors. */ }",
        "try { work(); } catch { /* Circular References */ }",
        "try { stash(); } catch { /* No changes to stash */ }",
        "try { work(); } catch (_err) {}",
        "function read() { try { return primary(); } catch {} return fallback(); }",
        "try { work(); } finally { cleanup(); }",
    ],
)
def test_l007_skips_handled_or_documented_catches(tmp_path, source):
    assert _rule(_scan(tmp_path, source), "SKY-L007") == []


@pytest.mark.parametrize(
    "source",
    [
        "/* eslint-disable */\nexport const value = 1;",
        "/* eslint-disable -- legacy migration */\nexport const value = 1;",
        "#!/usr/bin/env node\n/* eslint-disable */\nrun();",
    ],
)
def test_l035_flags_file_wide_bare_eslint_disables(tmp_path, source):
    disables = _rule(_scan(tmp_path, source), "SKY-L035")

    assert len(disables) == 1
    assert disables[0]["severity"] == "HIGH"
    assert disables[0]["name"] == "eslint-disable"


@pytest.mark.parametrize(
    "source",
    [
        "/* eslint-disable no-console */\nconsole.log('ok');",
        "/** eslint-disable */\nexport const documented = true;",
        "/* eslint-disable */\nwork();\n/* eslint-enable */",
        "work();\n/* eslint-disable */\nlegacy();",
        "// eslint-disable-next-line no-console\nconsole.log('ok');",
        "const text = '/* eslint-disable */';",
    ],
)
def test_l035_skips_narrow_scoped_or_ineffective_eslint_comments(tmp_path, source):
    assert _rule(_scan(tmp_path, source), "SKY-L035") == []


@pytest.mark.parametrize(
    ("filename", "header"),
    [
        ("generated/app.ts", ""),
        ("app.generated.ts", ""),
        ("app.ts", "// Code generated by tool. DO NOT EDIT.\n"),
        ("app.ts", "\ufeff// Code generated by tool. DO NOT EDIT.\n"),
        ("app.ts", "// This file was generated by tool.\n"),
        ("app.ts", "// THIS IS AN AUTOGENERATED FILE. DO NOT EDIT.\n"),
        ("app.ts", "// This code was generated by tool. DO NOT EDIT.\n"),
        ("app.ts", "// Generated by tool. DO NOT EDIT.\n"),
        ("app.ts", "// GENERATED CODE - DO NOT EDIT.\n"),
        ("app.ts", "// <auto-generated> DO NOT EDIT.\n"),
        ("app.ts", "// DO NOT EDIT. This file is generated.\n"),
    ],
)
def test_quality_signals_skip_generated_files(tmp_path, filename, header):
    findings = _scan(
        tmp_path,
        header
        + "/* eslint-disable */\n"
        + "export function later(value: any) { throw new Error('Not implemented'); }\n"
        + "[1].forEach(async value => work(value));\n"
        + "try { work(); } catch {}\n",
        filename=filename,
    )

    assert not {
        "SKY-L007",
        "SKY-L026",
        "SKY-L035",
        "SKY-Q405",
        "SKY-Q406",
        "SKY-Q407",
        "SKY-T106",
    }.intersection(finding["rule_id"] for finding in findings)


@pytest.mark.parametrize(
    "header",
    [
        "// Generated by combining the configured rules at runtime.\n",
        "// Generated by the request handler below.\n",
    ],
)
def test_generated_by_prose_does_not_disable_quality_signals(tmp_path, header):
    findings = _scan(
        tmp_path,
        header
        + "export function parse(value: any) { return value; }\n"
        + "[1].forEach(async value => work(value));\n",
    )

    assert len(_rule(findings, "SKY-Q406")) == 1
    assert len(_rule(findings, "SKY-T106")) == 1


def test_quality_signals_fail_closed_on_parse_recovery(tmp_path):
    findings = _scan(
        tmp_path,
        "export function broken(value: any {\n  new Promise(async () => work());\n",
    )

    assert not {
        "SKY-Q405",
        "SKY-Q406",
        "SKY-Q407",
        "SKY-T106",
    }.intersection(finding["rule_id"] for finding in findings)


def test_deep_array_chain_fails_closed_without_recursion(tmp_path):
    source = (
        "[1]\n" + ".filter(Boolean)\n" * 500 + ".forEach(async value => work(value));\n"
    )

    findings = _scan(tmp_path, source, filename="deep-chain.js")

    assert _rule(findings, "SKY-Q406") == []


def test_large_scope_count_does_not_hide_direct_async_promise_executor(tmp_path):
    source = "".join(f"function f{index}() {{}}\n" for index in range(8_200))
    source += "new Promise(async resolve => resolve(1));"

    findings = _scan(tmp_path, source, filename="many-scopes.js")

    assert len(_rule(findings, "SKY-Q405")) == 1


@pytest.mark.parametrize(
    "source, filename",
    [
        (
            (
                "export default withAuth(handler);\n"
                "new Promise(async resolve => resolve(1));"
            ),
            "pages/api/handler.ts",
        ),
        (
            "".join(
                f'app.get("/{index}", (req, res) => res.send("ok"));\n'
                for index in range(513)
            )
            + "new Promise(async resolve => resolve(1));",
            "many-routes.ts",
        ),
    ],
)
def test_unrelated_route_analysis_does_not_hide_q405(tmp_path, source, filename):
    findings = _scan(tmp_path, source, filename=filename)

    assert len(_rule(findings, "SKY-Q405")) == 1


@pytest.mark.parametrize(
    "source",
    [
        "function identity(value) { return value; } [1].map(identity);",
        "function outer(){ async function callback(v){ await work(v); } } function callback(v){ return v; } [1].map(callback);",
    ],
)
def test_sync_named_callbacks_do_not_build_security_flow(tmp_path, monkeypatch, source):
    def unexpected_flow(*args, **kwargs):
        raise AssertionError("sync callback should be filtered before flow analysis")

    monkeypatch.setattr(
        "skylos.visitors.languages.typescript.quality_signals.build_security_flow",
        unexpected_flow,
    )

    findings = _scan(tmp_path, source, filename="sync-callback.js")

    assert _rule(findings, "SKY-Q407") == []


def test_named_callback_prefilter_scales_across_sibling_scopes(tmp_path, monkeypatch):
    def unexpected_flow(*args, **kwargs):
        raise AssertionError("out-of-scope callbacks should be filtered before flow")

    monkeypatch.setattr(
        "skylos.visitors.languages.typescript.quality_signals.build_security_flow",
        unexpected_flow,
    )
    source = "".join(
        f"function outer{index}() {{ async function callback(value) {{ await work(value); }} }}\n"
        for index in range(800)
    )
    source += "function callback(value) { return value; }\n"
    source += "[1].map(callback);\n" * 800

    findings = _scan(tmp_path, source, filename="many-sibling-callbacks.js")

    assert _rule(findings, "SKY-Q407") == []


def test_nested_member_checks_scale_across_unrelated_sibling_scopes(tmp_path):
    count = 600
    source = "".join(
        f"function unrelated{index}() {{ return {index}; }}\n" for index in range(count)
    )
    source += "".join(
        f"const values{index} = [1]; values{index}.map(async value => work(value));\n"
        for index in range(count)
    )

    findings = _scan(tmp_path, source, filename="many-array-bindings.js")

    assert len(_rule(findings, "SKY-Q407")) == count


@pytest.mark.parametrize(
    "filename",
    ["client.test.ts", "client.e2e.ts", "client.cy.ts", "cypress/client.ts"],
)
def test_l007_skips_empty_catches_in_recognized_test_sources(tmp_path, filename):
    findings = _scan(
        tmp_path,
        "try { expectedFailure(); } catch {}",
        filename=filename,
    )

    assert _rule(findings, "SKY-L007") == []


def test_quality_signal_rule_ids_respect_project_ignore(tmp_path):
    findings = _scan(
        tmp_path,
        "/* eslint-disable */\n[1].forEach(async value => work(value));",
        config={"ignore": ["sky-l035", "SKY-Q406"]},
    )

    assert _rule(findings, "SKY-L035") == []
    assert _rule(findings, "SKY-Q406") == []


def test_quality_signals_can_be_disabled_without_disabling_parsing(tmp_path):
    findings = _scan(
        tmp_path,
        "/* eslint-disable */\n[1].forEach(async value => work(value));",
        enable_quality_rules=False,
    )

    assert findings == []


def test_quality_signals_reach_analyzer_json_output(tmp_path):
    path = tmp_path / "app.ts"
    path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        "/* eslint-disable */\n"
        "export function later(value: any): Record<string, any> {\n"
        "  throw new Error('Not implemented');\n"
        "}\n"
        "new Promise(async resolve => resolve(await work()));\n"
        "const first = [1];\n"
        "first.forEach(async value => work(value));\n"
        "const second = [2];\n"
        "second.map(async value => work(value));\n"
        "try { work(); } catch {}\n",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )
    rule_ids = {
        finding["rule_id"]
        for finding in result["quality"]
        if finding["rule_id"]
        in {
            "SKY-L007",
            "SKY-L026",
            "SKY-L035",
            "SKY-Q405",
            "SKY-Q406",
            "SKY-Q407",
            "SKY-T106",
        }
    }

    assert rule_ids == {
        "SKY-L007",
        "SKY-L026",
        "SKY-L035",
        "SKY-Q405",
        "SKY-Q406",
        "SKY-Q407",
        "SKY-T106",
    }
