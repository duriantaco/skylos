import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.core import TypeScriptCore
from skylos.visitors.languages.typescript.security_flow import build_security_flow
from skylos.visitors.languages.typescript.type_safety import scan_type_safety


def _scan(tmp_path, source, *, filename="app.ts", config=None):
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        source,
        encoding="utf-8",
    )
    result = scan_typescript_file(str(path), config=config)
    return result[6]


def _rule(findings, rule_id):
    return [finding for finding in findings if finding["rule_id"] == rule_id]


@pytest.mark.parametrize(
    ("expression", "bridge"),
    [
        ("input as unknown as User", "unknown"),
        ("input as any as User", "any"),
        ("input as object as User", "object"),
        ("input as {} as User", "{}"),
        ("(input as unknown) as User", "unknown"),
        ("<User><unknown>input", "unknown"),
        ("<User>(input as any)", "any"),
    ],
)
def test_t103_flags_only_broad_bridge_assertion_chains(
    tmp_path, expression, bridge
):
    findings = _scan(tmp_path, f"const user = {expression};\n")

    chained = _rule(findings, "SKY-T103")

    assert len(chained) == 1
    assert chained[0]["severity"] == "MEDIUM"
    assert chained[0]["line"] == 1
    assert chained[0]["col"] == 13
    assert chained[0]["name"] == "User"
    assert f"uses '{bridge}'" in chained[0]["message"]


@pytest.mark.parametrize("filename", ["app.ts", "app.tsx", "app.mts", "app.cts"])
def test_t103_supports_typed_typescript_extensions(tmp_path, filename):
    findings = _scan(
        tmp_path,
        "declare const input: unknown;\nconst user = input as unknown as User;\n",
        filename=filename,
    )

    assert len(_rule(findings, "SKY-T103")) == 1


def test_t103_reports_one_finding_for_a_triple_chain(tmp_path):
    findings = _scan(
        tmp_path,
        "const admin = input as unknown as User as Admin;\n",
    )

    chained = _rule(findings, "SKY-T103")

    assert len(chained) == 1
    assert chained[0]["name"] == "User"


def test_t103_does_not_flag_normal_type_operations(tmp_path):
    findings = _scan(
        tmp_path,
        """
const one = input as User;
const two = input as unknown;
const three = input as unknown as any;
const four = input as Base as User;
const five = input satisfies User;
const six = { value: 1 } as const;
const seven = input as unknown as (User | unknown);
const eight = input as any as (User & any);
const nine = input as unknown as Array<any>;
const ten = input as unknown as Promise<unknown>;
const eleven = input as unknown as unknown[];
const twelve = input as unknown as Record<string, unknown>;
const text = "input as unknown as User";
// input as unknown as User
""",
    )

    assert _rule(findings, "SKY-T103") == []


def test_t103_does_not_treat_typescript_syntax_in_js_as_a_finding(tmp_path):
    findings = _scan(
        tmp_path,
        "const user = input as unknown as User;\n",
        filename="app.js",
    )

    assert _rule(findings, "SKY-T103") == []


def test_t103_preserves_spaces_inside_literal_type_names(tmp_path):
    findings = _scan(
        tmp_path,
        "const value = input as unknown as 'hello world';\n",
    )

    chained = _rule(findings, "SKY-T103")

    assert len(chained) == 1
    assert chained[0]["name"] == "'hello world'"
    assert "'hello world'" in chained[0]["message"]


@pytest.mark.parametrize(
    ("directive", "filename"),
    [
        ("// @ts-ignore -- old library has bad types", "app.ts"),
        ("/// @ts-ignore", "app.tsx"),
        ("/* @ts-ignore */", "app.ts"),
        ("/** @ts-ignore */", "app.ts"),
        ("/* note\n * @ts-ignore */", "app.ts"),
        ("// @ts-ignore-this-is-still-a-real-directive", "app.js"),
    ],
)
def test_t104_flags_effective_ts_ignore_directives(tmp_path, directive, filename):
    findings = _scan(
        tmp_path,
        f"{directive}\nconst value: string = 1;\n",
        filename=filename,
    )

    suppressions = _rule(findings, "SKY-T104")

    assert len(suppressions) == 1
    assert suppressions[0]["severity"] == "MEDIUM"
    assert suppressions[0]["line"] == 1
    assert suppressions[0]["col"] == 0
    assert suppressions[0]["name"] == "@ts-ignore"


def test_t104_flags_only_the_effective_leading_ts_nocheck(tmp_path):
    findings = _scan(
        tmp_path,
        """
// Copyright Example
// @ts-nocheck
// @ts-ignore
const one: string = 1;
// @ts-ignore
const two: string = 2;
""".lstrip(),
    )

    suppressions = _rule(findings, "SKY-T104")

    assert len(suppressions) == 1
    assert suppressions[0]["severity"] == "HIGH"
    assert suppressions[0]["line"] == 2
    assert suppressions[0]["name"] == "@ts-nocheck"


@pytest.mark.parametrize(
    ("pragmas", "expected_line"),
    [
        ("// @ts-check\n// @ts-nocheck\n", 2),
        ("// @TS-CHECK\n// @TS-NOCHECK: generated migration\n", 2),
    ],
)
def test_t104_uses_the_last_leading_check_pragma(
    tmp_path, pragmas, expected_line
):
    findings = _scan(tmp_path, pragmas + "const value: string = 1;\n")

    suppressions = _rule(findings, "SKY-T104")

    assert len(suppressions) == 1
    assert suppressions[0]["severity"] == "HIGH"
    assert suppressions[0]["line"] == expected_line


def test_t104_later_ts_check_reenables_file_checking(tmp_path):
    findings = _scan(
        tmp_path,
        "// @ts-nocheck\n// @ts-check\nconst value: string = 1;\n",
    )

    assert _rule(findings, "SKY-T104") == []


def test_t104_ignores_safer_or_compiler_ineffective_comments(tmp_path):
    findings = _scan(
        tmp_path,
        r'''
// @ts-expect-error -- deliberate type-level test
const one: string = 1;
// @ts-check
const two = 2;
// Do not use @ts-ignore here
const three: string = 3;
// @TS-IGNORE
const four: string = 4;
/*
 * @ts-ignore
 */
const five: string = 5;
const text = "// @ts-ignore";
const template = `// @ts-nocheck`;
const before = true;
// @ts-nocheck
const six: string = 6;
// @ts-nocheck-suffix
const seven: string = 7;
/* @ts-nocheck */
const eight: string = 8;
''',
    )

    assert _rule(findings, "SKY-T104") == []


@pytest.mark.parametrize(
    "expression",
    [
        "JSON.parse(payload) as User",
        "(JSON.parse(payload)) as Readonly<User>",
        "<User>JSON.parse(payload)",
    ],
)
def test_t105_flags_direct_builtin_json_parse_assertions(tmp_path, expression):
    findings = _scan(tmp_path, f"const user = {expression};\n")

    boundary = _rule(findings, "SKY-T105")

    assert len(boundary) == 1
    assert boundary[0]["severity"] == "MEDIUM"
    assert boundary[0]["line"] == 1
    assert boundary[0]["col"] == 13
    assert "without runtime validation" in boundary[0]["message"]


def test_t105_preserves_spaces_inside_object_type_keys(tmp_path):
    findings = _scan(
        tmp_path,
        "const value = JSON.parse(payload) as { 'display name': string };\n",
    )

    boundary = _rule(findings, "SKY-T105")

    assert len(boundary) == 1
    assert boundary[0]["name"] == "{ 'display name': string }"
    assert "'display name'" in boundary[0]["message"]


@pytest.mark.parametrize(
    "source",
    [
        (
            "const response = await fetch(url);\n"
            "const user = (await response.json()) as User;\n"
        ),
        "const user = (await (await fetch(url)).json()) as User;\n",
    ],
)
def test_t105_flags_asserted_fetch_response_json(tmp_path, source):
    findings = _scan(tmp_path, source)

    boundary = _rule(findings, "SKY-T105")

    assert len(boundary) == 1
    assert "Response.json() result" in boundary[0]["message"]


@pytest.mark.parametrize(
    "source",
    [
        "const user = JSON.parse(payload) as unknown;",
        "const user = JSON.parse(payload) as any;",
        "const user = JSON.parse(payload) as object;",
        "const user = JSON.parse(payload) as {};",
        "const user = JSON.parse(payload) as Array<any>;",
        "const user = JSON.parse(payload) as Promise<unknown>;",
        "const user = JSON.parse(payload) as Record<string, unknown>;",
        "const user = UserSchema.parse(JSON.parse(payload)) as User;",
        (
            "const user = JSON.parse(payload, (_key, value) => value) "
            "as User;"
        ),
        'const user = JSON.parse("{\\"id\\":\\"known\\"}") as User;',
        "const user = JSON.parse(`{\"id\":\"known\"}`) as User;",
        "const user = serializer.json() as User;",
        "const response = await fetch(url); const user = response.json() as User;",
        "const response = await fetch(url); const user = (await response.json(body)) as User;",
        "const response = await fetch(url); const user = (await response.json<User>()) as User;",
        "let response = await fetch(url); const user = (await response.json()) as User;",
        "const response = await customFetch(url); const user = (await response.json()) as User;",
    ],
)
def test_t105_skips_unproven_or_already_broad_boundary_casts(tmp_path, source):
    findings = _scan(tmp_path, source)

    assert _rule(findings, "SKY-T105") == []


@pytest.mark.parametrize(
    "source",
    [
        "const JSON = parser; const user = JSON.parse(payload) as User;",
        "function parse(JSON: Parser) { return JSON.parse(payload) as User; }",
        'import JSON from "custom-json"; const user = JSON.parse(payload) as User;',
        "JSON.parse = customParse; const user = JSON.parse(payload) as User;",
        (
            "const fetch = customFetch; const response = await fetch(url); "
            "const user = (await response.json()) as User;"
        ),
        (
            "function load(fetch: Fetcher) { const response = fetch(url); "
            "return response.json() as User; }"
        ),
        "const { JSON } = registry; const user = JSON.parse(payload) as User;",
        (
            "const { JSON = parser } = registry; "
            "const user = JSON.parse(payload) as User;"
        ),
        "({ JSON } = registry); const user = JSON.parse(payload) as User;",
        (
            "const { JSON: parser } = registry; "
            "const user = parser.parse(payload) as User;"
        ),
        (
            "({ JSON: globalThis.JSON } = registry); "
            "const user = JSON.parse(payload) as User;"
        ),
        (
            "({ fetch } = registry); const response = await fetch(url); "
            "const user = (await response.json()) as User;"
        ),
        (
            "const { fetch = customFetch } = registry; "
            "const response = await fetch(url); "
            "const user = (await response.json()) as User;"
        ),
        (
            "globalThis.fetch = customFetch; "
            "const response = await fetch(url); "
            "const user = (await response.json()) as User;"
        ),
        (
            "const J = JSON; J.parse = customParse; "
            "const user = JSON.parse(payload) as User;"
        ),
        (
            "const J = JSON; mutate(J); "
            "const user = JSON.parse(payload) as User;"
        ),
        "mutate(JSON); const user = JSON.parse(payload) as User;",
        (
            "const key = 'JSON'; globalThis[key].parse = customParse; "
            "const user = JSON.parse(payload) as User;"
        ),
        (
            "const key = 'parse'; JSON[key] = customParse; "
            "const user = JSON.parse(payload) as User;"
        ),
        (
            "const J = new Proxy(JSON, {}); J.parse = customParse; "
            "const user = JSON.parse(payload) as User;"
        ),
        "new Mutator(JSON); const user = JSON.parse(payload) as User;",
    ],
)
def test_t105_skips_shadowed_or_replaced_builtins(tmp_path, source):
    findings = _scan(tmp_path, source)

    assert _rule(findings, "SKY-T105") == []


@pytest.mark.parametrize(
    "replacement",
    [
        'Object.defineProperty(JSON, "parse", { value: parser });',
        "Object.assign(JSON, { parse: parser });",
        'Reflect.set(JSON, "parse", parser);',
        "Reflect.set(JSON, key, parser);",
        'Reflect.defineProperty(JSON, "parse", { value: parser });',
        'Reflect.deleteProperty(JSON, "parse");',
        'Object.defineProperty(globalThis[key], "parse", { value: parser });',
        "delete JSON.parse;",
    ],
)
def test_t105_skips_json_member_replaced_by_common_mutators(
    tmp_path, replacement
):
    findings = _scan(
        tmp_path,
        f"{replacement}\nconst user = JSON.parse(payload) as User;\n",
    )

    assert _rule(findings, "SKY-T105") == []


@pytest.mark.parametrize(
    "replacement",
    [
        'Object.defineProperty(globalThis, "fetch", { value: customFetch });',
        "Object.assign(globalThis, { fetch: customFetch });",
        'Reflect.set(globalThis, "fetch", customFetch);',
        "Reflect.set(globalThis, key, customFetch);",
        "const globals = globalThis; globals.fetch = customFetch;",
        (
            "const globals = new Proxy(globalThis, {}); "
            "globals.fetch = customFetch;"
        ),
    ],
)
def test_t105_skips_global_fetch_replaced_by_common_mutators(
    tmp_path, replacement
):
    findings = _scan(
        tmp_path,
        (
            f"{replacement}\n"
            "const response = await fetch(url);\n"
            "const user = (await response.json()) as User;\n"
        ),
    )

    assert _rule(findings, "SKY-T105") == []


@pytest.mark.parametrize(
    "mutation",
    [
        "response.json = customJson;",
        'Object.defineProperty(response, "json", { value: customJson });',
        "mutate(response);",
        "const alias = response; alias.json = customJson;",
        "const alias = response; alias[key] = customJson;",
        "const alias = response; delete alias[key];",
        "const alias = response; alias[key]++;",
        (
            "const { response: alias } = { response }; "
            "alias.json = customJson;"
        ),
        "const [alias] = [response]; alias.json = customJson;",
        "const { response: alias } = { response }; mutate(alias);",
        "({ json: response.json } = custom);",
        "new Mutator(response);",
        "Response.prototype.json = customJson;",
        'Object.defineProperty(Response.prototype, "json", { value: customJson });',
        "const proto = Response.prototype; proto.json = customJson;",
    ],
)
def test_t105_drops_fetch_response_proof_after_mutation_or_escape(
    tmp_path, mutation
):
    findings = _scan(
        tmp_path,
        (
            "const response = await fetch(url);\n"
            f"{mutation}\n"
            "const user = (await response.json()) as User;\n"
        ),
    )

    assert _rule(findings, "SKY-T105") == []


def test_boundary_laundering_emits_the_more_specific_chain_rule_once(tmp_path):
    findings = _scan(
        tmp_path,
        "const user = JSON.parse(payload) as unknown as User;\n",
    )

    assert len(_rule(findings, "SKY-T103")) == 1
    assert _rule(findings, "SKY-T105") == []


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("types.d.ts", "declare const user: JSON.parse(payload) as unknown as User;"),
        ("types.d.mts", "declare const user: unknown;"),
        ("types.d.cts", "declare const user: unknown;"),
        ("model.generated.ts", "const user = input as unknown as User;"),
        ("generated/model.ts", "const user = input as unknown as User;"),
        ("model.generated.js", "// @ts-ignore\nconst value = 1;"),
        ("model.gen.jsx", "// @ts-ignore\nconst value = <div />;"),
        ("model.generated.mjs", "// @ts-ignore\nexport const value = 1;"),
        ("model.gen.cjs", "// @ts-ignore\nexports.value = 1;"),
        ("app.ts", "// Code generated by tool. DO NOT EDIT.\nconst user = input as unknown as User;"),
        ("other.ts", "// This file is automatically generated.\nconst user = input as unknown as User;"),
    ],
)
def test_type_safety_rules_skip_declarations_and_generated_files(
    tmp_path, filename, source
):
    findings = _scan(tmp_path, source, filename=filename)

    assert not {"SKY-T103", "SKY-T104", "SKY-T105"} & {
        finding["rule_id"] for finding in findings
    }


def test_normal_do_not_edit_comment_does_not_mark_file_as_generated(tmp_path):
    findings = _scan(
        tmp_path,
        "// Do not edit this lookup manually.\n"
        "const user = input as unknown as User;\n",
    )

    assert len(_rule(findings, "SKY-T103")) == 1


@pytest.mark.parametrize("rule_id", ["SKY-T103", "SKY-T104", "SKY-T105"])
def test_typescript_quality_rules_honor_project_ignore(tmp_path, rule_id):
    source_by_rule = {
        "SKY-T103": "const user = input as unknown as User;",
        "SKY-T104": "// @ts-ignore\nconst value: string = 1;",
        "SKY-T105": "const user = JSON.parse(payload) as User;",
    }

    findings = _scan(
        tmp_path,
        source_by_rule[rule_id],
        config={"ignore": [rule_id]},
    )

    assert _rule(findings, rule_id) == []


def test_existing_typescript_quality_rule_also_honors_project_ignore(tmp_path):
    findings = _scan(
        tmp_path,
        "function decide(value: number) { if (value) return 1; return 0; }",
        config={
            "ignore": ["SKY-Q301"],
            "languages": {"typescript": {"complexity": 1}},
        },
    )

    assert _rule(findings, "SKY-Q301") == []


def test_type_safety_rules_do_not_run_when_quality_is_disabled(tmp_path):
    path = tmp_path / "app.ts"
    path.write_text(
        "// @ts-ignore\n"
        "const one = input as unknown as User;\n"
        "const two = JSON.parse(payload) as User;\n",
        encoding="utf-8",
    )

    quality = scan_typescript_file(str(path), enable_quality_rules=False)[6]

    assert quality == []


def test_type_safety_scan_handles_malformed_and_deep_input_without_crashing(tmp_path):
    malformed = "const user = " + ("(" * 2_000) + "input as unknown as User;"

    findings = _scan(tmp_path, malformed)

    assert _rule(findings, "SKY-T103") == []
    assert _rule(findings, "SKY-T105") == []


def test_t103_still_reports_valid_assertion_before_unrelated_parse_error(tmp_path):
    findings = _scan(
        tmp_path,
        "const user = input as unknown as User;\nconst broken = ;\n",
    )

    assert len(_rule(findings, "SKY-T103")) == 1
    assert _rule(findings, "SKY-T105") == []


def test_t103_unwraps_deep_parentheses_and_satisfies_without_a_depth_bypass(
    tmp_path,
):
    wrapped = "(" * 128 + "input as unknown satisfies unknown" + ")" * 128

    findings = _scan(tmp_path, f"const user = {wrapped} as User;\n")

    assert len(_rule(findings, "SKY-T103")) == 1


def test_t103_handles_deeply_parenthesized_target_without_quadratic_unwrap(
    tmp_path,
):
    target = "(" * 2_048 + "User" + ")" * 2_048

    findings = _scan(
        tmp_path,
        f"const user = input as unknown as {target};\n",
    )

    assert len(_rule(findings, "SKY-T103")) == 1


def test_t103_handles_a_long_assertion_chain_in_one_tree_walk():
    source = ("const user = x" + " as unknown as User" * 512 + ";\n").encode()
    core = TypeScriptCore("app.ts", source)

    findings = scan_type_safety(
        core.root_node,
        source,
        "app.ts",
        core.lang,
    )

    assert len(_rule(findings, "SKY-T103")) == 512


def test_global_path_checks_reuse_cached_scope_facts():
    source = "\n".join(f"String(value{index});" for index in range(500)).encode()
    core = TypeScriptCore("app.ts", source)
    flow = build_security_flow(
        core.root_node,
        source,
        "app.ts",
        core.lang,
    )
    calls = [
        event
        for event in flow.calls
        if event.callee is not None
        and event.callee.member_path == ("String",)
    ]

    assert len(calls) == 500
    assert all(
        flow.is_unshadowed_global_name(
            "String", event.span.start_byte, event.scope_id
        )
        for event in calls
    )
    assert flow.analysis_complete


@pytest.mark.parametrize(
    "prefix",
    [
        "root" + ".member" * 1_200 + " = replacement;",
        "consume(" + "root" + ".member" * 1_200 + ");",
        "Object.assign(" + "root" + ".member" * 1_200 + ", {});",
    ],
)
def test_t105_fails_closed_on_extremely_deep_member_paths(prefix):
    source = (
        prefix + "\nconst user = JSON.parse(payload) as User;\n"
    ).encode()
    core = TypeScriptCore("app.ts", source)

    findings = scan_type_safety(
        core.root_node,
        source,
        "app.ts",
        core.lang,
    )

    assert _rule(findings, "SKY-T105") == []


def test_t105_fails_closed_on_extremely_deep_binding_patterns():
    pattern = "{ value: " * 700 + "leaf" + " }" * 700
    source = (
        f"const {pattern} = input;\n"
        "const user = JSON.parse(payload) as User;\n"
    ).encode()
    core = TypeScriptCore("app.ts", source)

    findings = scan_type_safety(
        core.root_node,
        source,
        "app.ts",
        core.lang,
    )

    assert _rule(findings, "SKY-T105") == []


def test_type_safety_findings_reach_analyzer_json_quality_bucket(tmp_path):
    (tmp_path / "app.ts").write_text(
        "const one = input as unknown as User;\n"
        "const two = JSON.parse(payload) as User;\n",
        encoding="utf-8",
    )

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )
    type_findings = [
        finding
        for finding in result["quality"]
        if finding["rule_id"] in {"SKY-T103", "SKY-T105"}
    ]

    assert [finding["rule_id"] for finding in type_findings] == [
        "SKY-T103",
        "SKY-T105",
    ]
    assert result["analysis_summary"]["quality_count"] == len(result["quality"])
