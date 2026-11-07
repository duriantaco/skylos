"""Namespace imports consume members, with whole-object reads kept conservative."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript import scan_typescript_file


def _write(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324]


def _application(tmp_path, body, *, extension="ts"):
    _write(
        tmp_path / "package.json",
        json.dumps({"private": True, "scripts": {"start": f"node index.{extension}"}}),
    )
    _write(
        tmp_path / f"index.{extension}",
        'import * as api from "./library";\n' + body + "\n",
    )
    _write(
        tmp_path / f"library.{extension}",
        "export function used() { return 1; }\nexport function retired() { return 2; }\n",
    )
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return {
        item["name"]
        for category in (
            "unused_exports",
            "unused_functions",
            "unused_classes",
            "unused_variables",
        )
        for item in result.get(category, [])
        if Path(item["file"]).name == f"library.{extension}"
    }


@pytest.mark.parametrize("extension", ["ts", "js", "tsx"])
@pytest.mark.parametrize(
    "body",
    [
        "api.used();",
        'api["used"]();',
        "api?.used();",
        "api.used?.();",
        "api.used`value`;",
        "const alias = api; alias.used();",
        "const alias = api; const second = alias; second.used();",
        "const {used: chosen} = api; chosen();",
        "const {used} = api; used();",
        "const other = {retired() {}}; other.retired(); api.used();",
        "{ const api = {retired() {}}; api.retired(); } api.used();",
        "function run(api) { api.retired(); } run({retired() {}}); api.used();",
        "function run({api}) { api.retired(); } run({api: {retired() {}}}); api.used();",
        "function run() { var api = {retired() {}}; api.retired(); } run(); api.used();",
        "for (const api of [{retired() {}}]) { api.retired(); } api.used();",
        "try { throw {retired() {}}; } catch (api) { api.retired(); } api.used();",
        "function run(next = api.used) { var api = {retired() {}}; next(); } run();",
        "const alias = api; function invoke() { alias.used(); } invoke();",
        "const alias = api; { const alias = {retired() {}}; alias.retired(); } alias.used();",
        "const C = class api { static retired() {} static run() { api.retired(); } }; C.run(); api.used();",
    ],
)
def test_static_namespace_reads_leave_other_exports_unused(tmp_path, body, extension):
    assert _application(tmp_path, body, extension=extension) == {"retired"}


def test_jsx_namespace_component_keeps_selected_export_alive(tmp_path):
    assert _application(
        tmp_path, "globalThis.render(<api.used />);", extension="tsx"
    ) == {"retired"}


@pytest.mark.parametrize(
    "body",
    [
        "api[process.argv[2]]();",
        "external(api);",
        "external({...api});",
        "external(Object.keys(api));",
        "const {used, ...rest} = api; external(rest); used();",
        "export {api};",
        "const alias = api; external(alias);",
        "let alias = api; alias = {used() {}}; alias.used();",
        "const key = unknown(); const {[key]: chosen} = api; chosen();",
        "globalThis.api = api;",
        "api.used = replacement;",
        "api.used++;",
        "delete api.used;",
        "external(typeof api);",
        "external(api instanceof Object);",
        "api`unknown`;",
        'api["u\\x73ed"]();',
        "const alias = api; alias.used = replacement;",
        "const alias = api; alias = replacement; alias.used();",
        'eval("api.retired()");',
        r"api.\u0075sed();",
        r"const {\u0075sed: chosen} = api; chosen();",
        r"const \u0061lias = api; alias.used();",
        r"const alias = api; \u0061lias.used();",
    ],
)
def test_dynamic_escaped_and_unstable_namespaces_keep_all_exports(tmp_path, body):
    assert _application(tmp_path, body) == set()


def test_namespace_read_keeps_import_and_selected_export_alive(tmp_path):
    path = tmp_path / "index.ts"
    _write(path, 'import * as api from "./library"; api.used();\n')
    definitions, references, *rest = scan_typescript_file(str(path))
    assert any(
        definition.name == "api" and definition.type == "import"
        for definition in definitions
    )
    assert ("api", str(path)) in references
    assert rest[-1][0]["names"] == ["used"]


def test_two_namespace_sources_do_not_exchange_member_names(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"private":true,"scripts":{"start":"node index.ts"}}',
    )
    _write(
        tmp_path / "index.ts",
        'import * as first from "./one"; import * as second from "./two"; first.alpha(); second.beta();\n',
    )
    _write(
        tmp_path / "one.ts", "export function alpha() {}\nexport function beta() {}\n"
    )
    _write(
        tmp_path / "two.ts", "export function alpha() {}\nexport function beta() {}\n"
    )
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {
        (Path(item["file"]).name, item["name"])
        for category in ("unused_exports", "unused_functions")
        for item in result.get(category, [])
    }
    assert unused == {("one.ts", "beta"), ("two.ts", "alpha")}


def test_default_member_keeps_named_default_declaration_alive(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"private":true,"scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path / "index.ts", 'import * as api from "./library"; api.default();\n')
    _write(tmp_path / "library.ts", "export default function launch() {}\n")
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert not result.get("unused_functions")
    assert not result.get("unused_exports")


def test_mixed_default_namespace_import_keeps_default_binding_alive(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"private":true,"scripts":{"start":"node index.ts"}}',
    )
    _write(
        tmp_path / "index.ts",
        'import main, * as api from "./library"; main(); api.used();\n',
    )
    _write(
        tmp_path / "library.ts",
        "export default function launch() {}\nexport function used() {}\n",
    )
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert not result.get("unused_functions")
    assert not result.get("unused_exports")


def test_namespace_member_crosses_alias_and_wildcard_barrels(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"private":true,"scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path / "index.ts", 'import * as api from "./barrel"; api.start();\n')
    _write(tmp_path / "barrel.ts", 'export * from "./bridge";\n')
    _write(
        tmp_path / "bridge.ts", 'export {used as start, retired} from "./library";\n'
    )
    _write(
        tmp_path / "library.ts",
        "export function used() {}\nexport function retired() {}\n",
    )
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {
        item["name"]
        for category in ("unused_exports", "unused_functions")
        for item in result.get(category, [])
        if Path(item["file"]).name == "library.ts"
    }
    assert unused == {"retired"}


def test_exhausted_namespace_budget_preserves_all_exports(tmp_path, monkeypatch):
    from skylos.visitors.languages.typescript import namespace_references

    monkeypatch.setattr(namespace_references, "_MAX_NODES", 3)
    assert _application(tmp_path, "api.used();") == set()


@pytest.mark.parametrize(
    "provider, expected_unused",
    [
        (r"export function \u0075sed() {}" + "\nexport function retired() {}\n", set()),
        (
            r"function original() {} export {original as \u0075sed};"
            + "\nexport function retired() {}\n",
            {"retired"},
        ),
    ],
)
def test_escaped_provider_identity_keeps_used_function_alive(
    tmp_path, provider, expected_unused
):
    _write(
        tmp_path / "package.json",
        '{"private":true,"scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path / "index.ts", 'import * as api from "./library"; api.used();\n')
    _write(tmp_path / "library.ts", provider)
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert not result.get("analysis_errors")
    # An escaped declaration is opaque and also misses retired. A local alias
    # still has an unescaped original definition/reference, so retired is dead.
    unused = {
        item["name"]
        for category in ("unused_functions", "unused_exports")
        for item in result.get(category, [])
    }
    assert unused == expected_unused


def test_escaped_reexport_provider_keeps_original_function_alive(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"private":true,"scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path / "index.ts", 'import * as api from "./bridge"; api.used();\n')
    _write(
        tmp_path / "bridge.ts",
        r'export {original as \u0075sed} from "./library";' + "\n",
    )
    _write(tmp_path / "library.ts", "export function original() {}\n")
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert not result.get("analysis_errors")
    assert not result.get("unused_functions")
    assert not result.get("unused_exports")


def test_escaped_import_provider_keeps_original_function_alive(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"private":true,"scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path / "index.ts", 'import * as api from "./bridge"; api.used();\n')
    _write(
        tmp_path / "bridge.ts",
        r'import {original as \u0075sed} from "./library"; export {\u0075sed as used};'
        + "\n",
    )
    _write(tmp_path / "library.ts", "export function original() {}\n")
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert not result.get("analysis_errors")
    assert not result.get("unused_functions")
    assert not result.get("unused_exports")


def _namespace_shadow_report(tmp_path, body):
    _write(
        tmp_path / "package.json",
        '{"private":true,"scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path / "index.ts", 'import * as api from "./library";\n' + body + "\n")
    _write(
        tmp_path / "library.ts",
        "export function used() {}\nexport function retired() {}\n",
    )
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=True))
    assert not result.get("analysis_errors")
    return result


def test_shadowed_namespace_property_leaves_dead_function_finding(tmp_path):
    result = _namespace_shadow_report(
        tmp_path,
        "function inspect(api: {retired(): number}) {return api.retired();}\ninspect({retired() {return 0;}}); api.used();",
    )
    unused = [
        item
        for item in result.get("unused_functions", [])
        if Path(item["file"]).name == "library.ts"
    ]
    assert [(item["name"], item["line"]) for item in unused] == [("retired", 2)]
    assert not [
        item for item in result.get("unused_exports", []) if item["name"] == "retired"
    ]


@pytest.mark.parametrize(
    "body",
    [
        "function inspect(api) {api.retired();} inspect(api); api.used();",
        "function expose() {return api;} expose().retired(); api.used();",
        "const capture = () => api; capture().retired(); api.used();",
    ],
)
def test_namespace_escape_disables_shadowed_member_narrowing(tmp_path, body):
    result = _namespace_shadow_report(tmp_path, body)
    assert not result.get("unused_functions")
    assert not result.get("unused_exports")


def test_shadow_object_preserves_its_real_function_value(tmp_path):
    result = _namespace_shadow_report(
        tmp_path,
        "function retired() {}\nfunction inspect(api) {api.retired();}\ninspect({retired}); api.used();",
    )
    unused = {
        (Path(item["file"]).name, item["name"])
        for item in result.get("unused_functions", [])
    }
    assert unused == {("library.ts", "retired")}


def test_shadowed_namespace_receiver_keeps_cross_file_methods_uncertain(tmp_path):
    _write(tmp_path / "client.ts", "export class Client {retired() {return 1;}}\n")
    result = _namespace_shadow_report(
        tmp_path,
        'import {Client} from "./client";\nfunction inspect(api) {api.retired();}\ninspect(new Client()); api.used();',
    )
    unused = {
        (Path(item["file"]).name, item["name"])
        for item in result.get("unused_functions", [])
    }
    assert ("library.ts", "retired") in unused
    assert not any(file == "client.ts" for file, _ in unused)
