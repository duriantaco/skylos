"""Source-defined namespace export demand, including live and unused siblings."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript.core import TypeScriptCore


def _write(root, name, source):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324]


def _project(root, consumer, barrel='export * as tools from "./library";', **package):
    _write(
        root,
        "package.json",
        json.dumps({"private": True, "scripts": {"start": "node index.ts"}, **package}),
    )
    _write(root, "index.ts", consumer)
    _write(root, "barrel.ts", barrel)
    _write(
        root,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )


def _unused(root, filename="library.ts"):
    result = json.loads(
        analyze(
            str(root),
            conf=0,
            grep_verify=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return {
        item["name"]
        for category in (
            "unused_functions",
            "unused_exports",
            "unused_variables",
            "unused_classes",
        )
        for item in result.get(category, ())
        if Path(item["file"]).name == filename
    }


@pytest.mark.parametrize(
    "consumer",
    [
        'import {tools} from "./barrel"; tools.active();',
        'import {tools as api} from "./barrel"; api.active();',
        'import {tools} from "./barrel"; tools["active"]();',
        'import {tools} from "./barrel"; const api = tools; api.active();',
        'import {tools} from "./barrel"; const {active} = tools; active();',
        'import * as api from "./barrel"; api.tools.active();',
        'import * as api from "./barrel"; api["tools"]["active"]();',
    ],
)
def test_selected_namespace_export_keeps_actual_member_and_reports_sibling(
    tmp_path, consumer
):
    _project(tmp_path, consumer)
    assert _unused(tmp_path) == {"retired"}


@pytest.mark.parametrize("chain", ["named", "star", "default", "nested"])
def test_namespace_export_identity_survives_forwarding(tmp_path, chain):
    consumer = 'import {tools} from "./barrel"; tools.active();'
    if chain == "named":
        barrel = 'export {nested as tools} from "./bridge";'
        bridge = 'export * as nested from "./library";'
    elif chain == "star":
        barrel = 'export * from "./bridge";'
        bridge = 'export * as tools from "./library";'
    elif chain == "default":
        consumer = 'import tools from "./barrel"; tools.active();'
        barrel = 'export {tools as default} from "./bridge";'
        bridge = 'export * as tools from "./library";'
    else:
        consumer = 'import {bundle} from "./barrel"; bundle.tools.active();'
        barrel = 'export * as bundle from "./bridge";'
        bridge = 'export * as tools from "./library";'
    _project(tmp_path, consumer, barrel)
    _write(tmp_path, "bridge.ts", bridge)
    assert _unused(tmp_path) == {"retired"}


@pytest.mark.parametrize(
    "body",
    [
        "external(tools);",
        "tools[process.argv[2]]();",
        "const {active, ...others} = tools; external(others); active();",
        "let alias = tools; external(alias);",
        "tools.active = replacement;",
        "eval(process.argv[2]);",
    ],
)
def test_opaque_namespace_value_preserves_all_members(tmp_path, body):
    _project(tmp_path, 'import {tools} from "./barrel"; ' + body)
    assert _unused(tmp_path) == set()


def test_public_namespace_export_preserves_members_despite_selected_internal_read(
    tmp_path,
):
    _project(
        tmp_path, 'import {tools} from "./barrel"; tools.active();', main="./barrel.ts"
    )
    assert _unused(tmp_path) == set()


def test_namespace_consumer_shadow_does_not_credit_unrelated_member(tmp_path):
    _project(
        tmp_path,
        'import {tools} from "./barrel"; tools.active(); '
        "function inspect(tools: any) { tools.retired(); } inspect({retired() {}});",
    )
    assert _unused(tmp_path) == {"retired"}


def test_nested_namespace_escape_preserves_members(tmp_path):
    _project(tmp_path, 'import * as api from "./barrel"; external(api.tools);')
    assert _unused(tmp_path) == set()


def test_opaque_project_namespace_keeps_exported_api_without_hiding_private_dead_code(
    tmp_path,
):
    _project(
        tmp_path,
        'import {tools} from "./barrel"; tools.active(); import(process.argv[2]);',
    )
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\nfunction orphan() {}\n",
    )
    assert _unused(tmp_path) == {"orphan"}


def test_independently_read_namespace_member_stays_used(tmp_path):
    _project(
        tmp_path,
        'import {tools} from "./barrel"; tools.active(); '
        'import {retired} from "./library"; retired();',
    )
    assert _unused(tmp_path) == set()


@pytest.mark.parametrize(
    "consumer",
    [
        'import * as api from "./barrel"; api.tools.active = replacement;',
        'import * as api from "./barrel"; delete api.tools.active;',
        'import * as api from "./barrel"; api.tools[process.argv[2]]();',
    ],
)
def test_nested_namespace_mutation_or_unknown_keys_remain_opaque(tmp_path, consumer):
    _project(tmp_path, consumer)
    assert _unused(tmp_path) == set()


def test_valid_tagged_template_keeps_project_export_analysis_complete(tmp_path):
    _project(
        tmp_path,
        r"const prefix = String.raw`\undefined`;"
        '\nimport {tools} from "./barrel"; tools.active();',
    )
    assert _unused(tmp_path) == {"retired"}


def test_namespace_member_read_does_not_keep_unrelated_file_function_alive(tmp_path):
    _project(
        tmp_path, 'import {tools} from "./barrel"; tools.active(); import "./other";'
    )
    _write(tmp_path, "other.ts", 'function active() {}\nexport const label = "ready";')
    assert "active" in _unused(tmp_path, "other.ts")


def test_export_path_budget_falls_back_without_false_positive(tmp_path, monkeypatch):
    import skylos.visitors.languages.typescript.reexport_demand as demand

    _project(tmp_path, 'import {tools} from "./barrel"; tools.active();')
    monkeypatch.setattr(demand, "_MAX_EXPORT_DEMAND_ITEMS", 2)
    assert "active" not in _unused(tmp_path)


def test_namespace_export_metadata_keeps_its_identity():
    core = TypeScriptCore("barrel.ts", b'export * as tools from "./library";')
    core.scan()
    assert core.raw_imports[0]["names"] == ["* as tools"]
    assert not core.raw_imports[0].get("opaque_reexport")
