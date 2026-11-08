"""Source-derived contracts for demand through ECMAScript re-export chains."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze


def _write(root, relative, source):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324]


def _scan(root):
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
    return result


def _provider_unused(result, name="library.ts"):
    return {
        item["name"]
        for category in (
            "unused_functions",
            "unused_exports",
            "unused_variables",
            "unused_classes",
        )
        for item in result.get(category, [])
        if Path(item["file"]).name == name
    }


@pytest.mark.parametrize("extension", ["ts", "js", "mts"])
@pytest.mark.parametrize("chain", ["named", "alias", "mixed", "cycle", "long"])
def test_selected_export_crosses_reexport_chains(tmp_path, extension, chain):
    _write(
        tmp_path,
        "package.json",
        json.dumps({"private": True, "scripts": {"start": f"node index.{extension}"}}),
    )
    _write(
        tmp_path,
        f"index.{extension}",
        'import * as api from "./barrel"; api.start();\n',
    )
    _write(
        tmp_path,
        f"library.{extension}",
        "export function active() {}\nexport function retired() {}\n",
    )
    if chain == "named":
        _write(
            tmp_path,
            f"barrel.{extension}",
            'export {active as start, retired} from "./library";\n',
        )
    elif chain == "alias":
        _write(
            tmp_path,
            f"barrel.{extension}",
            'export {next as start, retired} from "./bridge";\n',
        )
        _write(
            tmp_path,
            f"bridge.{extension}",
            'export {active as next, retired} from "./library";\n',
        )
    elif chain == "mixed":
        _write(tmp_path, f"barrel.{extension}", 'export * from "./bridge";\n')
        _write(
            tmp_path,
            f"bridge.{extension}",
            'export {next as start, retired} from "./inner";\n',
        )
        _write(
            tmp_path,
            f"inner.{extension}",
            'export {active as next, retired} from "./library";\n',
        )
    elif chain == "cycle":
        _write(tmp_path, f"barrel.{extension}", 'export * from "./bridge";\n')
        _write(
            tmp_path,
            f"bridge.{extension}",
            'export * from "./barrel"; export {active as start, retired} from "./library";\n',
        )
    else:
        _write(tmp_path, f"barrel.{extension}", 'export * from "./hop0";\n')
        for index in range(25):
            source = f"./hop{index + 1}" if index < 24 else "./library"
            statement = (
                f'export * from "{source}";\n'
                if index < 24
                else 'export {active as start, retired} from "./library";\n'
            )
            _write(tmp_path, f"hop{index}.{extension}", statement)
    assert _provider_unused(_scan(tmp_path), f"library.{extension}") == {"retired"}


@pytest.mark.parametrize(
    "body",
    [
        "api[process.argv[2]]();",
        "external(api);",
        "const alias = api; external(alias);",
        "const {start, ...rest} = api; external(rest); start();",
    ],
)
def test_escaped_barrel_namespace_preserves_all_forwarded_exports(tmp_path, body):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(tmp_path, "index.ts", 'import * as api from "./barrel";\n' + body)
    _write(tmp_path, "barrel.ts", 'export * from "./bridge";\n')
    _write(
        tmp_path, "bridge.ts", 'export {active as start, retired} from "./library";\n'
    )
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == set()


@pytest.mark.parametrize("field", ["main", "module", "source", "exports"])
def test_package_api_barrel_retains_public_exports_with_internal_consumer(
    tmp_path, field
):
    package = {
        "name": "application-library",
        "private": True,
        field: "./barrel.ts",
        "scripts": {"start": "node index.ts"},
    }
    _write(tmp_path, "package.json", json.dumps(package))
    _write(tmp_path, "index.ts", 'import * as api from "./barrel"; api.start();\n')
    _write(
        tmp_path, "barrel.ts", 'export {active as start, retired} from "./library";\n'
    )
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == set()


def test_named_and_namespace_barrel_consumers_merge_their_demands(tmp_path):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(
        tmp_path,
        "index.ts",
        'import {first} from "./barrel"; import * as api from "./barrel"; first(); api.second();\n',
    )
    _write(
        tmp_path,
        "barrel.ts",
        'export {one as first, two as second, retired} from "./library";\n',
    )
    _write(
        tmp_path,
        "library.ts",
        "export function one() {}\nexport function two() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == {"retired"}


def test_reexport_does_not_hide_independent_provider_read(tmp_path):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(tmp_path, "index.ts", 'import * as api from "./barrel"; api.start();\n')
    _write(
        tmp_path,
        "barrel.ts",
        'import {retired} from "./library"; retired(); export {active as start, retired} from "./library";\n',
    )
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == set()


def test_default_export_crosses_named_reexport(tmp_path):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(tmp_path, "index.ts", 'import * as api from "./barrel"; api.start();\n')
    _write(
        tmp_path, "barrel.ts", 'export {default as start, retired} from "./library";\n'
    )
    _write(
        tmp_path,
        "library.ts",
        "export default function launch() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == {"retired"}


@pytest.mark.parametrize(
    "body",
    [
        'import {Worker} from "node:worker_threads"; new Worker(process.argv[2]);',
        "import(process.argv[2]).then(value => value.retired());",
        "const load = eval; load(process.argv[2]);",
    ],
)
def test_runtime_loader_boundary_keeps_forwarded_provider_uncertain(tmp_path, body):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(
        tmp_path, "index.ts", 'import * as api from "./barrel"; api.start();\n' + body
    )
    _write(
        tmp_path, "barrel.ts", 'export {active as start, retired} from "./library";\n'
    )
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == set()


@pytest.mark.parametrize("boundary", ["missing", "external", "namespace", "escaped"])
def test_opaque_forwarding_preserves_existing_reference_evidence(tmp_path, boundary):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(tmp_path, "index.ts", 'import * as api from "./barrel"; api.start();\n')
    statement = {
        "missing": 'export * from "./missing";',
        "external": 'export * from "external-package";',
        "namespace": 'export * as tools from "./library";',
        "escaped": r'export {active as \u0073tart} from "./library";',
    }[boundary]
    _write(
        tmp_path,
        "barrel.ts",
        'export {active as start, retired} from "./library";\n' + statement,
    )
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == (
        {"retired"} if boundary == "namespace" else set()
    )


def test_direct_default_import_resolves_reexported_default(tmp_path):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(tmp_path, "index.ts", 'import run from "./barrel"; run();\n')
    _write(
        tmp_path, "barrel.ts", 'export {active as default, retired} from "./library";\n'
    )
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == {"retired"}


def test_star_reexport_does_not_forward_default(tmp_path):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(tmp_path, "index.ts", 'import * as api from "./barrel"; external(api);\n')
    _write(tmp_path, "barrel.ts", 'export * from "./bridge";\n')
    _write(tmp_path, "bridge.ts", 'export {default, active} from "./library";\n')
    _write(
        tmp_path,
        "library.ts",
        "export default function launch() {}\nexport function active() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == {"launch"}


def test_unresolved_declared_package_api_prevents_negative_proof(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"main":"./generated.js","scripts":{"start":"node index.ts"}}',
    )
    _write(tmp_path, "index.ts", 'import * as api from "./barrel"; api.start();\n')
    _write(
        tmp_path, "barrel.ts", 'export {active as start, retired} from "./library";\n'
    )
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == set()


def test_namespace_export_declines_new_demand_inference(tmp_path):
    _write(
        tmp_path, "package.json", '{"private":true,"scripts":{"start":"node index.ts"}}'
    )
    _write(tmp_path, "index.ts", 'import {tools} from "./barrel"; tools.active();\n')
    _write(tmp_path, "barrel.ts", 'export * as tools from "./library";\n')
    _write(
        tmp_path,
        "library.ts",
        "export function active() {}\nexport function retired() {}\n",
    )
    assert _provider_unused(_scan(tmp_path)) == {"retired"}


def test_multiple_star_providers_preserve_prior_unused_symbol_findings(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"type":"module","scripts":{"start":"node index.mjs"}}',
    )
    _write(tmp_path, "index.mjs", 'import * as api from "./barrel.mjs"; api.unique();')
    _write(
        tmp_path, "barrel.mjs", 'export * from "./one.mjs"; export * from "./two.mjs";'
    )
    _write(
        tmp_path,
        "one.mjs",
        "export function unique() {}\nexport function collision() {}",
    )
    _write(
        tmp_path,
        "two.mjs",
        "export function collision() {}\nexport function spare() {}",
    )
    result = _scan(tmp_path)
    assert _provider_unused(result, "one.mjs") == {"collision"}
    assert _provider_unused(result, "two.mjs") == {"collision", "spare"}


def test_local_export_binding_shadows_forwarded_binding(tmp_path):
    _write(
        tmp_path,
        "package.json",
        '{"private":true,"type":"module","scripts":{"start":"node index.mjs"}}',
    )
    _write(tmp_path, "index.mjs", 'import * as api from "./barrel.mjs"; api.chosen();')
    _write(
        tmp_path,
        "barrel.mjs",
        'function chosen() {}\nexport {chosen};\nexport * from "./library.mjs";',
    )
    _write(
        tmp_path,
        "library.mjs",
        "export function chosen() {}\nexport function spare() {}",
    )
    assert _provider_unused(_scan(tmp_path), "library.mjs") == {"chosen", "spare"}
