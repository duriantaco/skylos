"""Unused TS/JS re-export entries: reported in modules, silent in entry points."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze


APP_PACKAGE = {"name": "app", "private": True, "type": "module", "main": "src/main.ts"}

HELPERS = (
    "export function used() { return 1; }\nexport function spare() { return 2; }\n"
)
TYPES = "export interface Shape { size: number }\nexport interface SpareShape { size: number }\n"
BARREL = (
    'export { used, spare } from "./helpers";\n'
    'export type { Shape, SpareShape } from "./types";\n'
)
MAIN = (
    'import { used } from "./lib";\n'
    'import type { Shape } from "./lib/index";\n'
    "const shape: Shape = { size: used() };\n"
    "console.log(shape);\n"
)
P1_FINDINGS = {("src/lib/index.ts", 1, "spare"), ("src/lib/index.ts", 2, "SpareShape")}


def _write(root, relative, source):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324]


def _project(root, package=None, files=None):
    _write(root, "package.json", json.dumps(package or APP_PACKAGE))
    for relative, source in (files or {}).items():
        _write(root, relative, source)


def _barrel_project(root, package=None, extra=None, main=MAIN):
    files = {
        "src/lib/helpers.ts": HELPERS,
        "src/lib/types.ts": TYPES,
        "src/lib/index.ts": BARREL,
        "src/main.ts": main,
    }
    files.update(extra or {})
    _project(root, package, files)


def _reexports(root):
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
    base = Path(root).resolve()
    found = set()
    for item in result.get("unused_exports", []):
        if item.get("type") != "reexport":
            continue
        assert item["rule_id"] == "SKY-E004"
        relative = Path(item["file"]).resolve().relative_to(base).as_posix()
        found.add((relative, item["line"], item["name"]))
    return found


def test_nested_barrel_reports_unrequested_named_and_type_reexports(tmp_path):
    _barrel_project(tmp_path)
    assert _reexports(tmp_path) == P1_FINDINGS


def test_multiline_list_reports_each_specifier_on_its_own_line(tmp_path):
    _project(
        tmp_path,
        files={
            "src/lib/parts.ts": (
                "export const alpha = 1;\nexport const beta = 2;\n"
                "export type Gamma = string;\nexport type Delta = number;\n"
            ),
            "src/lib/index.ts": (
                "export {\n  alpha,\n  beta as renamedBeta,\n  type Gamma,\n"
                '  type Delta,\n} from "./parts";\n'
            ),
            "src/main.ts": (
                'import { alpha, type Gamma } from "./lib";\n'
                "const value: Gamma = String(alpha);\nconsole.log(value);\n"
            ),
        },
    )
    assert _reexports(tmp_path) == {
        ("src/lib/index.ts", 3, "renamedBeta"),
        ("src/lib/index.ts", 5, "Delta"),
    }


def test_local_export_clause_of_import_bindings(tmp_path):
    _project(
        tmp_path,
        files={
            "src/lib/helpers.ts": "export const kept = 1;\nexport const dropped = 2;\n",
            "src/lib/types.ts": TYPES,
            "src/lib/index.ts": (
                'import { kept, dropped } from "./helpers";\n'
                'import type { Shape } from "./types";\n'
                "export { kept, dropped };\n"
                "export type { Shape };\n"
            ),
            "src/main.ts": 'import { kept } from "./lib";\nconsole.log(kept);\n',
        },
    )
    assert _reexports(tmp_path) == {
        ("src/lib/index.ts", 3, "dropped"),
        ("src/lib/index.ts", 4, "Shape"),
    }


FEATURE = "export function register() { return 1; }\n\nexport default register;\n"


def test_default_alias_of_a_named_export_without_default_importer(tmp_path):
    _project(
        tmp_path,
        files={
            "src/feature/index.ts": FEATURE,
            "src/main.ts": 'import { register } from "./feature";\nregister();\n',
        },
    )
    assert _reexports(tmp_path) == {("src/feature/index.ts", 3, "default")}


def test_default_alias_requested_by_a_default_import_stays_silent(tmp_path):
    _project(
        tmp_path,
        files={
            "src/feature/index.ts": FEATURE,
            "src/main.ts": 'import register from "./feature";\nregister();\n',
        },
    )
    assert _reexports(tmp_path) == set()


def test_default_export_of_an_unexported_declaration_is_not_a_reexport(tmp_path):
    _project(
        tmp_path,
        files={
            "src/feature/index.ts": (
                "function only() { return 1; }\nexport const named = 2;\n"
                "export default only;\n"
            ),
            "src/main.ts": 'import { named } from "./feature";\nconsole.log(named);\n',
        },
    )
    assert _reexports(tmp_path) == set()


def test_star_reexport_forwards_only_requested_names(tmp_path):
    _project(
        tmp_path,
        files={
            "src/api/lib/impl.ts": "export const a = 1;\nexport const b = 2;\n",
            "src/api/lib/index.ts": 'export { a, b } from "./impl";\n',
            "src/api/index.ts": 'export * from "./lib";\n',
            "src/main.ts": 'import { a } from "./api";\nconsole.log(a);\n',
        },
    )
    assert _reexports(tmp_path) == {("src/api/lib/index.ts", 1, "b")}


def test_named_alias_chain_forwards_the_original_name(tmp_path):
    _project(
        tmp_path,
        files={
            "src/lib/impl.ts": "export const inner = 1;\nexport const other = 2;\n",
            "src/lib/bridge.ts": 'export { inner as outer, other } from "./impl";\n',
            "src/lib/index.ts": 'export { outer, other } from "./bridge";\n',
            "src/main.ts": 'import { outer } from "./lib";\nconsole.log(outer);\n',
        },
    )
    assert _reexports(tmp_path) == {
        ("src/lib/index.ts", 1, "other"),
        ("src/lib/bridge.ts", 1, "other"),
    }


def test_namespace_member_reads_select_names(tmp_path):
    _barrel_project(
        tmp_path, main='import * as lib from "./lib";\nconsole.log(lib.used());\n'
    )
    assert _reexports(tmp_path) == {
        ("src/lib/index.ts", 1, "spare"),
        ("src/lib/index.ts", 2, "Shape"),
        ("src/lib/index.ts", 2, "SpareShape"),
    }


@pytest.mark.parametrize(
    "extra",
    [
        {"src/other.ts": 'import thing from "@app/other";\nconsole.log(thing);\n'},
        {"index.ts": 'export { used } from "./src/lib/helpers";\n'},
        {
            "src/other.ts": (
                'export const X = 1;\nexport async function load() { return import("./main"); }\n'
            ),
            "src/types.ts": 'export type T = typeof import("./other").X;\n',
        },
        {"README.md": "# app\n", "src/styles.css": "body { margin: 0; }\n"},
    ],
    ids=[
        "unrelated-unresolved",
        "root-entry-index",
        "literal-loads",
        "non-module-files",
    ],
)
def test_unrelated_project_facts_do_not_hide_the_barrel(tmp_path, extra):
    _barrel_project(tmp_path, extra=extra)
    assert _reexports(tmp_path) == P1_FINDINGS


@pytest.mark.parametrize(
    "package",
    [
        {**APP_PACKAGE, "main": "src/lib/index.ts"},
        {**APP_PACKAGE, "module": "src/lib/index.ts"},
        {**APP_PACKAGE, "types": "src/lib/index.ts"},
        {**APP_PACKAGE, "exports": {".": "./src/lib/index.ts"}},
        {
            **APP_PACKAGE,
            "exports": {".": "./src/main.ts", "./lib": "./src/lib/index.ts"},
        },
        {**APP_PACKAGE, "bin": {"app-lib": "./src/lib/index.ts"}},
    ],
    ids=["main", "module", "types", "exports-root", "exports-subpath", "bin"],
)
def test_package_entry_points_are_public(tmp_path, package):
    _barrel_project(tmp_path, package=package)
    assert _reexports(tmp_path) == set()


def test_package_root_index_without_main_is_public(tmp_path):
    _project(
        tmp_path,
        package={"name": "lib", "private": True, "type": "module"},
        files={
            "src/helpers.ts": HELPERS,
            "index.ts": 'export { used, spare } from "./src/helpers";\n',
            "src/app.ts": 'import { used } from "../index";\nconsole.log(used());\n',
        },
    )
    assert _reexports(tmp_path) == set()


def test_src_index_without_main_is_public(tmp_path):
    _project(
        tmp_path,
        package={"name": "lib", "private": True, "type": "module"},
        files={
            "src/helpers.ts": HELPERS,
            "src/index.ts": 'export { used, spare } from "./helpers";\n',
            "src/app.ts": 'import { used } from "./index";\nconsole.log(used());\n',
        },
    )
    assert _reexports(tmp_path) == set()


@pytest.mark.parametrize(
    "main, barrel",
    [
        (
            'import * as lib from "./lib";\nexport function wire(fn: (x: object) => void) { fn(lib); }\n',
            BARREL,
        ),
        (
            'import * as lib from "./lib";\nconsole.log(Object.keys(lib));\n',
            'export * from "./helpers";\nexport { Shape, SpareShape } from "./types";\n',
        ),
    ],
    ids=["namespace-escapes", "star-barrel-enumerated"],
)
def test_namespace_consumers_keep_every_reexport(tmp_path, main, barrel):
    _barrel_project(tmp_path, main=main, extra={"src/lib/index.ts": barrel})
    assert _reexports(tmp_path) == set()


def test_public_namespace_reexport_forwards_everything(tmp_path):
    _barrel_project(
        tmp_path,
        package={**APP_PACKAGE, "main": "src/index.ts"},
        extra={
            "src/index.ts": 'export * as tools from "./lib";\nexport * from "./main";\n',
            "src/main.ts": 'import { used } from "./lib";\nexport const value = used();\n',
        },
    )
    assert _reexports(tmp_path) == set()


@pytest.mark.parametrize(
    "consumer",
    [
        {
            "src/shapes.ts": 'import type { SpareShape } from "./lib";\nexport const s: SpareShape = { size: 1 };\n'
        },
        {
            "src/shapes.ts": 'import { type SpareShape } from "./lib";\nexport const s: SpareShape = { size: 1 };\n'
        },
        {
            "src/shapes.js": (
                "/** @type {import('./lib/index.js').SpareShape} */\n"
                "export const s = { size: 1 };\n"
            )
        },
    ],
    ids=["import-type", "inline-type", "jsdoc"],
)
def test_type_consumers_request_type_reexports(tmp_path, consumer):
    _barrel_project(
        tmp_path,
        extra={
            **consumer,
            "src/main.ts": MAIN + 'import "./shapes";\n',
        },
    )
    assert ("src/lib/index.ts", 2, "SpareShape") not in _reexports(tmp_path)
    assert ("src/lib/index.ts", 1, "spare") in _reexports(tmp_path)


def test_type_query_import_keeps_the_type_reexport(tmp_path):
    _barrel_project(
        tmp_path,
        extra={
            "src/shapes.ts": 'export type Alias = import("./lib").SpareShape;\n',
            "src/main.ts": MAIN + 'import "./shapes";\n',
        },
    )
    assert ("src/lib/index.ts", 2, "SpareShape") not in _reexports(tmp_path)


@pytest.mark.parametrize(
    "extra",
    [
        {
            "src/extra.ts": 'import { spare as other } from "./lib";\nconsole.log(other());\n',
            "src/main.ts": MAIN + 'import "./extra";\n',
        },
        {
            "src/extra.ts": 'export async function load() { return (await import("./lib")).used(); }\n',
            "src/main.ts": MAIN + 'import "./extra";\n',
        },
        {
            "src/extra.js": 'const lib = require("./lib");\nmodule.exports = lib;\n',
            "src/main.ts": MAIN + 'import "./extra.js";\n',
        },
        {
            "src/extra.ts": 'import lib = require("./lib");\nexport const value = lib.used();\n',
            "src/main.ts": MAIN + 'import "./extra";\n',
        },
    ],
    ids=["aliased-import", "dynamic-import", "require", "import-equals"],
)
def test_consumers_through_the_barrel_keep_the_name(tmp_path, extra):
    _barrel_project(tmp_path, extra=extra)
    assert ("src/lib/index.ts", 1, "spare") not in _reexports(tmp_path)


def test_public_entry_reexport_through_the_barrel_keeps_the_name(tmp_path):
    _barrel_project(
        tmp_path,
        package={
            **APP_PACKAGE,
            "exports": {".": "./src/main.ts", "./public": "./src/public.ts"},
        },
        extra={"src/public.ts": 'export { spare } from "./lib";\n'},
    )
    assert _reexports(tmp_path) == {("src/lib/index.ts", 2, "SpareShape")}


def test_default_reexport_requested_by_default_import(tmp_path):
    _project(
        tmp_path,
        files={
            "src/lib/thing.ts": "export default function thing() { return 1; }\n",
            "src/lib/index.ts": 'export { default } from "./thing";\n',
            "src/main.ts": 'import thing from "./lib";\nthing();\n',
        },
    )
    assert _reexports(tmp_path) == set()


def test_barrel_that_no_file_imports_is_left_to_the_file_rule(tmp_path):
    _barrel_project(tmp_path, main="console.log(1);\n")
    assert _reexports(tmp_path) == set()


def test_unresolved_specifier_that_may_name_the_barrel(tmp_path):
    _barrel_project(
        tmp_path,
        extra={
            "src/extra.ts": 'import { spare } from "@app/lib";\nconsole.log(spare());\n'
        },
        main=MAIN + 'import "./extra";\n',
    )
    assert _reexports(tmp_path) == set()


def test_declaration_files_and_test_barrels_are_roots(tmp_path):
    _project(
        tmp_path,
        files={
            "src/lib/types.ts": TYPES,
            "src/lib/index.d.ts": 'export type { Shape, SpareShape } from "./types";\n',
            "src/__tests__/helpers/index.ts": 'export { Shape, SpareShape } from "../../lib/types";\n',
            "src/__tests__/app.test.ts": 'import type { Shape } from "./helpers";\nexport const s: Shape = { size: 1 };\n',
            "src/main.ts": 'import type { Shape } from "./lib";\nexport const s: Shape = { size: 1 };\n',
        },
    )
    assert _reexports(tmp_path) == set()


def test_component_files_that_can_import_modules_stop_the_check(tmp_path):
    _barrel_project(
        tmp_path,
        extra={
            "src/Widget.vue": (
                '<script setup lang="ts">\nimport { spare } from "./lib";\n'
                "spare();\n</script>\n<template><div /></template>\n"
            )
        },
    )
    assert _reexports(tmp_path) == set()


def test_computed_loader_with_a_static_directory_reaches_the_barrel(tmp_path):
    _barrel_project(
        tmp_path,
        extra={
            "src/loader.ts": (
                "export async function load(name: string) {\n"
                "  return import(`./lib/${name}`);\n}\n"
            )
        },
        main=MAIN + 'import "./loader";\n',
    )
    assert _reexports(tmp_path) == set()


def test_inline_module_script_in_html_stops_the_check(tmp_path):
    _barrel_project(
        tmp_path,
        extra={
            "index.html": (
                '<html><body><script type="module">\n'
                'import { spare } from "./src/lib/index.ts";\nspare();\n'
                "</script></body></html>\n"
            )
        },
    )
    assert _reexports(tmp_path) == set()


def test_html_module_entry_loaded_by_src_keeps_the_report(tmp_path):
    _barrel_project(
        tmp_path,
        extra={
            "index.html": (
                '<html><body><script type="module" src="/src/main.ts">'
                "</script></body></html>\n"
            )
        },
    )
    assert _reexports(tmp_path) == P1_FINDINGS


LOADER_PROJECT_MAIN = MAIN + 'import "./loader";\n'


@pytest.mark.parametrize(
    "loader",
    [
        "export function load(name: string) { return import(name); }\n",
        "export function load(name: string) { return import(`./plugins/${name}`); }\n",
    ],
    ids=["opaque-name", "other-directory"],
)
def test_loaders_that_cannot_reach_the_barrel_keep_the_report(tmp_path, loader):
    _barrel_project(
        tmp_path,
        extra={
            "src/loader.ts": loader,
            "src/plugins/one.ts": "export const one = 1;\n",
        },
        main=LOADER_PROJECT_MAIN,
    )
    assert _reexports(tmp_path) == P1_FINDINGS


@pytest.mark.parametrize(
    "loader",
    [
        'import { createRequire } from "node:module";\n'
        "const load = createRequire(import.meta.url);\n"
        'export const lib = load("./lib/index.ts");\n',
        'export const modules = require.context("./lib", true, /\\.ts$/);\n',
        'import path from "node:path";\n'
        "export function load(name: string) {\n"
        '  return import(path.join(__dirname, "lib", name));\n}\n',
    ],
    ids=["create-require-literal", "require-context", "path-join-piece"],
)
def test_loaders_that_reach_the_barrel_keep_it_silent(tmp_path, loader):
    _barrel_project(
        tmp_path,
        extra={"src/loader.ts": loader},
        main=LOADER_PROJECT_MAIN,
    )
    assert ("src/lib/index.ts", 1, "spare") not in _reexports(tmp_path)


def test_built_entry_targets_map_to_sources_and_keep_the_report(tmp_path):
    _barrel_project(
        tmp_path,
        package={
            "name": "tool",
            "private": True,
            "type": "module",
            "main": "dist/index.mjs",
            "module": "dist/index.mjs",
            "types": "dist/index.d.mts",
            "bin": {"tool": "bin/cli.mjs"},
        },
        extra={
            "src/index.ts": 'export { run } from "./main";\n',
            "src/main.ts": MAIN + "export function run() { return 1; }\n",
            "bin/cli.mjs": 'import "../dist/index.mjs";\n',
        },
    )
    assert _reexports(tmp_path) == P1_FINDINGS


def test_unresolvable_package_entry_keeps_the_package_silent(tmp_path):
    _barrel_project(
        tmp_path,
        package={**APP_PACKAGE, "main": "lib/index.js"},
    )
    assert _reexports(tmp_path) == set()


MOCK_TEST = (
    'import { vi } from "vitest";\n'
    'import { used } from "../lib";\n'
    'vi.mock("../lib", () => ({ used: () => 1 }));\n'
    "export const value = used();\n"
)
ACTUAL_TEST = (
    'import { vi } from "vitest";\n'
    'export const real = await vi.importActual("../lib");\n'
)


def test_mock_registration_is_not_a_load(tmp_path):
    _barrel_project(tmp_path, extra={"src/__tests__/app.test.ts": MOCK_TEST})
    assert _reexports(tmp_path) == P1_FINDINGS


def test_import_actual_reads_the_real_module(tmp_path):
    _barrel_project(tmp_path, extra={"src/__tests__/app.test.ts": ACTUAL_TEST})
    assert ("src/lib/index.ts", 1, "spare") not in _reexports(tmp_path)


@pytest.mark.parametrize(
    "main, expected",
    [("dist-app/server.cjs", P1_FINDINGS), ("dist-app/index.cjs", set())],
    ids=["other-stem", "same-stem"],
)
def test_unresolvable_entry_keeps_only_same_named_modules_public(
    tmp_path, main, expected
):
    _barrel_project(tmp_path, package={**APP_PACKAGE, "main": main})
    assert _reexports(tmp_path) == expected


@pytest.mark.parametrize(
    "extra, expected",
    [
        (
            {
                "src/extra.ts": "export async function f() {\n"
                '  const { used } = await import("./lib");\n  return used();\n}\n'
            },
            P1_FINDINGS,
        ),
        (
            {
                "src/extra.js": 'const { used } = require("./lib");\nmodule.exports = used;\n'
            },
            P1_FINDINGS,
        ),
        (
            {
                "src/extra.ts": "export async function f() {\n"
                '  const { spare } = await import("./lib");\n  return spare();\n}\n'
            },
            {("src/lib/index.ts", 2, "SpareShape")},
        ),
        (
            {
                "src/extra.ts": "export async function f() {\n"
                '  const { used, ...rest } = await import("./lib");\n'
                "  return [used, rest];\n}\n"
            },
            set(),
        ),
    ],
    ids=["import-used", "require-used", "import-spare", "import-rest"],
)
def test_destructured_dynamic_loads_request_their_names(tmp_path, extra, expected):
    name = next(iter(extra))
    main = MAIN + f'import "./{Path(name).name}";\n'
    _barrel_project(tmp_path, extra=extra, main=main)
    assert _reexports(tmp_path) == expected


@pytest.mark.parametrize(
    "rule, expected",
    [
        ("SKY-E004", {("src/lib/index.ts", 2, "SpareShape")}),
        ("SKY-U001", P1_FINDINGS),
    ],
    ids=["same-rule", "other-rule"],
)
def test_inline_ignore_applies_to_its_rule_only(tmp_path, rule, expected):
    barrel = (
        f'export {{ used, spare }} from "./helpers"; // skylos: ignore[{rule}]\n'
        'export type { Shape, SpareShape } from "./types";\n'
    )
    _barrel_project(tmp_path, extra={"src/lib/index.ts": barrel})
    assert _reexports(tmp_path) == expected
