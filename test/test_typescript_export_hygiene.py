"""Unused exported types (SKY-E004), duplicate exports (SKY-E005), unused
namespace members (SKY-U008) and release tags on TS exports."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze

APP = {"name": "app", "private": True, "type": "module", "main": "src/main.ts"}


def _project(root, files, package=None):
    for relative, source in {"package.json": json.dumps(package or APP), **files}.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path, literal names


def _scan(root, **kwargs):
    result = json.loads(
        analyze(
            str(root),
            conf=0,
            grep_verify=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
            **kwargs,
        )
    )
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return result


def _found(result, rule_id, category="unused_exports", kinds=None):
    base = None
    found = set()
    for item in result.get(category, []):
        if item.get("rule_id") != rule_id:
            continue
        if kinds is not None and item.get("type") not in kinds:
            continue
        path = Path(item["file"]).resolve()
        base = base or path
        found.add((path.name, item["line"], item["name"]))
    return found


def _types(result):
    return _found(result, "SKY-E004", kinds={"type", "interface"})


# --- SKY-E004: unused exported types --------------------------------------

LIB_TYPES = (
    "export type UnusedType = { a: number };\n"
    "export interface UnusedIface { b: string }\n"
    "export declare type DeclaredType = string;\n"
    "export type Used = string;\n"
    "export const value = 1;\n"
)


def test_unrequested_exported_types_and_interfaces_are_reported(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": LIB_TYPES,
            "src/main.ts": 'import { value, type Used } from "./lib";\nconst x: Used = String(value);\nconsole.log(x);\n',
        },
    )
    result = _scan(tmp_path)
    assert _types(result) == {
        ("lib.ts", 1, "UnusedType"),
        ("lib.ts", 2, "UnusedIface"),
        ("lib.ts", 3, "DeclaredType"),
    }
    kinds = {item["name"]: item["type"] for item in result["unused_exports"]}
    assert kinds["UnusedIface"] == "interface" and kinds["UnusedType"] == "type"


def test_type_used_only_in_its_file_reports_the_unnecessary_export(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": (
                "export type Local = { n: number };\n"
                "export function report(): void { const local: Local = { n: 1 }; console.log(local); }\n"
                "export type Held = { h: number };\n"
                "const held: Held = { h: 1 };\n"
                "export const value = held.h;\n"
            ),
            "src/main.ts": 'import { value, report } from "./lib";\nconsole.log(value, report);\n',
        },
    )
    result = _scan(tmp_path)
    # ``value`` has an inferred type built from ``held: Held``, so Held is in
    # its shape; ``report`` declares its return type, so its body is not.
    assert _types(result) == {("lib.ts", 1, "Local")}
    message = next(item["message"] for item in result["unused_exports"] if item["name"] == "Local")
    assert "used in this file" in message


def test_local_type_exported_by_a_specifier_is_reported_on_the_specifier(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": "type Hidden = string;\ninterface Shape { s: Hidden }\nexport type { Shape };\nexport const value = 1;\n",
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
        },
    )
    assert _types(_scan(tmp_path)) == {("lib.ts", 3, "Shape")}


@pytest.mark.parametrize(
    "consumer",
    [
        'import type { Wanted } from "./lib";\nlet w: Wanted;\nconsole.log(w);\n',
        'import { type Wanted } from "./lib";\nlet w: Wanted;\nconsole.log(w);\n',
        'import * as lib from "./lib";\nlet w: lib.Wanted;\nconsole.log(w);\n',
        'type W = import("./lib").Wanted;\nlet w: W;\nconsole.log(w);\n',
    ],
)
def test_requested_type_is_not_reported(tmp_path, consumer):
    _project(
        tmp_path,
        {
            "src/lib.ts": "export type Wanted = string;\nexport type Spare = number;\n",
            "src/use.ts": consumer,
            "src/main.ts": 'import "./use";\n',
        },
    )
    assert _types(_scan(tmp_path)) == {("lib.ts", 2, "Spare")}


@pytest.mark.parametrize(
    "consumer",
    [
        'import("./lib").then((module) => console.log(module));\n',
        'import * as lib from "./lib";\ndeclare function register(value: object): void;\nregister(lib);\n',
        'const lib = require("./lib");\nconsole.log(lib);\n',
    ],
)
def test_runtime_whole_module_use_requests_values_not_types(tmp_path, consumer):
    _project(
        tmp_path,
        {
            "src/lib.ts": "export type Spare = number;\nexport type Shape = { v: number };\nexport const value: Shape = { v: 1 };\n",
            "src/main.ts": consumer,
        },
    )
    # ``value`` counts as requested and keeps Shape in its shape.
    assert _types(_scan(tmp_path)) == {("lib.ts", 1, "Spare")}


@pytest.mark.parametrize(
    "consumer",
    [
        'import * as lib from "./lib";\ndeclare function register(value: object): void;\nlet s: lib.Spare | undefined;\nregister(lib);\nconsole.log(s);\n',
        'import type * as lib from "./lib";\nexport type All = typeof lib;\n',
    ],
)
def test_namespace_type_reads_and_type_only_namespaces_keep_types(tmp_path, consumer):
    _project(
        tmp_path,
        {
            "src/lib.ts": "export type Spare = number;\nexport const value = 1;\n",
            "src/main.ts": consumer,
        },
    )
    assert _types(_scan(tmp_path)) == set()


def test_javascript_runtime_use_keeps_the_whole_module(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": "export type Spare = number;\nexport const value = 1;\n",
            "src/main.js": 'import * as lib from "./lib.js";\n/** @type {lib.Spare} */\nconst s = 1;\nconsole.log(lib, s);\n',
        },
        package={**APP, "main": "src/main.js"},
    )
    assert _types(_scan(tmp_path)) == set()


def test_reexported_type_requested_through_a_barrel_is_not_reported(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib/types.ts": "export interface Wanted { w: 1 }\nexport interface Spare { s: 1 }\n",
            "src/lib/index.ts": 'export * from "./types";\n',
            "src/main.ts": 'import type { Wanted } from "./lib";\nlet w: Wanted;\nconsole.log(w);\n',
        },
    )
    assert _types(_scan(tmp_path)) == {("types.ts", 2, "Spare")}


@pytest.mark.parametrize(
    "library",
    [
        "export const Config = { a: 1 };\nexport type Config = typeof Config;\n",
        "export class Config {}\nexport interface Config { extra: number }\n",
        "export function Config() {}\nexport namespace Config { export const a = 1; }\nexport interface Config { b: 2 }\n",
    ],
)
def test_declaration_merged_with_a_value_is_not_reported(tmp_path, library):
    _project(
        tmp_path,
        {
            "src/lib.ts": library + "export const value = 1;\n",
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
        },
    )
    assert _types(_scan(tmp_path)) == set()


def test_type_in_the_shape_of_a_requested_export_stays_silent(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": (
                "export interface Props { p: Inner }\n"
                "export type Inner = string;\n"
                "export type BodyOnly = number;\n"
                "export type Inferred = number;\n"
                "export function button(props: Props): string { const b: BodyOnly = 1; return props.p + b; }\n"
                "export function infer() { return 1 as Inferred; }\n"
                "export interface Orphan { o: 1 }\n"
            ),
            "src/main.ts": 'import { button, infer } from "./lib";\nconsole.log(button, infer);\n',
        },
    )
    # Props is in button's signature and Inferred in infer's inferred return
    # type. BodyOnly sits behind an explicit return type. Inner is named only
    # by the exported type Props, which does not hold it.
    assert _types(_scan(tmp_path)) == {
        ("lib.ts", 2, "Inner"),
        ("lib.ts", 3, "BodyOnly"),
        ("lib.ts", 7, "Orphan"),
    }


def test_jsx_rendered_components_do_not_hold_their_prop_types(tmp_path):
    _project(
        tmp_path,
        {
            "src/dialog.tsx": (
                "export type InnerProps = { title: string };\n"
                "export type OuterProps = { open: boolean };\n"
                "export type MadeProps = { made: true };\n"
                "const Inner = (props: InnerProps) => <h1>{props.title}</h1>;\n"
                "const make = (): MadeProps => ({ made: true });\n"
                "export const Dialog = (props: OuterProps) => {\n"
                "  if (!props.open) return make();\n"
                '  return <Inner title="x" />;\n'
                "};\n"
            ),
            "src/main.tsx": 'import { Dialog } from "./dialog";\nconsole.log(Dialog);\n',
        },
    )
    # A JSX element is a JSX.Element whatever it renders: InnerProps only
    # types a component the requested Dialog renders. OuterProps is in its
    # signature and MadeProps in its inferred return type.
    assert _types(_scan(tmp_path)) == {("dialog.tsx", 1, "InnerProps")}


@pytest.mark.parametrize(
    ("unresolved", "expected"),
    [
        # An unresolved stylesheet or asset names no module.
        ('import "@ui/kit/index.css";\nimport logo from "./missing/logo.svg";\n', {("index.ts", 1, "Spare")}),
        # An unresolved module path may name any ``index`` module.
        ('import "./missing/index";\n', set()),
    ],
)
def test_unresolved_asset_imports_do_not_hold_back_modules_by_name(tmp_path, unresolved, expected):
    _project(
        tmp_path,
        {
            "src/feature/index.ts": "export type Spare = string;\nexport const value = 1;\n",
            "src/main.ts": unresolved + 'import { value } from "./feature";\nconsole.log(value);\n',
        },
    )
    assert _types(_scan(tmp_path)) == expected


def test_requested_type_does_not_hold_the_types_it_names(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": (
                "export interface Base { id: string }\n"
                "export interface Derived extends Base { name: string }\n"
                "type Local = { base: Base };\n"
                "export const value: Local | undefined = undefined;\n"
            ),
            "src/main.ts": 'import { value, type Derived } from "./lib";\nlet d: Derived | undefined;\nconsole.log(value, d);\n',
        },
    )
    # ``value`` reaches Base through the module-local Local, so Base stays.
    assert _types(_scan(tmp_path)) == set()
    (tmp_path / "src/main.ts").write_text('import type { Derived } from "./lib";\nlet d: Derived | undefined;\nconsole.log(d);\n', encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path
    assert _types(_scan(tmp_path)) == {("lib.ts", 1, "Base")}


@pytest.mark.parametrize(
    "package",
    [
        {"name": "lib", "main": "src/lib.ts"},
        {"name": "lib", "types": "src/lib.ts", "main": "src/main.ts"},
        {"name": "lib", "exports": {".": "./src/main.ts", "./lib": "./src/lib.ts"}},
    ],
)
def test_types_of_a_public_module_stay_silent(tmp_path, package):
    _project(
        tmp_path,
        {
            "src/lib.ts": LIB_TYPES,
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
        },
        package=package,
    )
    assert _types(_scan(tmp_path)) == set()


def test_ambient_and_augmenting_declarations_stay_silent(tmp_path):
    _project(
        tmp_path,
        {
            "src/types.d.ts": "export interface Ambient { a: 1 }\n",
            "src/lib.ts": (
                "export interface Extended { x: number }\n"
                "export interface InGlobal { g: 1 }\n"
                "declare global { interface Window { lib: InGlobal } }\n"
                "export const value = 1;\n"
            ),
            "src/augment.ts": 'export {};\ndeclare module "./lib" { interface Extended { y: number } }\n',
            "src/main.ts": 'import "./augment";\nimport type { Ambient } from "./types";\nimport { value } from "./lib";\nlet a: Ambient;\nconsole.log(a, value);\n',
        },
    )
    assert _types(_scan(tmp_path)) == set()


@pytest.mark.parametrize("tag", ["@public", "@alpha", "@beta", "@alias"])
def test_release_tagged_type_stays_silent(tmp_path, tag):
    _project(
        tmp_path,
        {
            "src/lib.ts": f"/** Shared shape.\n * {tag}\n */\nexport type Tagged = string;\n/** @internal */\nexport type Internal = string;\nexport const value = 1;\n",
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
        },
    )
    assert _types(_scan(tmp_path)) == {("lib.ts", 6, "Internal")}


UNREQUESTED_LIB_TYPES = {
    ("lib.ts", 2, "UnusedIface"),
    ("lib.ts", 3, "DeclaredType"),
    ("lib.ts", 4, "Used"),
}


@pytest.mark.parametrize(
    ("name", "component"),
    [
        ("View.vue", '<script setup lang="ts">import type { UnusedType } from "./lib";</script>\n<template><div /></template>\n'),
        ("View.svelte", '<script lang="ts">\n  import type { UnusedType } from "./lib";\n</script>\n<p>hi</p>\n'),
        ("View.astro", '---\nimport type { UnusedType } from "./lib";\n---\n<p>hi</p>\n'),
    ],
)
def test_component_script_imports_request_only_their_names(tmp_path, name, component):
    _project(
        tmp_path,
        {
            "src/lib.ts": LIB_TYPES,
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
            f"src/{name}": component,
        },
    )
    result = _scan(tmp_path)
    assert _types(result) == UNREQUESTED_LIB_TYPES
    assert result["analysis_summary"]["namespace_member_analysis"]["status"] != "not_run"


@pytest.mark.parametrize(
    "component",
    [
        # Another script language: the block is not parsed.
        '<script lang="coffee">\nimport { value } from "./lib"\n</script>\n',
        # A syntax error in the script.
        '<script setup lang="ts">\nimport { value } from "./lib";\nconst = ;\n</script>\n',
    ],
)
def test_unparsed_component_holds_back_only_the_modules_it_names(tmp_path, component):
    _project(
        tmp_path,
        {
            "src/lib.ts": LIB_TYPES,
            "src/other.ts": "export type Spare = string;\nexport const other = 1;\n",
            "src/main.ts": (
                'import { value } from "./lib";\nimport { other } from "./other";\n'
                "console.log(value, other);\n"
            ),
            "src/View.vue": component,
        },
    )
    assert _types(_scan(tmp_path)) == {("other.ts", 1, "Spare")}


def test_unreadable_consumer_leaves_the_export_surface_unavailable(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Real.vue").write_text('<script setup lang="ts">import { value } from "../app/src/lib";</script>\n', encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path
    root = tmp_path / "app"
    root.mkdir()
    _project(
        root,
        {
            "src/lib.ts": LIB_TYPES,
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
        },
    )
    (root / "src" / "View.vue").symlink_to(outside / "Real.vue")
    result = _scan(root)
    assert _types(result) == set()
    receipt = result["analysis_summary"]["namespace_member_analysis"]
    assert receipt["reasons"] == [{"kind": "export_surface_unavailable"}]


def test_html_module_script_src_is_an_entry_and_inline_imports_request_names(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": LIB_TYPES,
            "src/entry.ts": LIB_TYPES,
            "src/main.ts": 'import { value } from "./lib";\nimport { value as other } from "./entry";\nconsole.log(value, other);\n',
            "index.html": '<html><body><script type="module" src="/src/entry.ts"></script></body></html>\n',
        },
    )
    assert _types(_scan(tmp_path)) == {("lib.ts", 1, "UnusedType"), *UNREQUESTED_LIB_TYPES}


def test_project_ignore_turns_off_type_findings_with_e004(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": LIB_TYPES,
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
            "pyproject.toml": '[tool.skylos]\nignore = ["SKY-E004"]\n',
        },
    )
    assert _types(_scan(tmp_path)) == set()


# --- SKY-E005: duplicate exports ------------------------------------------

def _duplicates(result):
    return _found(result, "SKY-E005")


def test_duplicate_exports_of_one_binding_are_reported(tmp_path):
    _project(
        tmp_path,
        {
            "src/nav.ts": "export const NAV_ITEMS = [1];\nexport const ALL_NAV_ITEMS = NAV_ITEMS;\n",
            "src/button.tsx": "export function Button() { return null; }\nexport default Button;\n",
            "src/store.ts": "export class Store {}\nexport default Store;\n",
            "src/main.ts": (
                'import { NAV_ITEMS, ALL_NAV_ITEMS } from "./nav";\n'
                'import Button from "./button";\n'
                'import Store from "./store";\n'
                "console.log(NAV_ITEMS, ALL_NAV_ITEMS, Button, Store);\n"
            ),
        },
    )
    result = _scan(tmp_path)
    assert _duplicates(result) == {
        ("nav.ts", 2, "NAV_ITEMS|ALL_NAV_ITEMS"),
        ("button.tsx", 2, "Button|default"),
        ("store.ts", 2, "Store|default"),
    }
    item = next(item for item in result["unused_exports"] if item["rule_id"] == "SKY-E005")
    assert item["severity"] == "LOW" and item["type"] == "duplicate_export"


def test_spied_package_entry_does_not_silence_duplicates_it_forwards(tmp_path):
    # ``vi.spyOn(ns, "x")`` uses the public barrel whole; its forwarded
    # aliases are still one binding under two names. An internal barrel
    # enumerated with ``Object.keys`` keeps its forwarded aliases.
    library = "export const A = 1;\nexport const B = A;\n"
    _project(
        tmp_path,
        {
            "src/index.ts": 'export * from "./colors";\n',
            "src/colors.ts": library,
            "src/internal/barrel.ts": 'export * from "./aliases";\n',
            "src/internal/aliases.ts": library,
            "src/internal/use.ts": 'import * as all from "./barrel";\nexport const keys = Object.keys(all);\n',
            "test/index.test.ts": 'import * as lib from "../src/index";\nvi.spyOn(lib, "A");\n',
        },
        package={"name": "lib", "exports": {".": "./src/index.ts", "./use": "./src/internal/use.ts"}},
    )
    assert _duplicates(_scan(tmp_path)) == {("colors.ts", 2, "A|B")}


@pytest.mark.parametrize(
    "library",
    [
        # A reassigned binding is not the same binding as its alias.
        "export let A = 1;\nexport const B = A;\nA = 2;\n",
        "export const A = 1;\nexport let B = A;\n",
        # An explicit alias tag.
        "export const A = 1;\n/** @alias */\nexport const B = A;\n",
        # Specifier lists and specifier-exported defaults are not grouped.
        "const A = 1;\nexport { A, A as B };\n",
        "const A = 1;\nexport { A };\nexport default A;\n",
        # Imported bindings are re-exports, not own declarations.
        'import { A } from "./source";\nexport { A };\nexport const B = A;\n',
        # A different value.
        "export const A = 1;\nexport const B = A as number;\n",
    ],
)
def test_non_duplicates_stay_silent(tmp_path, library):
    _project(
        tmp_path,
        {
            "src/source.ts": "export const A = 1;\n",
            "src/lib.ts": library,
            "src/main.ts": 'import * as lib from "./lib";\nconsole.log(lib.A, lib.B, lib.default);\n',
        },
    )
    assert _duplicates(_scan(tmp_path)) == set()


def test_duplicates_in_public_modules_are_reported_but_enumerated_modules_stay_silent(tmp_path):
    # A package entry's alias is still one binding under two names; a module
    # whose keys an importer enumerates observes both.
    library = "export const A = 1;\nexport const B = A;\n"
    _project(
        tmp_path,
        {
            "src/lib.ts": library,
            "src/starred.ts": library,
            "src/enumerated.ts": library,
            "src/dynamic.ts": library,
            "src/main.ts": (
                'import * as all from "./enumerated";\nconsole.log(Object.keys(all));\n'
                'export { A } from "./lib";\nexport * from "./starred";\n'
                'export const load = () => import("./dynamic");\n'
            ),
            "src/types.d.ts": "export declare const A: 1;\nexport declare const B: typeof A;\n",
            "src/__fixtures__/data.ts": library,
            "src/lib.stories.ts": "export const A = {};\nexport const B = A;\nexport default {};\n",
        },
        package={"name": "lib", "main": "src/main.ts", "exports": {".": "./src/main.ts", "./lib": "./src/lib.ts"}},
    )
    assert _duplicates(_scan(tmp_path)) == {("lib.ts", 2, "A|B"), ("starred.ts", 2, "A|B")}


# --- SKY-U008: unused namespace members -----------------------------------

def _members(result):
    return _found(result, "SKY-U008", category="unused_variables")


NAMESPACE = (
    "export namespace Shapes {\n"
    "  export const Circle = 1;\n"
    "  export const Square = 2;\n"
    "  export const Base = 3;\n"
    "  export const Derived = Base + 1;\n"
    "  export type Kind = string;\n"
    "  export interface Spare { s: 1 }\n"
    "  export namespace Inner { export const used = 1; export const spare = 2; }\n"
    "  export function helper() { return 1; }\n"
    "}\n"
)


def test_unread_namespace_members_are_reported(tmp_path):
    _project(
        tmp_path,
        {
            "src/shapes.ts": NAMESPACE,
            "src/main.ts": (
                'import { Shapes } from "./shapes";\n'
                "const kind: Shapes.Kind = String(Shapes.Circle + Shapes.Derived + Shapes.Inner.used);\n"
                "console.log(kind);\n"
            ),
        },
    )
    result = _scan(tmp_path)
    assert _members(result) == {
        ("shapes.ts", 3, "Shapes.Square"),
        ("shapes.ts", 7, "Shapes.Spare"),
        ("shapes.ts", 8, "Shapes.Inner.spare"),
    }
    receipt = result["analysis_summary"]["namespace_member_analysis"]
    assert receipt["checked_namespaces"] == 1 and receipt["complete"] is True
    # The function member keeps its existing unused-function finding only.
    assert not any(item["name"].endswith("helper") for item in result["unused_variables"])


def test_member_read_in_its_own_file_is_live(tmp_path):
    _project(
        tmp_path,
        {
            "src/shapes.ts": NAMESPACE + "console.log(Shapes.Square, Shapes.Inner);\n",
            "src/main.ts": 'import { Shapes } from "./shapes";\nconsole.log(Shapes.Circle);\n',
        },
    )
    assert _members(_scan(tmp_path)) == {
        ("shapes.ts", 5, "Shapes.Derived"),
        ("shapes.ts", 6, "Shapes.Kind"),
        ("shapes.ts", 7, "Shapes.Spare"),
    }


@pytest.mark.parametrize(
    "use",
    [
        "consume(Shapes);",
        "Object.keys(Shapes);",
        "const copy = { ...Shapes };",
        "console.log(Shapes[key]);",
        "export { Shapes as Again };",
    ],
)
def test_escaping_namespace_retains_every_member(tmp_path, use):
    _project(
        tmp_path,
        {
            "src/shapes.ts": NAMESPACE,
            "src/main.ts": (
                'import { Shapes } from "./shapes";\n'
                "declare const key: string;\ndeclare function consume(value: unknown): void;\n"
                f"console.log(Shapes.Circle);\n{use}\n"
            ),
        },
    )
    result = _scan(tmp_path)
    assert _members(result) == set()
    reasons = {item["reason"] for item in result["analysis_summary"]["namespace_member_analysis"]["abstained_namespaces"]}
    assert reasons == {"escaping_namespace"}


@pytest.mark.parametrize(
    "own_use, reason",
    [
        ("consume(Shapes);", "opaque_namespace_use"),
        ("export default Shapes;", "opaque_namespace_use"),
        ("export namespace Shapes { export const More = 1; }", "merged_declaration"),
    ],
)
def test_opaque_or_merged_namespace_in_its_own_file_abstains(tmp_path, own_use, reason):
    _check_abstention(tmp_path, NAMESPACE + "declare function consume(value: unknown): void;\n" + own_use + "\n", reason)


def test_ambient_namespace_abstains(tmp_path):
    _check_abstention(
        tmp_path,
        "export declare namespace Shapes {\n  export const Circle: number;\n  export const Square: number;\n}\n",
        "ambient_namespace",
    )


def _check_abstention(tmp_path, shapes, reason):
    _project(
        tmp_path,
        {
            "src/shapes.ts": shapes,
            "src/main.ts": 'import { Shapes } from "./shapes";\nconsole.log(Shapes.Circle);\n',
        },
    )
    result = _scan(tmp_path)
    assert _members(result) == set()
    receipt = result["analysis_summary"]["namespace_member_analysis"]
    assert {item["reason"] for item in receipt["abstained_namespaces"]} == {reason}


def test_public_module_and_tagged_namespaces_stay_silent(tmp_path):
    _project(
        tmp_path,
        {
            "src/shapes.ts": NAMESPACE,
            "src/tagged.ts": "/** @public */\nexport namespace Api { export const a = 1; export const b = 2; }\nexport namespace Some {\n  /** @beta */\n  export const kept = 1;\n  export const read = 2;\n}\n",
            "src/main.ts": 'import { Api, Some } from "./tagged";\nconsole.log(Api.a, Some.read);\nexport { Shapes } from "./shapes";\n',
        },
        package={"name": "lib", "main": "src/main.ts"},
    )
    assert _members(_scan(tmp_path)) == set()


def test_namespace_member_rule_can_be_ignored(tmp_path):
    _project(
        tmp_path,
        {
            "src/shapes.ts": NAMESPACE.replace("export const Square = 2;", "export const Square = 2; // skylos: ignore[SKY-U008]"),
            "src/main.ts": 'import { Shapes } from "./shapes";\nlet kind: Shapes.Kind | Shapes.Spare | undefined;\nconsole.log(kind, Shapes.Circle, Shapes.Derived, Shapes.Inner);\n',
        },
    )
    result = _scan(tmp_path)
    assert _members(result) == set()
    assert any(item.get("rule_id") == "SKY-U008" for item in result.get("suppressed", []))
    (tmp_path / "pyproject.toml").write_text('[tool.skylos]\nignore = ["SKY-U008"]\n', encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path
    result = _scan(tmp_path)
    assert result["analysis_summary"]["namespace_member_analysis"]["status"] == "not_run"


# --- Release tags on value exports -----------------------------------------

def test_public_tagged_exports_are_never_reported_unused(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": (
                "export const used = () => 1;\n"
                "/** @public */\nexport const taggedPublic = () => 3;\n"
                "/**\n * Experimental.\n * @beta\n */\nexport function taggedBeta() { return 4; }\n"
                "/** @alpha */\nexport class TaggedAlpha {}\n"
                "/** @internal */\nexport const internalOnly = () => 5;\n"
                "foo(); // @public\nexport const trailingComment = () => 6;\n"
                "declare function foo(): void;\n"
            ),
            "src/main.ts": 'import { used } from "./lib";\nconsole.log(used());\n',
        },
    )
    result = _scan(tmp_path)
    unused = {
        item["name"]
        for category in ("unused_functions", "unused_classes", "unused_variables", "unused_exports")
        for item in result.get(category, [])
        if Path(item["file"]).name == "lib.ts"
    }
    assert unused == {"internalOnly", "trailingComment"}


def test_public_tagged_reexport_entry_is_not_reported(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib/parts.ts": "export const kept = 1;\nexport const spare = 2;\nexport const other = 3;\n",
            "src/lib/index.ts": '/** @public */\nexport { spare } from "./parts";\nexport { kept, other } from "./parts";\n',
            "src/main.ts": 'import { kept } from "./lib/index";\nconsole.log(kept);\n',
        },
    )
    found = _found(_scan(tmp_path), "SKY-E004", kinds={"reexport"})
    assert found == {("index.ts", 3, "other")}


# --- SKY-U007 on a public package ------------------------------------------

def test_enum_members_of_an_internal_module_in_a_public_package(tmp_path):
    _project(
        tmp_path,
        {
            "src/enums.ts": "export enum Color { Red, Green }\n",
            "src/main.ts": 'import { Color } from "./enums";\nimport missing from "./missing";\nconsole.log(Color.Red, missing);\n',
        },
        package={"name": "app", "main": "src/main.ts"},
    )
    result = _scan(tmp_path)
    assert _found(result, "SKY-U007", category="unused_variables") == {("enums.ts", 1, "Color.Green")}
    assert result["analysis_summary"]["enum_member_analysis"]["complete"] is True


# --- MDX documents without module statements -------------------------------

BLOG_POST = """---
title: Scanning Python
---

# Scanning Python

Run the scanner, then export the report.

```python
import os
export_path = os.getcwd()
```

~~~bash
export PYTHONDONTWRITEBYTECODE=1
~~~
"""


def test_mdx_without_module_statements_does_not_hold_back_export_checks(tmp_path):
    _project(
        tmp_path,
        {
            "src/lib.ts": LIB_TYPES,
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
            "src/content/blog/post.mdx": BLOG_POST,
        },
    )
    assert _types(_scan(tmp_path)) == {
        ("lib.ts", 1, "UnusedType"),
        ("lib.ts", 2, "UnusedIface"),
        ("lib.ts", 3, "DeclaredType"),
        ("lib.ts", 4, "Used"),
    }


ALL_LIB_TYPES = {("lib.ts", 1, "UnusedType"), *UNREQUESTED_LIB_TYPES}


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        # An MDX import requests its names like any module import.
        ('import { value, type UnusedType } from "../../lib";', UNREQUESTED_LIB_TYPES),
        ('export { type UnusedType } from "../../lib";', UNREQUESTED_LIB_TYPES),
        # A local export loads nothing.
        ('export const meta = { title: "Post" };', ALL_LIB_TYPES),
        # An expression load is not parsed: it holds back the module it names.
        ('{await import("../../lib").then((lib) => lib.value)}', set()),
        # An ESM block that does not parse holds back the modules it names.
        ('import { value } from "../../lib" with oops;', set()),
    ],
)
def test_mdx_module_statements_are_read_for_export_checks(tmp_path, statement, expected):
    _project(
        tmp_path,
        {
            "src/lib.ts": LIB_TYPES,
            "src/main.ts": 'import { value } from "./lib";\nconsole.log(value);\n',
            "src/content/blog/post.mdx": statement + "\n\n" + BLOG_POST,
        },
    )
    assert _types(_scan(tmp_path)) == expected


def test_mdx_reader_splits_esm_blocks_from_prose(tmp_path):
    from skylos.visitors.languages.typescript.mdx_modules import mdx_module_parts

    blocks, specifiers = mdx_module_parts(
        "---\ntitle: x\n---\nimport A from './a';\nimport B from './b';\n\n"
        "Some prose that mentions `import('./c')`.\n\n```js\nimport D from './d';\n```\n"
        "\n<Chart data={require('./e.json')} />\n\nexport const meta = 1;\n"
    )
    assert blocks == [
        (3, "import A from './a';\nimport B from './b';"),
        (14, "export const meta = 1;"),
    ]
    assert specifiers == {"./e.json"}


def test_mdx_reader_ignores_fenced_code_only(tmp_path):
    from skylos.visitors.languages.typescript.mdx_modules import (
        mdx_has_module_statements,
    )

    path = tmp_path / "post.mdx"
    path.write_text(BLOG_POST, encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path
    assert mdx_has_module_statements(path) is False
    path.write_text("```js\nimport x from './x';\n", encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path
    assert mdx_has_module_statements(path) is False
    path.write_text("Check dynamic `import()` and `require(\"pkg\")` uses.\n| Unused import (`readFileSync`) | Found |\n", encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path
    assert mdx_has_module_statements(path) is False
    path.write_text("Intro\n\n  import x from './x';\n", encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path
    assert mdx_has_module_statements(path) is True
    path.write_text("Total: {require('./x').total}\n", encoding="utf-8")  # skylos: ignore[SKY-D324] fresh pytest tmp_path
    assert mdx_has_module_statements(path) is True


def test_hygiene_abstains_without_analysed_sources(tmp_path):
    from skylos.visitors.languages.typescript.export_hygiene import (
        find_ts_export_hygiene,
    )

    report = find_ts_export_hygiene(
        [str(tmp_path / "notes.md")],
        {str(tmp_path / "main.ts"): [{"source": "./lib", "names": ["x"], "line": 1}]},
        project_root=str(tmp_path),
    )
    assert report["exports"] == [] and report["surface"] is None
    assert report["namespace_receipt"]["status"] == "not_run"
