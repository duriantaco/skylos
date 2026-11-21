"""Entries and consumers the TS dead-code checks used to miss.

Magic-comment dynamic imports, Docusaurus and SvelteKit aliases, package
entries named through conditions-only exports or built outputs, types-only
wildcard exports, jscodeshift transforms and text fixtures, SolidStart and
Nuxt conventions and Lit controller hooks. Every case keeps a genuinely dead
neighbour and requires it to stay reported.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _project(root: Path, files: dict[str, str | dict]) -> Path:
    for relative, content in files.items():
        if isinstance(content, dict):
            content = json.dumps(content)
        _write(root / relative, content)
    return root


def _scan(root: Path) -> dict:
    return json.loads(
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


def _reported(result: dict, root: Path) -> set[tuple[str, str, str]]:
    found = set()
    for key in (
        "unused_functions",
        "unused_variables",
        "unused_classes",
        "unused_imports",
        "unused_files",
        "unused_exports",
    ):
        for item in result.get(key) or []:
            rel = Path(item["file"]).resolve().relative_to(root.resolve()).as_posix()
            found.add((key, rel, item.get("name") or ""))
    return found


def _files(result: dict, root: Path) -> set[str]:
    return {name for key, name, _ in _reported(result, root) if key == "unused_files"}


APP = {"name": "app", "private": True, "type": "module", "main": "src/main.ts"}


# --- dynamic imports with a leading magic comment ---------------------------


def test_magic_comment_dynamic_import_and_require_load_their_module(tmp_path):
    _project(
        tmp_path,
        {
            "package.json": APP,
            "src/main.ts": (
                "export async function run() {\n"
                '  const m = await import(/* webpackChunkName: "chunk" */ "./chunk");\n'
                '  const r = require(/* keep */ "./required");\n'
                "  return [m.default, r];\n}\nrun();\n"
            ),
            "src/chunk.ts": "export default function chunk() { return 1; }\n",
            "src/required.ts": "module.exports = 1;\n",
            "src/orphan.ts": "export const orphan = 1;\n",
        },
    )
    assert _files(_scan(tmp_path), tmp_path) == {"src/orphan.ts"}


# --- Docusaurus @site / @theme aliases --------------------------------------


def _docusaurus_site(root: Path, *, config: bool = True) -> Path:
    files = {
        "package.json": {
            "name": "docs",
            "private": True,
            "dependencies": {"@docusaurus/core": "3"},
        },
        "src/pages/index.tsx": (
            'import Homepage from "@site/src/components/Homepage";\n'
            'import Highlight from "@site/src/components/Highlight";\n'
            "export default function Page() { return [Homepage, Highlight]; }\n"
        ),
        "src/components/Homepage/index.js": "export default function Homepage() { return 1; }\n",
        "src/components/Homepage/index.tsx": "export default function Homepage() { return 2; }\n",
        "src/components/Highlight.js": "export default function Highlight() { return 3; }\n",
        "src/components/Orphan.js": "export default function Orphan() { return 4; }\n",
    }
    if config:
        files["docusaurus.config.js"] = "module.exports = { title: 'Docs' };\n"
    return _project(root, files)


def test_docusaurus_site_alias_resolves_with_webpack_extension_order(tmp_path):
    root = _docusaurus_site(tmp_path)
    # webpack in Docusaurus tries ``.js`` before ``.tsx``: index.tsx is shadowed.
    assert _files(_scan(root), root) == {
        "src/components/Homepage/index.tsx",
        "src/components/Orphan.js",
    }


def test_site_alias_needs_a_docusaurus_config(tmp_path):
    root = _docusaurus_site(tmp_path, config=False)
    from skylos.visitors.languages.typescript.analysis import resolve_ts_module

    importer = str(root / "src/pages/index.tsx")
    assert resolve_ts_module("@site/src/components/Highlight", importer) is None
    assert resolve_ts_module("./missing", importer) is None


def test_theme_alias_resolves_only_swizzled_components(tmp_path):
    root = _project(
        tmp_path,
        {
            "docusaurus.config.ts": "export default {};\n",
            "package.json": {"name": "docs", "private": True},
            "src/theme/Footer/index.tsx": "export default function Footer() {}\n",
        },
    )
    from skylos.visitors.languages.typescript.analysis import resolve_ts_module

    importer = str(root / "src/pages/index.tsx")
    assert resolve_ts_module("@theme/Footer", importer) == str(
        root / "src/theme/Footer/index.tsx"
    )
    assert resolve_ts_module("@theme/Navbar", importer) is None


# --- SvelteKit $lib and Svelte 5 rune modules --------------------------------


def _sveltekit(root: Path, dependencies: dict) -> Path:
    return _project(
        root,
        {
            "package.json": {
                "name": "kit",
                "private": True,
                "devDependencies": dependencies,
            },
            "src/lib/stores.svelte.ts": (
                "export const errorRate = 1;\nexport const spare = 2;\n"
                "console.log(errorRate, spare);\n"
            ),
            "src/lib/api.ts": 'import { errorRate } from "$lib/stores.svelte";\nexport const api = errorRate;\n',
        },
    )


def test_sveltekit_lib_alias_reaches_rune_modules(tmp_path):
    root = _sveltekit(tmp_path, {"@sveltejs/kit": "2"})
    from skylos.visitors.languages.typescript.analysis import resolve_ts_module

    assert resolve_ts_module("$lib/stores.svelte", str(root / "src/lib/api.ts")) == str(
        root / "src/lib/stores.svelte.ts"
    )


def test_lib_alias_needs_sveltekit(tmp_path):
    root = _sveltekit(tmp_path, {"svelte": "5"})
    from skylos.visitors.languages.typescript.analysis import resolve_ts_module

    assert resolve_ts_module("$lib/stores.svelte", str(root / "src/lib/api.ts")) is None


# --- package entries: conditions-only exports, built outputs, budget ----------


def _workspace(root: Path, package: dict, files: dict) -> Path:
    return _project(
        root,
        {
            "package.json": {
                "name": "root",
                "private": True,
                "workspaces": ["packages/*", "apps/*"],
            },
            "packages/lib/package.json": package,
            **{f"packages/lib/{name}": text for name, text in files.items()},
            "apps/web/package.json": {
                "name": "web",
                "private": True,
                "main": "src/main.ts",
                "dependencies": {"lib": "workspace:*"},
            },
            "apps/web/src/main.ts": 'import { used } from "lib";\nconsole.log(used);\n',
        },
    )


LIB_INDEX = (
    "export const used = 1;\nexport const publicApi = 2;\n"
    'export { helper } from "./helper";\n'
)


def test_conditions_only_exports_object_is_the_package_root(tmp_path):
    root = _workspace(
        tmp_path,
        {
            "name": "lib",
            "exports": {
                "@lib/source": "./src/index.ts",
                "import": {
                    "types": "./build/index.d.ts",
                    "default": "./build/index.js",
                },
            },
        },
        {
            "src/index.ts": LIB_INDEX,
            "src/helper.ts": "export function helper() { return 1; }\n",
        },
    )
    from skylos.visitors.languages.typescript.resolve import _resolve_package_exports

    assert _resolve_package_exports(str(root / "packages/lib")) == str(
        root / "packages/lib/src/index.ts"
    )
    reported = _reported(_scan(root), root)
    assert not {
        item for item in reported if item[1].startswith("packages/lib/src/index")
    }


TSDOWN = (
    'import { defineConfig } from "tsdown";\n'
    'import { modernConfig } from "./shared.config.js";\n'
    'export default defineConfig([modernConfig({ entry: ["src/*.ts", "!src/*.test.ts"] })]);\n'
)


@pytest.mark.parametrize("bundler", ["tsdown.config.ts", "tsup.config.ts"])
def test_built_output_target_maps_back_to_the_bundler_entry(tmp_path, bundler):
    root = _workspace(
        tmp_path,
        {
            "name": "lib",
            "exports": {
                ".": {"import": "./build/modern/index.js"},
                "./production": {
                    "import": {
                        "types": "./build/modern/production.d.ts",
                        "default": "./build/modern/production.js",
                    }
                },
            },
        },
        {
            "src/index.ts": LIB_INDEX,
            "src/helper.ts": "export function helper() { return 1; }\n",
            "src/production.ts": "export const ProductionDevtools = 1;\n",
            "src/orphan-entry.test.ts": "export const notShipped = 1;\n",
            "src/nested/unshipped.ts": "export const unshipped = 1;\n",
            bundler: TSDOWN,
            "shared.config.js": "export function modernConfig(options) { return { ...options, outDir: 'build/modern' }; }\n",
        },
    )
    from skylos.visitors.languages.typescript.bundler_entries import built_output_source

    lib = str(root / "packages/lib")
    assert built_output_source(lib, "./build/modern/production.js") == str(
        root / "packages/lib/src/production.ts"
    )
    assert built_output_source(lib, "./build/modern/missing.js") is None
    reported = _reported(_scan(root), root)
    assert not {
        item for item in reported if "production" in item[1] or "src/index" in item[1]
    }
    assert ("unused_files", "packages/lib/src/nested/unshipped.ts", "") in reported


def test_built_output_without_a_bundler_config_stays_unmapped(tmp_path):
    root = _workspace(
        tmp_path,
        {
            "name": "lib",
            "exports": {
                ".": "./src/index.ts",
                "./production": "./build/modern/production.js",
            },
        },
        {
            "src/index.ts": LIB_INDEX,
            "src/helper.ts": "export function helper() { return 1; }\n",
            "src/production.ts": "export const ProductionDevtools = 1;\n",
        },
    )
    assert ("unused_files", "packages/lib/src/production.ts", "") in _reported(
        _scan(root), root
    )


def test_published_packages_keep_their_api_past_the_package_budget(tmp_path):
    files = {
        "package.json": {
            "name": "root",
            "private": True,
            "workspaces": ["examples/*", "packages/*"],
        },
        "packages/zlib/package.json": {
            "name": "zlib",
            "exports": {".": "./src/index.ts"},
        },
        "packages/zlib/src/index.ts": "export const publicApi = 1;\nexport const otherApi = 2;\n",
    }
    for index in range(130):
        files[f"examples/e{index:03d}/package.json"] = {
            "name": f"e{index:03d}",
            "private": True,
        }
    root = _project(tmp_path, files)
    reported = _reported(_scan(root), root)
    assert not {item for item in reported if item[1].startswith("packages/zlib")}


# --- types-only wildcard exports ---------------------------------------------


def _types_wildcard(root: Path, exports: dict) -> Path:
    return _project(
        root,
        {
            "package.json": {"name": "lib", "exports": exports},
            "tsconfig.json": {
                "compilerOptions": {
                    "rootDir": "src",
                    "outDir": "dist/types",
                    "declaration": True,
                }
            },
            "src/index.ts": 'import { value } from "./mixed";\nexport const api = value;\n',
            "src/mixed.ts": (
                "export const value = 1;\nexport const spareValue = 2;\n"
                "export type SpareType = string;\nconsole.log(spareValue);\n"
            ),
            "src/declarations.ts": "export namespace Api {\n  export interface Input { a: string }\n}\n",
            "src/valueOnly.ts": "export const Paragraph = 1;\n",
        },
    )


def test_types_only_wildcard_publishes_types_but_not_values(tmp_path):
    root = _types_wildcard(
        tmp_path,
        {".": "./src/index.ts", "./*": {"types": "./dist/types/*.d.ts"}},
    )
    reported = _reported(_scan(root), root)
    assert ("unused_files", "src/valueOnly.ts", "") in reported
    assert ("unused_files", "src/declarations.ts", "") not in reported
    assert ("unused_exports", "src/mixed.ts", "spareValue") in reported
    assert ("unused_exports", "src/mixed.ts", "SpareType") not in reported


def test_without_a_types_wildcard_unused_types_and_type_modules_are_reported(tmp_path):
    root = _types_wildcard(tmp_path, {".": "./src/index.ts"})
    reported = _reported(_scan(root), root)
    assert ("unused_files", "src/declarations.ts", "") in reported
    assert ("unused_exports", "src/mixed.ts", "SpareType") in reported


# --- jscodeshift transforms and text fixtures ---------------------------------


def _codemods(root: Path, test: str) -> Path:
    return _project(
        root,
        {
            "package.json": {
                "name": "codemods",
                "private": True,
                "devDependencies": {"jscodeshift": "17"},
            },
            "src/v5/rename/rename.cjs": 'const helper = require("../utils/helper.cjs");\nmodule.exports = (file, api) => helper(file, api);\n',
            "src/v5/utils/helper.cjs": "module.exports = function helper(file) { return file.source; };\n",
            "src/v5/rename/__tests__/rename.test.cjs": test,
            "src/v5/rename/__testfixtures__/default.input.tsx": (
                'import { useQuery } from "react-query";\n'
                "export function Example() { return useQuery(); }\n"
                "function unusedInFixture() { return 1; }\n"
            ),
            "src/v5/rename/__testfixtures__/default.output.tsx": "export const Output = 1;\n",
            "src/v5/stale/stale.cjs": "module.exports = () => null;\n",
            "src/__fixtures__/data.ts": "export const fixtureData = 1;\nexport function spare() {}\n",
        },
    )


def test_define_test_transforms_are_entries_and_fixtures_are_text(tmp_path):
    root = _codemods(
        tmp_path,
        "const defineTest = require('jscodeshift/dist/testUtils').defineTest\n"
        "defineTest(__dirname, 'rename.cjs', null, 'default', { parser: 'tsx' })\n",
    )
    reported = _reported(_scan(root), root)
    assert not {
        item
        for item in reported
        if "__testfixtures__" in item[1] or "__fixtures__" in item[1]
    }
    assert ("unused_files", "src/v5/rename/rename.cjs", "") not in reported
    assert ("unused_files", "src/v5/utils/helper.cjs", "") not in reported
    assert ("unused_files", "src/v5/stale/stale.cjs", "") in reported


def test_transform_not_named_by_a_test_stays_reported(tmp_path):
    root = _codemods(tmp_path, "test('noop', () => {})\n")
    reported = _reported(_scan(root), root)
    assert ("unused_files", "src/v5/rename/rename.cjs", "") in reported
    assert not {item for item in reported if "__testfixtures__" in item[1]}


# --- SolidStart and Nuxt conventions -------------------------------------------


SOLID_FILES = {
    "src/app.tsx": "export default function App() { return null; }\n",
    "src/entry-server.tsx": "export default function handler() { return null; }\n",
    "src/entry-client.tsx": "export default function mount() { return null; }\n",
    "src/routes/index.tsx": "export default function Home() { return null; }\nexport const route = {};\n",
    "src/orphan.ts": "export const orphan = 1;\n",
}


def test_solidstart_entries_and_routes_are_loaded_by_the_framework(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "solid",
                "private": True,
                "dependencies": {"@solidjs/start": "2"},
            },
            **SOLID_FILES,
        },
    )
    reported = _reported(_scan(root), root)
    assert {item for item in reported if item[1] != "src/orphan.ts"} == set()
    assert ("unused_files", "src/orphan.ts", "") in reported


def test_solidstart_names_need_the_dependency(tmp_path):
    root = _project(
        tmp_path, {"package.json": {"name": "solid", "private": True}, **SOLID_FILES}
    )
    assert "src/app.tsx" in _files(_scan(root), root)


NUXT_FILES = {
    "plugins/vue-query.ts": "export default function plugin() { return 1; }\n",
    "middleware/auth.ts": "export default function auth() { return 1; }\n",
    "composables/useCounter.ts": "export function useCounter() { return 1; }\nexport const counterKey = 'c';\n",
    "server/api/hello.ts": "export default function hello() { return 'hi'; }\n",
    "server/utils/db.ts": "export function db() { return 1; }\n",
    "app/plugins/v4.ts": "export default function v4() { return 1; }\n",
    "lib/orphan.ts": "export const orphan = 1;\n",
}


def test_nuxt_directories_are_loaded_by_convention(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "nuxt-app",
                "private": True,
                "dependencies": {"nuxt": "3"},
            },
            **NUXT_FILES,
        },
    )
    reported = _reported(_scan(root), root)
    assert {item for item in reported if item[1] != "lib/orphan.ts"} == set()
    assert ("unused_files", "lib/orphan.ts", "") in reported


def test_nuxt_directories_need_the_dependency(tmp_path):
    root = _project(
        tmp_path, {"package.json": {"name": "app", "private": True}, **NUXT_FILES}
    )
    assert {"plugins/vue-query.ts", "composables/useCounter.ts"} <= _files(
        _scan(root), root
    )


# --- Lit reactive controllers ---------------------------------------------------


def _controller(header: str, implements: str, register: str) -> str:
    return (
        header
        + f"export abstract class Base{implements} {{\n"
        + "  constructor(protected host: { addController(c: unknown): void }) {\n"
        + f"    {register}\n  }}\n"
        + "  hostConnected(): void {}\n  hostDisconnected(): void {}\n"
        + "  hostUpdate(): void {}\n  protected unusedHelper(): number { return 1; }\n}\n"
        + "export class Clock extends Base {\n  value = 1;\n}\n"
    )


def _lit_methods(root: Path, controller: str) -> set[str]:
    _project(
        root,
        {
            "package.json": {
                "name": "lit-app",
                "private": True,
                "main": "src/main.ts",
                "dependencies": {"lit": "3"},
            },
            "src/main.ts": 'import { Clock } from "./clock";\nconst c = new Clock({ addController() {} });\nconsole.log(c.value);\n',
            "src/clock.ts": controller,
        },
    )
    return {
        name
        for key, rel, name in _reported(_scan(root), root)
        if key == "unused_functions" and rel == "src/clock.ts"
    }


LIT_IMPORT = 'import type { ReactiveController } from "lit";\n'
HOOKS = {"hostConnected", "hostDisconnected", "hostUpdate"}


@pytest.mark.parametrize(
    ("header", "implements", "register"),
    [
        (LIT_IMPORT, " implements ReactiveController", "void host;"),
        ('import { html } from "lit";\nvoid html;\n', "", "host.addController(this);"),
    ],
)
def test_lit_controller_hooks_are_called_by_the_host(
    tmp_path, header, implements, register
):
    assert _lit_methods(tmp_path, _controller(header, implements, register)) == {
        "unusedHelper"
    }


@pytest.mark.parametrize(
    ("header", "implements", "register"),
    [
        # Same names without Lit: nothing calls them.
        ("", "", "host.addController(this);"),
        # A Lit import alone does not make a class a controller.
        (LIT_IMPORT, "", "void host;"),
    ],
)
def test_hook_names_without_a_controller_contract_stay_reported(
    tmp_path, header, implements, register
):
    assert _lit_methods(tmp_path, _controller(header, implements, register)) == {
        "unusedHelper",
        *HOOKS,
    }


# --- unit contracts ---------------------------------------------------------------


def test_call_arguments_skip_comments():
    from skylos.core.js_ast import call_arguments, first_call_argument
    from skylos.visitors.languages.typescript.core import TypeScriptCore

    core = TypeScriptCore(
        "a.ts", b'load(/* first */ "./x", /* second */ 2);\nload();\n'
    )
    calls = [
        node
        for node in core._iter_nodes(core.root_node)
        if node.type == "call_expression"
    ]
    first, empty = (call.child_by_field_name("arguments") for call in calls)
    assert core._get_text(first_call_argument(first)) == '"./x"'
    assert [core._get_text(node) for node in call_arguments(first)] == ['"./x"', "2"]
    assert first_call_argument(empty) is None and call_arguments(None) == []


def test_module_consumers_read_pages_documents_and_templates(tmp_path):
    from skylos.visitors.languages.typescript.module_consumers import (
        collect_module_consumers,
        entry_specifier,
    )

    _project(
        tmp_path,
        {
            "index.html": (
                '<!-- <script type="module" src="/src/old.ts"></script> -->\n'
                '<script type="module" src="/src/main.ts"></script>\n'
                '<script type="module">import { a } from "./src/a.ts";</script>\n'
                "<script>window.classic = 1;</script>\n"
            ),
            "docs/page.mdx": "import { b } from '../src/b';\n\n{import('../src/c')}\n",
            "src/View.marko": "import { d } from './d';\n<div/>\n",
            "src/plain.html": "<p>no scripts</p>\n",
        },
    )
    found = collect_module_consumers(tmp_path)
    assert found.complete
    page = found.consumers[str((tmp_path / "index.html").resolve())]
    assert page.entries == {"/src/main.ts"}
    assert [(item["source"], item["names"]) for item in page.imports] == [
        ("./src/a.ts", ["a"])
    ]
    doc = found.consumers[str((tmp_path / "docs/page.mdx").resolve())]
    assert [(item["source"], item["names"]) for item in doc.imports] == [
        ("../src/b", ["b"])
    ]
    assert doc.held == {"../src/c"}
    assert found.consumers[str((tmp_path / "src/View.marko").resolve())].held == {"./d"}
    assert str((tmp_path / "src/plain.html").resolve()) not in found.consumers
    assert entry_specifier("/src/main.ts?v=1") == "./src/main.ts"
    assert entry_specifier("main.ts") == "./main.ts"


def test_named_bundler_entries_map_by_key(tmp_path):
    from skylos.visitors.languages.typescript.bundler_entries import built_output_source

    _project(
        tmp_path,
        {
            "rollup.config.mjs": (
                'import html from "@rollup/plugin-html";\n'
                'export default { input: { cli: "src/bin/run.ts", index: "src/index.ts" },\n'
                '  plugins: [html({ input: "index.html" })] };\n'
            ),
            "index.html": "<html></html>\n",
            "src/bin/run.ts": "export {};\n",
            "src/index.ts": "export {};\n",
        },
    )
    root = str(tmp_path)
    assert built_output_source(root, "./dist/cli.js") == str(
        tmp_path / "src/bin/run.ts"
    )
    assert built_output_source(root, "./dist/index.d.ts") == str(
        tmp_path / "src/index.ts"
    )
    assert built_output_source(root, "./dist/run.js") is None
