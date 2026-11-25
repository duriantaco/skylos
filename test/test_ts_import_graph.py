"""JS/TS import graph: unresolved imports (SKY-Q414) and cycles (SKY-CIRC).

Synthetic projects only; fixtures are written to ``tmp_path`` and never run.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript.core import TypeScriptCore


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str], *, quality: bool = True) -> dict:
    _write_tree(root, files)
    return json.loads(
        analyze(
            str(root),
            conf=0,
            grep_verify=False,
            enable_quality=quality,
            exclude_folders=sorted(DEFAULT_EXCLUDE_FOLDERS),
        )
    )


def _relative(root: Path, file_name: str) -> str:
    return Path(file_name).resolve().relative_to(root.resolve()).as_posix()


def _unresolved(root: Path, result: dict) -> set[tuple[str, int, str]]:
    return {
        (_relative(root, item["file"]), item["line"], item["name"])
        for item in result.get("quality", [])
        if item.get("rule_id") == "SKY-Q414"
    }


def _cycles(result: dict) -> list[list[str]]:
    return [
        item["cycle"]
        for item in result.get("circular_dependencies", [])
        if any(part.endswith((".ts", ".js", ".vue", ".tsx")) for part in item["cycle"])
    ]


def _raw(source: str, name: str = "/project/src/x.ts") -> list[dict]:
    core = TypeScriptCore(name, source.encode("utf-8"))
    core.scan()
    return core.raw_imports


# -- module request tagging ---------------------------------------------------


def test_literal_module_requests_carry_their_kind():
    records = {
        item["source"]: item
        for item in _raw(
            "import type {A} from './a';\n"
            "import {type B, type C} from './b';\n"
            "import D, {type E} from './d';\n"
            "export type {F} from './f';\n"
            "export * from './h';\n"
            "const j = require('./j');\n"
            "try { require('./k') } catch {}\n"
            "function f() { return require('./l') }\n"
            "import('./m').catch(() => {});\n"
            "const o = await import('./o');\n"
            "import {} from './p';\n"
            "require.resolve('./q');\n"
            "const r = require(['./r']);\n"
        )
    }
    assert records["./a"]["import_kind"] == "import" and records["./a"]["type_import"]
    assert records["./b"]["type_import"]
    assert "type_import" not in records["./d"]
    assert records["./f"]["import_kind"] == "reexport" and records["./f"]["type_import"]
    assert "type_import" not in records["./h"]
    assert records["./j"]["import_kind"] == "require"
    assert records["./k"]["guarded_import"]
    assert records["./l"]["deferred_import"]
    assert records["./m"]["import_kind"] == "dynamic" and records["./m"]["guarded_import"]
    assert "guarded_import" not in records["./o"]
    assert "type_import" not in records["./p"]
    # resolve calls and computed arguments are not literal module requests.
    assert "import_kind" not in records["./q"]
    assert "import_kind" not in records["./r"]


# -- SKY-Q414 unresolved imports --------------------------------------------------


def test_unresolved_relative_alias_and_package_import_requests_are_reported(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps(
                {"name": "app", "imports": {"#lib/*": "./src/lib/*.ts"}}
            ),
            "tsconfig.json": json.dumps(
                {"compilerOptions": {"paths": {"@/*": ["./src/*"]}}}
            ),
            "src/lib/ok.ts": "export const ok = 1;\n",
            "src/index.ts": (
                "import { ok } from './lib/ok';\n"
                "import missing from './missing';\n"
                "import { alias } from '@/gone';\n"
                "import { pkg } from '#lib/nothing';\n"
                "export { again } from '../src/absent';\n"
                "const legacy = require('./old');\n"
                "const lazy = () => import('./later');\n"
                "console.log(ok, missing, alias, pkg, legacy, lazy);\n"
            ),
        },
    )
    assert _unresolved(tmp_path, result) == {
        ("src/index.ts", 2, "./missing"),
        ("src/index.ts", 3, "@/gone"),
        ("src/index.ts", 4, "#lib/nothing"),
        ("src/index.ts", 5, "../src/absent"),
        ("src/index.ts", 6, "./old"),
        ("src/index.ts", 7, "./later"),
    }
    finding = next(
        item for item in result["quality"] if item.get("name") == "@/gone"
    )
    assert finding["severity"] == "MEDIUM"
    assert "tsconfig paths alias '@/*'" in finding["message"]
    assert result["analysis_summary"]["unresolved_import_analysis"]["reported"] == 6


def test_component_script_requests_are_checked_in_their_own_file(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "src/main.ts": "import App from './App.vue';\nconsole.log(App);\n",
            "src/App.vue": (
                "<template><div /></template>\n"
                '<script setup lang="ts">\n'
                "import Child from './Child.vue';\n"
                "import { helper } from './helpers';\n"
                "</script>\n"
            ),
            "src/Card.svelte": (
                "<script>\n  import { gone } from './gone.js';\n</script>\n"
            ),
        },
    )
    assert _unresolved(tmp_path, result) == {
        ("src/App.vue", 3, "./Child.vue"),
        ("src/App.vue", 4, "./helpers"),
        ("src/Card.svelte", 2, "./gone.js"),
    }


def test_project_resolution_rules_keep_existing_targets_quiet(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "name": "app",
                    "dependencies": {"react-native": "0.74.0"},
                    "imports": {"#util": "./dist/util.js", "#dep": "some-package"},
                }
            ),
            "tsconfig.json": json.dumps(
                {
                    "compilerOptions": {
                        "allowImportingTsExtensions": True,
                        "paths": {"@/*": ["./src/*"], "~lib": ["./src/lib/index"]},
                    }
                }
            ),
            "src/util.ts": "export const util = 1;\n",
            "src/ts-source.ts": "export const a = 1;\n",
            "src/esm.mts": "export const b = 1;\n",
            "src/typed.d.ts": "export declare const c: number;\n",
            "src/View.vue": "<template><div /></template>\n",
            "src/Widget.svelte": "<div />\n",
            "src/Page.astro": "<div />\n",
            "src/data.json": "{}\n",
            "src/logo.svg": "<svg />\n",
            "src/styles.css": "a {}\n",
            "src/scale.ios.ts": "export const scale = 1;\n",
            "src/folder/index.tsx": "export const d = 1;\n",
            "src/pkg/package.json": json.dumps({"main": "./build/out.js"}),
            "src/lib/index.ts": "export const lib = 1;\n",
            "src/index.ts": (
                "import { a } from './ts-source.js';\n"
                "import { b } from './esm.mjs';\n"
                "import { c } from './typed';\n"
                "import { c as c2 } from './typed.js';\n"
                "import View from './View.vue';\n"
                "import Widget from './Widget';\n"
                "import Page from './Page';\n"
                "import data from './data';\n"
                "import logo from './logo.svg';\n"
                "import './styles.css';\n"
                "import { scale } from './scale';\n"
                "import { d } from './folder';\n"
                "import pkg from './pkg';\n"
                "import { a as a2 } from './ts-source.ts';\n"
                "import { a as a3 } from '@/ts-source';\n"
                "import { lib } from '~lib';\n"
                "import { util } from '#util';\n"
                "import dep from '#dep';\n"
                "import raw from './missing.txt?raw';\n"
                "import url from './gone.png?url';\n"
                "import pwa from 'virtual:pwa-register';\n"
                "import Icon from '~icons/mdi/home';\n"
                "import { getCollection } from 'astro:content';\n"
                "import { page } from '$app/stores';\n"
                "import { SECRET } from '$env/static/private';\n"
                "import nuxt from '#imports';\n"
                "import lodash from 'lodash-not-installed';\n"
                "import { built } from './dist/generated';\n"
                "import { outside } from '../../outside-project';\n"
                "try { require('./optional-config'); } catch {}\n"
                "import('./optional-chunk').catch(() => null);\n"
                "console.log(a, b, c, c2, View, Widget, Page, data, logo, scale, d,\n"
                "  pkg, a2, a3, lib, util, dep, raw, url, pwa, Icon, getCollection,\n"
                "  page, SECRET, nuxt, lodash, built, outside);\n"
            ),
        },
    )
    assert _unresolved(tmp_path, result) == set()


def test_tsconfig_paths_follow_typescript_extends_semantics(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "tsconfig.base.json": json.dumps(
                {"compilerOptions": {"paths": {"@old/*": ["./legacy/*"]}}}
            ),
            # The child's own paths replace the base's paths entirely.
            "tsconfig.json": json.dumps(
                {
                    "extends": "./tsconfig.base.json",
                    "compilerOptions": {"paths": {"@/*": ["./src/*"]}},
                }
            ),
            "packages/lib/tsconfig.base.json": json.dumps(
                {"compilerOptions": {"paths": {"#shared/*": ["./shared/*"]}}}
            ),
            # Inherited paths without a baseUrl stay relative to their config.
            "packages/lib/app/tsconfig.json": json.dumps(
                {
                    "extends": "../tsconfig.base.json",
                    "compilerOptions": {"baseUrl": "./src"},
                }
            ),
            # ``${configDir}`` is the directory of the config in use.
            "configs/tsconfig.shared.json": json.dumps(
                {"compilerOptions": {"paths": {"~web/*": ["${configDir}/src/*"]}}}
            ),
            "apps/web/tsconfig.json": json.dumps(
                {"extends": "../../configs/tsconfig.shared.json"}
            ),
            "apps/web/src/page.ts": "export const page = 1;\n",
            "apps/web/src/main.ts": (
                "import { page } from '~web/page';\nimport gone from '~web/gone';\n"
                "console.log(page, gone);\n"
            ),
            "packages/lib/shared/util.ts": "export const util = 1;\n",
            "packages/lib/app/src/main.ts": (
                "import { util } from '#shared/util';\nconsole.log(util);\n"
            ),
            "src/index.ts": (
                "import a from '@old/missing';\nimport b from '@/missing';\n"
                "console.log(a, b);\n"
            ),
        },
    )
    assert _unresolved(tmp_path, result) == {
        ("src/index.ts", 2, "@/missing"),
        ("apps/web/src/main.ts", 2, "~web/gone"),
    }


def test_bundler_aliases_hold_back_only_their_prefixes(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "tsconfig.json": json.dumps(
                {"compilerOptions": {"paths": {"@/*": ["./src/*"], "~/*": ["./src/*"]}}}
            ),
            "vite.config.ts": (
                "import { defineConfig } from 'vite';\n"
                "export default defineConfig({\n"
                "  resolve: { alias: { '@': '/elsewhere' } },\n"
                "});\n"
            ),
            "src/index.ts": (
                "import a from '@/by-vite';\n"
                "import b from '~/missing';\n"
                "import c from './missing';\n"
                "console.log(a, b, c);\n"
            ),
        },
    )
    assert _unresolved(tmp_path, result) == {
        ("src/index.ts", 2, "~/missing"),
        ("src/index.ts", 3, "./missing"),
    }


def test_unreadable_bundler_alias_holds_back_alias_requests_in_its_scope(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "tsconfig.json": json.dumps(
                {"compilerOptions": {"paths": {"~/*": ["./src/*"]}}}
            ),
            "aliases.json": "{}\n",
            "webpack.config.js": (
                "const aliases = require('./aliases.json');\n"
                "module.exports = { resolve: { alias: aliases } };\n"
            ),
            "src/index.ts": (
                "import b from '~/missing';\nimport c from './missing';\n"
                "console.log(b, c);\n"
            ),
        },
    )
    assert _unresolved(tmp_path, result) == {("src/index.ts", 2, "./missing")}


def test_ambient_module_declarations_hold_back_matching_specifiers(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "tsconfig.json": json.dumps(
                {"compilerOptions": {"paths": {"@/*": ["./src/*"]}}}
            ),
            "src/env.d.ts": (
                "declare module '*.svg' { const url: string; export default url; }\n"
                "declare module '@/generated/client';\n"
            ),
            # Only declarations count, not the same words in a comment.
            "src/notes.ts": (
                "// a `declare module '*.png'` shim would hide this\n"
                "export const notes = 1;\n"
            ),
            "src/index.ts": (
                "import logo from './missing.svg';\n"
                "import client from '@/generated/client';\n"
                "import gone from './missing.png';\n"
                "console.log(logo, client, gone);\n"
            ),
        },
    )
    assert _unresolved(tmp_path, result) == {("src/index.ts", 3, "./missing.png")}


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_git_ignored_generated_targets_stay_quiet(tmp_path):
    _write_tree(
        tmp_path,
        {
            ".gitignore": "src/__generated__/\n*.gen.ts\n",
            "package.json": json.dumps({"name": "app"}),
            "src/index.ts": (
                "import { gql } from './__generated__/graphql';\n"
                "import { routes } from './routeTree.gen';\n"
                "import { gone } from './gone';\n"
                "console.log(gql, routes, gone);\n"
            ),
        },
    )
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    result = _scan(tmp_path, {})
    assert _unresolved(tmp_path, result) == {("src/index.ts", 3, "./gone")}


def test_type_only_requests_and_generated_config_aliases_stay_quiet(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app", "main": "src/routes/+page.ts"}),
            "tsconfig.json": json.dumps(
                {
                    "extends": "./.svelte-kit/tsconfig.json",
                    "compilerOptions": {"paths": {"@/*": ["./src/*"]}},
                }
            ),
            "src/routes/+page.ts": (
                "import type { PageLoad } from './$types';\n"
                "import { value } from './missing';\n"
                "import { other } from '@/gone';\n"
                "export const load: import('./$types').PageLoad = () => [value, other];\n"
                "export type { Gone } from './gone-types';\n"
                "import { type Only } from './only-types';\n"
                "export const typed: Only | null = null;\n"
            ),
        },
    )
    assert _unresolved(tmp_path, result) == {
        ("src/routes/+page.ts", 2, "./missing")
    }


def test_fixture_template_and_test_input_files_stay_quiet(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "test/__fixtures__/broken.ts": "import x from './missing';\nconsole.log(x);\n",
            "src/codemod/__testfixtures__/input.ts": "import y from '../gone';\n",
            "scripts/templates/errors.js": "import { z } from './internal/gone.js';\n",
            # Compiler/plugin inputs read as text by a test, imported by nothing.
            "packages/plugin/test/Input.svelte": (
                "<script>\n  import logo from './no.png';\n</script>\n"
            ),
            "packages/plugin/test/plugin.spec.ts": (
                "import { helper } from './helper';\nimport gone from './gone';\n"
                "console.log(helper, gone);\n"
            ),
            "packages/plugin/test/helper.ts": (
                "import missing from './missing-helper';\nexport const helper = missing;\n"
            ),
            "src/index.ts": (
                "import x from './missing'; // skylos: ignore[SKY-Q414] restored in CI\n"
                "console.log(x);\n"
            ),
        },
    )
    # Test files and test-directory modules that something imports still count.
    assert _unresolved(tmp_path, result) == {
        ("packages/plugin/test/plugin.spec.ts", 2, "./gone"),
        ("packages/plugin/test/helper.ts", 1, "./missing-helper"),
    }
    assert any(
        item.get("rule_id") == "SKY-Q414" for item in result.get("suppressed", [])
    )


def test_unresolved_imports_need_quality_and_respect_ignore(tmp_path):
    files = {
        "package.json": json.dumps({"name": "app"}),
        "src/index.ts": "import x from './missing';\nconsole.log(x);\n",
    }
    assert _unresolved(tmp_path, _scan(tmp_path, files, quality=False)) == set()
    files["pyproject.toml"] = '[tool.skylos]\nignore = ["SKY-Q414"]\n'
    assert _unresolved(tmp_path, _scan(tmp_path, files)) == set()


# -- SKY-CIRC for JS/TS ----------------------------------------------------------


def test_runtime_import_cycle_is_reported_once_per_component(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "src/a.ts": (
                "import { b } from './b';\nimport './b';\nexport const a = () => b;\n"
            ),
            "src/b.ts": (
                "import { a } from './a';\nimport { c } from './c';\n"
                "export const b = () => [a, c];\n"
            ),
            "src/c.ts": "import { b } from './b';\nexport const c = () => b;\n",
            "src/index.ts": "import { a } from './a';\nconsole.log(a);\n",
        },
        quality=False,
    )
    findings = [
        item
        for item in result.get("circular_dependencies", [])
        if item["cycle"] and item["cycle"][0].endswith(".ts")
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "SKY-CIRC"
    assert finding["severity"] == "LOW"
    assert finding["cycle"] == ["src/a.ts", "src/b.ts"]
    assert finding["cycle_length"] == 2
    assert finding["component_files"] == ["src/a.ts", "src/b.ts", "src/c.ts"]
    assert finding["cycle_edges"] == [
        ["src/a.ts", "src/b.ts"],
        ["src/b.ts", "src/a.ts"],
        ["src/b.ts", "src/c.ts"],
        ["src/c.ts", "src/b.ts"],
    ]
    assert [
        (_relative(tmp_path, site["file"]), site["start_line"], site["end_line"])
        for site in finding["related_locations"]
    ] == [
        ("src/a.ts", 1, 1),
        ("src/a.ts", 2, 2),
        ("src/b.ts", 1, 1),
        ("src/b.ts", 2, 2),
        ("src/c.ts", 1, 1),
    ]
    assert finding["message"] == (
        "Circular dependency: src/a.ts → src/b.ts → src/a.ts"
    )
    assert _relative(tmp_path, finding["file"]) == "src/a.ts"
    assert finding["line"] == 1


@pytest.mark.parametrize(
    ("specifier", "cyclic_suffix", "expected"),
    [
        ("$lib/runtime.js", "js", [["src/lib/runtime.js", "src/routes/+page.js"]]),
        ("../lib/runtime.js", "ts", []),
    ],
)
def test_sveltekit_cycles_follow_the_proved_runtime_file(
    tmp_path, specifier, cyclic_suffix, expected
):
    providers = {suffix: "export const helper = () => 1;" for suffix in ("js", "ts")}
    providers[cyclic_suffix] = (
        "import { load } from '../routes/+page.js';\n"
        "export const helper = () => typeof load;\n"
    )
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "name": "app",
                    "private": True,
                    "type": "module",
                    "devDependencies": {"@sveltejs/kit": "^2.55.0"},
                }
            ),
            "svelte.config.js": "export default { kit: {} };\n",
            "vite.config.js": (
                "import { sveltekit } from '@sveltejs/kit/vite';\n"
                "export default { plugins: [sveltekit()] };\n"
            ),
            "src/routes/+page.js": (
                f"import {{ helper }} from '{specifier}';\n"
                "export const load = () => ({ value: typeof helper });\n"
            ),
            **{f"src/lib/runtime.{suffix}": text for suffix, text in providers.items()},
        },
        quality=False,
    )
    assert _cycles(result) == expected


def test_reexport_require_and_component_cycles_are_reported(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "src/barrel.ts": "export * from './leaf';\nexport const barrel = 1;\n",
            "src/leaf.ts": "import { barrel } from './barrel';\nexport const leaf = barrel;\n",
            "lib/one.js": "const two = require('./two');\nmodule.exports = two;\n",
            "lib/two.js": "const one = require('./one');\nmodule.exports = one;\n",
            "ui/store.ts": "import Panel from './Panel.vue';\nexport const store = Panel;\n",
            "ui/Panel.vue": (
                '<script setup lang="ts">\nimport { store } from "./store";\n</script>\n'
            ),
        },
        quality=False,
    )
    assert sorted(_cycles(result)) == [
        ["lib/one.js", "lib/two.js"],
        ["src/barrel.ts", "src/leaf.ts"],
        ["ui/Panel.vue", "ui/store.ts"],
    ]


def test_type_only_lazy_and_self_imports_do_not_form_cycles(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "src/t1.ts": "import type { T2 } from './t2';\nexport type T1 = T2;\n",
            "src/t2.ts": "import { type T1 } from './t1';\nexport type T2 = T1 | 1;\n",
            "src/e1.ts": "export type { E2 } from './e2';\nexport type E1 = 1;\n",
            "src/e2.ts": "import { e1 } from './e1';\nexport type E2 = 2;\nexport const x = e1;\n",
            "src/d1.ts": "import { d2 } from './d2';\nexport const d1 = d2;\n",
            "src/d2.ts": "export const d2 = () => import('./d1');\n",
            "lib/r1.js": "const r2 = require('./r2');\nmodule.exports = r2;\n",
            "lib/r2.js": "module.exports = () => require('./r1');\n",
            "src/self.ts": "import * as self from './self';\nexport const s = self;\n",
            "src/types.d.ts": (
                "import { helper } from './helper';\n"
                "export declare const x: typeof helper;\n"
            ),
            "src/helper.ts": "import './types.d.ts';\nexport const helper = 1;\n",
        },
        quality=False,
    )
    assert _cycles(result) == []


def test_typescript_cycles_follow_check_circular(tmp_path):
    result = _scan(
        tmp_path,
        {
            "package.json": json.dumps({"name": "app"}),
            "pyproject.toml": "[tool.skylos]\ncheck_circular = false\n",
            "src/a.ts": "import { b } from './b';\nexport const a = b;\n",
            "src/b.ts": "import { a } from './a';\nexport const b = () => a;\n",
        },
        quality=False,
    )
    assert _cycles(result) == []
