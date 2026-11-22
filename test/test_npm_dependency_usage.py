"""Npm package ownership, source/config use, and script-only tools."""

import json
from pathlib import Path

import pytest

from skylos.rules.quality import npm_dependencies as npm


def _write(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")  # skylos: ignore[SKY-D324] every caller uses a fresh pytest tmp_path
    return path


def _package(root, data, relative="package.json"):
    return _write(root, relative, json.dumps(data, indent=2))


def _scan(root, *files, **kwargs):
    receipt = {}
    findings = npm.scan_npm_dependencies(root, files, coverage=receipt, **kwargs)
    return findings, receipt


def _names(findings, rule):
    return {item["name"] for item in findings if item["rule_id"] == rule}


def test_source_imports_and_subpaths_leave_only_unused_dependency(tmp_path):
    _package(tmp_path, {"dependencies": {"axios": "1", "@acme/tools": "1", "unused": "1"}})
    source = _write(tmp_path, "src/app.ts", 'import axios from "axios";\nexport {x} from "@acme/tools/api";\nimport "node:fs";\nconsole.log(axios);\n')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert receipt["complete"] is True


@pytest.mark.parametrize("source", ['import {x} from "missing/subpath";', 'const x = require("missing/subpath");', 'const x = import("missing/subpath");', 'import type {X} from "missing/subpath";'])
def test_literal_unlisted_dependency_is_reported_at_source(tmp_path, source):
    _package(tmp_path, {"name": "demo", "dependencies": {}})
    path = _write(tmp_path, "app.ts", source)
    findings, _ = _scan(tmp_path, path)
    assert _names(findings, npm.RULE_UNLISTED) == {"missing"}
    item = next(item for item in findings if item["rule_id"] == npm.RULE_UNLISTED)
    assert item["file"] == str(path) and item["line"] == 1


def test_package_scripts_keep_command_only_dependency_without_import(tmp_path):
    _package(tmp_path, {"devDependencies": {"typescript": "1", "vite": "1", "unused": "1"}, "scripts": {"build": "tsc --noEmit && vite build"}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is True


def test_known_npm_binary_without_provider_is_unlisted(tmp_path):
    _package(tmp_path, {"scripts": {"build": "tsc --noEmit"}})
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_BINARY) == {"tsc"}
    assert findings[0]["metadata"]["package_name"] == "typescript"


@pytest.mark.parametrize("command", ["node $RUNNER", "bash -c 'tool build'", "npx -p possibly-used run", "if [ -f x ]; then tool; fi", "yarn workspace web build"])
def test_unknown_or_expanded_script_blocks_unused_claims(tmp_path, command):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}, "scripts": {"build": command}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is False
    assert receipt["abstained_count"] == 1


def test_plugin_config_and_executable_config_imports_count_as_usage(tmp_path):
    _package(tmp_path, {"devDependencies": {"eslint-plugin-react": "1", "@babel/preset-env": "1", "@vitejs/plugin-react": "1", "spare": "1"}, "eslintConfig": {"plugins": ["react"]}, "babel": {"presets": ["@babel/env"]}})
    config = _write(tmp_path, "vite.config.ts", 'import react from "@vitejs/plugin-react"; export default {plugins:[react()]};')
    findings, receipt = _scan(tmp_path, config)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert receipt["complete"] is True


def test_eslint_json_plugin_config_is_a_source_consumer(tmp_path):
    _package(tmp_path, {"devDependencies": {"eslint-plugin-react": "1", "unused": "1"}})
    _write(tmp_path, ".eslintrc.json", '{"plugins": ["react"]}')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


def test_workspace_import_ownership_and_shared_root_tooling(tmp_path):
    _package(tmp_path, {"name": "root", "workspaces": ["packages/*"], "devDependencies": {"typescript": "1", "shared-lib": "1"}})
    _package(tmp_path, {"name": "web", "dependencies": {"local-lib": "1", "own-unused": "1"}, "scripts": {"typecheck": "tsc --noEmit"}}, "packages/web/package.json")
    source = _write(tmp_path, "packages/web/app.ts", 'import "shared-lib"; import "local-lib";')
    findings, receipt = _scan(tmp_path, source)
    unused = {(Path(item["file"]).relative_to(tmp_path).as_posix(), item["name"]) for item in findings if item["rule_id"] == npm.RULE_UNUSED}
    # The root declaration is what resolves the import.
    assert unused == {("packages/web/package.json", "own-unused")}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert receipt["ancestor_declared_production_imports"] == 1
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is True
    # Strict mode: published source needs its own declaration for consumers.
    findings, receipt = _scan(tmp_path, source, strict=True)
    assert _names(findings, npm.RULE_UNLISTED) == {"shared-lib"}
    item = next(item for item in findings if item["rule_id"] == npm.RULE_UNLISTED)
    assert item["metadata"]["ancestor_manifest"] == str(tmp_path / "package.json")
    assert receipt["strict"] is True


@pytest.mark.parametrize("source", ['const p = import(packageName);', 'const p = require(packageName);', 'const load = require; load(packageName);', 'const load = createRequire(import.meta.url); load("possibly-used");'])
def test_unresolved_loaders_abstain_instead_of_hiding_missing_use(tmp_path, source):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    path = _write(tmp_path, "app.ts", source)
    findings, receipt = _scan(tmp_path, path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_missing_source_inventory_does_not_establish_absence(tmp_path):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    _write(tmp_path, "unselected.ts", 'import "possibly-used";')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_unselected_component_declines_absence(tmp_path):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    _write(tmp_path, "App.vue", '<script setup>import x from "possibly-used";</script>')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_peer_and_ambient_type_contracts_do_not_require_runtime_import(tmp_path):
    _package(tmp_path, {"peerDependencies": {"react": "1"}, "devDependencies": {"@types/node": "1", "unused": "1"}})
    source = _write(tmp_path, "src/env.ts", "export const mode = process.env.NODE_ENV;")
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}


def test_tsconfig_alias_is_not_an_unlisted_package(tmp_path):
    _package(tmp_path, {"dependencies": {}})
    _write(tmp_path, "tsconfig.json", '{"compilerOptions":{"baseUrl":".","paths":{"@app/*":["src/*"]}}}')
    module = _write(tmp_path, "src/helper.ts", 'export const value=1;')
    source = _write(tmp_path, "app.ts", 'import {value} from "@app/helper"; console.log(value);')
    findings, receipt = _scan(tmp_path, source, module)
    assert findings == []
    assert receipt["complete"] is True


def test_installed_literal_bin_metadata_can_map_nonmatching_name(tmp_path):
    _package(tmp_path, {"devDependencies": {"some-cli-provider": "1", "unused": "1"}, "scripts": {"build": "compile-assets"}})
    _write(tmp_path, "node_modules/some-cli-provider/package.json", '{"bin":{"compile-assets":"bin/main.js"}}')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


def test_partial_scope_disables_only_absence_diagnostics(tmp_path):
    _package(tmp_path, {"dependencies": {"unused": "1"}})
    source = _write(tmp_path, "app.ts", 'import "unlisted";')
    findings, receipt = _scan(tmp_path, source, complete_scope=False)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert _names(findings, npm.RULE_UNLISTED) == {"unlisted"}
    assert receipt["complete"] is False


def test_jsdoc_import_type_is_usage_but_prose_is_not(tmp_path):
    _package(tmp_path, {"dependencies": {"typed-api": "1", "comment-only": "1"}})
    source = _write(tmp_path, "app.js", '/** @type {import("typed-api").Response} */\nlet response;\n// import "comment-only"\nconsole.log(response);')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"comment-only"}
    assert receipt["complete"] is True


def test_tsconfig_plugin_and_extends_are_usage(tmp_path):
    _package(tmp_path, {"devDependencies": {"@tsconfig/node20": "1", "ts-plugin": "1", "unused": "1"}})
    _write(tmp_path, "tsconfig.json", '{// compiler configuration\n"extends":"@tsconfig/node20/tsconfig.json", "compilerOptions":{"plugins":[{"name":"ts-plugin"}],},}')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


def test_prettier_plugin_is_config_usage(tmp_path):
    _package(tmp_path, {"devDependencies": {"prettier-plugin-example": "1", "unused": "1"}})
    _write(tmp_path, ".prettierrc.json", '{"plugins":["prettier-plugin-example"]}')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


def test_unmodelled_tool_config_abstains_instead_of_dropping_plugins(tmp_path):
    _package(tmp_path, {"devDependencies": {"possibly-configured": "1", "jest-watch-typeahead": "1", "unrelated": "1"}, "jest": {"preset": "possibly-configured", "watchPlugins": [["./local-plugin.js"]]}})
    findings, receipt = _scan(tmp_path)
    # Named packages are read; only jest-family packages stay unresolved.
    assert _names(findings, npm.RULE_UNUSED) == {"unrelated"}
    assert receipt["complete"] is False
    assert [item["name"] for item in receipt["abstained_dependencies"]] == ["jest-watch-typeahead"]


def test_unreadable_nested_manifest_cannot_hide_root_tooling_consumer(tmp_path):
    _package(tmp_path, {"devDependencies": {"possibly-used": "1"}})
    _write(tmp_path, "packages/broken/package.json", '{')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_source_directory_symlink_is_not_followed_or_labelled_clean(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "app.ts", 'import "possibly-used";')
    _package(root, {"dependencies": {"possibly-used": "1"}})
    (root / "linked").symlink_to(outside, target_is_directory=True)
    findings, receipt = _scan(root)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_package_import_map_keeps_external_target_dependency(tmp_path):
    _package(tmp_path, {"dependencies": {"mapped-provider": "1", "unused": "1"}, "imports": {"#client": {"node": "mapped-provider", "default": "./local.js"}}})
    source = _write(tmp_path, "app.ts", 'import client from "#client"; console.log(client);')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert receipt["complete"] is True


def test_source_walk_budget_abstains_for_absence(tmp_path, monkeypatch):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    _write(tmp_path, "one.txt", "data")
    monkeypatch.setattr(npm, "MAX_WALK_ENTRIES", 1)
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_script_with_same_name_as_binary_does_not_hide_tool_use(tmp_path):
    _package(tmp_path, {"devDependencies": {"vite": "1", "unused": "1"}, "scripts": {"vite": "vite build", "build": "yarn vite"}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


def test_node_preload_is_actual_package_usage(tmp_path):
    _package(tmp_path, {"devDependencies": {"esm": "1", "unused": "1"}, "scripts": {"start": "node --require esm app.js"}})
    source = _write(tmp_path, "app.js", 'console.log("hello");')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


def test_unknown_ci_and_unselected_stylesheet_consumers_decline_unused_claims(tmp_path):
    _package(tmp_path, {"devDependencies": {"possibly-used": "1"}})
    _write(tmp_path, ".github/workflows/test.yml", "jobs: {}")
    _write(tmp_path, "style.css", '@import "possibly-used";')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def _analyse(root, **kwargs):
    from skylos.analyzer import analyze

    return json.loads(analyze(str(root), conf=0, grep_verify=False, enable_quality=True,
        enable_danger=False, enable_secrets=False, enable_ai_defects=False,
        enable_dependency_hallucinations=False, enable_sca=False, **kwargs))


def test_analysis_wires_npm_quality_findings_and_receipt(tmp_path):
    _package(tmp_path, {"private": True, "main": "app.ts", "dependencies": {"used": "1", "unused": "1"}, "scripts": {"build": "tsc"}})
    _write(tmp_path, "app.ts", 'import "used"; import "unlisted";')
    result = _analyse(tmp_path)
    findings = result.get("quality", [])
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_UNLISTED) == {"unlisted"}
    assert _names(findings, npm.RULE_BINARY) == {"tsc"}
    assert result["analysis_summary"]["npm_dependency_analysis"]["complete"] is True


def test_analysis_honours_project_ignores_for_npm_rules(tmp_path):
    _package(tmp_path, {"private": True, "main": "app.ts", "dependencies": {"unused": "1"}, "scripts": {"build": "tsc"}})
    _write(tmp_path, "app.ts", 'import "unlisted";')
    _write(tmp_path, "pyproject.toml", '[tool.skylos]\nignore=["SKY-U005", "SKY-Q408", "SKY-Q409"]\n')
    result = _analyse(tmp_path)
    assert not {item.get("rule_id") for item in result.get("quality", [])} & {npm.RULE_UNUSED, npm.RULE_UNLISTED, npm.RULE_BINARY}


def test_analysis_honours_inline_ignore_for_unlisted_source_import(tmp_path):
    _package(tmp_path, {"private": True, "main": "app.ts"})
    _write(tmp_path, "app.ts", 'import "unlisted"; // skylos: ignore[SKY-Q408]\n')
    result = _analyse(tmp_path)
    assert _names(result.get("quality", []), npm.RULE_UNLISTED) == set()
    assert any(item.get("rule_id") == npm.RULE_UNLISTED for item in result.get("suppressed", []))


def test_pnpm_script_and_binary_shorthand_is_resolved_without_execution(tmp_path):
    _package(tmp_path, {"devDependencies": {"vitest": "1", "unused": "1"}, "scripts": {"build": "node build.js", "prepack": "pnpm build", "test": "pnpm vitest run", "release": "pnpm build && pnpm publish"}})
    source = _write(tmp_path, "build.js", 'console.log("build");')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is True


def _virtual_css_project(root, config, *, declared=True):
    _package(root, {"devDependencies": {"unocss": "1", "vite": "1", "vitest": "1"} if declared else {"vite": "1"}})
    config_path = _write(root, "vite.config.ts", config)
    source = _write(root, "app.ts", 'import "uno.css"; import "missing.css";')
    return _scan(root, config_path, source)


@pytest.mark.parametrize("wrapper", ["defineConfig", "testConfig"])
def test_generated_css_alias_requires_actual_configured_plugin(tmp_path, wrapper):
    config = f'import UnoCSS from "unocss/vite"; import {{defineConfig as {wrapper}}} from "vitest/config"; export default {wrapper}({{plugins:[UnoCSS()]}});'
    findings, receipt = _virtual_css_project(tmp_path, config)
    assert _names(findings, npm.RULE_UNLISTED) == {"missing.css"}
    assert receipt["complete"] is True


@pytest.mark.parametrize("config", [
    'import UnoCSS from "unocss/vite"; export default {plugins:[]};',
    'function UnoCSS(){return {name:"fake"}}; export default {plugins:[UnoCSS()]};',
    'import UnoCSS from "other/vite"; export default {plugins:[UnoCSS()]};',
    'import UnoCSS from "unocss/vite"; export default {plugins:[UnoCSS()], plugins:[]};',
    'import UnoCSS from "unocss/vite"; function defineConfig(x){return {plugins:[]}}; export default defineConfig({plugins:[UnoCSS()]});',
    'import UnoCSS from "unocss/vite"; const config={plugins:[UnoCSS()]}; export default {...config,plugins:[]};',
])
def test_generated_css_lookalikes_do_not_hide_unlisted_package(tmp_path, config):
    findings, _ = _virtual_css_project(tmp_path, config)
    assert {"uno.css", "missing.css"} <= _names(findings, npm.RULE_UNLISTED)


def test_generated_css_requires_declared_provider(tmp_path):
    findings, _ = _virtual_css_project(tmp_path, 'import UnoCSS from "unocss/vite"; export default {plugins:[UnoCSS()]};', declared=False)
    assert {"unocss", "uno.css", "missing.css"} <= _names(findings, npm.RULE_UNLISTED)


def test_renamed_create_require_import_cannot_hide_runtime_usage(tmp_path):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    source = _write(tmp_path, "app.ts", 'import {createRequire as custom} from "node:module"; const load=custom(import.meta.url); load("possibly-used");')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_typescript_reference_directive_is_type_usage(tmp_path):
    _package(tmp_path, {"devDependencies": {"vitest": "1", "vite": "1", "unused": "1"}})
    source = _write(tmp_path, "app.ts", '/// <reference types="vitest" />\n/// <reference types="vite/client" />\nexport {};')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert receipt["complete"] is True


def test_typescript_reference_to_undeclared_package_is_unlisted(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {}})
    source = _write(tmp_path, "react-app-env.d.ts", '/// <reference types="react-scripts" />\n/// <reference types="node" />\n')
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNLISTED) == {"react-scripts"}
    item = next(item for item in findings if item["rule_id"] == npm.RULE_UNLISTED)
    assert item["file"] == str(source) and item["line"] == 1


# Component, MDX and stylesheet sources are read when the caller selects them.

@pytest.mark.parametrize("relative, content", [
    ("src/App.vue", '<script setup lang="ts">\nimport Chart from "chart-lib";\n</script>\n<template><p>import "unused"</p></template>\n'),
    ("src/Widget.svelte", '<script context="module">\nexport { default as Chart } from "chart-lib";\n</script>\n<div />\n'),
    ("src/page.astro", '---\nimport Chart from "chart-lib";\n---\n<Chart />\n'),
])
def test_component_script_imports_are_usage_but_template_text_is_not(tmp_path, relative, content):
    _package(tmp_path, {"dependencies": {"chart-lib": "1", "unused": "1"}})
    component = _write(tmp_path, relative, content)
    findings, receipt = _scan(tmp_path, component)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


def test_component_style_block_and_undeclared_script_import(tmp_path):
    _package(tmp_path, {"dependencies": {"theme-lib": "1", "unused": "1"}})
    component = _write(tmp_path, "App.vue", '<template><div/></template>\n<script>\nimport "missing-lib";\n</script>\n<style lang="scss">\n@import "~theme-lib/vars";\n</style>\n')
    findings, receipt = _scan(tmp_path, component)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    unlisted = [item for item in findings if item["rule_id"] == npm.RULE_UNLISTED]
    assert [(item["name"], Path(item["file"]).name, item["line"]) for item in unlisted] == [("missing-lib", "App.vue", 3)]
    assert receipt["complete"] is True


@pytest.mark.parametrize("content", [
    '<script lang="coffee">\nimport "possibly-used"\n</script>',
    '<script setup>\nimport x from "possibly-used";\n',
    '<script setup>\nconst x = await import(name);\n</script>',
])
def test_unreadable_component_scripts_still_decline_absence(tmp_path, content):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    component = _write(tmp_path, "App.vue", content)
    findings, receipt = _scan(tmp_path, component)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_component_framework_runtime_is_implicitly_used(tmp_path):
    _package(tmp_path, {"dependencies": {"vue": "3", "svelte": "4", "unused": "1"}})
    component = _write(tmp_path, "App.vue", "<template><div/></template>")
    findings, _ = _scan(tmp_path, component)
    assert _names(findings, npm.RULE_UNUSED) == {"svelte", "unused"}


def test_mdx_esm_imports_are_usage_but_code_fences_and_prose_are_not(tmp_path):
    _package(tmp_path, {"dependencies": {"chart-lib": "1", "layout-lib": "1", "fenced-lib": "1"}})
    post = _write(tmp_path, "posts/hello.mdx", '---\ntitle: import "fenced-lib"\n---\nimport Chart from "chart-lib"\nimport {\n  Layout,\n} from "layout-lib/components"\nimport "missing-lib"\n\n# Hello\n\nWe import "fenced-lib" in prose.\n\n```js\nimport "fenced-lib";\n```\n\n<Chart />\n')
    findings, receipt = _scan(tmp_path, post)
    assert _names(findings, npm.RULE_UNUSED) == {"fenced-lib"}
    unlisted = [(item["name"], item["line"]) for item in findings if item["rule_id"] == npm.RULE_UNLISTED]
    assert unlisted == [("missing-lib", 8)]
    assert receipt["complete"] is True


def test_unparseable_mdx_esm_declines_absence(tmp_path):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    post = _write(tmp_path, "post.mdx", 'import { from "possibly-used"\n\n# Title\n')
    findings, receipt = _scan(tmp_path, post)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_css_imports_plugins_and_tilde_urls_are_usage(tmp_path):
    _package(tmp_path, {"devDependencies": {"tailwindcss": "4", "@tailwindcss/typography": "1", "@fontsource/inter": "1", "commented-lib": "1", "url-lib": "1"}})
    style = _write(tmp_path, "app.css", '/* @import "commented-lib"; */\n@import "tailwindcss" source("../src");\n@import url("https://fonts.example/css");\n@import url("url-lib/x.css");\n@import "./local.css";\n@plugin "@tailwindcss/typography";\n@plugin "daisyui";\n@plugin "./local-plugin.js";\n@font-face { src: url(~@fontsource/inter/files/inter.woff2); }\n')
    findings, receipt = _scan(tmp_path, style)
    assert _names(findings, npm.RULE_UNUSED) == {"commented-lib", "url-lib"}
    unlisted = [(item["name"], item["line"]) for item in findings if item["rule_id"] == npm.RULE_UNLISTED]
    assert unlisted == [("daisyui", 7)]
    assert receipt["complete"] is True


def test_preprocessor_imports_are_usage_without_ambiguous_unlisted_claims(tmp_path):
    _package(tmp_path, {"dependencies": {"bootstrap": "5", "animate.css": "4", "antd": "5", "unused": "1"}})
    scss = _write(tmp_path, "theme.scss", '@use "sass:math";\n// @import "unused";\n@use "pkg:bootstrap" as bs;\n@import "~animate.css/animate", "variables";\n')
    less = _write(tmp_path, "theme.less", '@import (reference) "~antd/lib/style/themes/default.less";\n@plugin "less-plugin-lookalike";\n')
    findings, receipt = _scan(tmp_path, scss, less)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert receipt["complete"] is True


def test_sass_pkg_import_of_undeclared_package_is_unlisted(tmp_path):
    _package(tmp_path, {"dependencies": {}})
    scss = _write(tmp_path, "theme.scss", '@use "pkg:missing-theme";\n')
    findings, _ = _scan(tmp_path, scss)
    assert _names(findings, npm.RULE_UNLISTED) == {"missing-theme"}


def test_interpolated_stylesheet_import_declines_absence(tmp_path):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    scss = _write(tmp_path, "theme.scss", '$theme: "possibly-used";\n@import "#{$theme}/vars";\n')
    findings, receipt = _scan(tmp_path, scss)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_analysis_selects_components_mdx_and_stylesheets(tmp_path):
    _package(tmp_path, {"private": True, "main": "src/main.ts", "dependencies": {"vue": "3", "chart-lib": "1", "mdx-lib": "1", "css-lib": "1", "unused": "1"}})
    _write(tmp_path, "src/main.ts", 'import App from "./App.vue"; console.log(App);')
    _write(tmp_path, "src/App.vue", '<script setup>\nimport Chart from "chart-lib";\n</script>\n<template><Chart/></template>\n')
    _write(tmp_path, "content/post.mdx", 'import Box from "mdx-lib"\n\n<Box />\n')
    _write(tmp_path, "src/app.css", '@import "css-lib/base.css";\n')
    result = _analyse(tmp_path)
    assert _names(result.get("quality", []), npm.RULE_UNUSED) == {"unused"}
    assert result["analysis_summary"]["npm_dependency_analysis"]["complete"] is True


def test_analysis_keeps_excluded_component_as_unanalysed(tmp_path):
    _package(tmp_path, {"private": True, "main": "app.ts", "dependencies": {"possibly-used": "1"}})
    _write(tmp_path, "app.ts", "export const x = 1;")
    _write(tmp_path, "legacy/App.vue", '<script>\nimport "possibly-used";\n</script>')
    result = _analyse(tmp_path, exclude_folders=["legacy"])
    assert _names(result.get("quality", []), npm.RULE_UNUSED) == set()
    reasons = result["analysis_summary"]["npm_dependency_analysis"]["reasons"]
    assert any(reason["kind"] == "unanalysed_source" and reason["file"].endswith("App.vue") for reason in reasons)


# Compiler options and literal PostCSS configs name packages without imports.

def test_typescript_compiler_and_options_are_usage(tmp_path):
    _package(tmp_path, {"devDependencies": {"typescript": "5", "tslib": "2", "vitest": "1", "@emotion/react": "11", "unused": "1"}})
    _write(tmp_path, "tsconfig.json", '{"compilerOptions": {"importHelpers": true, "types": ["vitest/globals"], "jsx": "react-jsx", "jsxImportSource": "@emotion/react"}}')
    source = _write(tmp_path, "app.ts", "export const x = 1;")
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert receipt["complete"] is True


def test_typescript_without_typescript_sources_or_config_is_unused(tmp_path):
    _package(tmp_path, {"devDependencies": {"typescript": "5"}})
    source = _write(tmp_path, "app.js", "export const x = 1;")
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"typescript"}


@pytest.mark.parametrize("name, content", [
    ("postcss.config.mjs", 'export default { plugins: { "@tailwindcss/postcss": {}, autoprefixer: {} } };'),
    ("postcss.config.js", 'const config = { plugins: ["@tailwindcss/postcss", require("autoprefixer")] };\nmodule.exports = config;'),
    (".postcssrc.json", '{"plugins": {"@tailwindcss/postcss": {}, "autoprefixer": {}}}'),
    (".postcssrc.yml", "plugins:\n  '@tailwindcss/postcss': {}\n  autoprefixer: {}\n"),
])
def test_literal_postcss_config_plugins_are_usage(tmp_path, name, content):
    _package(tmp_path, {"devDependencies": {"@tailwindcss/postcss": "4", "autoprefixer": "10", "unused": "1"}})
    config = _write(tmp_path, name, content)
    findings, receipt = _scan(tmp_path, config)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


@pytest.mark.parametrize("content", [
    "export default (ctx) => ({ plugins: { [ctx.env]: {} } });",
    "import shared from './shared.mjs';\nexport default { ...shared };",
    "import shared from './shared.mjs';\nexport default { plugins: shared };",
])
def test_computed_postcss_config_declines_absence(tmp_path, content):
    _package(tmp_path, {"devDependencies": {"possibly-used": "1"}})
    config = _write(tmp_path, "postcss.config.mjs", content)
    findings, receipt = _scan(tmp_path, config)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_framework_and_installed_peer_contracts_are_usage(tmp_path):
    _package(tmp_path, {"dependencies": {"next": "16", "react": "19", "react-dom": "19", "host-lib": "1", "peer-lib": "1", "unused": "1"}})
    _write(tmp_path, "node_modules/host-lib/package.json", '{"name": "host-lib", "peerDependencies": {"peer-lib": "*"}}')
    source = _write(tmp_path, "app.ts", 'import Link from "next/link";\nimport host from "host-lib";\nconsole.log(Link, host);')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


# Script binaries: unknown commands hold back only plausible providers.

def test_unknown_binary_is_unlisted_and_unrelated_dependencies_stay_checked(tmp_path):
    _package(tmp_path, {"dependencies": {"chalk": "5", "lodash": "4"}, "scripts": {"build": "tsup src/index.ts"}})
    source = _write(tmp_path, "src/index.ts", 'import _ from "lodash"; console.log(_);')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"chalk"}
    assert _names(findings, npm.RULE_BINARY) == {"tsup"}
    assert receipt["complete"] is True


def test_unmapped_unknown_binary_assumes_command_names_package(tmp_path):
    _package(tmp_path, {"dependencies": {"chalk": "5"}, "scripts": {"assets": "gen-assets --out dist"}})
    findings, _ = _scan(tmp_path)
    item = next(item for item in findings if item["rule_id"] == npm.RULE_BINARY)
    assert item["name"] == "gen-assets"
    assert item["metadata"]["package_name"] == "gen-assets" and item["metadata"]["provider_evidence"] == "command_name"
    assert _names(findings, npm.RULE_UNUSED) == {"chalk"}


@pytest.mark.parametrize("command", ["psql -f schema.sql", "docker compose up", "make build", "jq . data.json", "ffmpeg -i in.mov out.mp4"])
def test_system_tools_are_not_unlisted_binaries(tmp_path, command):
    _package(tmp_path, {"dependencies": {"chalk": "5"}, "scripts": {"task": command}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_BINARY) == set()
    assert _names(findings, npm.RULE_UNUSED) == {"chalk"}
    assert receipt["complete"] is True


@pytest.mark.parametrize("command, provider", [("mytool build", "mytool-core"), ("mytool-run", "mytool"), ("deploy", "@deploy/cli"), ("deploy", "deploy-cli"), ("start-storybook", "@storybook/react")])
def test_unknown_binary_holds_back_only_name_related_uninstalled_dependency(tmp_path, command, provider):
    _package(tmp_path, {"dependencies": {provider: "1", "chalk": "5"}, "scripts": {"build": command}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"chalk"}
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is False
    assert receipt["abstained_dependencies"] == [{"package_manifest": str(tmp_path / "package.json"), "name": provider, "binaries": [command.split()[0]]}]


def test_installed_metadata_excludes_unrelated_provider(tmp_path):
    _package(tmp_path, {"dependencies": {"mytool-core": "1"}, "scripts": {"build": "mytool build"}})
    _write(tmp_path, "node_modules/mytool-core/package.json", '{"name": "mytool-core", "bin": {"other": "bin.js"}}')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"mytool-core"}
    assert _names(findings, npm.RULE_BINARY) == {"mytool"}
    assert receipt["complete"] is True


@pytest.mark.parametrize("command, provider", [
    ("changeset version", "@changesets/cli"), ("biome check .", "@biomejs/biome"),
    ("run-s build test", "npm-run-all2"), ("firebase deploy", "firebase-tools"),
    ("gql-gen --config codegen.ts", "@graphql-codegen/cli"), ("svelte-kit sync", "@sveltejs/kit"),
    ("tailwindcss -i in.css", "@tailwindcss/cli"), ("lhci autorun", "@lhci/cli"),
])
def test_known_binary_map_credits_differently_named_provider(tmp_path, command, provider):
    _package(tmp_path, {"devDependencies": {provider: "1", "unused": "1"}, "scripts": {"task": command}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is True


def test_known_binary_without_provider_names_expected_package(tmp_path):
    _package(tmp_path, {"scripts": {"lint": "biome check ."}})
    findings, _ = _scan(tmp_path)
    item = next(item for item in findings if item["rule_id"] == npm.RULE_BINARY)
    assert item["name"] == "biome" and item["metadata"]["package_name"] == "@biomejs/biome"


def test_workspace_and_own_bins_resolve_without_install(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "workspaces": ["packages/*"]})
    _package(tmp_path, {"name": "@acme/tools", "bin": {"acme-build": "bin.js"}}, "packages/tools/package.json")
    _package(tmp_path, {"name": "app", "bin": {"app-cli": "cli.js"}, "devDependencies": {"@acme/tools": "workspace:*", "unused": "1"}, "scripts": {"build": "acme-build", "smoke": "app-cli --help"}}, "packages/app/package.json")
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_BINARY) == set()
    assert {(Path(item["file"]).parent.name, item["name"]) for item in findings if item["rule_id"] == npm.RULE_UNUSED} == {("app", "unused")}
    assert receipt["complete"] is True


@pytest.mark.parametrize("script", [
    "cross-env NODE_ENV=production webpack --mode production",
    'concurrently -k -n web,types "webpack serve" "npm:watch-*"',
    "env NODE_ENV=test webpack",
])
def test_wrapped_commands_are_resolved(tmp_path, script):
    _package(tmp_path, {"devDependencies": {"cross-env": "7", "concurrently": "8", "webpack-cli": "5", "unused": "1"}, "scripts": {"build": script}})
    findings, receipt = _scan(tmp_path)
    assert {"cross-env", "concurrently", "unused"} >= _names(findings, npm.RULE_UNUSED) >= {"unused"}
    assert "webpack-cli" not in _names(findings, npm.RULE_UNUSED)
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is True


def test_npx_and_package_manager_shorthand_never_claim_missing_provider(tmp_path):
    _package(tmp_path, {"dependencies": {"chalk": "5"}, "scripts": {"a": "npx only-allow pnpm", "b": "pnpm some-unknown-bin", "c": "bunx create-thing"}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_BINARY) == set()
    assert _names(findings, npm.RULE_UNUSED) == {"chalk"}
    assert receipt["complete"] is True


def test_npx_command_credits_declared_provider(tmp_path):
    _package(tmp_path, {"devDependencies": {"eslint": "9", "unused": "1"}, "scripts": {"lint": "npx eslint ."}})
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}


# pnpm catalogs.

def _catalog_workspace(root, yaml_text, *manifests):
    _write(root, "pnpm-workspace.yaml", yaml_text)
    for relative, data in manifests:
        _package(root, data, relative)


def test_unused_default_and_named_catalog_entries_are_reported(tmp_path):
    _catalog_workspace(
        tmp_path,
        "packages:\n  - packages/*\ncatalog:\n  lodash: ^4.17.21\n  left-pad: ^1.3.0\ncatalogs:\n  react18:\n    react: ^18.2.0\n  legacy:\n    old-lib: ^1.0.0\n",
        ("package.json", {"name": "root", "private": True}),
        ("packages/web/package.json", {"name": "web", "dependencies": {"lodash": "catalog:", "react": "catalog:react18"}}),
    )
    findings, receipt = _scan(tmp_path)
    unused = {(item["name"], item["metadata"]["catalog"], item["line"]) for item in findings if item["rule_id"] == npm.RULE_CATALOG_UNUSED}
    assert unused == {("left-pad", "default", 5), ("old-lib", "legacy", 10)}
    assert all(item["severity"] == "LOW" for item in findings if item["rule_id"] == npm.RULE_CATALOG_UNUSED)
    assert receipt["catalog_analysis"][0]["status"] == "complete"


def test_catalog_entries_referenced_outside_dependency_maps_are_used(tmp_path):
    _catalog_workspace(
        tmp_path,
        "packages:\n  - tools/*\ncatalog:\n  in-build-dir: ^1.0.0\n  overridden: ^2.0.0\n  root-override: ^1.0.0\n  scripted: ^3.0.0\n  default-named: ^1.0.0\noverrides:\n  'parent>overridden': 'catalog:'\n",
        ("package.json", {"name": "root", "private": True, "pnpm": {"overrides": {"root-override@<1": "catalog:"}}, "scripts": {"gen": "pnpm dlx scripted@catalog: run"}}),
        ("tools/build/package.json", {"name": "build-tools", "devDependencies": {"in-build-dir": "catalog:", "default-named": "catalog:default"}}),
    )
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_CATALOG_UNUSED) == set()


@pytest.mark.parametrize("extra", [".pnpmfile.cjs", ".yarnrc.yml"])
def test_unmodelled_catalog_consumers_decline_unused_entries(tmp_path, extra):
    _catalog_workspace(tmp_path, "catalog:\n  maybe-used: ^1.0.0\n", ("package.json", {"name": "root", "private": True}))
    _write(tmp_path, extra, "module.exports = {};\n")
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_CATALOG_UNUSED) == set()
    assert receipt["catalog_analysis"][0]["status"] == "incomplete"


def test_unreadable_workspace_manifest_declines_unused_catalog_entries(tmp_path):
    _catalog_workspace(tmp_path, "packages:\n  - packages/*\ncatalog:\n  maybe-used: ^1.0.0\n", ("package.json", {"name": "root", "private": True}))
    _write(tmp_path, "packages/broken/package.json", "{")
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_CATALOG_UNUSED) == set()


def test_unresolved_catalog_references_are_reported_for_workspace_members(tmp_path):
    _catalog_workspace(
        tmp_path,
        "packages:\n  - packages/*\n  - '!packages/ignored'\ncatalog:\n  lodash: ^4.17.21\ncatalogs:\n  react18:\n    react: ^18.2.0\n",
        ("package.json", {"name": "root", "private": True}),
        ("packages/web/package.json", {"name": "web", "dependencies": {"lodash": "catalog:default", "react": "catalog:react18", "zod": "catalog:", "vue": "catalog:missing"}}),
        ("packages/ignored/package.json", {"name": "ignored", "dependencies": {"nope": "catalog:"}}),
        ("examples/demo/package.json", {"name": "demo", "dependencies": {"nope": "catalog:"}}),
    )
    findings, _ = _scan(tmp_path)
    unresolved = {(item["name"], item["metadata"]["catalog"], Path(item["file"]).parent.name) for item in findings if item["rule_id"] == npm.RULE_CATALOG_UNRESOLVED}
    assert unresolved == {("zod", "default", "web"), ("vue", "missing", "web")}


def test_malformed_workspace_yaml_reports_no_catalog_findings(tmp_path):
    _catalog_workspace(tmp_path, "catalog: [unclosed\n", ("package.json", {"name": "root", "private": True, "dependencies": {"zod": "catalog:"}}))
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_CATALOG_UNUSED) == _names(findings, npm.RULE_CATALOG_UNRESOLVED) == set()
    assert receipt["catalog_analysis"][0]["status"] == "not_run"


# Referenced optional peer dependencies.

def _optional_peer_package(root, **extra):
    data = {"name": "lib", "peerDependencies": {"react": "^18"}, "peerDependenciesMeta": {"react": {"optional": True}}}
    data.update(extra)
    _package(root, data)


def test_static_import_of_optional_peer_is_reported(tmp_path):
    _optional_peer_package(tmp_path)
    source = _write(tmp_path, "src/index.ts", 'export const x = 1;\nimport React from "react";\nimport { useState } from "react";\nconsole.log(React, useState);')
    findings, _ = _scan(tmp_path, source)
    peers = [item for item in findings if item["rule_id"] == npm.RULE_OPTIONAL_PEER]
    assert [(item["name"], Path(item["file"]).name, item["line"], item["severity"]) for item in peers] == [("react", "index.ts", 2, "LOW")]
    assert peers[0]["metadata"]["import_count"] == 2


@pytest.mark.parametrize("source, extra", [
    ('import type { FC } from "react";\nexport type X = FC;', {}),
    ('import { type FC } from "react";\nexport type X = FC;', {}),
    ('export async function load() { try { return await import("react"); } catch { return null; } }', {}),
    ('let react; try { react = require("react"); } catch {}', {}),
    ('import React from "react"; console.log(React);', {"devDependencies": {"react": "^18"}}),
    ('import React from "react"; console.log(React);', {"peerDependenciesMeta": {"react": {"optional": False}}}),
    ('import React from "react"; console.log(React);', {"exports": {".": "./index.js", "./react": "./react.js"}}),
])
def test_guarded_or_contracted_optional_peer_use_stays_quiet(tmp_path, source, extra):
    _optional_peer_package(tmp_path, **extra)
    path = _write(tmp_path, "src/index.ts", source)
    findings, _ = _scan(tmp_path, path)
    assert _names(findings, npm.RULE_OPTIONAL_PEER) == set()


def test_mdx_import_lines_continuing_a_paragraph_are_prose(tmp_path):
    _package(tmp_path, {"dependencies": {"chart-lib": "1", "prose-lib": "1"}})
    post = _write(tmp_path, "post.mdx", '# Title\nimport Chart from "chart-lib"\n\nThe scanner can\nexport every result page, and\nimport "prose-lib" is only prose here.\n')
    findings, receipt = _scan(tmp_path, post)
    assert _names(findings, npm.RULE_UNUSED) == {"prose-lib"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert receipt["complete"] is True


@pytest.mark.parametrize("declared, expected", [({"@docusaurus/core": "3"}, set()), ({}, {"@site/src"})])
def test_framework_module_aliases_are_not_unlisted_packages(tmp_path, declared, expected):
    _package(tmp_path, {"dependencies": declared})
    post = _write(tmp_path, "docs/intro.mdx", 'import Tabs from "@theme/Tabs";\nimport data from "@site/src/data.json";\n\n<Tabs />\n')
    findings, _ = _scan(tmp_path, post)
    assert _names(findings, npm.RULE_UNLISTED) == expected


@pytest.mark.parametrize("name, content, used", [
    ("nuxt.config.ts", 'export default defineNuxtConfig({ modules: ["@nuxt/content", "@pinia/nuxt"] });', {"@nuxt/content", "@pinia/nuxt"}),
    ("docusaurus.config.ts", 'export default { presets: [["classic", {}]], themes: ["@docusaurus/theme-mermaid"], plugins: ["@acme"] };', {"@docusaurus/preset-classic", "@docusaurus/theme-mermaid", "@acme/docusaurus-plugin"}),
    ("jest.config.js", 'module.exports = { preset: "ts-jest", testEnvironment: "jsdom" };', {"ts-jest", "jest-environment-jsdom"}),
    (".storybook/main.ts", 'export default { addons: ["@storybook/addon-essentials"] };', {"@storybook/addon-essentials"}),
])
def test_config_string_package_references_are_usage(tmp_path, name, content, used):
    _package(tmp_path, {"devDependencies": {**{package: "1" for package in used}, "unused": "1"}})
    config = _write(tmp_path, name, content)
    findings, receipt = _scan(tmp_path, config)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert receipt["complete"] is True


def test_string_literals_outside_config_files_are_not_usage(tmp_path):
    _package(tmp_path, {"dependencies": {"named-only": "1"}})
    source = _write(tmp_path, "src/app.ts", 'export const label = "named-only";')
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"named-only"}


def test_quoted_parentheses_in_script_arguments_are_inert(tmp_path):
    _package(tmp_path, {"devDependencies": {"eslint": "9", "unused": "1"}, "scripts": {"lint": "eslint --max-warnings 0 'src/app/(group)/page.tsx' src/app/[id]/route.ts"}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert receipt["complete"] is True


@pytest.mark.parametrize("script", ["tsc > out.log", "tsc 2>&1", "tsc --noEmit 2>/dev/null || true"])
def test_redirections_do_not_hide_the_command(tmp_path, script):
    _package(tmp_path, {"devDependencies": {"typescript": "5", "unused": "1"}, "scripts": {"build": script}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"unused"}
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is True


@pytest.mark.parametrize("script", ["(cd web && tsc)", "tsc <<EOF"])
def test_unquoted_subshell_and_redirection_stay_unresolved(tmp_path, script):
    _package(tmp_path, {"devDependencies": {"possibly-used": "1"}, "scripts": {"build": script}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False
