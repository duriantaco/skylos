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


@pytest.mark.parametrize("command", ["some-system-tool build", "node $RUNNER", "bash -c 'tool build'", "npx unknown-tool"])
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
    assert unused == {("package.json", "shared-lib"), ("packages/web/package.json", "own-unused")}
    assert _names(findings, npm.RULE_UNLISTED) == {"shared-lib"}
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is True


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


def test_unparsed_component_and_invalid_source_decline_absence(tmp_path):
    _package(tmp_path, {"dependencies": {"possibly-used": "1"}})
    _write(tmp_path, "App.vue", '<script setup>import x from "possibly-used";</script>')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_peer_and_ambient_type_contracts_do_not_require_runtime_import(tmp_path):
    _package(tmp_path, {"peerDependencies": {"react": "1"}, "devDependencies": {"@types/node": "1", "unused": "1"}})
    findings, _ = _scan(tmp_path)
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
    _package(tmp_path, {"devDependencies": {"possibly-configured": "1"}, "jest": {"preset": "possibly-configured"}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


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


def test_unknown_ci_and_stylesheet_consumers_decline_unused_claims(tmp_path):
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


def test_typescript_reference_directive_is_not_a_clean_absence_proof(tmp_path):
    _package(tmp_path, {"devDependencies": {"vitest": "1"}})
    source = _write(tmp_path, "app.ts", '/// <reference types="vitest" />\nexport {};')
    findings, receipt = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False
