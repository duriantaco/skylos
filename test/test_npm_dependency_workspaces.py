"""Npm dependency rules across workspaces, CI files and narrowed abstentions."""

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


def _rows(findings, rule, root):
    return {(Path(item["file"]).relative_to(root).as_posix(), item["name"]) for item in findings if item["rule_id"] == rule}


def _names(findings, rule):
    return {item["name"] for item in findings if item["rule_id"] == rule}


def _monorepo(root, child=None, root_deps=None):
    _package(root, {"name": "root", "private": True, "workspaces": ["packages/*"], "devDependencies": root_deps or {"vitest": "3", "vite": "5"}})
    _package(root, child or {"name": "@acme/lib", "version": "1.0.0"}, "packages/lib/package.json")


# SKY-Q408: ancestor declarations satisfy tooling files and private packages.

@pytest.mark.parametrize("relative, source", [
    ("packages/lib/src/__tests__/sum.test.ts", 'import { it } from "vitest";'),
    ("packages/lib/test-setup.ts", 'import "vitest";'),
    ("packages/lib/vite.config.ts", 'import { defineConfig } from "vite";'),
    ("packages/lib/scripts/release.ts", 'import "vite";'),
    ("packages/lib/src/Button.stories.tsx", 'import "vite";'),
    ("packages/lib/examples/demo.ts", 'import "vite";'),
])
def test_tooling_files_resolve_ancestor_declarations(tmp_path, relative, source):
    _monorepo(tmp_path)
    path = _write(tmp_path, relative, source)
    findings, receipt = _scan(tmp_path, path)
    assert _names(findings, npm.RULE_UNLISTED) == set()
    # The ancestor declaration is the one the import uses.
    used = {"vitest"} if "vitest" in source else {"vite"}
    assert not used & _names(findings, npm.RULE_UNUSED)
    assert receipt["complete"] is True


def test_private_package_source_resolves_ancestor_declaration(tmp_path):
    _monorepo(tmp_path, {"name": "web", "private": True}, {"lodash": "4"})
    source = _write(tmp_path, "packages/lib/src/app.ts", 'import "lodash";')
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert _names(findings, npm.RULE_UNUSED) == set()


def test_published_source_ancestor_declaration_is_strict_only(tmp_path):
    _monorepo(tmp_path, root_deps={"lodash": "4"})
    source = _write(tmp_path, "packages/lib/src/index.ts", 'import "lodash";')
    # Default (non-strict): the root declaration resolves it.
    findings, receipt = _scan(tmp_path, source)
    assert _rows(findings, npm.RULE_UNLISTED, tmp_path) == set()
    assert receipt["strict"] is False
    assert receipt["ancestor_declared_production_imports"] == 1
    # Strict mode: consumers of the published package will not install it.
    findings, _ = _scan(tmp_path, source, strict=True)
    assert _rows(findings, npm.RULE_UNLISTED, tmp_path) == {("packages/lib/src/index.ts", "lodash")}
    assert "declared only by an ancestor" in findings[0]["message"]


def test_strict_mode_keeps_undeclared_imports_reported_by_default(tmp_path):
    _monorepo(tmp_path)
    source = _write(tmp_path, "packages/lib/src/index.ts", 'import "lodash";')
    findings, _ = _scan(tmp_path, source)
    assert _rows(findings, npm.RULE_UNLISTED, tmp_path) == {("packages/lib/src/index.ts", "lodash")}
    assert "declared only by an ancestor" not in findings[0]["message"]


def test_sibling_declaration_does_not_satisfy_a_test_file(tmp_path):
    _monorepo(tmp_path)
    _package(tmp_path, {"name": "@acme/other", "devDependencies": {"@testing-library/react": "16"}}, "packages/other/package.json")
    test = _write(tmp_path, "packages/lib/tests/view.test.tsx", 'import { render } from "@testing-library/react";')
    findings, _ = _scan(tmp_path, test)
    assert _names(findings, npm.RULE_UNLISTED) == {"@testing-library/react"}


# SKY-Q408: workspace packages mapped to source by tsconfig paths or aliases.

def _aliased_workspace(root, private):
    _package(root, {"name": "root", "private": True, "workspaces": ["packages/*", "app"]})
    _package(root, {"name": "@acme/core", "version": "1.0.0"}, "packages/core/package.json")
    _package(root, {"name": "app", **({"private": True} if private else {"version": "1.0.0"})}, "app/package.json")
    _write(root, "tsconfig.json", '{"compilerOptions": {"paths": {"@acme/core": ["./packages/core/src/index.ts"]}}}')
    return _write(root, "packages/core/src/index.ts", "export const core = 1;")


def test_private_app_imports_workspace_source_through_tsconfig_paths(tmp_path):
    core = _aliased_workspace(tmp_path, private=True)
    app = _write(tmp_path, "app/main.ts", 'import { core } from "@acme/core"; console.log(core);')
    findings, _ = _scan(tmp_path, app, core)
    assert _names(findings, npm.RULE_UNLISTED) == set()


def test_published_source_importing_aliased_workspace_package_is_unlisted(tmp_path):
    core = _aliased_workspace(tmp_path, private=False)
    app = _write(tmp_path, "app/main.ts", 'import { core } from "@acme/core"; console.log(core);')
    test = _write(tmp_path, "app/main.test.ts", 'import { core } from "@acme/core"; console.log(core);')
    declaration = _write(tmp_path, "app/global.d.ts", 'import "@acme/core";')
    findings, _ = _scan(tmp_path, app, test, declaration, core)
    # Emitted JS keeps the bare specifier; tests and .d.ts inputs are not emitted.
    assert _rows(findings, npm.RULE_UNLISTED, tmp_path) == {("app/main.ts", "@acme/core")}


def test_workspace_package_without_alias_is_unlisted_even_when_private(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "workspaces": ["packages/*", "examples/*"]})
    _package(tmp_path, {"name": "@acme/core", "version": "1.0.0"}, "packages/core/package.json")
    _package(tmp_path, {"name": "demo", "private": True}, "examples/demo/package.json")
    _write(tmp_path, "examples/demo/tsconfig.json", '{"compilerOptions": {"paths": {"@/*": ["./src/*"]}}}')
    source = _write(tmp_path, "examples/demo/src/app.ts", 'import "@acme/core";')
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNLISTED) == {"@acme/core"}


def test_readable_bundler_alias_maps_workspace_package(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "workspaces": ["packages/*", "app"]})
    _package(tmp_path, {"name": "@acme/core", "version": "1.0.0"}, "packages/core/package.json")
    _package(tmp_path, {"name": "app", "private": True, "devDependencies": {"vite": "5"}}, "app/package.json")
    config = _write(tmp_path, "app/vite.config.ts", 'import { defineConfig } from "vite";\nexport default defineConfig({ resolve: { alias: { "@acme/core": "../packages/core/src" } } });')
    source = _write(tmp_path, "app/main.ts", 'import "@acme/core/feature";')
    findings, _ = _scan(tmp_path, source, config)
    assert _names(findings, npm.RULE_UNLISTED) == set()


def test_file_compiled_by_another_packages_tsconfig_uses_its_declarations(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "workspaces": ["checks/*"]})
    _package(tmp_path, {"name": "check", "private": True, "devDependencies": {"@angular/core": "20", "spare": "1"}}, "checks/ng/package.json")
    _write(tmp_path, "checks/ng/tsconfig.json", '{"extends": "../../scripts/shared/tsconfig.json"}')
    _write(tmp_path, "scripts/shared/tsconfig.json", '{"include": ["consumer.ts"]}')
    consumer = _write(tmp_path, "scripts/shared/consumer.ts", 'import { Component } from "@angular/core";')
    findings, _ = _scan(tmp_path, consumer)
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert _rows(findings, npm.RULE_UNUSED, tmp_path) == {("checks/ng/package.json", "spare")}


# SKY-Q408: fixture files read as text by test harnesses.

@pytest.mark.parametrize("relative", [
    "src/__testfixtures__/rename.input.tsx",
    "src/__fixtures__/plugin/code.js",
    "test/fixtures/basic/input.ts",
    "test/fixtures/basic/case.output.tsx",
])
def test_fixture_text_is_not_an_unlisted_import(tmp_path, relative):
    _package(tmp_path, {"name": "codemods", "version": "1.0.0"})
    fixture = _write(tmp_path, relative, 'import React from "react";')
    findings, _ = _scan(tmp_path, fixture)
    assert _names(findings, npm.RULE_UNLISTED) == set()


@pytest.mark.parametrize("relative", ["test/fixtures/helpers.ts", "src/fixtures.ts"])
def test_executed_fixture_helpers_keep_unlisted_imports(tmp_path, relative):
    _package(tmp_path, {"name": "codemods", "version": "1.0.0"})
    helper = _write(tmp_path, relative, 'import React from "react";')
    findings, _ = _scan(tmp_path, helper)
    assert _names(findings, npm.RULE_UNLISTED) == {"react"}


# SKY-U005: CI, container and task files are read instead of abstaining.

def test_workflow_commands_are_usage_and_do_not_block_unused_claims(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"size-limit": "11", "@changesets/cli": "2", "spare": "1"}, "scripts": {"test": "echo ok"}})
    _write(tmp_path, ".github/workflows/ci.yml", """
jobs:
  test:
    steps:
      - run: |
          # comment lines are ignored
          yarn test
          npx size-limit
          if [ -n "${{ github.ref }}" ]; then
            changeset version
          fi
      - run: Write-Host hi
        shell: pwsh
""")
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert receipt["complete"] is True


def test_dockerfile_procfile_and_makefile_commands_are_usage(tmp_path):
    _package(tmp_path, {"name": "app", "dependencies": {"pm2": "5", "serve": "14", "prisma": "5", "spare": "1"}})
    _write(tmp_path, "Dockerfile", 'FROM node:22\nRUN --mount=type=cache,target=/root/.cache \\\n    npm_config_arch=${TARGETARCH} yarn --frozen-lockfile\nCMD ["npx", "pm2-runtime", "start"]\nENTRYPOINT ["serve", "-s", "build"]\n')
    _write(tmp_path, "Procfile", "web: pm2 start server.js\n")
    _write(tmp_path, "Makefile", "migrate:\n\t@prisma migrate deploy --schema $(SCHEMA)\n\t-prisma generate\n")
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert receipt["complete"] is True


def test_unknown_ci_command_holds_back_only_name_related_dependencies(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"mytool-core": "1", "spare": "1"}})
    _write(tmp_path, ".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: mytool build\n")
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert _names(findings, npm.RULE_BINARY) == set()  # CI tools may be installed globally.
    assert [item["name"] for item in receipt["abstained_dependencies"]] == ["mytool-core"]


@pytest.mark.parametrize("content", ["jobs:\n  a:\n    steps:\n      - run: $TOOL build\n", "jobs: [unclosed\n"])
def test_unparseable_ci_command_still_abstains(tmp_path, content):
    _package(tmp_path, {"name": "app", "devDependencies": {"possibly-used": "1"}})
    _write(tmp_path, ".github/workflows/ci.yml", content)
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_ci_shell_script_is_followed(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"wrangler": "3", "spare": "1"}})
    _write(tmp_path, ".github/workflows/deploy.yml", "jobs:\n  a:\n    steps:\n      - run: ./scripts/deploy.sh\n")
    _write(tmp_path, "scripts/deploy.sh", "#!/bin/sh\nset -e\nwrangler deploy\n")
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}


def test_ci_runs_non_shell_executables_without_parsing_them(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"spare": "1"}})
    _write(tmp_path, ".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: ./bin/setup\n")
    _write(tmp_path, "bin/setup", "#!/usr/bin/env perl\n$x = shift;\n")
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert receipt["complete"] is True


# SKY-U005: package scripts are read segment by segment.

def test_script_segments_follow_runtime_scripts_outside_the_package(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "workspaces": ["packages/*"]})
    _package(tmp_path, {"name": "@acme/lib", "devDependencies": {"rimraf": "5", "esbuild": "0.20", "typescript": "5", "spare": "1"}, "scripts": {"build": "rimraf dist && node ../../scripts/build.js && yarn gen:types", "gen:types": "tsc"}}, "packages/lib/package.json")
    build = _write(tmp_path, "scripts/build.js", 'const { build } = require("esbuild");\nrequire("./helpers");\n')
    helpers = _write(tmp_path, "scripts/helpers.js", 'module.exports = require("path");\n')
    findings, receipt = _scan(tmp_path, build, helpers)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert receipt["complete"] is True


def test_missing_script_outside_the_package_still_abstains(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "workspaces": ["packages/*"]})
    _package(tmp_path, {"name": "@acme/lib", "devDependencies": {"possibly-used": "1"}, "scripts": {"build": "node ../../scripts/missing.js"}}, "packages/lib/package.json")
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def test_script_running_a_package_file_from_node_modules_uses_that_package(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"typescript58": "npm:typescript@5.8", "spare": "1"}, "scripts": {"types": "node ../node_modules/typescript58/lib/tsc.js --noEmit"}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert receipt["complete"] is True


@pytest.mark.parametrize("script", [
    "cross-env VITE_SHA=$VERCEL_GIT_COMMIT_SHA cross-env MODE=prod vite build",
    "VERSION=$(git describe) vite build",
    "vite build --base ${BASE_URL}",
])
def test_expansions_in_arguments_do_not_hide_commands(tmp_path, script):
    _package(tmp_path, {"name": "app", "devDependencies": {"cross-env": "7", "vite": "5", "spare": "1"}, "scripts": {"build": script}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) <= {"spare", "cross-env"} and "spare" in _names(findings, npm.RULE_UNUSED)
    assert "vite" not in _names(findings, npm.RULE_UNUSED)
    assert receipt["complete"] is True


def test_expanded_command_name_stays_unresolved(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"possibly-used": "1"}, "scripts": {"build": "$BUILDER --prod"}})
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()
    assert receipt["complete"] is False


def _cwd_workspace(root, script):
    _package(root, {"name": "root", "private": True, "workspaces": ["app"], "devDependencies": {"vite": "5", "spare": "1"}, "scripts": {"task": script}})
    _package(root, {"name": "app", "private": True, "scripts": {"build:app": "vite build"}}, "app/package.json")


@pytest.mark.parametrize("script", ["yarn --cwd ./app build:app", "npm --prefix app run build:app", "pnpm -C app build:app", "yarn workspace app build:app", "pnpm --filter app run build:app"])
def test_package_manager_targets_run_the_target_packages_script(tmp_path, script):
    _cwd_workspace(tmp_path, script)
    findings, receipt = _scan(tmp_path)
    assert _rows(findings, npm.RULE_UNUSED, tmp_path) == {("package.json", "spare")}
    assert _names(findings, npm.RULE_BINARY) == set()
    assert receipt["complete"] is True


def test_package_manager_target_binary_resolves_in_the_target_lineage(tmp_path):
    _cwd_workspace(tmp_path, "yarn --cwd ./app cross-env MODE=stats vite build")
    findings, _ = _scan(tmp_path)
    item = next(item for item in findings if item["rule_id"] == npm.RULE_BINARY)
    assert item["name"] == "cross-env" and item["file"] == str(tmp_path / "package.json")
    assert "vite" not in _names(findings, npm.RULE_UNUSED)


def test_unknown_package_manager_target_stays_unresolved(tmp_path):
    _cwd_workspace(tmp_path, "yarn --cwd ./missing build")
    findings, receipt = _scan(tmp_path)
    assert ("package.json", "spare") not in _rows(findings, npm.RULE_UNUSED, tmp_path)
    assert receipt["complete"] is False


# SKY-U005: TypeScript configuration and declaration packages.

def test_relative_tsconfig_extends_is_followed(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"@types/jest": "29", "ts-plugin": "1", "spare": "1"}})
    _write(tmp_path, "tsconfig.json", '{"extends": "./config/tsconfig.base.json"}')
    _write(tmp_path, "config/tsconfig.base.json", '{"compilerOptions": {"types": ["jest"], "plugins": [{"name": "ts-plugin"}]}}')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert receipt["complete"] is True


def test_missing_relative_tsconfig_parent_abstains_but_generated_one_does_not(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"@types/x": "1", "spare": "1"}})
    _write(tmp_path, "tsconfig.json", '{"extends": "./.svelte-kit/tsconfig.json"}')
    findings, receipt = _scan(tmp_path)
    # A framework-generated config can only add type packages.
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert [item["name"] for item in receipt["abstained_dependencies"]] == ["@types/x"]
    _write(tmp_path, "tsconfig.json", '{"extends": "./missing/tsconfig.json"}')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == set()


def test_tsconfig_types_entry_must_be_declared_by_the_lineage(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "workspaces": ["packages/*"], "devDependencies": {"vitest": "3"}})
    _package(tmp_path, {"name": "@acme/lib", "version": "1.0.0"}, "packages/lib/package.json")
    config = _write(tmp_path, "tsconfig.json", '{\n  "compilerOptions": {\n    "types": ["vitest/globals", "@testing-library/jest-dom", "node"]\n  }\n}')
    _write(tmp_path, "packages/lib/tsconfig.json", '{"compilerOptions": {"types": ["vitest/globals"]}}')
    findings, _ = _scan(tmp_path)
    assert _rows(findings, npm.RULE_UNLISTED, tmp_path) == {("tsconfig.json", "@testing-library/jest-dom")}
    item = next(item for item in findings if item["rule_id"] == npm.RULE_UNLISTED)
    assert item["file"] == str(config) and item["line"] == 3


def test_unused_type_package_is_reported_when_its_package_is_unused(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"chai": "4", "@types/chai": "4", "@types/react": "19", "react": "19", "@types/resize-observer-browser": "1", "@types/chrome": "1", "@types/jest": "29"}})
    source = _write(tmp_path, "src/app.tsx", 'import React from "react";\nchrome.runtime.sendMessage({});\nexport default React;\n')
    _write(tmp_path, "tsconfig.json", '{"compilerOptions": {"types": ["jest"]}}')
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"chai", "@types/chai", "@types/resize-observer-browser"}


def test_node_types_follow_node_api_use(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"@types/node": "22"}})
    browser = _write(tmp_path, "src/app.ts", "export const x = 1;")
    findings, _ = _scan(tmp_path, browser)
    assert _names(findings, npm.RULE_UNUSED) == {"@types/node"}
    _write(tmp_path, "src/app.ts", 'import { readFileSync } from "node:fs";\nexport const x = readFileSync;')
    findings, _ = _scan(tmp_path, browser)
    assert _names(findings, npm.RULE_UNUSED) == set()


def test_type_only_import_is_satisfied_by_definitely_typed_package(tmp_path):
    _package(tmp_path, {"name": "lib", "version": "1.0.0", "devDependencies": {"@types/estree": "1"}})
    source = _write(tmp_path, "src/rule.ts", 'import type { Node } from "estree";\nimport { walk } from "estree-walker";\n')
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNLISTED) == {"estree-walker"}
    assert _names(findings, npm.RULE_UNUSED) == set()


def test_jsdoc_type_in_private_config_is_not_an_unlisted_package(tmp_path):
    _package(tmp_path, {"name": "docs", "private": True, "dependencies": {"@docusaurus/core": "3"}})
    config = _write(tmp_path, "docusaurus.config.js", "/** @type {import('@docusaurus/types').Config} */\nmodule.exports = {};\n")
    findings, _ = _scan(tmp_path, config)
    assert _names(findings, npm.RULE_UNLISTED) == set()


def test_jsdoc_type_in_published_source_is_unlisted(tmp_path):
    _package(tmp_path, {"name": "lib", "version": "1.0.0"})
    source = _write(tmp_path, "src/index.js", "/** @param {import('esbuild').Plugin} plugin */\nexport function use(plugin) { return plugin; }\n")
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNLISTED) == {"esbuild"}


# SKY-U005: workspace consumers only hold back declarations they can reach.

def test_unresolved_consumer_only_holds_back_ancestor_declarations_it_resolves(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "workspaces": ["packages/*"], "devDependencies": {"chai": "4", "reachable": "1"}})
    _package(tmp_path, {"name": "@acme/lib", "devDependencies": {"chai": "4"}}, "packages/lib/package.json")
    source = _write(tmp_path, "packages/lib/src/load.ts", "export const load = (name: string) => import(name);")
    findings, receipt = _scan(tmp_path, source)
    # The child's own chai shadows the root's; only "reachable" is held back.
    assert _rows(findings, npm.RULE_UNUSED, tmp_path) == {("package.json", "chai")}
    held = {(Path(item["package_manifest"]).relative_to(tmp_path).as_posix(), item["name"]) for item in receipt["abstained_dependencies"]}
    assert held == {("package.json", "reachable"), ("packages/lib/package.json", "chai")}


# SKY-U005: dynamic specifiers proven local and literal tool configs.

@pytest.mark.parametrize("source", [
    'const io = await import(/* webpackChunkName: "io" */ "socket.io-client");',
    'const fs = require(["fs"].join());\nrequire("socket.io-client");',
    'const path = require("path");\nconst pkg = require(path.resolve(__dirname, "../package.json"));\nrequire("socket.io-client");',
    'const entry = "./dist/server.js";\nawait import(entry);\nimport("socket.io-client");',
    'const dir = `${__dirname}/../locales`;\nrequire(`${dir}/en.json`);\nrequire("socket.io-client");',
    'const path = require("path");\nconst file = (name) => path.resolve("packages", name, "package.json");\nrequire(file("a"));\nrequire("socket.io-client");',
])
def test_computed_specifiers_proven_local_or_literal_do_not_abstain(tmp_path, source):
    _package(tmp_path, {"name": "app", "dependencies": {"socket.io-client": "4", "spare": "1"}})
    path = _write(tmp_path, "src/app.js", source)
    findings, receipt = _scan(tmp_path, path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    assert receipt["complete"] is True


def test_literal_babel_config_is_read_and_computed_one_holds_babel_family(tmp_path):
    _package(tmp_path, {"name": "docs", "private": True, "dependencies": {"@docusaurus/core": "3"}, "devDependencies": {"@babel/preset-env": "7", "spare": "1"}})
    config = _write(tmp_path, "babel.config.js", 'module.exports = { presets: [require.resolve("@docusaurus/core/lib/babel/preset")] };')
    findings, receipt = _scan(tmp_path, config)
    assert _names(findings, npm.RULE_UNUSED) == {"@babel/preset-env", "spare"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    _write(tmp_path, "babel.config.js", "module.exports = (api) => ({ presets: [api.env('x')] });")
    findings, receipt = _scan(tmp_path, config)
    assert _names(findings, npm.RULE_UNUSED) == {"@docusaurus/core", "spare"}
    assert [item["name"] for item in receipt["abstained_dependencies"]] == ["@babel/preset-env"]


def test_uninstalled_shareable_eslint_config_holds_back_only_eslint_family(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "devDependencies": {"@acme/eslint-config": "1", "eslint-plugin-prettier": "3", "eslint-plugin-import": "2", "@babel/preset-env": "7"}})
    _write(tmp_path, ".eslintrc.json", '{"extends": ["@acme/eslint-config"], "rules": {"import/order": "warn"}}')
    findings, receipt = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"@babel/preset-env"}
    assert _names(findings, npm.RULE_UNLISTED) == set()
    assert [item["name"] for item in receipt["abstained_dependencies"]] == ["eslint-plugin-prettier"]


# SKY-U005: framework and tool conventions.

def test_preprocessor_stylesheets_use_their_compiler(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"sass": "1", "less": "4", "spare": "1"}})
    sheet = _write(tmp_path, "src/app.scss", "$x: 1;")
    findings, _ = _scan(tmp_path, sheet)
    assert _names(findings, npm.RULE_UNUSED) == {"less", "spare"}


def test_runner_flags_and_subcommands_use_optional_packages(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"vitest": "3", "@vitest/ui": "3", "astro": "5", "@astrojs/check": "0.9", "@vitest/browser": "3"}, "scripts": {"test": "vitest", "test:ui": "yarn test --ui", "check": "astro check"}})
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"@vitest/browser"}


def test_angular_workspace_config_and_peers_are_usage(tmp_path):
    _package(tmp_path, {"name": "ng-app", "private": True, "dependencies": {"@angular/core": "20", "@angular/common": "20", "@angular/platform-browser": "20", "rxjs": "7", "zone.js": "0.15", "@angular/forms": "20"}, "devDependencies": {"@angular/build": "20", "@angular/compiler-cli": "20", "@angular/compiler": "20"}})
    _write(tmp_path, "angular.json", '{"projects": {"app": {"architect": {"build": {"builder": "@angular/build:application"}}}}}')
    source = _write(tmp_path, "src/main.ts", 'import { bootstrapApplication } from "@angular/platform-browser";')
    findings, _ = _scan(tmp_path, source)
    assert _names(findings, npm.RULE_UNUSED) == {"@angular/forms"}


def test_size_limit_config_uses_its_plugins(tmp_path):
    _package(tmp_path, {"name": "lib", "devDependencies": {"@size-limit/preset-big-lib": "11", "spare": "1"}})
    _write(tmp_path, ".size-limit.json", '[{"path": "dist/index.js"}]')
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}


def test_dependency_declared_in_two_sections_is_reported_in_each(tmp_path):
    _package(tmp_path, {"name": "lib", "dependencies": {"cross-env": "7"}, "devDependencies": {"cross-env": "7"}})
    findings, _ = _scan(tmp_path)
    sections = sorted(item["metadata"]["dependency_section"] for item in findings if item["rule_id"] == npm.RULE_UNUSED)
    assert sections == ["dependencies", "devDependencies"]
    assert len({item["line"] for item in findings}) == 2


# SKY-Q409: tool binaries, configs and compiler maps.

def test_eslint_plugins_and_configs_do_not_provide_the_eslint_binary(tmp_path):
    _package(tmp_path, {"name": "root", "private": True, "devDependencies": {"eslint-config-prettier": "8", "eslint-plugin-import": "2", "@acme/eslint-config": "1"}, "scripts": {"lint": "eslint ."}})
    findings, _ = _scan(tmp_path)
    item = next(item for item in findings if item["rule_id"] == npm.RULE_BINARY)
    assert item["name"] == "eslint" and item["metadata"]["package_name"] == "eslint"


def test_unrelated_preset_does_not_hide_a_missing_binary(tmp_path):
    _package(tmp_path, {"name": "app", "devDependencies": {"@babel/preset-env": "7"}, "scripts": {"build": "cross-env NODE_ENV=production vite build"}})
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_BINARY) == {"cross-env", "vite"}


@pytest.mark.parametrize("command, provider", [("ngc -p tsconfig.json", "@angular/compiler-cli"), ("svelte-package --input src", "@sveltejs/package"), ("vue-demi-switch 3", "vue-demi")])
def test_compiler_binaries_map_to_their_packages(tmp_path, command, provider):
    _package(tmp_path, {"name": "lib", "devDependencies": {provider: "1", "spare": "1"}, "scripts": {"build": command}})
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_BINARY) == set()
    assert _names(findings, npm.RULE_UNUSED) == {"spare"}
    _package(tmp_path, {"name": "lib", "scripts": {"build": command}})
    findings, _ = _scan(tmp_path)
    item = next(item for item in findings if item["rule_id"] == npm.RULE_BINARY)
    assert item["metadata"]["package_name"] == provider


@pytest.mark.parametrize("script", ["git describe --tags > VERSION", "readarray -t lines < <(ls)", "docker build ."])
def test_system_tools_and_builtins_stay_quiet(tmp_path, script):
    _package(tmp_path, {"name": "app", "scripts": {"task": script}})
    findings, _ = _scan(tmp_path)
    assert _names(findings, npm.RULE_BINARY) == set()
