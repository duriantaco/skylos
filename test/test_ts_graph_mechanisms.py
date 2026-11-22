"""Graph mechanisms for the JS/TS dead-code checks.

Marker manifests that own nothing, one finding per unused file (and
unreachable import cycles), type-check projects as entries, canonical file
identity through symlinks, component pages as graph roots, one command model
for scripts, CI and git hooks, and class members of external contracts.
Every case keeps a genuinely dead neighbour and requires it to stay
reported. Synthetic projects only; nothing is executed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.result_builder import fold_findings_into_unused_files
from skylos.visitors.languages.typescript.script_inputs import (
    ScriptInputs,
    _installed_binary,
    bundler_script_entries,
    project_source_files,
    read_arguments,
    read_command_line,
    read_tsconfig_project,
)
from skylos.visitors.languages.typescript.workspace import is_marker_manifest


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


def _scan(root: Path, *, quality: bool = False) -> dict:
    return json.loads(
        analyze(
            str(root),
            conf=0,
            grep_verify=False,
            enable_danger=False,
            enable_quality=quality,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
        )
    )


def _rel(root: Path, file_name: str) -> str:
    return Path(file_name).resolve().relative_to(root.resolve()).as_posix()


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
            if item.get("folded_into"):
                continue  # reported inside its unused file's finding
            found.add((key, _rel(root, item["file"]), item.get("name") or ""))
    return found


def _files(result: dict, root: Path) -> set[str]:
    return {name for key, name, _ in _reported(result, root) if key == "unused_files"}


def _symbols(result: dict, root: Path) -> set[tuple[str, str]]:
    return {
        (name, symbol)
        for key, name, symbol in _reported(result, root)
        if key != "unused_files"
    }


def _quality(result: dict, root: Path, rule: str) -> set[tuple[str, str]]:
    return {
        (_rel(root, item["file"]), item.get("name") or "")
        for item in result.get("quality") or []
        if item.get("rule_id") == rule
    }


# --- 1. marker manifests do not own files -------------------------------------


def test_marker_manifest_is_transparent_for_dependency_ownership(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "lib",
                "version": "1.0.0",
                "main": "src/index.js",
                "dependencies": {"left-pad": "1"},
            },
            "src/index.js": 'module.exports = require("./schematics/x");\n',
            "src/schematics/package.json": {"type": "commonjs"},
            "src/schematics/x.js": 'module.exports = require("left-pad");\n',
            # A real nested package still owns its files.
            "tools/package.json": {"name": "tools", "version": "1.0.0", "main": "t.js"},
            "tools/t.js": 'module.exports = require("right-pad");\n',
        },
    )
    q408 = _quality(_scan(root, quality=True), root, "SKY-Q408")
    assert ("src/schematics/x.js", "left-pad") not in q408
    assert ("tools/t.js", "right-pad") in q408


def test_a_root_marker_manifest_still_owns_its_files(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"type": "module"},
            "index.js": 'import pad from "left-pad";\nconsole.log(pad);\n',
        },
    )
    assert ("index.js", "left-pad") in _quality(
        _scan(root, quality=True), root, "SKY-Q408"
    )


@pytest.mark.parametrize(
    ("manifest", "marker"),
    [
        ({"type": "commonjs"}, True),
        ({"private": True, "type": "module"}, True),
        ({"name": "x"}, False),
        ({"dependencies": {"a": "1"}}, False),
        ({"scripts": {"build": "tsc"}}, False),
        ({"workspaces": ["packages/*"]}, False),
        ([], False),
    ],
)
def test_marker_manifest_predicate(manifest, marker):
    assert is_marker_manifest(manifest) is marker


# --- 2. one finding per unused file, and unreachable cycles --------------------


def test_symbols_inside_an_unused_file_fold_into_the_file_finding(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "app", "private": True, "main": "src/main.ts"},
            "src/main.ts": 'import { used } from "./live";\nconsole.log(used);\n',
            "src/live.ts": "export const used = 1;\nexport const unusedLive = 2;\n",
            "src/dead.ts": (
                'import { used } from "./live";\n'
                "export function deadHelper() { return used; }\n"
                "export const deadValue = 3;\n"
            ),
        },
    )
    result = _scan(root)
    assert _files(result, root) == {"src/dead.ts"}
    symbols = _symbols(result, root)
    assert ("src/live.ts", "unusedLive") in symbols
    assert not {name for name, _ in symbols} & {"src/dead.ts"}
    folded = result["analysis_summary"]["dead_code_folded_into_unused_files"]
    assert folded["count"] >= 2


def test_fold_keeps_findings_of_files_that_are_not_reported_unused():
    result = {
        "unused_files": [
            {"rule_id": "SKY-E003", "file": "/p/dead.ts"},
            {"rule_id": "SKY-E002", "file": "/p/empty.py"},
        ],
        "unused_functions": [
            {"file": "/p/dead.ts", "name": "a"},
            {"file": "/p/live.ts", "name": "b"},
            {"file": "/p/empty.py", "name": "c"},
        ],
        "unused_exports": [{"file": "/p/dead.ts", "name": "d", "rule_id": "SKY-E004"}],
        "quality": [
            {"file": "/p/dead.ts", "rule_id": "SKY-Q408", "name": "pkg"},
            {"file": "/p/dead.ts", "rule_id": "SKY-C303", "name": "complex"},
        ],
        "analysis_summary": {},
    }
    assert fold_findings_into_unused_files(result) == 3
    # Rows stay in their sections (other features read them there); only the
    # ones inside the unused file are tagged and listed on its finding.
    tagged = {
        item["name"]
        for key in ("unused_functions", "unused_exports", "quality")
        for item in result[key]
        if item.get("folded_into")
    }
    assert tagged == {"a", "d", "pkg"}
    assert [item["name"] for item in result["unused_functions"]] == ["a", "b", "c"]
    assert {f["name"] for f in result["unused_files"][0]["folded_findings"]} == {
        "a",
        "d",
        "pkg",
    }
    assert "folded_findings" not in result["unused_files"][1]
    assert result["analysis_summary"]["dead_code_folded_into_unused_files"] == {
        "count": 3,
        "by_rule": {"SKY-E004": 1, "SKY-Q408": 1, "unused_functions": 1},
    }
    assert [
        (item["rule_id"], item["name"])
        for item in result["unused_files"][0]["folded_findings"]
    ] == [("unused_functions", "a"), ("SKY-E004", "d"), ("SKY-Q408", "pkg")]
    assert "folded_findings" not in result["unused_files"][1]


def test_an_unreachable_import_cycle_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "app", "private": True, "main": "src/main.ts"},
            "src/main.ts": 'import { live } from "./live";\nconsole.log(live);\n',
            "src/live.ts": "export const live = 1;\n",
            "src/a.ts": 'import { b } from "./b";\nexport const a = () => b();\n',
            "src/b.ts": 'import { a } from "./a";\nexport const b = () => a();\n',
        },
    )
    assert _files(_scan(root), root) == {"src/a.ts", "src/b.ts"}


def test_a_cycle_reached_from_a_test_or_named_by_a_config_stays_live(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "app", "private": True, "main": "src/main.ts"},
            "src/main.ts": "console.log(1);\n",
            "src/a.ts": 'import { b } from "./b";\nexport const a = () => b();\n',
            "src/b.ts": 'import { a } from "./a";\nexport const b = () => a();\n',
            "src/a.test.ts": 'import { a } from "./a";\na();\n',
            "src/c.ts": 'import { d } from "./d";\nexport const c = () => d();\n',
            "src/d.ts": 'import { c } from "./c";\nexport const d = () => c();\n',
            "tsconfig.json": {"files": ["src/main.ts", "src/c.ts"]},
            "src/dead.ts": "export const dead = 1;\n",
        },
    )
    assert _files(_scan(root), root) == {"src/dead.ts"}


def test_a_large_unreachable_region_is_left_unreported(tmp_path):
    files = {
        "package.json": {"name": "app", "private": True, "main": "src/main.ts"},
        "src/main.ts": "console.log(1);\n",
    }
    count = 10
    for index in range(count):
        following = (index + 1) % count
        files[f"src/m{index}.ts"] = (
            f'import {{ f{following} }} from "./m{following}";\n'
            f"export const f{index} = () => f{following};\n"
        )
    root = _project(tmp_path, files)
    assert _files(_scan(root), root) == set()


# --- 3. type-check projects are entries ----------------------------------------


def test_type_check_fixture_projects_are_entries(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "root", "private": True, "workspaces": ["fx/*"]},
            "fx/nodenext/package.json": {
                "name": "fx-nodenext",
                "private": True,
                "scripts": {
                    "test:types": "node ../../node_modules/typescript/lib/tsc.js"
                    " --pretty false --project tsconfig.json"
                },
            },
            "fx/nodenext/tsconfig.json": {
                "compilerOptions": {"declaration": True, "emitDeclarationOnly": True},
                "include": ["./src"],
            },
            "fx/nodenext/src/hooks.ts": "export function useMyHook() { return 1; }\n",
            "fx/emit/package.json": {
                "name": "fx-emit",
                "private": True,
                "scripts": {
                    "t": "tsc -p tsconfig.emit.json && tsc --project=tsconfig.consume.json"
                },
            },
            "fx/emit/tsconfig.emit.json": {
                "compilerOptions": {"declaration": True},
                "include": ["./src"],
            },
            "fx/emit/tsconfig.consume.json": {
                "compilerOptions": {"noEmit": True},
                "include": ["./consumer"],
            },
            "fx/emit/src/q.ts": "export const a = 1;\n",
            "fx/emit/consumer/c.ts": (
                'import { a } from "../src/q";\nexport const options = { a };\n'
            ),
        },
    )
    result = _scan(root)
    assert _files(result, root) == set()
    symbols = _symbols(result, root)
    assert ("fx/nodenext/src/hooks.ts", "useMyHook") not in symbols
    # noEmit publishes nothing: the consumer's export stays judged.
    assert ("fx/emit/consumer/c.ts", "options") in symbols


def test_type_check_of_an_app_with_its_own_entries_proves_nothing(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "app",
                "private": True,
                "scripts": {"typecheck": "tsc --noEmit -p tsconfig.json"},
            },
            "tsconfig.json": {"include": ["src"]},
            "src/index.ts": "console.log(1);\n",
            "src/orphan.ts": "export const orphan = 1;\n",
        },
    )
    assert _files(_scan(root), root) == {"src/orphan.ts"}


def test_include_patterns_that_climb_out_of_the_config_are_not_entries(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "root",
                "private": True,
                "workspaces": ["fx", "lib"],
            },
            "lib/package.json": {"name": "lib", "version": "1.0.0", "main": "index.ts"},
            "lib/index.ts": "export const x = 1;\n",
            "lib/orphan.ts": "export const orphan = 1;\n",
            "fx/package.json": {
                "name": "fx",
                "private": True,
                "scripts": {"t": "ngc -p tsconfig.json"},
            },
            "fx/tsconfig.json": {
                "compilerOptions": {"noEmit": True},
                "include": ["consumer.ts", "../lib/**/*.ts"],
            },
            "fx/consumer.ts": 'import { x } from "../lib";\nconsole.log(x);\n',
        },
    )
    assert _files(_scan(root), root) == {"lib/orphan.ts"}


def test_tsconfig_project_reader_follows_extends_and_emit(tmp_path):
    _project(
        tmp_path,
        {
            "base/tsconfig.json": {
                "compilerOptions": {"declaration": True},
                "include": ["consumer.ts", "../pkg/src/**/*.ts"],
                "exclude": ["../pkg/src/**/*.test.ts"],
            },
            "fx/a/tsconfig.json": {"extends": "../../base/tsconfig.json"},
            "fx/b/tsconfig.json": {
                "extends": "@tsconfig/missing/tsconfig.json",
                "compilerOptions": {"declaration": True},
            },
            "base/consumer.ts": "export {};\n",
            "pkg/src/x.ts": "export {};\n",
            "pkg/src/x.test.ts": "export {};\n",
            "fx/b/y.ts": "export {};\n",
        },
    )
    real = os.path.realpath
    project = read_tsconfig_project(real(tmp_path / "fx/a/tsconfig.json"))
    assert project is not None and project.emits_declarations
    ts_files = {
        real(tmp_path / name)
        for name in (
            "base/consumer.ts",
            "pkg/src/x.ts",
            "pkg/src/x.test.ts",
            "fx/b/y.ts",
        )
    }
    _listed, local = project_source_files(project, ts_files, local_only=True)
    _listed, everything = project_source_files(project, ts_files, local_only=False)
    assert local == {real(tmp_path / "base/consumer.ts")}
    assert everything == {
        real(tmp_path / "base/consumer.ts"),
        real(tmp_path / "pkg/src/x.ts"),
    }
    # An uninstalled shared base leaves the options unknown: no emit claim.
    other = read_tsconfig_project(real(tmp_path / "fx/b/tsconfig.json"))
    assert other is not None and not other.emits_declarations
    assert project_source_files(other, ts_files, local_only=True)[1] == {
        real(tmp_path / "fx/b/y.ts")
    }


# --- 5. canonical identity through symlinks ------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_module_reached_through_a_symlink_is_the_linked_file(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "app", "private": True, "main": "pkg/index.ts"},
            "scripts/shared.js": (
                "export function used() { return 1; }\n"
                "export function unusedShared() { return 2; }\n"
            ),
            "pkg/index.ts": 'import { used } from "./root.config.js";\nconsole.log(used());\n',
        },
    )
    os.symlink("../scripts/shared.js", root / "pkg" / "root.config.js")
    symbols = _symbols(_scan(root), root)
    assert ("scripts/shared.js", "used") not in symbols
    assert ("scripts/shared.js", "unusedShared") in symbols


# --- 6. component pages are graph roots ----------------------------------------


def test_astro_pages_and_layouts_keep_their_imports_live(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "site",
                "private": True,
                "dependencies": {"astro": "5"},
            },
            "src/pages/index.astro": (
                '---\nimport App from "../components/App";\n'
                'import Layout from "../layouts/Layout.astro";\n---\n'
                "<Layout><App client:load /></Layout>\n"
            ),
            "src/layouts/Layout.astro": (
                '---\nimport { title } from "../lib/meta";\n---\n'
                "<html><title>{title}</title><slot /></html>\n"
            ),
            "src/lib/meta.ts": "export const title = 'x';\nexport const unusedMeta = 1;\n",
            "src/components/App.tsx": "export default function App() { return null; }\n",
            "src/components/Dead.tsx": "export default function Dead() { return null; }\n",
        },
    )
    result = _scan(root)
    assert _files(result, root) == {"src/components/Dead.tsx"}
    symbols = _symbols(result, root)
    assert ("src/components/App.tsx", "App") not in symbols
    assert ("src/lib/meta.ts", "unusedMeta") in symbols


def test_a_component_only_a_dead_loader_imports_stays_dead(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "app",
                "private": True,
                "main": "src/main.ts",
                "dependencies": {"vue": "3"},
            },
            "src/main.ts": "console.log(1);\n",
            "src/loader.ts": 'import Widget from "./Widget.vue";\nexport default Widget;\n',
            "src/Widget.vue": (
                '<script setup lang="ts">\nimport { helper } from "./helper";\n'
                "helper();\n</script>\n<template><div /></template>\n"
            ),
            "src/helper.ts": "export function helper() { return 1; }\n",
        },
    )
    assert _files(_scan(root), root) == {"src/loader.ts", "src/helper.ts"}


# --- 7. one command model ------------------------------------------------------


def test_a_webpack_entry_in_a_build_script_is_an_entry(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "root",
                "private": True,
                "scripts": {"build-node": "node ./scripts/build-node.js"},
            },
            "scripts/build-node.js": (
                'const rewire = require("rewire");\n'
                'const defaults = rewire("react-scripts/scripts/build.js");\n'
                'const config = defaults.__get__("config");\n'
                'config.entry = "../packages/app/index-node";\n'
            ),
            "packages/app/index-node.ts": "console.log(1);\n",
            "packages/app/dead.ts": "console.log(2);\n",
            # Not run by any command: its entry is not credited.
            "tools/unused-build.js": (
                'const webpack = require("webpack");\n'
                'webpack({ entry: "../packages/app/other" });\n'
            ),
            "packages/app/other.ts": "console.log(3);\n",
        },
    )
    files = _files(_scan(root), root)
    assert "packages/app/index-node.ts" not in files
    assert {"packages/app/dead.ts", "packages/app/other.ts"} <= files


def test_ci_steps_and_git_hooks_run_project_files(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "app", "private": True, "main": "src/main.ts"},
            "src/main.ts": "console.log(1);\n",
            ".github/workflows/ci.yml": (
                "on: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: npx tsx tools/check.ts --strict\n"
                "      - run: node -r ./tools/setup.cjs tools/report.mjs\n"
            ),
            ".husky/pre-commit": "#!/bin/sh\nnode tools/hook.mjs\n",
            "tools/check.ts": "export {};\nconsole.log('check');\n",
            "tools/setup.cjs": "module.exports = {};\n",
            "tools/report.mjs": "console.log('report');\n",
            "tools/hook.mjs": "console.log('hook');\n",
            "tools/orphan.mjs": "console.log('orphan');\n",
        },
    )
    assert _files(_scan(root), root) == {"tools/orphan.mjs"}


def test_command_arguments_name_projects_configs_preloads_and_entries(tmp_path):
    _project(
        tmp_path,
        {
            "tsconfig.json": {},
            "tsconfig.build.json": {},
            "lib/tsconfig.json": {},
            "vitest.unit.ts": "export default {};\n",
            "setup.mjs": "export {};\n",
            "src/index.ts": "export {};\n",
        },
    )
    real = os.path.realpath
    cwd = str(tmp_path)
    inputs = ScriptInputs()
    read_arguments("tsc", ["--pretty", "false", "-p", "lib"], cwd, inputs)
    read_arguments("tsc", ["-b", "tsconfig.build.json", "--verbose"], cwd, inputs)
    read_arguments("vitest", ["run", "--config=vitest.unit.ts"], cwd, inputs)
    read_arguments("node", ["--import=./setup.mjs"], cwd, inputs)
    read_arguments("tsdown", ["src/index.ts", "--format", "esm"], cwd, inputs)
    read_arguments("unknown-tool", ["src/index.ts"], cwd, inputs)
    assert set(inputs.projects) == {
        real(tmp_path / "lib/tsconfig.json"),
        real(tmp_path / "tsconfig.build.json"),
    }
    assert set(inputs.configs) == {real(tmp_path / "vitest.unit.ts")}
    assert inputs.entries == {
        real(tmp_path / "setup.mjs"): "command-preload",
        real(tmp_path / "src/index.ts"): "command-entry",
    }

    built = ScriptInputs()
    read_command_line("tsc --build", cwd, built, lenient=False)
    assert set(built.projects) == {real(tmp_path / "tsconfig.json")}
    plain = ScriptInputs()
    read_command_line("tsc --noEmit", cwd, plain, lenient=False)
    assert plain.projects == {}


@pytest.mark.parametrize(
    ("script", "binary"),
    [
        ("../../node_modules/typescript/lib/tsc.js", "tsc"),
        ("node_modules/typescript71/lib/tsc.js", "tsc"),
        ("./node_modules/.bin/vue-tsc", "vue-tsc"),
        ("node_modules/@angular/compiler-cli/bundles/src/bin/ngc.js", "ngc"),
        ("scripts/tsc.js", None),
        ("node_modules/some-tool/cli.js", None),
    ],
)
def test_installed_binary_scripts_run_their_binary(script, binary):
    assert _installed_binary(script) == binary


def test_bundler_entries_need_a_bundler_and_a_path(tmp_path):
    _project(
        tmp_path,
        {
            "build.js": (
                'const { rollup } = require("rollup");\n'
                'rollup({ input: ["./src/a.ts", "react"], entry: `./src/${x}.ts` });\n'
            ),
            "plain.js": 'const options = { entry: "./src/b.ts" };\n',
            "src/a.ts": "export {};\n",
            "src/b.ts": "export {};\n",
        },
    )
    real = os.path.realpath
    ts_files = {real(tmp_path / "src/a.ts"), real(tmp_path / "src/b.ts")}
    assert bundler_script_entries(
        real(tmp_path / "build.js"), str(tmp_path), ts_files
    ) == {real(tmp_path / "src/a.ts")}
    assert (
        bundler_script_entries(real(tmp_path / "plain.js"), str(tmp_path), ts_files)
        == set()
    )


# --- 10. public methods of external contracts ----------------------------------


def _contract_methods(root: Path, header: str, implements: str) -> set[str]:
    _project(
        root,
        {
            "package.json": {
                "name": "app",
                "private": True,
                "main": "src/main.ts",
                "dependencies": {"some-lib": "1"},
            },
            "src/contract.ts": "export interface Runner { dispose(): void }\n",
            "src/main.ts": (
                'import { Clock } from "./clock";\n'
                "const c = new Clock({ register() {} });\nconsole.log(c.value);\n"
            ),
            "src/clock.ts": (
                header
                + f"export abstract class Base{implements} {{\n"
                + "  constructor(protected host: { register(c: unknown): void }) {\n"
                + "    host.register(this);\n  }\n"
                + "  dispose(): void {}\n  refresh(): void {}\n"
                + "  protected unusedHelper(): number { return 1; }\n}\n"
                + "export class Clock extends Base {\n  value = 1;\n}\n"
            ),
        },
    )
    return {
        name
        for key, rel, name in _reported(_scan(root), root)
        if key == "unused_functions" and rel == "src/clock.ts"
    }


def test_public_methods_of_an_external_contract_are_not_judged(tmp_path):
    header = 'import type { Disposable } from "some-lib";\n'
    assert _contract_methods(tmp_path, header, " implements Disposable") == {
        "unusedHelper"
    }


@pytest.mark.parametrize(
    ("header", "implements"),
    [
        ('import type { Runner } from "./contract";\n', " implements Runner"),
        ('import type { Disposable } from "some-lib";\nvoid 0;\n', ""),
    ],
)
def test_methods_of_project_contracts_and_plain_classes_stay_judged(
    tmp_path, header, implements
):
    assert _contract_methods(tmp_path, header, implements) == {
        "dispose",
        "refresh",
        "unusedHelper",
    }


# --- 12. scripts/ and examples/ files need evidence ------------------------------


def test_scripts_and_examples_need_evidence_to_be_roots(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "app",
                "private": True,
                "main": "src/main.ts",
                "scripts": {"build": "node scripts/build.js"},
            },
            "src/main.ts": "console.log(1);\n",
            # Run by a package script, and what it imports.
            "scripts/build.js": 'require("./buildUtils");\n',
            "scripts/buildUtils.js": "module.exports = 1;\n",
            # Named by nothing: reported.
            "scripts/buildDocs.js": 'const { exec } = require("child_process");\nexec("git diff");\n',
            "examples/demo/src/orphanDemo.ts": "export const demo = 1;\n",
            # Named in a generated file's comment, documented, or executable.
            "scripts/buildWasm.js": "console.log(1);\n",
            "src/generated.ts": "// generated with `scripts/buildWasm.js`\nconsole.log(2);\n",
            "scripts/documented.js": "console.log(1);\n",
            "README.md": "Run `node scripts/documented.js` to rebuild.\n",
            "scripts/release.js": "#!/usr/bin/env node\nconsole.log(1);\n",
            # An entry file by name stays a root.
            "examples/demo/src/main.ts": "console.log(1);\n",
        },
    )
    files = _files(_scan(root), root)
    assert {"scripts/buildDocs.js", "examples/demo/src/orphanDemo.ts"} <= files
    assert not files & {
        "scripts/build.js",
        "scripts/buildUtils.js",
        "scripts/buildWasm.js",
        "scripts/documented.js",
        "scripts/release.js",
        "examples/demo/src/main.ts",
    }


def test_a_scripts_file_imported_by_a_live_file_stays_live(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "app", "private": True, "main": "src/main.ts"},
            "src/main.ts": 'import { helper } from "../scripts/shared";\nconsole.log(helper);\n',
            "scripts/shared.ts": "export const helper = 1;\n",
        },
    )
    assert _files(_scan(root), root) == set()


def test_a_svelte_route_importing_a_rune_module_keeps_it_live(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {
                "name": "app",
                "private": True,
                "dependencies": {"@sveltejs/kit": "2", "svelte": "5"},
            },
            "src/lib/state.svelte.ts": "export const count = 1;\n",
            "src/lib/unused.svelte.ts": "export const other = 1;\n",
            "src/routes/+page.svelte": (
                '<script lang="ts">\nimport { count } from "$lib/state.svelte";\n'
                "console.log(count);\n</script>\n"
            ),
        },
    )
    files = _files(_scan(root), root)
    assert "src/lib/state.svelte.ts" not in files
    assert "src/lib/unused.svelte.ts" in files


def test_import_equals_bindings_are_imports_for_contracts(tmp_path):
    from skylos.visitors.languages.typescript import scan_typescript_file

    path = _write(
        tmp_path / "terminal.ts",
        'import api = require("vscode");\n'
        "export class Terminal implements api.Pseudoterminal {\n"
        "  open(): void {}\n}\n"
        "export class Listener implements EventListenerObject {\n"
        "  handleEvent(): void {}\n}\n",
    )
    names = {definition.name for definition in scan_typescript_file(str(path))[0]}
    # ``vscode`` is not a declared dependency here, so the imported contract
    # is a project-facing name and stays judged; the ambient DOM type is not.
    assert "Terminal.open" in names
    assert "Listener.handleEvent" not in names


def test_a_package_without_entries_is_not_judged_for_missing_evidence(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "root", "private": True, "main": "src/main.ts"},
            "src/main.ts": "console.log(1);\n",
            # A lint demo: ``eslint ./src`` reads these files, nothing runs them.
            "examples/lint-demo/package.json": {
                "name": "lint-demo",
                "private": True,
                "scripts": {"test:eslint": "eslint ./src"},
            },
            "examples/lint-demo/src/rule-demo.tsx": "export const demo = 1;\n",
            "examples/app/package.json": {"name": "app-demo", "private": True},
            "examples/app/src/main.ts": "console.log(1);\n",
            "examples/app/src/forgotten.ts": "export const forgotten = 1;\n",
        },
    )
    files = _files(_scan(root), root)
    assert "examples/lint-demo/src/rule-demo.tsx" not in files
    assert "examples/app/src/forgotten.ts" in files


def test_a_package_with_only_tool_configs_is_not_judged_for_missing_evidence(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": {"name": "root", "private": True, "main": "src/main.ts"},
            "src/main.ts": "console.log(1);\n",
            "examples/lint-demo/package.json": {
                "name": "lint-demo",
                "private": True,
                "scripts": {"test:eslint": "eslint ./src"},
            },
            "examples/lint-demo/eslint.config.js": "export default [];\n",
            "examples/lint-demo/src/rule-demo.tsx": "export const demo = 1;\n",
        },
    )
    assert "examples/lint-demo/src/rule-demo.tsx" not in _files(_scan(root), root)
