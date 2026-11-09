from __future__ import annotations

import json
import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.done import checks as done_checks
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext
from skylos.done.config import DoneConfig
from skylos.rules.ai_defect import diff_dependencies as diff_mod
from skylos.rules.ai_defect.diff_dependencies import (
    _parse_added_lines,
    scan_diff_dependency_hallucinations,
)

PACKAGE = {
    "name": "shop",
    "dependencies": {"zod": "^3.23.8", "lodash": "^4.17.21"},
    "devDependencies": {"vitest": "^2.0.0"},
    "peerDependencies": {"react": "^18.0.0"},
    "optionalDependencies": {"fsevents": "^2.3.0"},
}


class Registry:
    def __init__(self, missing=(), unknown=()):
        self.missing = set(missing)
        self.unknown = set(unknown)
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, ecosystem, name, version, _cache):
        self.calls.append((ecosystem, name, version))
        if name in self.unknown:
            return "unknown"
        if name in self.missing:
            return "missing_package"
        return "present"


@pytest.fixture(autouse=True)
def _isolated_registry_config(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in (
        "npm_config_registry",
        "NPM_CONFIG_REGISTRY",
        "YARN_NPM_REGISTRY_SERVER",
        "YARN_REGISTRY",
    ):
        monkeypatch.delenv(name, raising=False)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, {"package.json": json.dumps(PACKAGE, indent=2) + "\n", **files})
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


def _change(root: Path, files: dict[str, str]) -> str:
    _write(root, files)
    _git(root, "add", "-A")
    return _git(root, "diff", "--cached")


def _scan(root: Path, diff: str, registry: Registry) -> dict:
    return scan_diff_dependency_hallucinations(diff, str(root), status_checker=registry)


def _ids(result: dict) -> list[tuple[str, str, int, str]]:
    return sorted(
        (f["rule_id"], f["file"], f["line"], f["symbol"]) for f in result["findings"]
    )


CHECKOUT = (
    'import { z } from "zod";\n\nexport const Order = z.object({ id: z.string() });\n'
)


def test_made_up_package_imported_by_typescript_is_reported(tmp_path):
    root = _repo(tmp_path, {"web/checkout.ts": CHECKOUT})
    diff = _change(
        root,
        {
            "web/checkout.ts": 'import { z } from "zod";\n'
            'import { charge } from "stripe-checkout-pro";\n\n'
            "export const Order = z.object({ id: z.string() });\n"
            "export const pay = (id: string) => charge(id);\n"
        },
    )
    registry = Registry(missing={"stripe-checkout-pro"})
    result = _scan(root, diff, registry)
    assert _ids(result) == [("SKY-D222", "web/checkout.ts", 2, "stripe-checkout-pro")]
    assert result["findings"][0]["severity"] == "CRITICAL"
    assert result["findings"][0]["kind"] == "hallucinated_import"
    assert registry.calls == [("npm", "stripe-checkout-pro", "*")]
    assert result["registry_unreachable"] is False
    assert result["unchecked_import_files"] == {}


def test_every_module_loader_form_is_read(tmp_path):
    root = _repo(tmp_path, {"src/keep.ts": "export const keep = 1;\n"})
    loaders = dedent(
        """\
        import "side-effect-ghost";
        import def from "default-ghost";
        export * from "reexport-ghost";
        export { thing } from "named-reexport-ghost";
        import legacy = require("import-equals-ghost");
        const lazy = await import("dynamic-ghost");
        const cjs = require("require-ghost");
        import type { Shape } from "type-only-ghost";
        import client from "@ghost-scope/sdk/client";
        export const all = [def, legacy, lazy, cjs, client];
        """
    )
    diff = _change(
        root,
        {
            "src/loaders.ts": loaders,
            "src/view.jsx": 'import Chart from "jsx-ghost";\n'
            "export const View = () => <Chart />;\n",
            "src/legacy.cjs": 'const old = require("cjs-ghost");\nmodule.exports = old;\n',
        },
    )
    names = {
        "side-effect-ghost",
        "default-ghost",
        "reexport-ghost",
        "named-reexport-ghost",
        "import-equals-ghost",
        "dynamic-ghost",
        "require-ghost",
        "type-only-ghost",
        "@ghost-scope/sdk",
        "jsx-ghost",
        "cjs-ghost",
    }
    result = _scan(root, diff, Registry(missing=names))
    assert _ids(result) == sorted(
        [
            ("SKY-D222", "src/loaders.ts", 1, "side-effect-ghost"),
            ("SKY-D222", "src/loaders.ts", 2, "default-ghost"),
            ("SKY-D222", "src/loaders.ts", 3, "reexport-ghost"),
            ("SKY-D222", "src/loaders.ts", 4, "named-reexport-ghost"),
            ("SKY-D222", "src/loaders.ts", 5, "import-equals-ghost"),
            ("SKY-D222", "src/loaders.ts", 6, "dynamic-ghost"),
            ("SKY-D222", "src/loaders.ts", 7, "require-ghost"),
            ("SKY-D222", "src/loaders.ts", 8, "type-only-ghost"),
            ("SKY-D222", "src/loaders.ts", 9, "@ghost-scope/sdk"),
            ("SKY-D222", "src/view.jsx", 1, "jsx-ghost"),
            ("SKY-D222", "src/legacy.cjs", 1, "cjs-ghost"),
        ]
    )


def test_local_builtin_declared_and_non_package_specifiers_stay_silent(tmp_path):
    root = _repo(tmp_path, {"web/app.ts": "export const ready = true;\n"})
    quiet = dedent(
        """\
        import a from "./local";
        import b from "../shared/b";
        import c from "/abs/path";
        import fs from "fs";
        import fsp from "fs/promises";
        import { join } from "node:path";
        import { test } from "node:test";
        import { z } from "zod";
        import fp from "lodash/fp";
        import { describe } from "vitest";
        import React from "react";
        import type { Schema } from "zod";
        import events from "fsevents";
        import Button from "@/components/Button";
        import icon from "~icons/mdi/home";
        import { registerSW } from "virtual:pwa-register";
        import { expect } from "bun:test";
        import inline from "data:text/javascript,export default 1";
        import remote from "https://esm.sh/preact";
        import internal from "#internal/util";
        import lib from "$lib/util";
        const s = "import x from 'ghost-in-string'";
        // import y from "ghost-in-comment";
        /* require("ghost-in-block-comment") */
        const t = `require("ghost-in-template")`;
        const page = await import(`./pages/${s}`);
        export const used = [a, b, c, fs, fsp, join, test, z, fp, describe, React];
        export const more = [events, Button, icon, registerSW, expect, inline, remote];
        export const rest = [internal, lib, t, page];
        """
    )
    diff = _change(root, {"web/app.ts": quiet})
    registry = Registry(missing={"ghost-in-string", "ghost-in-comment"})
    result = _scan(root, diff, registry)
    assert result["findings"] == []
    assert registry.calls == []
    assert result["unchecked_import_files"] == {}


def test_workspace_path_alias_and_bundler_alias_claims_stay_silent(tmp_path):
    root = _repo(
        tmp_path,
        {
            "packages/kit/package.json": '{"name": "@shop/kit"}\n',
            "packages/ui/package.json": '{"name": "ui-kit"}\n',
            "tsconfig.json": json.dumps(
                {"compilerOptions": {"baseUrl": ".", "paths": {"@app/*": ["src/*"]}}}
            ),
            "legacy/jsconfig.json": json.dumps(
                {"compilerOptions": {"paths": {"oldlib/*": ["lib/*"]}}}
            ),
            "legacy/main.js": "module.exports = {};\n",
            "vite.config.ts": dedent(
                """\
                export default {
                  resolve: { alias: { "stripe-checkout-pro": "./src/stub.ts" } },
                };
                """
            ),
            "src/utils/format.ts": "export const format = String;\n",
            "src/global-config.tsx": "export const GlobalConfig = 1;\n",
            "src/main.ts": "export const main = 1;\n",
        },
    )
    root_package = dict(PACKAGE, workspaces=["packages/*"])
    diff = _change(
        root,
        {
            "package.json": json.dumps(root_package, indent=2) + "\n",
            "src/main.ts": dedent(
                """\
                import { button } from "@shop/kit/button";
                import { theme } from "ui-kit";
                import { Order } from "@app/models";
                import { pay } from "stripe-checkout-pro";
                import { format } from "utils/format";
                import { GlobalConfig } from "global-config";
                export const main = [button, theme, Order, pay, format, GlobalConfig];
                """
            ),
            "legacy/main.js": 'const thing = require("oldlib/thing");\n'
            "module.exports = { thing };\n",
        },
    )
    registry = Registry(
        missing={"ui-kit", "stripe-checkout-pro", "oldlib", "global-config"}
    )
    result = _scan(root, diff, registry)
    assert result["findings"] == []
    assert registry.calls == []


def test_types_package_installed_and_nested_declarations_stay_silent(tmp_path):
    package = dict(PACKAGE, devDependencies={"@types/vscode": "^1.90.0"})
    root = _repo(
        tmp_path,
        {
            "web/package.json": '{"name": "web", "dependencies": {"chart.js": "^4"}}\n',
            "web/app.ts": "export const app = 1;\n",
            "ext/main.ts": "export const ext = 1;\n",
            "node_modules/left-pad/package.json": '{"name": "left-pad"}\n',
        },
    )
    _write(root, {"package.json": json.dumps(package, indent=2) + "\n"})
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "types")
    diff = _change(
        root,
        {
            "web/app.ts": 'import Chart from "chart.js";\nexport const app = Chart;\n',
            "ext/main.ts": 'import * as vscode from "vscode";\n'
            'import pad from "left-pad";\n'
            "export const ext = [vscode, pad];\n",
        },
    )
    registry = Registry(missing={"chart.js", "vscode", "left-pad"})
    result = _scan(root, diff, registry)
    assert result["findings"] == []
    assert registry.calls == []


def test_ambient_declaration_already_in_the_project_claims_the_import(tmp_path):
    root = _repo(
        tmp_path,
        {
            "types/ghost.d.ts": 'declare module "stripe-checkout-pro";\n',
            "web/checkout.ts": CHECKOUT,
        },
    )
    diff = _change(
        root,
        {
            "web/checkout.ts": 'import { charge } from "stripe-checkout-pro";\n'
            + CHECKOUT
        },
    )
    registry = Registry(missing={"stripe-checkout-pro"})
    assert _scan(root, diff, registry)["findings"] == []
    assert registry.calls == []


def test_ambient_declaration_added_by_the_same_change_does_not_hide_the_import(
    tmp_path,
):
    root = _repo(tmp_path, {"web/checkout.ts": CHECKOUT})
    diff = _change(
        root,
        {
            "types/ghost.d.ts": 'declare module "stripe-checkout-pro";\n',
            "web/checkout.ts": 'import { charge } from "stripe-checkout-pro";\n'
            + CHECKOUT,
        },
    )
    result = _scan(root, diff, Registry(missing={"stripe-checkout-pro"}))
    assert _ids(result) == [("SKY-D222", "web/checkout.ts", 1, "stripe-checkout-pro")]


def test_package_that_exists_but_is_undeclared_is_advice(tmp_path):
    root = _repo(tmp_path, {"web/app.ts": "export const app = 1;\n"})
    diff = _change(
        root,
        {"web/app.ts": 'import dayjs from "dayjs";\nexport const app = dayjs;\n'},
    )
    registry = Registry()
    result = _scan(root, diff, registry)
    assert _ids(result) == [("SKY-D223", "web/app.ts", 1, "dayjs")]
    assert result["findings"][0]["kind"] == "undeclared_import"
    assert registry.calls == [("npm", "dayjs", "*")]


def test_unreachable_registry_is_incomplete_and_stops_further_lookups(tmp_path):
    root = _repo(tmp_path, {"web/app.ts": "export const app = 1;\n"})
    diff = _change(
        root,
        {
            "web/app.ts": 'import a from "first-ghost";\n'
            'import b from "second-ghost";\n'
            "export const app = [a, b];\n"
        },
    )
    registry = Registry(unknown={"first-ghost"}, missing={"second-ghost"})
    result = _scan(root, diff, registry)
    assert result["findings"] == []
    assert result["registry_unreachable"] is True
    assert registry.calls == [("npm", "first-ghost", "*")]


def test_unchanged_import_lines_are_not_looked_up(tmp_path):
    source = 'import ghost from "ghost-pkg";\nexport const value = 1;\n'
    root = _repo(tmp_path, {"web/app.ts": source})
    diff = _change(
        root,
        {"web/app.ts": 'import ghost from "ghost-pkg";\nexport const value = 2;\n'},
    )
    registry = Registry(missing={"ghost-pkg"})
    assert _scan(root, diff, registry)["findings"] == []
    assert registry.calls == []


def test_lines_after_a_missing_final_newline_keep_their_numbers(tmp_path):
    root = _repo(tmp_path, {"web/app.ts": "export const a = 1;"})
    diff = _change(
        root,
        {
            "web/app.ts": "export const a = 1;\n"
            'import ghost from "ghost-pkg";\n'
            "export const b = ghost;\n"
        },
    )
    assert "\\ No newline at end of file" in diff
    assert _parse_added_lines(diff) == [
        (
            "web/app.ts",
            [
                (1, "export const a = 1;"),
                (2, 'import ghost from "ghost-pkg";'),
                (3, "export const b = ghost;"),
            ],
        )
    ]
    result = _scan(root, diff, Registry(missing={"ghost-pkg"}))
    assert _ids(result) == [("SKY-D222", "web/app.ts", 2, "ghost-pkg")]


@pytest.mark.parametrize(
    "files",
    [
        {".npmrc": "registry=https://npm.internal.example/\n"},
        {".yarnrc.yml": "npmRegistryServer: https://npm.internal.example\n"},
        {"web/.npmrc": "registry = https://npm.internal.example/\n"},
    ],
    ids=["npmrc", "yarnrc-yml", "nested-npmrc"],
)
def test_private_registry_leaves_imports_unchecked(tmp_path, files):
    root = _repo(tmp_path, {"web/app.ts": "export const app = 1;\n", **files})
    diff = _change(
        root,
        {"web/app.ts": 'import ghost from "ghost-pkg";\nexport const app = ghost;\n'},
    )
    registry = Registry(missing={"ghost-pkg"})
    result = _scan(root, diff, registry)
    assert result["findings"] == []
    assert registry.calls == []
    assert result["unchecked_import_files"] == {"JavaScript/TypeScript": 1}


def test_private_registry_in_home_config_leaves_imports_unchecked(tmp_path):
    root = _repo(tmp_path, {"web/app.ts": "export const app = 1;\n"})
    (tmp_path / "home" / ".npmrc").write_text(
        "registry=https://npm.internal.example/\n", encoding="utf-8"
    )
    diff = _change(
        root,
        {"web/app.ts": 'import ghost from "ghost-pkg";\nexport const app = ghost;\n'},
    )
    registry = Registry(missing={"ghost-pkg"})
    assert _scan(root, diff, registry)["findings"] == []
    assert registry.calls == []


def test_private_scope_covers_only_its_own_packages(tmp_path):
    root = _repo(
        tmp_path,
        {
            "web/app.ts": "export const app = 1;\n",
            ".npmrc": "@acme:registry=https://npm.internal.example/\n"
            "registry=https://registry.npmjs.org/\n",
            ".yarnrc.yml": "npmScopes:\n  corp:\n    npmRegistryServer: https://npm.corp.example\n",
        },
    )
    diff = _change(
        root,
        {
            "web/app.ts": 'import billing from "@acme/billing";\n'
            'import auth from "@corp/auth";\n'
            'import ghost from "ghost-pkg";\n'
            "export const app = [billing, auth, ghost];\n"
        },
    )
    registry = Registry(missing={"@acme/billing", "@corp/auth", "ghost-pkg"})
    result = _scan(root, diff, registry)
    assert _ids(result) == [("SKY-D222", "web/app.ts", 3, "ghost-pkg")]
    assert registry.calls == [("npm", "ghost-pkg", "*")]
    assert result["unchecked_import_files"] == {"JavaScript/TypeScript": 1}


def test_file_that_does_not_parse_is_counted_as_unchecked(tmp_path):
    root = _repo(tmp_path, {"web/app.ts": "export const app = 1;\n"})
    diff = _change(root, {"web/app.ts": 'import { from "ghost-pkg";\n'})
    registry = Registry(missing={"ghost-pkg"})
    result = _scan(root, diff, registry)
    assert result["findings"] == []
    assert registry.calls == []
    assert result["unchecked_import_files"] == {"JavaScript/TypeScript": 1}


def test_done_imports_check_blocks_a_made_up_npm_import(tmp_path, monkeypatch):
    root = _repo(tmp_path, {"web/checkout.ts": CHECKOUT})
    _write(
        root,
        {
            "web/checkout.ts": 'import { charge } from "stripe-checkout-pro";\n'
            + CHECKOUT
        },
    )
    registry = Registry(missing={"stripe-checkout-pro"})
    monkeypatch.setattr(diff_mod, "check_dependency_version_status", registry)
    result = done_checks.check_unknown_imports(
        CheckContext(open_comparison(root, None), DoneConfig())
    )
    assert result.status == "fail"
    assert [(f.rule, f.file, f.line, f.blocking) for f in result.findings] == [
        ("SKY-D222", "web/checkout.ts", 1, True)
    ]
    assert result.summary == "1 import(s) or package(s) do not exist"


def test_done_imports_summary_names_languages_it_did_not_check(tmp_path, monkeypatch):
    root = _repo(tmp_path, {"cmd/main.go": "package main\n\nfunc main() {}\n"})
    _write(
        root,
        {
            "cmd/main.go": 'package main\n\nimport "github.com/ghost/sdk"\n\n'
            "func main() { sdk.Run() }\n"
        },
    )
    registry = Registry()
    monkeypatch.setattr(diff_mod, "check_dependency_version_status", registry)
    result = done_checks.check_unknown_imports(
        CheckContext(open_comparison(root, None), DoneConfig())
    )
    assert result.status == "pass"
    assert result.summary == (
        "Every added import and package resolves; "
        "imports in 1 Go file(s) were not checked"
    )
    assert result.evidence["unchecked_import_files"] == {"Go": 1}
    assert registry.calls == []


def test_framework_runtime_and_bundler_provided_modules_stay_silent(tmp_path):
    root = _repo(
        tmp_path,
        {
            "docs/package.json": '{"name": "docs", "dependencies": {"@docusaurus/core": "^3"}}\n',
            "docs/src/page.tsx": "export const page = 1;\n",
            "app/package.json": '{"name": "app", "devDependencies": {"vite": "^6"}}\n',
            "app/main.ts": "export const main = 1;\n",
            "ext/package.json": '{"name": "ext", "engines": {"vscode": "^1.90.0"}}\n',
            "ext/extension.ts": "export const ext = 1;\n",
            "lib/rolldown.config.ts": "export default { external: ['@acme/virtual-env'] };\n",
            "lib/index.ts": "export const lib = 1;\n",
            "deno/plugin/deno.json": '{"name": "@fresh/plugin-x", "exports": "./mod.ts"}\n',
            "deno/www/deno.precompile.json": '{"imports": {"@std/assert": "jsr:@std/assert@^1"}}\n',
            "deno/www/dev.ts": "export const dev = 1;\n",
        },
    )
    diff = _change(
        root,
        {
            "docs/src/page.tsx": 'import Layout from "@theme/Layout";\n'
            'import { useHistory } from "@docusaurus/router";\n'
            'import Home from "@site/src/components/Home";\n'
            "export const page = [Layout, useHistory, Home];\n",
            "app/main.ts": 'import "@vite/client";\nexport const main = 1;\n',
            "ext/extension.ts": 'import * as vscode from "vscode";\nexport const ext = vscode;\n',
            "lib/index.ts": 'import "@acme/virtual-env";\n'
            'import { serve } from "bun";\n'
            "export const lib = serve;\n",
            "deno/www/dev.ts": 'import tailwind from "@fresh/plugin-x";\n'
            'import { assert } from "@std/assert";\n'
            'import "uno.css";\n'
            "export const dev = [tailwind, assert];\n",
        },
    )
    registry = Registry(
        missing={
            "@theme/Layout",
            "@docusaurus/router",
            "@site/src",
            "@vite/client",
            "vscode",
            "@acme/virtual-env",
            "bun",
            "@fresh/plugin-x",
            "@std/assert",
            "uno.css",
        }
    )
    result = _scan(root, diff, registry)
    assert result["findings"] == []
    assert registry.calls == []


def test_framework_alias_needs_the_framework_to_be_declared(tmp_path):
    root = _repo(tmp_path, {"web/page.tsx": "export const page = 1;\n"})
    diff = _change(
        root,
        {
            "web/page.tsx": 'import { useHistory } from "@docusaurus/router";\n'
            "export const page = useHistory;\n"
        },
    )
    result = _scan(root, diff, Registry(missing={"@docusaurus/router"}))
    assert _ids(result) == [("SKY-D222", "web/page.tsx", 1, "@docusaurus/router")]


def test_transform_fixtures_are_unchecked_but_test_files_are_read(tmp_path):
    root = _repo(tmp_path, {"src/keep.ts": "export const keep = 1;\n"})
    diff = _change(
        root,
        {
            "codemod/__testfixtures__/rename.input.ts": 'import { a } from "other-pkg";\n',
            "codemod/transforms/rename.output.ts": 'import { a } from "other-pkg";\n',
            "src/keep.test.ts": 'import { helper } from "ghost-test-helper";\n'
            "export const t = helper;\n",
        },
    )
    registry = Registry(missing={"other-pkg", "ghost-test-helper"})
    result = _scan(root, diff, registry)
    assert _ids(result) == [("SKY-D222", "src/keep.test.ts", 1, "ghost-test-helper")]
    assert registry.calls == [("npm", "ghost-test-helper", "*")]
    assert result["unchecked_import_files"] == {"JavaScript/TypeScript": 2}
