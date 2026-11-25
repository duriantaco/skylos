import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.deadcode.sveltekit import discover_sveltekit_entries

VITE_CONFIG = """\
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
export default defineConfig({ plugins: [sveltekit()] });
"""

KIT_MANIFEST = {
    "private": True,
    "type": "module",
    "devDependencies": {"@sveltejs/kit": "^2.55.0"},
}


def _write_project(root, files):
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def _warnings(root):
    report = json.loads(
        analyze(str(root), conf=60, grep_verify=False, enable_danger=False)
    )
    assert not report.get("analysis_errors"), report.get("analysis_errors")

    def relpath(finding):
        path = Path(finding["file"])
        return (
            path.relative_to(root).as_posix() if path.is_absolute() else path.as_posix()
        )

    return (
        {relpath(row) for row in report.get("unused_files", ())},
        {
            (relpath(row), row.get("simple_name") or row["name"])
            for category in ("unused_functions", "unused_variables", "unused_exports")
            for row in report.get(category, ())
        },
    )


def test_sveltekit_reads_real_route_exports_and_component_bindings(tmp_path):
    _write_project(
        tmp_path,
        {
            "package.json": json.dumps(KIT_MANIFEST),
            "vite.config.js": VITE_CONFIG,
            "svelte.config.js": "export default { kit: {} };\n",
            "src/hooks.server.js": "export function handle({ event, resolve }) { return resolve(event); }\n",
            "src/routes/+page.server.js": (
                "import { getData } from '$lib/server.js';\n"
                "export function load() { return getData(); }\n"
                "export function _abandonedSibling() { return 0; }\n"
                "export function _localOnly() { return 2; }\n"
                "console.log(_localOnly());\n"
            ),
            "src/routes/+page.svelte": (
                "<script>import Card from '$lib/Card.svelte';</script><Card />\n"
            ),
            "src/routes/named/+page.js": "export { getData as load } from '$lib/server.js';\n",
            "src/routes/private/+page.server.js": "function load() { return 3; }\n",
            "src/routes/nested/package.json": '{"name": "nested"}',
            "src/routes/nested/+page.js": (
                "export function load() { return {}; }\n"
                "export function _deadInNestedRoute() { return 4; }\n"
            ),
            "src/lib/Card.svelte": (
                "<script>import { label } from '$lib/labels.js';\n"
                "import { state } from '$lib/state.svelte';</script>"
                "<p>{label} {state}</p>\n"
            ),
            "src/lib/labels.js": "export const label = 'used';\n",
            "src/lib/labels.ts": "export const label = 'unused';\n",
            "src/lib/state.svelte.ts": "export const state: string = 'ready';\n",
            "src/lib/server.js": (
                "import { ok } from './status.js';\n"
                "export function getData() { return { ok }; }\n"
            ),
            "src/lib/status.js": "export const ok = true;\n",
            "src/lib/status.ts": "export const ok = false;\n",
            "src/routes/orphan/+layout.svelte": (
                "<script>import { orphan } from '$lib/orphan.js';</script>{orphan}\n"
            ),
            "src/lib/orphan.js": "export const orphan = 'unused';\n",
            "src/ordinary/+page.js": "export function load() { return 1; }\n",
        },
    )

    files, symbols = _warnings(tmp_path)

    assert {"src/lib/orphan.js", "src/ordinary/+page.js", "src/lib/labels.ts", "src/lib/status.ts"} <= files
    assert not files.intersection(
        {
            "src/hooks.server.js",
            "src/routes/+page.server.js",
            "src/routes/named/+page.js",
            "src/routes/nested/+page.js",
            "src/lib/labels.js",
            "src/lib/state.svelte.ts",
            "src/lib/server.js",
            "src/lib/status.js",
        }
    )
    assert {
        ("src/routes/+page.server.js", "_abandonedSibling"),
        ("src/routes/+page.server.js", "_localOnly"),
        ("src/routes/private/+page.server.js", "load"),
        ("src/routes/nested/+page.js", "_deadInNestedRoute"),
        ("src/ordinary/+page.js", "load"),
        ("src/lib/orphan.js", "orphan"),
        ("src/lib/labels.ts", "label"),
        ("src/lib/status.ts", "ok"),
    } <= symbols
    assert not symbols.intersection(
        {
            ("src/hooks.server.js", "handle"),
            ("src/routes/+page.server.js", "load"),
            ("src/routes/named/+page.js", "load"),
            ("src/routes/nested/+page.js", "load"),
            ("src/lib/server.js", "getData"),
            ("src/lib/labels.js", "label"),
            ("src/lib/state.svelte.ts", "state"),
            ("src/lib/status.js", "ok"),
        }
    )


@pytest.mark.parametrize("kit", [False, True])
def test_sveltekit_root_admission_uses_package_and_proven_config(tmp_path, kit):
    _write_project(
        tmp_path,
        {
            "package.json": json.dumps(KIT_MANIFEST if kit else {"private": True}),
            "vite.config.js": VITE_CONFIG,
            "svelte.config.js": (
                "import { redirect } from './redirect.js';\n"
                "const config = { kit: {} };\n"
                "const initialized = redirect(config);\n"
                "export default config;\n"
                if kit
                else "export default { kit: {} };\n"
            ),
            "redirect.js": (
                "export function redirect(config) { config.kit.files = { routes: 'app/routes' }; }\n"
            ),
            "src/routes/+page.svelte": "<p>Unused route</p>\n",
            "src/routes/+page.js": "export function load() { return 1; }\n",
        },
    )

    files, symbols = _warnings(tmp_path)

    exact = discover_sveltekit_entries(tmp_path, list(tmp_path.rglob("*.js")))
    assert not exact.module_exports
    assert not exact.components
    # Opaque Kit config retains the upstream convention until we can prove
    # a different route directory. Plain projects have no Kit convention.
    assert ("src/routes/+page.js" in files) is not kit
    assert (("src/routes/+page.js", "load") in symbols) is not kit


def test_sveltekit_literal_route_directory_keeps_default_lookalike_unused(tmp_path):
    _write_project(
        tmp_path,
        {
            "package.json": json.dumps(KIT_MANIFEST),
            "vite.config.js": VITE_CONFIG,
            "svelte.config.js": (
                "export default { kit: { files: { routes: 'app/routes', lib: 'app/lib' } } };\n"
            ),
            "src/routes/+page.js": "export const load = () => ({ mode: 'unused' });\n",
            "app/routes/+page.js": (
                "function data() { return { mode: 'active' }; }\n"
                "export { data as load };\n"
            ),
            "app/routes/+page.server.js": (
                "export { data as load, maintenance as _maintenance } from '$lib/data.js';\n"
            ),
            "src/lib/data.js": "export const maintenance = () => 'dead default alias';\n",
            "src/routes/+page.svelte": "<p>Unused default route</p>\n",
            "app/lib/data.js": (
                "export const data = () => ({ mode: 'active' });\n"
                "export const maintenance = () => 'required by re-export';\n"
            ),
        },
    )

    files, symbols = _warnings(tmp_path)

    assert "src/routes/+page.js" in files
    assert ("src/routes/+page.js", "load") in symbols
    assert "app/routes/+page.js" not in files
    assert ("app/routes/+page.js", "data") not in symbols
    assert "src/lib/data.js" in files
    assert ("app/lib/data.js", "maintenance") not in symbols


@pytest.mark.parametrize("has_mock", [False, True])
def test_test_only_component_keeps_jest_alias_precedence(tmp_path, has_mock):
    manifest = {
        **KIT_MANIFEST,
        "jest": {"moduleNameMapper": {r"^\$lib/(.*)$": "<rootDir>/mocks/$1.js"}},
    }
    _write_project(
        tmp_path,
        {
            "package.json": json.dumps(manifest),
            "vite.config.js": VITE_CONFIG,
            "svelte.config.js": "export default {};\n",
            "src/routes/+page.js": "export function load() { return {}; }\n",
            "src/lib/helper.js": "export function helper() { return 'unused'; }\n",
            "tests/demo.test.js": "import Demo from './Demo.svelte'; console.log(Demo);\n",
            "tests/Demo.svelte": (
                "<script>import { helper } from '$lib/helper';</script><p>{helper()}</p>\n"
            ),
        },
    )
    if has_mock:
        _write_project(
            tmp_path, {"mocks/helper.js": "export function helper() { return 'test'; }\n"}
        )

    files, _ = _warnings(tmp_path)

    assert "src/lib/helper.js" in files
    assert "mocks/helper.js" not in files
    assert "src/routes/+page.js" not in files
