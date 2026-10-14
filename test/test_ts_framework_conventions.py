"""JS/TS files loaded by framework or tool convention (Expo Router, React
Email, Jest manual mocks, tool configs, Turborepo generators), plus reference
contexts the TS reference pass used to miss. Each case keeps a genuinely dead
symbol next to the convention file and requires it to stay reported."""

from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript.analysis import (
    _discover_esbuild_config_entries,
)
from skylos.visitors.languages.typescript.conventions import (
    convention_reason,
    expo_router_exports,
    is_react_email_template,
)
from skylos.visitors.languages.typescript.core import TypeScriptCore


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _scan(root: Path) -> dict:
    return json.loads(analyze(str(root), conf=60, grep_cache=False))


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


def _expo_app(root: Path) -> None:
    _write(
        root / "package.json",
        '{"name": "mobile", "main": "expo-router/entry",'
        ' "dependencies": {"expo-router": "~6.0.0", "react": "19.1.0"}}',
    )
    _write(
        root / "src/app/_layout.tsx",
        'import { Stack } from "expo-router";\n'
        'export const unstable_settings = { initialRouteName: "index" };\n'
        "export default function RootLayout() { return <Stack />; }\n",
    )
    _write(
        root / "src/app/index.tsx",
        'import { greet } from "../utils/greet";\n'
        "export function helperNobodyUses() { return 1; }\n"
        "export default function Index() { return <>{greet()}</>; }\n",
    )
    _write(
        root / "src/app/post/[id].tsx",
        "export default function Post() { return null; }\n",
    )
    _write(
        root / "src/app/hello+api.ts",
        "export function GET(request: Request) { return Response.json({}); }\n",
    )
    _write(root / "src/utils/greet.ts", 'export function greet() { return "hi"; }\n')
    _write(
        root / "src/utils/orphan.ts",
        "export function deleteToken() { return 0; }\n",
    )


def test_expo_router_routes_are_entrypoints_and_dead_code_stays_reported(tmp_path):
    _expo_app(tmp_path)

    reported = _reported(_scan(tmp_path), tmp_path)

    for route in (
        "src/app/_layout.tsx",
        "src/app/index.tsx",
        "src/app/post/[id].tsx",
        "src/app/hello+api.ts",
        "src/utils/greet.ts",
    ):
        assert ("unused_files", route, "") not in reported
    assert not {
        name
        for _kind, _file, name in reported
        if name in {"RootLayout", "Index", "Post", "GET", "unstable_settings"}
    }
    assert ("unused_files", "src/utils/orphan.ts", "") in reported
    assert ("unused_functions", "src/utils/orphan.ts", "deleteToken") in reported
    # A non-conventional export from a route file is still judged.
    assert ("unused_functions", "src/app/index.tsx", "helperNobodyUses") in reported


def test_expo_router_needs_the_dependency_and_honours_the_router_root(tmp_path):
    _write(tmp_path / "plain/package.json", '{"name": "plain"}')
    page = _write(tmp_path / "plain/app/page.tsx", "export default function P() {}\n")
    assert convention_reason(page) is None

    _write(
        tmp_path / "custom/package.json",
        '{"dependencies": {"expo-router": "6.0.0"}}',
    )
    _write(
        tmp_path / "custom/app.json",
        '{"expo": {"plugins": [["expo-router", {"root": "./routes"}]]}}',
    )
    not_route = _write(tmp_path / "custom/app/not-a-route.tsx", "export default 1;\n")
    route = _write(tmp_path / "custom/routes/home.tsx", "export default 1;\n")
    api = _write(tmp_path / "custom/routes/items+api.ts", "export const GET = 1;\n")

    assert convention_reason(route) == "expo-router-route"
    assert convention_reason(not_route) is None
    assert "GET" in expo_router_exports(api)
    assert "unstable_settings" in expo_router_exports(route)


def test_react_email_templates_are_rendered_by_the_cli(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"name": "mail", "scripts": {"export": "email export --outDir out"},'
        ' "dependencies": {"react-email": "4.0.0"}}',
    )
    _write(
        tmp_path / "emails/welcome.tsx",
        'import { Button } from "./_parts/button";\n'
        "export const WelcomeEmail = () => <Button />;\n"
        "WelcomeEmail.PreviewProps = {};\n"
        "export default WelcomeEmail;\n",
    )
    _write(
        tmp_path / "emails/_parts/button.tsx",
        "export function Button() { return null; }\n",
    )
    _write(
        tmp_path / "emails/_parts/divider.tsx",
        "export function Divider() { return null; }\n",
    )

    reported = _reported(_scan(tmp_path), tmp_path)

    assert ("unused_files", "emails/welcome.tsx", "") not in reported
    assert ("unused_files", "emails/_parts/button.tsx", "") not in reported
    assert not any(name == "WelcomeEmail" for _k, _f, name in reported)
    # ``_``-prefixed folders hold parts, not templates: an unused part is dead.
    assert ("unused_files", "emails/_parts/divider.tsx", "") in reported
    assert ("unused_functions", "emails/_parts/divider.tsx", "Divider") in reported


def test_react_email_dir_option_and_dependency_gate(tmp_path):
    _write(
        tmp_path / "with/package.json",
        '{"scripts": {"dev": "email dev --dir src/mail"},'
        ' "devDependencies": {"react-email": "4.0.0"}}',
    )
    template = _write(tmp_path / "with/src/mail/reset.jsx", "export default () => 1;\n")
    no_default = _write(tmp_path / "with/src/mail/helpers.jsx", "export const x = 1;\n")
    ts_file = _write(tmp_path / "with/emails/types.ts", "export default 1;\n")
    _write(tmp_path / "without/package.json", '{"name": "app"}')
    other = _write(tmp_path / "without/emails/welcome.tsx", "export default 1;\n")

    assert is_react_email_template(template)
    assert not is_react_email_template(no_default)
    # react-email only renders .js/.jsx/.tsx files.
    assert not is_react_email_template(ts_file)
    assert not is_react_email_template(other)


def test_tool_configs_mocks_and_turbo_generators(tmp_path):
    _write(tmp_path / "package.json", '{"name": "web", "private": true}')
    _write(
        tmp_path / "metro.config.js", "const config = {};\nmodule.exports = config;\n"
    )
    _write(tmp_path / "drizzle.config.ts", 'export default { schema: "./s.ts" };\n')
    _write(
        tmp_path / "app.config.ts",
        "const config = { name: 'x' };\nexport default config;\n",
    )
    _write(tmp_path / "auth.config.ts", "export const auth = { secret: 'x' };\n")
    _write(
        tmp_path / "turbo/generators/config.ts",
        "export default function generator(plop: unknown) { void plop; }\n",
    )
    _write(
        tmp_path / "__mocks__/expo-localization.ts",
        "export const locale = 'en-US';\nexport const locales = ['en-US'];\n",
    )
    # Not next to a package.json: an ordinary module, judged normally.
    _write(tmp_path / "src/site.config.ts", "export const siteName = 'x';\n")

    reported = _reported(_scan(tmp_path), tmp_path)

    for path in (
        "metro.config.js",
        "drizzle.config.ts",
        "app.config.ts",
        "auth.config.ts",
        "turbo/generators/config.ts",
        "__mocks__/expo-localization.ts",
    ):
        assert not any(file == path for _k, file, _n in reported), path
    assert ("unused_files", "src/site.config.ts", "") in reported
    assert ("unused_variables", "src/site.config.ts", "siteName") in reported


def test_js_package_entry_default_export_is_public_api(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"name": "@acme/prettier-config", "type": "module",'
        ' "exports": {".": "./index.js"}}',
    )
    _write(
        tmp_path / "index.js",
        "const config = { semi: true };\nexport default config;\n",
    )
    _write(tmp_path / "lib/unused.js", "export function stale() { return 1; }\n")

    reported = _reported(_scan(tmp_path), tmp_path)

    assert not any(name == "config" for _k, _f, name in reported)
    assert ("unused_functions", "lib/unused.js", "stale") in reported


def _refs(source: str, name: str = "x.ts") -> set[str]:
    core = TypeScriptCore(name, source.encode())
    core.scan()
    return {ref for ref, _file in core.refs}


def test_reference_contexts_ternary_condition_parentheses_and_casts():
    refs = _refs(
        "import {A, B, C, D, E, F} from './m';\n"
        "export const x: string = A ? 'a' : 'b';\n"
        "let flag = false;\n"
        "export function f() { if (flag) { flag = false; } }\n"
        "export const g = (w: Window | null) => B;\n"
        "export const h = C!.value;\n"
        "export const i = <string>D;\n"
        "export function* j() { yield E; }\n"
        "export function k() { throw F; }\n"
    )

    assert {"A", "B", "C", "D", "E", "F", "flag"} <= refs


def test_type_alias_value_is_a_use_but_declared_names_are_not():
    refs = _refs(
        "import type {Serialized} from './m';\n"
        "export type SerializedQuote = Serialized;\n"
        "export interface Shape { x: number }\n"
    )

    assert "Serialized" in refs
    assert "SerializedQuote" not in refs
    assert "Shape" not in refs


def test_tsx_files_still_collect_refs_without_the_cast_pattern():
    refs = _refs(
        "import {A} from './m';\nexport const v = A ? <div /> : null;\n", "x.tsx"
    )

    assert "A" in refs


def test_nested_helper_in_an_exported_function_is_not_an_export():
    core = TypeScriptCore(
        "x.ts",
        b"export function outer() {\n"
        b"  function isEmpty(r: number) { return r > 0; }\n"
        b"  return isEmpty(1);\n"
        b"}\n"
        b"export class K { method() { return 1; } }\n",
    )
    core.scan()
    exported = {d.name: d.is_exported for d in core.defs}

    assert exported["outer"] is True
    assert exported["isEmpty"] is False
    # Methods of an exported class keep their exported status.
    assert exported["K.method"] is True


def test_esbuild_entries_survive_added_keys_and_import_meta_dirname(tmp_path):
    for name in ("app.ts", "admin.ts"):
        _write(tmp_path / "src" / name, "export {};\n")
    build = _write(
        tmp_path / "dev/build.mjs",
        "import * as esbuild from 'esbuild';\n"
        "import * as path from 'node:path';\n"
        "const __dirname = import.meta.dirname;\n"
        "const mode = process.argv[2];\n"
        "const entryPoints = {\n"
        "  app: path.join(__dirname, '../src/app.ts'),\n"
        "  admin: path.join(__dirname, '../src/admin.ts'),\n"
        "};\n"
        "if (mode === 'watch') {\n"
        "  entryPoints['styles'] = path.join(__dirname, '../dist/styles.css');\n"
        "}\n"
        "const options = { bundle: true, entryPoints };\n"
        "if (mode === 'watch') { options.inject = [path.join(__dirname, 'live.js')]; }\n"
        "const ctx = await esbuild.context(options);\n"
        "await ctx.serve({ servedir: path.join(__dirname, '../public') });\n",
    )
    sources = {str((tmp_path / "src" / n).resolve()) for n in ("app.ts", "admin.ts")}

    found = _discover_esbuild_config_entries(str(build), sources, str(tmp_path))

    assert {Path(p).name for p in found} == {"app.ts", "admin.ts"}


def test_esbuild_overwriting_an_existing_entry_key_stays_unknown(tmp_path):
    _write(tmp_path / "src/app.ts", "export {};\n")
    build = _write(
        tmp_path / "build.mjs",
        "import * as esbuild from 'esbuild';\n"
        "const entryPoints = { app: './src/app.ts' };\n"
        "entryPoints.app = process.env.ENTRY;\n"
        "await esbuild.build({ entryPoints });\n",
    )

    found = _discover_esbuild_config_entries(
        str(build), {str((tmp_path / "src/app.ts").resolve())}, str(tmp_path)
    )

    assert found == set()


def test_esbuild_script_in_an_excluded_build_folder_still_names_entries(tmp_path):
    _write(
        tmp_path / "package.json",
        '{"name": "app", "type": "module",'
        ' "scripts": {"build:js": "node dev/build/esbuild.mjs"},'
        ' "devDependencies": {"esbuild": "^0.25.0"}}',
    )
    _write(
        tmp_path / "dev/build/esbuild.mjs",
        "import * as esbuild from 'esbuild';\n"
        "import * as path from 'node:path';\n"
        "const __dirname = import.meta.dirname;\n"
        "const entryPoints = { app: path.join(__dirname, '../../src/app.ts') };\n"
        "await esbuild.build({ entryPoints, bundle: true });\n",
    )
    _write(
        tmp_path / "src/app.ts",
        "import { boot } from './boot';\nboot();\n"
        "export function init() { return 1; }\n",
    )
    _write(tmp_path / "src/boot.ts", "export function boot() {}\n")
    _write(tmp_path / "src/old.ts", "export function old() {}\n")

    reported = _reported(_scan(tmp_path), tmp_path)

    assert ("unused_files", "src/app.ts", "") not in reported
    assert ("unused_files", "src/boot.ts", "") not in reported
    assert ("unused_files", "src/old.ts", "") in reported
    # The entry's exports are the bundle's interface (``bundle.init()``).
    assert ("unused_functions", "src/app.ts", "init") not in reported
    assert ("unused_functions", "src/old.ts", "old") in reported
