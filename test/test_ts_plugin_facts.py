"""The data-driven plugin table: enabler-gated entry patterns, the exports a
tool reads, config keys read statically, and abstention when a config cannot
be read. Every positive case keeps a genuinely dead symbol or file next to
the convention and requires it to stay reported."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript import plugin_facts
from skylos.visitors.languages.typescript.conventions import convention_reason
from skylos.visitors.languages.typescript.framework_aliases import (
    resolve_sveltekit_alias,
)
from skylos.visitors.languages.typescript.glob_patterns import (
    GlobSet,
    compile_glob,
    expand_braces,
)
from skylos.visitors.languages.typescript.plugin_facts import (
    enabled_plugins,
    load_table,
    plugin_entry,
    plugin_named,
)
from skylos.visitors.languages.typescript.text_fixtures import is_text_fixture


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


def _files(reported) -> set[str]:
    return {rel for key, rel, _name in reported if key == "unused_files"}


# ------------------------------------------------------------------ the table


def test_table_rows_compile_their_patterns():
    table = load_table()
    assert len(table) >= 200
    assert {"solid-start", "jscodeshift", "docusaurus-v1"} <= {p.name for p in table}
    unsupported = []
    for plugin in table:
        for pattern in (*plugin.row["entry"], *plugin.row["production"], *plugin.row["config"]):
            body = pattern.removeprefix("!")
            if compile_glob(body) is None:
                unsupported.append((plugin.name, pattern))
    assert unsupported == []


def test_table_rows_are_data_with_their_sources():
    data = json.loads(plugin_facts.DATA_FILE.read_text(encoding="utf-8"))
    own = {"solid-start", "jscodeshift", "docusaurus-v1"}
    for row in data["plugins"]:
        assert isinstance(row["enablers"], list), row["name"]
        if row["name"] not in own:
            assert row.get("source"), row["name"]
    remix = plugin_named("remix")
    assert "@remix-run/dev" in remix.enabler_names
    assert "app/routes/*.{js,jsx,ts,tsx,md,mdx}" in remix.row["production"]


@pytest.mark.parametrize(
    "pattern, path, expected",
    [
        ("**/*.{bench,test,test-d,spec,spec-d}.?(c|m)[jt]s?(x)", "a/b.test-d.tsx", True),
        ("**/*.{bench,test,test-d,spec,spec-d}.?(c|m)[jt]s?(x)", "a/test.ts", False),
        ("**/*.@(mdx|stories.@(mdx|js|jsx|mjs|ts|tsx))", "src/a.stories.tsx", True),
        ("{,src/}app/{,[(]*[)]/}{manifest,robots}.{js,ts}", "src/app/(g)/robots.ts", True),
        ("{,src/}app/{,[(]*[)]/}{manifest,robots}.{js,ts}", "src/app/x/robots.ts", False),
        ("{mise,.mise}/conf.d/[!.]*.toml", "mise/conf.d/.hidden.toml", False),
        ("src/mastra/agents/*/*(subagents/*/)config.ts", "src/mastra/agents/a/subagents/b/config.ts", True),
        ("app/routes/**/*.{js,ts,tsx}", "app/routes.ts", False),
    ],
)
def test_glob_patterns(pattern, path, expected):
    assert bool(compile_glob(pattern).fullmatch(path)) is expected


def test_glob_set_negation_and_brace_expansion():
    pages = GlobSet(["src/pages/**/*.ts", "!src/pages/**/_*", "!src/pages/**/_*/**"])
    assert pages.matches("src/pages/a/b.ts")
    assert not pages.matches("src/pages/_draft.ts")
    assert not pages.matches("src/pages/_parts/a.ts")
    assert sorted(expand_braces("a.{js,ts}")) == ["a.js", "a.ts"]
    assert compile_glob("!(x)") is None  # unsupported: ignored, never widened


# ------------------------------------------------------------------- enablers


def test_routing_conventions_need_the_enabler(tmp_path):
    _write(tmp_path / "plain/package.json", '{"name": "plain"}')
    plain = _write(tmp_path / "plain/app/routes/index.tsx", "export default 1;\n")
    assert plugin_entry(plain) is None
    assert convention_reason(plain) is None

    _write(tmp_path / "remix/package.json", '{"devDependencies": {"@remix-run/dev": "2"}}')
    route = _write(tmp_path / "remix/app/routes/index.tsx", "export default 1;\n")
    found = plugin_entry(route)
    assert found is not None and found.plugin == "remix" and found.kind == "production"
    assert convention_reason(route) == "framework-convention"


def test_a_workspace_inherits_its_ancestors_plugins(tmp_path):
    _write(tmp_path / "package.json", '{"private": true, "devDependencies": {"vike": "0.4"}}')
    _write(tmp_path / "apps/web/package.json", '{"name": "web"}')
    page = _write(tmp_path / "apps/web/pages/about/+Page.tsx", "export default 1;\n")
    assert "vike" in enabled_plugins(str(tmp_path / "apps/web"))
    assert plugin_entry(page).plugin == "vike"


def test_custom_file_enablers(tmp_path):
    _write(tmp_path / "package.json", '{"name": "x"}')
    hook = _write(tmp_path / ".pnpmfile.cjs", "module.exports = {};\n")
    assert plugin_entry(hook) is None
    plugin_facts.clear_caches()
    _write(tmp_path / "pnpm-workspace.yaml", "packages: []\n")
    assert plugin_entry(hook).plugin == "pnpm"


def test_deferred_rows_produce_no_entries(tmp_path):
    # Next.js routing is modelled by nextjs.py (private folders, pageExtensions).
    _write(tmp_path / "package.json", '{"dependencies": {"next": "15"}}')
    private = _write(tmp_path / "app/_lib/page.tsx", "export default 1;\n")
    assert plugin_named("next").deferred
    assert plugin_entry(private) is None


# --------------------------------------------------------- end-to-end liveness


def test_remix_routes_are_roots_and_dead_code_next_to_them_stays_reported(tmp_path):
    _write(tmp_path / "package.json", '{"name": "app", "private": true, "devDependencies": {"@remix-run/dev": "2"}}')
    _write(
        tmp_path / "app/routes/index.tsx",
        'import { label } from "../lib/label";\n'
        "export const loader = () => label();\n"
        "export default function Index() { return null; }\n",
    )
    _write(tmp_path / "app/lib/label.ts", "export function label() { return 'x'; }\n")
    _write(tmp_path / "app/lib/orphan.ts", "export function orphan() { return 1; }\n")

    reported = _reported(_scan(tmp_path), tmp_path)

    assert "app/routes/index.tsx" not in _files(reported)
    assert "app/lib/label.ts" not in _files(reported)
    assert not any(name in {"loader", "Index"} for _k, _f, name in reported)
    assert "app/lib/orphan.ts" in _files(reported)


def test_solid_start_routes_read_only_their_route_exports(tmp_path):
    _write(tmp_path / "package.json", '{"name": "s", "private": true, "dependencies": {"@solidjs/start": "1"}}')
    _write(
        tmp_path / "src/routes/about.tsx",
        "export const route = {};\n"
        "export function GET() { return 1; }\n"
        "export default function About() { return null; }\n"
        "export const notReadBySolid = 1;\n",
    )
    reported = _reported(_scan(tmp_path), tmp_path)
    names = {name for _k, rel, name in reported if rel == "src/routes/about.tsx"}
    assert {"route", "GET", "About"}.isdisjoint(names)
    assert "notReadBySolid" in names


def test_nuxt_auto_imports_keep_every_export_but_pages_only_default(tmp_path):
    _write(tmp_path / "package.json", '{"name": "n", "private": true, "devDependencies": {"nuxt": "3"}}')
    _write(tmp_path / "composables/useCounter.ts", "export const useCounter = () => 1;\nexport const helper = 2;\n")
    _write(
        tmp_path / "server/api/hello.ts",
        "export default defineEventHandler(() => 'hi');\nexport const notRead = 1;\n",
    )
    reported = _reported(_scan(tmp_path), tmp_path)
    assert not {n for _k, rel, n in reported if rel == "composables/useCounter.ts"}
    assert "notRead" in {n for _k, rel, n in reported if rel == "server/api/hello.ts"}


def test_sveltekit_routes_and_lib_alias_come_from_the_table(tmp_path):
    _write(tmp_path / "package.json", '{"name": "k", "private": true, "devDependencies": {"@sveltejs/kit": "2"}}')
    util = _write(tmp_path / "src/lib/util.ts", "export const x = 1;\n")
    page = _write(
        tmp_path / "src/routes/blog/+page.ts",
        "import { x } from '$lib/util';\nexport const load = () => x;\n",
    )
    assert resolve_sveltekit_alias("$lib/util", str(page)) == str(util)
    assert plugin_entry(page).plugin == "sveltekit"
    reported = _reported(_scan(tmp_path), tmp_path)
    assert {"src/routes/blog/+page.ts", "src/lib/util.ts"}.isdisjoint(_files(reported))


def test_jscodeshift_and_text_fixture_rows(tmp_path):
    _write(tmp_path / "package.json", '{"name": "codemods", "private": true}')
    transform = _write(tmp_path / "src/v5/rename/rename.cjs", "module.exports = function t() {};\n")
    _write(
        tmp_path / "src/v5/rename/__tests__/rename.test.js",
        "defineTest(__dirname, 'rename.cjs', null, 'basic');\n",
    )
    fixture = _write(tmp_path / "src/v5/rename/__testfixtures__/basic.input.tsx", "export const a = 1;\n")
    other = _write(tmp_path / "src/v5/other/other.cjs", "module.exports = 1;\n")
    assert plugin_entry(transform).plugin == "jscodeshift"
    assert plugin_entry(other) is None
    assert is_text_fixture(fixture)


def test_lit_contract_is_table_data():
    contract = next(c for c in plugin_facts.class_contracts() if c["interface"] == "ReactiveController")
    assert "hostConnected" in contract["methods"]
    from skylos.visitors.languages.typescript import framework

    assert framework._LIT_CONTROLLER_HOOKS == frozenset(contract["methods"])


# ------------------------------------------------- config keys and abstention


def test_cypress_spec_pattern_from_a_literal_config(tmp_path):
    _write(tmp_path / "package.json", '{"name": "c", "private": true, "devDependencies": {"cypress": "13"}}')
    _write(
        tmp_path / "cypress.config.ts",
        "import { defineConfig } from 'cypress';\n"
        "export default defineConfig({ e2e: { specPattern: 'tests/e2e/**/*.e2e.ts', supportFile: 'tests/support.ts' } });\n",
    )
    spec = _write(tmp_path / "tests/e2e/login.e2e.ts", "it('x', () => {});\n")
    support = _write(tmp_path / "tests/support.ts", "export {};\n")
    default_spec = _write(tmp_path / "cypress/e2e/home.cy.ts", "it('y', () => {});\n")
    stray = _write(tmp_path / "tests/stray.ts", "export const stray = 1;\n")
    assert plugin_entry(spec).kind == "entry"
    assert plugin_entry(support).kind == "entry"
    # Defaults survive a config that names other entries.
    assert plugin_entry(default_spec) is not None
    assert plugin_entry(stray) is None


def test_unreadable_config_never_removes_entries_and_abstains(tmp_path):
    _write(tmp_path / "package.json", '{"name": "c", "private": true, "devDependencies": {"cypress": "13"}}')
    _write(
        tmp_path / "cypress.config.ts",
        "import { defineConfig } from 'cypress';\nimport { specs } from './specs';\n"
        "export default defineConfig({ e2e: { specPattern: specs() } });\n",
    )
    default_spec = _write(tmp_path / "cypress/e2e/home.cy.ts", "it('y', () => {});\n")
    helper = _write(tmp_path / "cypress/plugins/helper.ts", "export const helper = 1;\n")
    outside = _write(tmp_path / "src/orphan.ts", "export const orphan = 1;\n")
    assert plugin_entry(default_spec).kind == "entry"
    # The unread key could select files under the tool's folder: abstain.
    assert plugin_entry(helper).kind == "abstain"
    assert convention_reason(helper) == "plugin-abstained"
    assert plugin_entry(outside) is None
    assert plugin_facts.abstained_config_keys(str(tmp_path)) == [
        "cypress:cypress.config.ts:e2e.specPattern"
    ]
    reported = _reported(_scan(tmp_path), tmp_path)
    assert "cypress/plugins/helper.ts" not in _files(reported)
    assert "src/orphan.ts" in _files(reported)


def test_a_config_that_does_not_parse_keeps_the_defaults(tmp_path):
    _write(tmp_path / "package.json", '{"name": "m", "private": true, "devDependencies": {"mocha": "10"}}')
    _write(tmp_path / ".mocharc.json", "{ this is not json")
    default = _write(tmp_path / "test/a.js", "it('x', () => {});\n")
    assert plugin_entry(default) is not None


def test_dir_key_relocates_conventions_and_keeps_defaults(tmp_path):
    _write(tmp_path / "package.json", '{"name": "r", "private": true, "devDependencies": {"@react-router/dev": "7"}}')
    _write(
        tmp_path / "react-router.config.ts",
        "export default { appDirectory: 'source' } satisfies Config;\n",
    )
    moved = _write(tmp_path / "source/root.tsx", "export default 1;\n")
    default = _write(tmp_path / "app/root.tsx", "export default 1;\n")
    assert plugin_entry(moved).kind == "production"
    assert plugin_entry(default).kind == "production"


def test_entry_files_read_from_package_json_key(tmp_path):
    _write(
        tmp_path / "package.json",
        json.dumps({"name": "a", "private": True, "devDependencies": {"ava": "6"}, "ava": {"files": ["checks/**/*.mjs"]}}),
    )
    check = _write(tmp_path / "checks/one.mjs", "export const x = 1;\n")
    assert plugin_entry(check).kind == "entry"


def test_test_runner_entries_are_roots_whose_exports_stay_judged(tmp_path):
    _write(tmp_path / "package.json", '{"name": "v", "private": true, "devDependencies": {"vitest": "3"}}')
    typecheck = _write(tmp_path / "src/types.test-d.ts", "export const onlyHere = 1;\nconst x = onlyHere;\n")
    found = plugin_entry(typecheck)
    assert found.plugin == "vitest" and found.kind == "entry"
    assert found.exports == frozenset()


def test_jasmine_spec_files_are_relative_to_spec_dir(tmp_path):
    _write(tmp_path / "package.json", '{"name": "j", "private": true, "devDependencies": {"jasmine": "5"}}')
    _write(
        tmp_path / "spec/support/jasmine.json",
        '{"spec_dir": "checks", "spec_files": ["**/*.check.js"], "helpers": ["helpers/**/*.js"]}',
    )
    check = _write(tmp_path / "checks/a/one.check.js", "it('x', () => {});\n")
    helper = _write(tmp_path / "checks/helpers/setup.js", "beforeEach(() => {});\n")
    assert plugin_entry(check).kind == "entry"
    assert plugin_entry(helper).kind == "entry"


def test_array_config_with_computed_entries_abstains_only_on_the_tools_patterns(tmp_path):
    _write(tmp_path / "package.json", '{"name": "lib", "devDependencies": {"tsdown": "0.15"}}')
    _write(
        tmp_path / "tsdown.config.ts",
        "import { defineConfig } from 'tsdown'\nimport { modern } from './shared.js'\n"
        "export default defineConfig([modern({ entry: ['src/*.ts'] }), { entry: 'src/legacy.ts' }])\n",
    )
    orphan = _write(tmp_path / "src/orphan.ts", "export const orphan = 1;\n")
    assert plugin_facts.abstained_config_keys(str(tmp_path)) == ["tsdown:tsdown.config.ts:entry"]
    # tsdown has no default entry patterns: nothing beyond them is held back.
    assert plugin_entry(orphan) is None


def test_unread_directory_key_abstains_on_relocated_patterns(tmp_path):
    _write(tmp_path / "package.json", '{"name": "r", "private": true, "devDependencies": {"@react-router/dev": "7"}}')
    _write(
        tmp_path / "react-router.config.ts",
        "import { dir } from './dir'\nexport default { appDirectory: dir() }\n",
    )
    moved_root = _write(tmp_path / "web/root.tsx", "export default 1;\n")
    unrelated = _write(tmp_path / "web/helpers.ts", "export const h = 1;\n")
    found = plugin_entry(moved_root)
    assert found.kind == "abstain" and "*" in found.exports
    assert plugin_entry(unrelated) is None


def test_astro_endpoints_and_underscore_files(tmp_path):
    _write(tmp_path / "package.json", '{"name": "a", "private": true, "dependencies": {"astro": "5"}}')
    endpoint = _write(tmp_path / "src/pages/api/data.json.ts", "export function GET() {}\n")
    private = _write(tmp_path / "src/pages/_helpers.ts", "export const h = 1;\n")
    content = _write(tmp_path / "src/content.config.ts", "export const collections = {};\n")
    found = plugin_entry(endpoint)
    assert found.plugin == "astro" and "GET" in found.exports and "*" not in found.exports
    # Astro does not route files whose name starts with "_".
    assert plugin_entry(private) is None
    assert plugin_entry(content).exports == frozenset({"collections"})
