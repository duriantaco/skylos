"""Tests for TypeScript export graph, re-export handling, and Next.js conventions."""

from __future__ import annotations

from pathlib import Path

from skylos.visitors.base import Definition
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.workspace import (
    discover_workspace_inventory,
)
from skylos.visitors.languages.typescript.analysis import (
    build_ts_import_graph,
    find_unused_ts_exports,
    find_dead_ts_files,
    _is_nextjs_convention_file,
    _NEXTJS_CONVENTION_EXPORTS,
    _discover_vitest_config_entries,
)


def _make_def(name, typ, filename, line=1, exported=False):
    d = Definition(name, typ, filename, line)
    d.is_exported = exported
    return d


def _scan_raw_imports(*paths: Path) -> dict[str, list[dict]]:
    return {str(path): scan_typescript_file(str(path))[12] for path in paths}


# ---------- Aliased import consumption ----------


class TestAliasedImports:
    def test_aliased_import_consumes_original_name(self, tmp_path):
        """import { foo as bar } from './mod' should mark 'foo' as consumed."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function foo() {}")
        app_file = tmp_path / "app.ts"
        app_file.write_text("import { foo as bar } from './mod';")

        defs = {
            f"{mod_file}:foo": _make_def(
                "foo", "function", str(mod_file), exported=True
            ),
        }

        ts_raw_imports = {
            str(app_file): [{"source": "./mod", "names": ["foo as bar"], "line": 1}]
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "foo" in consumed[str(mod_file)]

    def test_plain_import_still_works(self, tmp_path):
        """import { foo } from './mod' should still mark 'foo' as consumed."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function foo() {}")
        app_file = tmp_path / "app.ts"
        app_file.write_text("import { foo } from './mod';")

        defs = {
            f"{mod_file}:foo": _make_def(
                "foo", "function", str(mod_file), exported=True
            ),
        }

        ts_raw_imports = {
            str(app_file): [{"source": "./mod", "names": ["foo"], "line": 1}]
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "foo" in consumed[str(mod_file)]

    def test_multiple_aliased_imports(self, tmp_path):
        """Multiple aliased imports from same module."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function foo() {} export function bar() {}")
        app_file = tmp_path / "app.ts"
        app_file.write_text("import { foo as f, bar as b } from './mod';")

        defs = {
            f"{mod_file}:foo": _make_def(
                "foo", "function", str(mod_file), exported=True
            ),
            f"{mod_file}:bar": _make_def(
                "bar", "function", str(mod_file), exported=True
            ),
        }

        ts_raw_imports = {
            str(app_file): [
                {"source": "./mod", "names": ["foo as f", "bar as b"], "line": 1}
            ]
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "foo" in consumed[str(mod_file)]
        assert "bar" in consumed[str(mod_file)]


# ---------- Default re-export tracking ----------


class TestDefaultReexport:
    def test_export_default_as_name(self, tmp_path):
        """export { default as MyComponent } from './comp' should mark 'default' consumed."""
        comp_file = tmp_path / "comp.ts"
        comp_file.write_text("export default function MyComponent() {}")
        index_file = tmp_path / "index.ts"
        index_file.write_text("export { default as MyComponent } from './comp';")
        consumer_file = tmp_path / "consumer.ts"
        consumer_file.write_text("import { MyComponent } from './index';")

        defs = {
            f"{comp_file}:default": _make_def(
                "default", "function", str(comp_file), exported=True
            ),
        }

        ts_raw_imports = {
            str(index_file): [
                {"source": "./comp", "names": ["default as MyComponent"], "line": 1}
            ],
            str(consumer_file): [
                {"source": "./index", "names": ["MyComponent"], "line": 1}
            ],
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        # MyComponent is consumed from index, and the alias resolver should
        # propagate to mark 'default' consumed in comp
        assert "default" in consumed[str(comp_file)]

    def test_export_named_as_alias(self, tmp_path):
        """export { foo as publicFoo } from './mod' should propagate."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function foo() {}")
        barrel_file = tmp_path / "barrel.ts"
        barrel_file.write_text("export { foo as publicFoo } from './mod';")
        consumer_file = tmp_path / "consumer.ts"
        consumer_file.write_text("import { publicFoo } from './barrel';")

        defs = {
            f"{mod_file}:foo": _make_def(
                "foo", "function", str(mod_file), exported=True
            ),
        }

        ts_raw_imports = {
            str(barrel_file): [
                {"source": "./mod", "names": ["foo as publicFoo"], "line": 1}
            ],
            str(consumer_file): [
                {"source": "./barrel", "names": ["publicFoo"], "line": 1}
            ],
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "foo" in consumed[str(mod_file)]


# ---------- Next.js convention export exclusion ----------


class TestNextjsConventionExports:
    def test_is_nextjs_convention_file_app_dir(self):
        assert _is_nextjs_convention_file("/project/app/dashboard/page.tsx")
        assert _is_nextjs_convention_file("/project/app/api/route.ts")

    def test_is_nextjs_convention_file_pages_dir(self):
        assert _is_nextjs_convention_file("/project/pages/index.tsx")
        assert _is_nextjs_convention_file("/project/pages/api/users.ts")

    def test_is_nextjs_convention_file_accepts_path_objects(self):
        assert _is_nextjs_convention_file(Path("/project/app/dashboard/page.tsx"))
        assert _is_nextjs_convention_file(Path("/project/pages/api/users.ts"))

    def test_is_not_nextjs_convention_file(self):
        assert not _is_nextjs_convention_file("/project/src/utils/helpers.ts")
        assert not _is_nextjs_convention_file("/project/lib/db.ts")

    def test_convention_exports_not_flagged(self):
        """Valid Next.js convention exports should not be flagged."""
        demoted = []
        for fname, export_name in (
            ("/project/app/dashboard/page.tsx", "default"),
            ("/project/app/api/users/route.ts", "GET"),
            ("/project/app/api/users/route.ts", "POST"),
            ("/project/app/api/users/route.ts", "maxDuration"),
        ):
            d = _make_def(export_name, "function", fname, exported=True)
            d.references = 1  # has internal refs
            d.is_exported = False  # demoted
            demoted.append(d)

        findings = find_unused_ts_exports(demoted, {})
        flagged_names = {f["name"] for f in findings}
        for export_name in ("default", "GET", "POST", "maxDuration"):
            assert export_name not in flagged_names

    def test_non_convention_export_still_flagged(self):
        """A non-convention export in app/ should still be flagged."""
        fname = "/project/app/utils/helpers.ts"

        d = _make_def("myHelper", "function", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert len(findings) == 1
        assert findings[0]["name"] == "myHelper"

    def test_convention_export_outside_app_dir_flagged(self):
        """Convention export names outside app/pages dirs should still be flagged."""
        fname = "/project/src/lib/utils.ts"

        d = _make_def("GET", "function", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert len(findings) == 1
        assert findings[0]["name"] == "GET"

    def test_middleware_config_not_flagged(self):
        fname = "/project/middleware.ts"

        d = _make_def("config", "variable", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert findings == []

    def test_proxy_config_not_flagged(self):
        fname = "/project/proxy.ts"

        d = _make_def("config", "variable", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert findings == []

    def test_instrumentation_register_not_flagged(self):
        fname = "/project/instrumentation.ts"

        d = _make_def("register", "function", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert findings == []

    def test_viewport_export_not_flagged(self):
        fname = "/project/app/blog/layout.tsx"

        d = _make_def("viewport", "variable", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert findings == []

    def test_non_convention_config_still_flagged(self):
        fname = "/project/app/lib/config.ts"

        d = _make_def("config", "variable", fname, exported=True)
        d.references = 1
        d.is_exported = False

        findings = find_unused_ts_exports([d], {})
        assert len(findings) == 1
        assert findings[0]["name"] == "config"

    def test_all_convention_exports_covered(self):
        """Verify key Next.js convention exports are in the set."""
        expected = {
            "default",
            "generateMetadata",
            "metadata",
            "generateStaticParams",
            "generateViewport",
            "viewport",
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
            "middleware",
            "proxy",
            "config",
            "register",
            "onRequestError",
            "loading",
            "error",
            "layout",
            "page",
            "maxDuration",
            "experimental_ppr",
        }
        assert expected.issubset(_NEXTJS_CONVENTION_EXPORTS)


# ---------- Wildcard re-export passthrough ----------


class TestWildcardPassthrough:
    def test_wildcard_reexport_propagates(self, tmp_path):
        """export * from './mod' should propagate consumed names."""
        mod_file = tmp_path / "mod.ts"
        mod_file.write_text("export function helper() {}")
        index_file = tmp_path / "index.ts"
        index_file.write_text("export * from './mod';")
        consumer_file = tmp_path / "consumer.ts"
        consumer_file.write_text("import { helper } from './index';")

        defs = {
            f"{mod_file}:helper": _make_def(
                "helper", "function", str(mod_file), exported=True
            ),
        }

        ts_raw_imports = {
            str(index_file): [{"source": "./mod", "names": ["*"], "line": 1}],
            str(consumer_file): [{"source": "./index", "names": ["helper"], "line": 1}],
        }

        consumed, _, _ = build_ts_import_graph(ts_raw_imports, defs)
        assert "helper" in consumed[str(mod_file)]


class TestTypeScriptDeadFiles:
    def test_main_tsx_is_treated_as_entrypoint(self, tmp_path):
        main_file = tmp_path / "src" / "main.tsx"
        app_file = tmp_path / "src" / "App.tsx"
        component_file = tmp_path / "src" / "components" / "UserMenu.tsx"

        component_file.parent.mkdir(parents=True)
        main_file.parent.mkdir(parents=True, exist_ok=True)

        for path in (main_file, app_file, component_file):
            path.write_text("", encoding="utf-8")

        files = [main_file, app_file, component_file]
        importers_of = {
            str(app_file): {str(main_file)},
            str(component_file): {str(app_file)},
        }

        dead_files = find_dead_ts_files(files, [], importers_of, {})
        assert dead_files == []

    def test_main_mjs_is_treated_as_entrypoint(self, tmp_path):
        main_file = tmp_path / "src" / "main.mjs"
        helper_file = tmp_path / "src" / "helper.mjs"

        helper_file.parent.mkdir(parents=True, exist_ok=True)
        main_file.write_text("import './helper.mjs';\n", encoding="utf-8")
        helper_file.write_text("export const helper = true;\n", encoding="utf-8")

        _, wildcard_edges, importers_of = build_ts_import_graph(
            _scan_raw_imports(main_file, helper_file),
            {},
        )
        dead_files = find_dead_ts_files(
            [main_file, helper_file],
            [],
            importers_of,
            wildcard_edges,
        )

        assert dead_files == []

    def test_nextjs_special_files_are_treated_as_entrypoints(self, tmp_path):
        template_file = tmp_path / "app" / "template.tsx"
        global_not_found_file = tmp_path / "app" / "global-not-found.tsx"
        instrumentation_file = tmp_path / "instrumentation.ts"
        instrumentation_client_file = tmp_path / "instrumentation-client.ts"
        proxy_file = tmp_path / "proxy.ts"
        pages_index = tmp_path / "pages" / "index.tsx"
        pages_api = tmp_path / "pages" / "api" / "users.ts"

        for path in (
            template_file,
            global_not_found_file,
            instrumentation_file,
            instrumentation_client_file,
            proxy_file,
            pages_index,
            pages_api,
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")

        files = [
            template_file,
            global_not_found_file,
            instrumentation_file,
            instrumentation_client_file,
            proxy_file,
            pages_index,
            pages_api,
        ]

        dead_files = find_dead_ts_files(files, [], {}, {})
        assert dead_files == []

    def test_package_json_entrypoint_keeps_workspace_files_live(self, tmp_path):
        public_api = tmp_path / "packages" / "ui" / "src" / "public-api.ts"
        helper_file = tmp_path / "packages" / "ui" / "src" / "helpers.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","workspaces":["packages/*"]}', encoding="utf-8"
        )
        (tmp_path / "packages" / "ui").mkdir(parents=True, exist_ok=True)
        (tmp_path / "packages" / "ui" / "package.json").write_text(
            '{"name":"@repo/ui","exports":"./src/public-api.ts"}', encoding="utf-8"
        )
        public_api.parent.mkdir(parents=True, exist_ok=True)
        public_api.write_text("export * from './helpers';\n", encoding="utf-8")
        helper_file.write_text("export const helper = () => 1;\n", encoding="utf-8")

        inventory = discover_workspace_inventory(tmp_path)
        dead_files = find_dead_ts_files(
            [public_api, helper_file],
            [],
            {str(helper_file): {str(public_api)}},
            {str(public_api): {str(helper_file)}},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert dead_files == []

    def test_package_json_entrypoint_keeps_single_package_live_without_inventory(
        self, tmp_path
    ):
        app_file = tmp_path / "src" / "app.js"

        (tmp_path / "package.json").write_text(
            '{"name":"app","type":"module","main":"src/app.js"}',
            encoding="utf-8",
        )
        app_file.parent.mkdir(parents=True, exist_ok=True)
        app_file.write_text("export const app = true;\n", encoding="utf-8")

        dead_files = find_dead_ts_files(
            [app_file],
            [],
            {},
            {},
            project_root=str(app_file.parent),
            workspace_inventory=None,
        )

        assert dead_files == []

    def test_package_json_subpath_export_keeps_exported_file_live(self, tmp_path):
        helper_file = tmp_path / "packages" / "ui" / "src" / "helpers.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","workspaces":["packages/*"]}', encoding="utf-8"
        )
        (tmp_path / "packages" / "ui").mkdir(parents=True, exist_ok=True)
        (tmp_path / "packages" / "ui" / "package.json").write_text(
            '{"name":"@repo/ui","exports":{"./helpers":"./src/helpers.ts"}}',
            encoding="utf-8",
        )
        helper_file.parent.mkdir(parents=True, exist_ok=True)
        helper_file.write_text("export const helper = () => 1;\n", encoding="utf-8")

        inventory = discover_workspace_inventory(tmp_path)
        dead_files = find_dead_ts_files(
            [helper_file],
            [],
            {},
            {},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert dead_files == []

    def test_package_json_script_entrypoint_keeps_cli_graph_live(self, tmp_path):
        cli_file = tmp_path / "src" / "cli.ts"
        helper_file = tmp_path / "src" / "helpers.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","scripts":{"dev":"tsx src/cli.ts"}}',
            encoding="utf-8",
        )
        cli_file.parent.mkdir(parents=True, exist_ok=True)
        cli_file.write_text("import './helpers';\n", encoding="utf-8")
        helper_file.write_text("export const helper = () => 1;\n", encoding="utf-8")

        inventory = discover_workspace_inventory(tmp_path)
        dead_files = find_dead_ts_files(
            [cli_file, helper_file],
            [],
            {str(helper_file): {str(cli_file)}},
            {},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert dead_files == []

    def test_vite_config_lib_entries_keep_nonstandard_entries_live(self, tmp_path):
        lib_entry = tmp_path / "src" / "library-entry.ts"
        worker_entry = tmp_path / "src" / "worker-entry.ts"
        helper_file = tmp_path / "src" / "helpers.ts"
        vite_config = tmp_path / "vite.config.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root"}',
            encoding="utf-8",
        )
        lib_entry.parent.mkdir(parents=True, exist_ok=True)
        vite_config.write_text(
            """
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: {
        library: "src/library-entry.ts",
        worker: "src/worker-entry.ts",
      },
    },
  },
});
""",
            encoding="utf-8",
        )
        lib_entry.write_text("import './helpers';\n", encoding="utf-8")
        worker_entry.write_text("export const worker = true;\n", encoding="utf-8")
        helper_file.write_text("export const helper = () => 1;\n", encoding="utf-8")

        inventory = discover_workspace_inventory(tmp_path)
        dead_files = find_dead_ts_files(
            [vite_config, lib_entry, worker_entry, helper_file],
            [],
            {str(helper_file): {str(lib_entry)}},
            {},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert dead_files == []

    def test_vitest_custom_config_include_keeps_matching_file_live(self, tmp_path):
        vitest_config = tmp_path / "tooling" / "vitest.workspace.ts"
        check_file = tmp_path / "checks" / "login.ts"
        helper_file = tmp_path / "src" / "support.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","scripts":{"test":"vitest --config tooling/vitest.workspace.ts"}}',
            encoding="utf-8",
        )
        vitest_config.parent.mkdir(parents=True, exist_ok=True)
        check_file.parent.mkdir(parents=True, exist_ok=True)
        helper_file.parent.mkdir(parents=True, exist_ok=True)

        vitest_config.write_text(
            """
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["checks/**/*.ts"],
  },
});
""",
            encoding="utf-8",
        )
        check_file.write_text("import '../src/support';\n", encoding="utf-8")
        helper_file.write_text("export const support = true;\n", encoding="utf-8")

        inventory = discover_workspace_inventory(tmp_path)
        dead_files = find_dead_ts_files(
            [vitest_config, check_file, helper_file],
            [],
            {str(helper_file): {str(check_file)}},
            {},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert dead_files == []

    def test_playwright_custom_config_testdir_keeps_matching_file_live(self, tmp_path):
        playwright_config = tmp_path / "tooling" / "playwright.e2e.ts"
        test_file = tmp_path / "browser" / "login.ts"
        helper_file = tmp_path / "src" / "driver.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","scripts":{"e2e":"playwright test --config tooling/playwright.e2e.ts"}}',
            encoding="utf-8",
        )
        playwright_config.parent.mkdir(parents=True, exist_ok=True)
        test_file.parent.mkdir(parents=True, exist_ok=True)
        helper_file.parent.mkdir(parents=True, exist_ok=True)

        playwright_config.write_text(
            """
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "../browser",
});
""",
            encoding="utf-8",
        )
        test_file.write_text("import '../src/driver';\n", encoding="utf-8")
        helper_file.write_text("export const driver = true;\n", encoding="utf-8")

        inventory = discover_workspace_inventory(tmp_path)
        dead_files = find_dead_ts_files(
            [playwright_config, test_file, helper_file],
            [],
            {str(helper_file): {str(test_file)}},
            {},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert dead_files == []

    def test_dynamic_import_keeps_module_graph_live(self, tmp_path):
        app_file = tmp_path / "src" / "main.ts"
        feature_file = tmp_path / "src" / "feature.ts"
        helper_file = tmp_path / "src" / "helper.ts"

        helper_file.parent.mkdir(parents=True, exist_ok=True)
        app_file.write_text(
            "async function load() { await import('./feature'); }\n", encoding="utf-8"
        )
        feature_file.write_text(
            "import './helper';\nexport const feature = true;\n", encoding="utf-8"
        )
        helper_file.write_text("export const helper = true;\n", encoding="utf-8")

        _, wildcard_edges, importers_of = build_ts_import_graph(
            _scan_raw_imports(app_file, feature_file, helper_file),
            {},
        )
        dead_files = find_dead_ts_files(
            [app_file, feature_file, helper_file],
            [],
            importers_of,
            wildcard_edges,
        )

        assert dead_files == []

    def test_require_resolve_keeps_module_live(self, tmp_path):
        app_file = tmp_path / "src" / "main.ts"
        feature_file = tmp_path / "src" / "feature.ts"

        feature_file.parent.mkdir(parents=True, exist_ok=True)
        app_file.write_text(
            "const target = require.resolve('./feature');\n", encoding="utf-8"
        )
        feature_file.write_text("export const feature = true;\n", encoding="utf-8")

        _, wildcard_edges, importers_of = build_ts_import_graph(
            _scan_raw_imports(app_file, feature_file),
            {},
        )
        dead_files = find_dead_ts_files(
            [app_file, feature_file],
            [],
            importers_of,
            wildcard_edges,
        )

        assert dead_files == []

    def test_import_meta_resolve_keeps_module_live(self, tmp_path):
        app_file = tmp_path / "src" / "main.ts"
        feature_file = tmp_path / "src" / "feature.ts"

        feature_file.parent.mkdir(parents=True, exist_ok=True)
        app_file.write_text(
            "const target = import.meta.resolve('./feature');\n", encoding="utf-8"
        )
        feature_file.write_text("export const feature = true;\n", encoding="utf-8")

        _, wildcard_edges, importers_of = build_ts_import_graph(
            _scan_raw_imports(app_file, feature_file),
            {},
        )
        dead_files = find_dead_ts_files(
            [app_file, feature_file],
            [],
            importers_of,
            wildcard_edges,
        )

        assert dead_files == []

    def test_import_meta_glob_keeps_matched_routes_live(self, tmp_path):
        app_file = tmp_path / "src" / "main.ts"
        route_file = tmp_path / "src" / "routes" / "index.ts"
        helper_file = tmp_path / "src" / "routes" / "helper.ts"

        route_file.parent.mkdir(parents=True, exist_ok=True)
        app_file.write_text(
            "const routes = import.meta.glob('./routes/**/*.ts');\n", encoding="utf-8"
        )
        route_file.write_text(
            "import './helper';\nexport const route = true;\n", encoding="utf-8"
        )
        helper_file.write_text("export const helper = true;\n", encoding="utf-8")

        _, wildcard_edges, importers_of = build_ts_import_graph(
            _scan_raw_imports(app_file, route_file, helper_file),
            {},
        )
        dead_files = find_dead_ts_files(
            [app_file, route_file, helper_file],
            [],
            importers_of,
            wildcard_edges,
        )

        assert dead_files == []

    def test_import_meta_glob_ignores_absolute_outside_file_root(self, tmp_path):
        app_file = tmp_path / "src" / "main.ts"
        outside_file = tmp_path / "outside" / "leak.ts"

        app_file.parent.mkdir(parents=True, exist_ok=True)
        outside_file.parent.mkdir(parents=True, exist_ok=True)
        outside_file.write_text("export const leak = true;\n", encoding="utf-8")
        app_file.write_text(
            f"const routes = import.meta.glob('{outside_file.parent}/**/*.ts');\n",
            encoding="utf-8",
        )

        raw_imports = scan_typescript_file(str(app_file))[12]

        assert raw_imports == []

    def test_import_meta_glob_ignores_parent_traversal(self, tmp_path):
        app_file = tmp_path / "src" / "main.ts"
        outside_file = tmp_path / "outside" / "leak.ts"

        app_file.parent.mkdir(parents=True, exist_ok=True)
        outside_file.parent.mkdir(parents=True, exist_ok=True)
        outside_file.write_text("export const leak = true;\n", encoding="utf-8")
        app_file.write_text(
            "const routes = import.meta.glob('../outside/**/*.ts');\n",
            encoding="utf-8",
        )

        raw_imports = scan_typescript_file(str(app_file))[12]

        assert raw_imports == []

    def test_vitest_config_root_cannot_escape_project_root(self, tmp_path):
        project_root = tmp_path / "project"
        outside_file = tmp_path / "outside" / "checks" / "login.ts"
        vitest_config = project_root / "vitest.config.ts"

        project_root.mkdir(parents=True, exist_ok=True)
        outside_file.parent.mkdir(parents=True, exist_ok=True)
        outside_file.write_text("export const leak = true;\n", encoding="utf-8")
        vitest_config.write_text(
            f"""
import {{ defineConfig }} from "vitest/config";

export default defineConfig({{
  root: "{outside_file.parent.parent}",
  test: {{
    include: ["**/*.ts"],
  }},
}});
""",
            encoding="utf-8",
        )

        entries = _discover_vitest_config_entries(
            str(vitest_config),
            {str(outside_file.resolve())},
            str(project_root),
        )

        assert entries == set()


class TestTypeScriptUnusedExports:
    def test_package_json_entrypoint_export_is_not_flagged(self, tmp_path):
        public_api = tmp_path / "packages" / "ui" / "src" / "public-api.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","workspaces":["packages/*"]}', encoding="utf-8"
        )
        (tmp_path / "packages" / "ui").mkdir(parents=True, exist_ok=True)
        (tmp_path / "packages" / "ui" / "package.json").write_text(
            '{"name":"@repo/ui","exports":"./src/public-api.ts"}', encoding="utf-8"
        )
        public_api.parent.mkdir(parents=True, exist_ok=True)
        public_api.write_text(
            "export function makeLabel(value: string) { return value.trim(); }\n",
            encoding="utf-8",
        )

        inventory = discover_workspace_inventory(tmp_path)
        defn = _make_def("makeLabel", "function", str(public_api), exported=True)
        defn.references = 1
        defn.is_exported = False

        findings = find_unused_ts_exports(
            [defn],
            {},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert findings == []

    def test_package_json_script_entry_export_is_not_flagged(self, tmp_path):
        cli_file = tmp_path / "src" / "cli.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","scripts":{"dev":"tsx src/cli.ts"}}',
            encoding="utf-8",
        )
        cli_file.parent.mkdir(parents=True, exist_ok=True)
        cli_file.write_text(
            "export function run() { return true; }\n", encoding="utf-8"
        )

        inventory = discover_workspace_inventory(tmp_path)
        defn = _make_def("run", "function", str(cli_file), exported=True)
        defn.references = 1
        defn.is_exported = False

        findings = find_unused_ts_exports(
            [defn],
            {},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert findings == []

    def test_default_cli_mts_export_is_not_flagged(self, tmp_path):
        cli_file = tmp_path / "src" / "cli.mts"

        cli_file.parent.mkdir(parents=True, exist_ok=True)
        cli_file.write_text(
            "export function runCli() { return true; }\n", encoding="utf-8"
        )

        defn = _make_def("runCli", "function", str(cli_file), exported=True)
        defn.references = 1
        defn.is_exported = False

        findings = find_unused_ts_exports(
            [defn],
            {},
            files=[str(cli_file)],
        )

        assert findings == []

    def test_vite_config_entry_export_is_not_flagged(self, tmp_path):
        vite_config = tmp_path / "vite.config.ts"
        entry_file = tmp_path / "src" / "library-entry.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root"}',
            encoding="utf-8",
        )
        entry_file.parent.mkdir(parents=True, exist_ok=True)
        vite_config.write_text(
            """
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "src/library-entry.ts",
    },
  },
});
""",
            encoding="utf-8",
        )
        entry_file.write_text(
            "export function buildLibrary() { return true; }\n",
            encoding="utf-8",
        )

        inventory = discover_workspace_inventory(tmp_path)
        defn = _make_def("buildLibrary", "function", str(entry_file), exported=True)
        defn.references = 1
        defn.is_exported = False

        findings = find_unused_ts_exports(
            [defn],
            {},
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert findings == []

    def test_vitest_root_export_is_still_flagged_as_dev_only(self, tmp_path):
        vitest_config = tmp_path / "tooling" / "vitest.workspace.ts"
        check_file = tmp_path / "checks" / "login.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","scripts":{"test":"vitest --config tooling/vitest.workspace.ts"}}',
            encoding="utf-8",
        )
        vitest_config.parent.mkdir(parents=True, exist_ok=True)
        check_file.parent.mkdir(parents=True, exist_ok=True)
        vitest_config.write_text(
            """
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["checks/**/*.ts"],
  },
});
""",
            encoding="utf-8",
        )
        check_file.write_text(
            "export function runCheck() { return true; }\n", encoding="utf-8"
        )

        inventory = discover_workspace_inventory(tmp_path)
        defn = _make_def("runCheck", "function", str(check_file), exported=True)
        defn.references = 1
        defn.is_exported = False

        findings = find_unused_ts_exports(
            [defn],
            {},
            files=[str(vitest_config), str(check_file)],
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert len(findings) == 1
        assert findings[0]["name"] == "runCheck"

    def test_playwright_root_export_is_still_flagged_as_dev_only(self, tmp_path):
        playwright_config = tmp_path / "tooling" / "playwright.e2e.ts"
        test_file = tmp_path / "browser" / "login.ts"

        (tmp_path / "package.json").write_text(
            '{"name":"@repo/root","scripts":{"e2e":"playwright test --config tooling/playwright.e2e.ts"}}',
            encoding="utf-8",
        )
        playwright_config.parent.mkdir(parents=True, exist_ok=True)
        test_file.parent.mkdir(parents=True, exist_ok=True)
        playwright_config.write_text(
            """
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "../browser",
});
""",
            encoding="utf-8",
        )
        test_file.write_text(
            "export function runBrowserTest() { return true; }\n",
            encoding="utf-8",
        )

        inventory = discover_workspace_inventory(tmp_path)
        defn = _make_def("runBrowserTest", "function", str(test_file), exported=True)
        defn.references = 1
        defn.is_exported = False

        findings = find_unused_ts_exports(
            [defn],
            {},
            files=[str(playwright_config), str(test_file)],
            project_root=str(tmp_path),
            workspace_inventory=inventory,
        )

        assert len(findings) == 1
        assert findings[0]["name"] == "runBrowserTest"

    def test_dynamic_import_consumes_all_exports_for_unused_export_detection(
        self, tmp_path
    ):
        app_file = tmp_path / "src" / "main.ts"
        feature_file = tmp_path / "src" / "feature.ts"

        feature_file.parent.mkdir(parents=True, exist_ok=True)
        app_file.write_text(
            "async function load() { await import('./feature'); }\n", encoding="utf-8"
        )
        feature_file.write_text(
            "export function renderFeature() { return true; }\n", encoding="utf-8"
        )

        defn = _make_def("renderFeature", "function", str(feature_file), exported=True)
        defs = {f"{feature_file}:renderFeature": defn}

        consumed, _, _ = build_ts_import_graph(
            _scan_raw_imports(app_file, feature_file),
            defs,
        )

        assert "renderFeature" in consumed[str(feature_file)]
