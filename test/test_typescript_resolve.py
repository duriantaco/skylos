from __future__ import annotations

import json
from pathlib import Path

from skylos.visitors.base import Definition
from skylos.visitors.languages.typescript.analysis import build_ts_import_graph
from skylos.visitors.languages.typescript.resolve import MonorepoResolver


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _make_def(name: str, filename: str, exported: bool = True) -> Definition:
    d = Definition(name, "function", filename, 1)
    d.is_exported = exported
    return d


def test_workspace_package_exports_root_and_subpath_resolution(tmp_path):
    ui_dir = tmp_path / "packages" / "ui"
    app_file = tmp_path / "packages" / "app" / "src" / "index.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@workspace/root", "workspaces": ["packages/*"]}),
    )
    _write(
        ui_dir / "package.json",
        json.dumps(
            {
                "name": "@workspace/ui",
                "exports": {
                    ".": "./src/index.ts",
                    "./utils": "./src/utils.ts",
                    "./helpers": "./dist/helpers.js",
                },
            }
        ),
    )
    _write(ui_dir / "src" / "index.ts", 'export const Button = () => "button";')
    _write(ui_dir / "src" / "utils.ts", "export const formatColor = () => 'red';")
    _write(ui_dir / "src" / "helpers.ts", "export const clamp = () => 1;")
    _write(app_file, "export const main = 1;")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@workspace/ui", str(app_file)) == str(
        ui_dir / "src" / "index.ts"
    )
    assert resolver.resolve("@workspace/ui/utils", str(app_file)) == str(
        ui_dir / "src" / "utils.ts"
    )
    assert resolver.resolve("@workspace/ui/helpers", str(app_file)) == str(
        ui_dir / "src" / "helpers.ts"
    )


def test_conditional_exports_prefer_runtime_target_over_types(tmp_path):
    ui_dir = tmp_path / "packages" / "ui"
    app_file = tmp_path / "packages" / "app" / "src" / "index.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@workspace/root", "workspaces": ["packages/*"]}),
    )
    _write(
        ui_dir / "package.json",
        json.dumps(
            {
                "name": "@workspace/ui",
                "exports": {
                    ".": {
                        "types": "./dist/index.d.ts",
                        "import": "./dist/index.js",
                        "default": "./dist/index.js",
                    }
                },
            }
        ),
    )
    _write(ui_dir / "src" / "index.ts", "export const Button = 1;")
    _write(app_file, "import { Button } from '@workspace/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@workspace/ui", str(app_file)) == str(
        ui_dir / "src" / "index.ts"
    )


def test_types_entry_can_fall_back_to_source_file(tmp_path):
    importer = tmp_path / "src" / "main.ts"
    target = tmp_path / "packages" / "core" / "src" / "index.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@workspace/root", "workspaces": ["packages/*"]}),
    )
    _write(
        tmp_path / "packages" / "core" / "package.json",
        json.dumps({"name": "@workspace/core", "types": "./dist/index.d.ts"}),
    )
    _write(target, "export const core = 1;\n")
    _write(importer, "import { core } from '@workspace/core';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@workspace/core", str(importer)) == str(target)


def test_package_subpath_js_import_without_exports_falls_back_to_ts_source(tmp_path):
    ui_dir = tmp_path / "packages" / "ui"
    app_file = tmp_path / "packages" / "app" / "src" / "index.ts"
    target = ui_dir / "src" / "foo.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@workspace/root", "workspaces": ["packages/*"]}),
    )
    _write(ui_dir / "package.json", json.dumps({"name": "@workspace/ui"}))
    _write(target, "export const foo = 1;\n")
    _write(app_file, "import { foo } from '@workspace/ui/foo.js';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@workspace/ui/foo.js", str(app_file)) == str(target)


def test_package_imports_exact_and_wildcard_resolution(tmp_path):
    importer = tmp_path / "src" / "index.ts"
    _write(
        tmp_path / "package.json",
        json.dumps(
            {
                "name": "subpath-imports",
                "imports": {
                    "#utils": "./src/utils/index.ts",
                    "#components/*": "./src/components/*",
                },
            }
        ),
    )
    _write(importer, "export const main = 1;")
    _write(tmp_path / "src" / "utils" / "index.ts", "export const helper = () => 42;")
    _write(
        tmp_path / "src" / "components" / "Button.ts",
        'export const Button = () => "button";',
    )

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("#utils", str(importer)) == str(
        tmp_path / "src" / "utils" / "index.ts"
    )
    assert resolver.resolve("#components/Button", str(importer)) == str(
        tmp_path / "src" / "components" / "Button.ts"
    )


def test_build_ts_import_graph_uses_exports_map_resolution(tmp_path):
    ui_dir = tmp_path / "packages" / "ui"
    app_file = tmp_path / "packages" / "app" / "src" / "index.ts"
    index_file = ui_dir / "src" / "index.ts"
    helpers_file = ui_dir / "src" / "helpers.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@workspace/root", "workspaces": ["packages/*"]}),
    )
    _write(
        ui_dir / "package.json",
        json.dumps(
            {
                "name": "@workspace/ui",
                "exports": {
                    ".": "./src/index.ts",
                    "./helpers": "./dist/helpers.js",
                },
            }
        ),
    )
    _write(index_file, 'export const Button = () => "button";')
    _write(helpers_file, "export const clamp = () => 1;")
    _write(
        app_file,
        "import { Button } from '@workspace/ui';\n"
        "import { clamp } from '@workspace/ui/helpers';\n",
    )

    defs = {
        f"{index_file}:Button": _make_def("Button", str(index_file)),
        f"{helpers_file}:clamp": _make_def("clamp", str(helpers_file)),
    }
    ts_raw_imports = {
        str(app_file): [
            {"source": "@workspace/ui", "names": ["Button"], "line": 1},
            {"source": "@workspace/ui/helpers", "names": ["clamp"], "line": 2},
        ]
    }

    consumed, _, _ = build_ts_import_graph(
        ts_raw_imports, defs, MonorepoResolver(str(tmp_path))
    )

    assert "Button" in consumed[str(index_file)]
    assert "clamp" in consumed[str(helpers_file)]


def test_build_ts_import_graph_resolves_extensionless_js_imports(tmp_path):
    app_file = tmp_path / "src" / "app.js"
    helper_file = tmp_path / "src" / "helper.js"

    _write(app_file, "import { helper } from './helper';\nhelper();\n")
    _write(helper_file, "export function helper() { return 1; }\n")

    defs = {f"{helper_file}:helper": _make_def("helper", str(helper_file))}
    ts_raw_imports = {
        str(app_file): [{"source": "./helper", "names": ["helper"], "line": 1}]
    }

    consumed, _, importers_of = build_ts_import_graph(ts_raw_imports, defs)

    assert consumed[str(helper_file)] == {"helper"}
    assert importers_of[str(helper_file)] == {str(app_file)}


def test_build_ts_import_graph_resolves_extensionless_mts_imports(tmp_path):
    app_file = tmp_path / "src" / "app.mts"
    helper_file = tmp_path / "src" / "helper.mts"

    _write(app_file, "import { helper } from './helper';\nhelper();\n")
    _write(helper_file, "export function helper() { return 1; }\n")

    defs = {f"{helper_file}:helper": _make_def("helper", str(helper_file))}
    ts_raw_imports = {
        str(app_file): [{"source": "./helper", "names": ["helper"], "line": 1}]
    }

    consumed, _, importers_of = build_ts_import_graph(ts_raw_imports, defs)

    assert consumed[str(helper_file)] == {"helper"}
    assert importers_of[str(helper_file)] == {str(app_file)}


def test_build_ts_import_graph_resolves_mjs_import_to_mts_source(tmp_path):
    app_file = tmp_path / "src" / "app.mts"
    helper_file = tmp_path / "src" / "helper.mts"

    _write(app_file, "import { helper } from './helper.mjs';\nhelper();\n")
    _write(helper_file, "export function helper() { return 1; }\n")

    defs = {f"{helper_file}:helper": _make_def("helper", str(helper_file))}
    ts_raw_imports = {
        str(app_file): [{"source": "./helper.mjs", "names": ["helper"], "line": 1}]
    }

    consumed, _, importers_of = build_ts_import_graph(ts_raw_imports, defs)

    assert consumed[str(helper_file)] == {"helper"}
    assert importers_of[str(helper_file)] == {str(app_file)}


def test_package_local_tsconfig_paths_override_root_in_monorepo(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "index.ts"
    local_target = app_dir / "src" / "components" / "Button.ts"
    root_target = tmp_path / "shared" / "components" / "Button.ts"

    _write(
        tmp_path / "tsconfig.json",
        json.dumps(
            {
                "compilerOptions": {
                    "baseUrl": ".",
                    "paths": {"@app/*": ["shared/*"]},
                }
            }
        ),
    )
    _write(
        app_dir / "tsconfig.json",
        json.dumps(
            {
                "extends": "../../tsconfig.json",
                "compilerOptions": {
                    "baseUrl": ".",
                    "paths": {"@app/*": ["src/*"]},
                },
            }
        ),
    )
    _write(importer, "export const main = 1;")
    _write(local_target, 'export const Button = () => "local";')
    _write(root_target, 'export const Button = () => "root";')

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@app/components/Button", str(importer)) == str(
        local_target
    )


def test_workspace_package_exports_mjs_target_resolves_to_mts_source(tmp_path):
    ui_dir = tmp_path / "packages" / "ui"
    app_file = tmp_path / "packages" / "app" / "src" / "index.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@workspace/root", "workspaces": ["packages/*"]}),
    )
    _write(
        ui_dir / "package.json",
        json.dumps(
            {
                "name": "@workspace/ui",
                "exports": {
                    ".": "./dist/index.mjs",
                },
            }
        ),
    )
    _write(ui_dir / "src" / "index.mts", 'export const Button = () => "button";')
    _write(app_file, "export const main = 1;\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@workspace/ui", str(app_file)) == str(
        ui_dir / "src" / "index.mts"
    )


def test_package_local_tsconfig_inherits_root_paths_via_extends(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "index.ts"
    shared_target = tmp_path / "shared" / "utils" / "format.ts"

    _write(
        tmp_path / "tsconfig.json",
        json.dumps(
            {
                "compilerOptions": {
                    "baseUrl": ".",
                    "paths": {"@shared/*": ["shared/*"]},
                }
            }
        ),
    )
    _write(
        app_dir / "tsconfig.json",
        json.dumps(
            {
                "extends": "../../tsconfig.json",
                "compilerOptions": {"baseUrl": "."},
            }
        ),
    )
    _write(importer, "export const main = 1;")
    _write(shared_target, 'export const format = () => "ok";')

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@shared/utils/format", str(importer)) == str(shared_target)


def test_root_package_self_import_uses_declared_root_package(tmp_path):
    importer = tmp_path / "src" / "consumer.ts"
    target = tmp_path / "src" / "index.ts"

    _write(
        tmp_path / "package.json",
        json.dumps(
            {
                "name": "@repo/root",
                "exports": "./src/index.ts",
                "workspaces": ["packages/*"],
            }
        ),
    )
    _write(importer, "import { core } from '@repo/root';\n")
    _write(target, "export const core = 1;\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/root", str(importer)) == str(target)


def test_pnpm_workspace_package_resolution_uses_declared_packages_only(tmp_path):
    importer = tmp_path / "src" / "main.ts"
    target = tmp_path / "packages" / "ui" / "src" / "index.ts"

    _write(tmp_path / "pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n")
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(importer, "import { Button } from '@repo/ui';\n")
    _write(target, "export const Button = 1;\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) == str(target)


def test_nested_workspace_package_resolution(tmp_path):
    importer = tmp_path / "apps" / "web" / "src" / "main.ts"
    target = tmp_path / "packages" / "platform" / "ui" / "src" / "index.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@repo/root", "workspaces": ["packages/*/*", "apps/*"]}),
    )
    _write(
        tmp_path / "packages" / "platform" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(
        tmp_path / "apps" / "web" / "package.json",
        json.dumps({"name": "@repo/web"}),
    )
    _write(target, "export const Button = 1;\n")
    _write(importer, "import { Button } from '@repo/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) == str(target)


def test_lerna_workspace_package_resolution_uses_declared_packages(tmp_path):
    importer = tmp_path / "src" / "main.ts"
    target = tmp_path / "packages" / "ui" / "src" / "index.ts"

    _write(tmp_path / "lerna.json", json.dumps({"packages": ["packages/*"]}))
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(importer, "import { Button } from '@repo/ui';\n")
    _write(target, "export const Button = 1;\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) == str(target)


def test_rush_workspace_package_resolution_uses_declared_projects(tmp_path):
    importer = tmp_path / "src" / "main.ts"
    target = tmp_path / "tools" / "cli" / "src" / "index.ts"

    _write(
        tmp_path / "rush.json",
        json.dumps({"projects": [{"projectFolder": "tools/cli"}]}),
    )
    _write(
        tmp_path / "tools" / "cli" / "package.json",
        json.dumps({"name": "@repo/cli", "exports": "./src/index.ts"}),
    )
    _write(importer, "import { run } from '@repo/cli';\n")
    _write(target, "export const run = 1;\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/cli", str(importer)) == str(target)


def test_undeclared_nested_package_does_not_participate_in_resolution(tmp_path):
    importer = tmp_path / "src" / "main.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@repo/root", "workspaces": ["packages/*"]}),
    )
    _write(
        tmp_path / "examples" / "demo" / "package.json",
        json.dumps({"name": "@repo/demo", "exports": "./src/index.ts"}),
    )
    _write(
        tmp_path / "examples" / "demo" / "src" / "index.ts", "export const demo = 1;\n"
    )
    _write(importer, "import { demo } from '@repo/demo';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/demo", str(importer)) is None


def test_declared_workspace_wins_when_undeclared_package_has_same_name(tmp_path):
    importer = tmp_path / "src" / "main.ts"
    declared_target = tmp_path / "packages" / "ui" / "src" / "index.ts"
    undeclared_target = tmp_path / "examples" / "ui" / "src" / "index.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@repo/root", "workspaces": ["packages/*"]}),
    )
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(
        tmp_path / "examples" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(declared_target, "export const declared = true;\n")
    _write(undeclared_target, "export const undeclared = true;\n")
    _write(importer, "import { declared } from '@repo/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) == str(declared_target)


def test_tsconfig_reference_without_package_json_is_not_name_resolved(tmp_path):
    importer = tmp_path / "src" / "main.ts"

    _write(
        tmp_path / "tsconfig.json",
        json.dumps({"references": [{"path": "./tools/build"}]}),
    )
    _write(
        tmp_path / "tools" / "build" / "src" / "index.ts", "export const tool = 1;\n"
    )
    _write(importer, "import { tool } from 'tools/build';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("tools/build", str(importer)) is None


def test_tsconfig_reference_without_package_name_does_not_bare_resolve(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "main.ts"

    _write(
        app_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../ui"}]}),
    )
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"exports": "./src/index.ts"}),
    )
    _write(tmp_path / "packages" / "ui" / "src" / "index.ts", "export const ui = 1;\n")
    _write(importer, "import { ui } from '@repo/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) is None


def test_direct_tsconfig_reference_with_package_json_resolves_importer_locally(
    tmp_path,
):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "main.ts"
    target = tmp_path / "packages" / "ui" / "src" / "index.ts"

    _write(
        app_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../ui"}]}),
    )
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(target, "export const ui = 1;\n")
    _write(importer, "import { ui } from '@repo/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) == str(target)


def test_tsconfig_reference_subpath_uses_referenced_package_exports(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "main.ts"
    target = tmp_path / "packages" / "ui" / "src" / "helpers.ts"

    _write(
        app_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../ui"}]}),
    )
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps(
            {
                "name": "@repo/ui",
                "exports": {
                    ".": "./src/index.ts",
                    "./helpers": "./dist/helpers.js",
                },
            }
        ),
    )
    _write(tmp_path / "packages" / "ui" / "src" / "index.ts", "export const ui = 1;\n")
    _write(target, "export const helper = 1;\n")
    _write(importer, "import { helper } from '@repo/ui/helpers';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui/helpers", str(importer)) == str(target)


def test_project_reference_does_not_leak_to_sibling_package(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    web_dir = tmp_path / "packages" / "web"
    importer = web_dir / "src" / "main.ts"

    _write(
        app_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../ui"}]}),
    )
    _write(web_dir / "tsconfig.json", json.dumps({"compilerOptions": {"baseUrl": "."}}))
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(tmp_path / "packages" / "ui" / "src" / "index.ts", "export const ui = 1;\n")
    _write(importer, "import { ui } from '@repo/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) is None


def test_tsconfig_paths_still_beat_project_references(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "main.ts"
    local_target = app_dir / "src" / "ui.ts"
    referenced_target = tmp_path / "packages" / "ui" / "src" / "index.ts"

    _write(
        app_dir / "tsconfig.json",
        json.dumps(
            {
                "compilerOptions": {
                    "baseUrl": ".",
                    "paths": {"@repo/ui": ["src/ui.ts"]},
                },
                "references": [{"path": "../ui"}],
            }
        ),
    )
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(local_target, "export const local = true;\n")
    _write(referenced_target, "export const referenced = true;\n")
    _write(importer, "import { local } from '@repo/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) == str(local_target)


def test_tsconfig_reference_via_explicit_config_file_path_resolves_package(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "main.ts"
    target = tmp_path / "packages" / "ui" / "src" / "index.ts"

    _write(
        app_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../ui/tsconfig.lib.json"}]}),
    )
    _write(tmp_path / "packages" / "ui" / "tsconfig.lib.json", json.dumps({}))
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(target, "export const ui = 1;\n")
    _write(importer, "import { ui } from '@repo/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) == str(target)


def test_direct_project_reference_precedes_declared_workspace_fallback(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "main.ts"
    referenced_target = tmp_path / "libs" / "ui" / "src" / "index.ts"
    workspace_target = tmp_path / "packages" / "ui" / "src" / "index.ts"

    _write(
        tmp_path / "package.json",
        json.dumps({"name": "@repo/root", "workspaces": ["packages/*"]}),
    )
    _write(
        app_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../../libs/ui"}]}),
    )
    _write(
        tmp_path / "libs" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(referenced_target, "export const referenced = true;\n")
    _write(workspace_target, "export const workspace = true;\n")
    _write(importer, "import { ui } from '@repo/ui';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/ui", str(importer)) == str(referenced_target)


def test_transitive_project_reference_does_not_resolve_without_direct_reference(
    tmp_path,
):
    app_dir = tmp_path / "packages" / "app"
    ui_dir = tmp_path / "packages" / "ui"
    importer = app_dir / "src" / "main.ts"

    _write(
        app_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../ui"}]}),
    )
    _write(
        ui_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../core"}]}),
    )
    _write(
        tmp_path / "packages" / "core" / "package.json",
        json.dumps({"name": "@repo/core", "exports": "./src/index.ts"}),
    )
    _write(
        tmp_path / "packages" / "core" / "src" / "index.ts",
        "export const core = 1;\n",
    )
    _write(importer, "import { core } from '@repo/core';\n")

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@repo/core", str(importer)) is None


def test_build_ts_import_graph_uses_project_reference_resolution(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    app_file = app_dir / "src" / "index.ts"
    index_file = tmp_path / "packages" / "ui" / "src" / "index.ts"

    _write(
        app_dir / "tsconfig.json",
        json.dumps({"references": [{"path": "../ui"}]}),
    )
    _write(
        tmp_path / "packages" / "ui" / "package.json",
        json.dumps({"name": "@repo/ui", "exports": "./src/index.ts"}),
    )
    _write(index_file, 'export const Button = () => "button";')
    _write(app_file, "import { Button } from '@repo/ui';\n")

    defs = {
        f"{index_file}:Button": _make_def("Button", str(index_file)),
    }
    ts_raw_imports = {
        str(app_file): [
            {"source": "@repo/ui", "names": ["Button"], "line": 1},
        ]
    }

    consumed, _, _ = build_ts_import_graph(
        ts_raw_imports, defs, MonorepoResolver(str(tmp_path))
    )

    assert "Button" in consumed[str(index_file)]


def test_tsconfig_paths_support_jsonc_comments_and_trailing_commas(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "index.ts"
    target = tmp_path / "shared" / "utils" / "format.ts"

    _write(
        tmp_path / "tsconfig.json",
        "{\n"
        "  // root config\n"
        '  "compilerOptions": {\n'
        '    "baseUrl": ".",\n'
        '    "paths": {\n'
        '      "@shared/*": ["shared/*"],\n'
        "    },\n"
        "  },\n"
        "}\n",
    )
    _write(
        app_dir / "tsconfig.json",
        "{\n"
        '  "extends": "../../tsconfig.json",\n'
        '  "compilerOptions": {\n'
        '    "baseUrl": ".",\n'
        "  },\n"
        "}\n",
    )
    _write(importer, "export const main = 1;\n")
    _write(target, 'export const format = () => "ok";\n')

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@shared/utils/format", str(importer)) == str(target)


def test_tsconfig_extends_supports_node_modules_package_paths(tmp_path):
    app_dir = tmp_path / "packages" / "app"
    importer = app_dir / "src" / "index.ts"
    target = tmp_path / "shared" / "utils" / "format.ts"

    _write(
        tmp_path / "node_modules" / "@repo" / "tsconfig-base" / "tsconfig.json",
        json.dumps(
            {
                "compilerOptions": {
                    "baseUrl": "../../..",
                    "paths": {"@shared/*": ["shared/*"]},
                }
            }
        ),
    )
    _write(
        app_dir / "tsconfig.json",
        json.dumps(
            {
                "extends": "@repo/tsconfig-base/tsconfig.json",
                "compilerOptions": {"baseUrl": "."},
            }
        ),
    )
    _write(importer, "export const main = 1;\n")
    _write(target, 'export const format = () => "ok";\n')

    resolver = MonorepoResolver(str(tmp_path))

    assert resolver.resolve("@shared/utils/format", str(importer)) == str(target)
