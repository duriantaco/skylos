from __future__ import annotations

import json
from pathlib import Path

from skylos.visitor import Definition
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
