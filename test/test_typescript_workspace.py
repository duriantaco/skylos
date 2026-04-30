from __future__ import annotations

import json

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript.workspace import discover_workspace_inventory


def test_discover_workspace_inventory_reports_sources_and_diagnostics(tmp_path):
    (tmp_path / "packages" / "app").mkdir(parents=True)
    (tmp_path / "packages" / "lib").mkdir(parents=True)
    (tmp_path / "apps" / "web").mkdir(parents=True)
    (tmp_path / "tools" / "cli").mkdir(parents=True)
    (tmp_path / "examples" / "demo").mkdir(parents=True)

    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "@repo/root",
                "workspaces": ["packages/*"],
                "dependencies": {"@repo/app": "workspace:*"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "packages:\n  - 'apps/*'\n",
        encoding="utf-8",
    )
    (tmp_path / "tsconfig.json").write_text(
        "{\n"
        "  // workspace refs\n"
        '  "references": [\n'
        '    { "path": "./tools/cli" },\n'
        "  ],\n"
        "}\n",
        encoding="utf-8",
    )

    (tmp_path / "packages" / "app" / "package.json").write_text(
        json.dumps({"name": "@repo/app", "dependencies": {"@repo/lib": "workspace:*"}}),
        encoding="utf-8",
    )
    (tmp_path / "packages" / "lib" / "package.json").write_text(
        json.dumps({"name": "@repo/lib"}),
        encoding="utf-8",
    )
    (tmp_path / "apps" / "web" / "package.json").write_text(
        json.dumps({"name": "@repo/web"}),
        encoding="utf-8",
    )
    (tmp_path / "examples" / "demo" / "package.json").write_text(
        json.dumps({"name": "@repo/demo"}),
        encoding="utf-8",
    )

    inventory = discover_workspace_inventory(tmp_path)

    assert inventory.root_package is not None
    assert inventory.root_package.name == "@repo/root"
    assert inventory.root_package.is_root is True

    packages = {pkg.name: pkg for pkg in inventory.packages}
    assert packages["@repo/app"].discovered_from == {"package.json:workspaces"}
    assert packages["@repo/web"].discovered_from == {"pnpm-workspace.yaml"}
    assert packages["@repo/lib"].is_internal_dependency is True

    ref_workspace = packages["tools/cli"]
    assert ref_workspace.has_package_json is False
    assert ref_workspace.discovered_from == {"tsconfig.json:references"}

    assert inventory.tsconfig_references == ["tools/cli"]
    assert any(
        diag.kind == "undeclared_workspace_package"
        and diag.path == (tmp_path / "examples" / "demo").resolve()
        for diag in inventory.diagnostics
    )


def test_analyze_reports_workspace_inventory_without_source_files(tmp_path):
    (tmp_path / "packages" / "app").mkdir(parents=True)

    (tmp_path / "package.json").write_text(
        json.dumps({"name": "@repo/root", "workspaces": ["packages/*"]}),
        encoding="utf-8",
    )
    (tmp_path / "packages" / "app" / "package.json").write_text(
        json.dumps({"name": "@repo/app"}),
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path)))

    assert result["analysis_summary"]["total_files"] == 0
    assert result["analysis_summary"]["monorepo_detected"] is True
    assert result["analysis_summary"]["workspace_count"] == 1
    assert result["analysis_summary"]["workspace_total_packages"] == 2
    assert result["analysis_summary"]["workspace_diagnostic_count"] == 0
    assert result["workspaces"]["root_package"]["name"] == "@repo/root"
    assert result["workspaces"]["packages"][0]["name"] == "@repo/app"


def test_pnpm_inline_yaml_workspace_patterns_are_supported(tmp_path):
    (tmp_path / "packages" / "ui").mkdir(parents=True)

    (tmp_path / "pnpm-workspace.yaml").write_text(
        'packages: ["packages/*"]\n',
        encoding="utf-8",
    )
    (tmp_path / "packages" / "ui" / "package.json").write_text(
        json.dumps({"name": "@repo/ui"}),
        encoding="utf-8",
    )

    inventory = discover_workspace_inventory(tmp_path)

    packages = {pkg.name: pkg for pkg in inventory.packages}
    assert packages["@repo/ui"].discovered_from == {"pnpm-workspace.yaml"}


def test_workspace_discovery_does_not_skip_hidden_parent_of_root(tmp_path):
    root = tmp_path / ".sandbox" / "repo"
    (root / "packages" / "ui").mkdir(parents=True)

    (root / "package.json").write_text(
        json.dumps({"name": "@repo/root", "workspaces": ["packages/*"]}),
        encoding="utf-8",
    )
    (root / "packages" / "ui" / "package.json").write_text(
        json.dumps({"name": "@repo/ui"}),
        encoding="utf-8",
    )

    inventory = discover_workspace_inventory(root)

    packages = {pkg.name: pkg for pkg in inventory.packages}
    assert "@repo/ui" in packages


def test_discover_workspace_inventory_includes_explicit_tsconfig_file_references(
    tmp_path,
):
    (tmp_path / "packages" / "ui").mkdir(parents=True)

    (tmp_path / "tsconfig.json").write_text(
        json.dumps({"references": [{"path": "./packages/ui/tsconfig.lib.json"}]}),
        encoding="utf-8",
    )
    (tmp_path / "packages" / "ui" / "tsconfig.lib.json").write_text(
        json.dumps({"compilerOptions": {}}),
        encoding="utf-8",
    )
    (tmp_path / "packages" / "ui" / "package.json").write_text(
        json.dumps({"name": "@repo/ui"}),
        encoding="utf-8",
    )

    inventory = discover_workspace_inventory(tmp_path)

    packages = {pkg.name: pkg for pkg in inventory.packages}
    assert packages["@repo/ui"].discovered_from == {"tsconfig.json:references"}
    assert inventory.tsconfig_references == ["packages/ui/tsconfig.lib.json"]


def test_discover_workspace_inventory_supports_lerna_and_rush(tmp_path):
    (tmp_path / "packages" / "ui").mkdir(parents=True)
    (tmp_path / "tools" / "cli").mkdir(parents=True)

    (tmp_path / "lerna.json").write_text(
        json.dumps({"packages": ["packages/*"]}),
        encoding="utf-8",
    )
    (tmp_path / "rush.json").write_text(
        json.dumps({"projects": [{"projectFolder": "tools/cli"}]}),
        encoding="utf-8",
    )
    (tmp_path / "packages" / "ui" / "package.json").write_text(
        json.dumps({"name": "@repo/ui"}),
        encoding="utf-8",
    )
    (tmp_path / "tools" / "cli" / "package.json").write_text(
        json.dumps({"name": "@repo/cli"}),
        encoding="utf-8",
    )

    inventory = discover_workspace_inventory(tmp_path)

    packages = {pkg.name: pkg for pkg in inventory.packages}
    assert packages["@repo/ui"].discovered_from == {"lerna.json:packages"}
    assert packages["@repo/cli"].discovered_from == {"rush.json:projects"}
    assert "packages/*" in inventory.declared_patterns
