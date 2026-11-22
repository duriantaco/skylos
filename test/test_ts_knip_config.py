"""A repository's own Knip config, honoured only where it removes findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript import knip_config, plugin_facts
from skylos.visitors.languages.typescript.knip_config import (
    apply_knip_config,
    knip_entry,
    load_knip_config,
)


@pytest.fixture(autouse=True)
def _fresh_settings():
    knip_config.configure()
    knip_config.clear_caches()
    plugin_facts.clear_caches()
    yield
    knip_config.configure()
    knip_config.clear_caches()
    plugin_facts.clear_caches()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _scan(root: Path) -> dict:
    return json.loads(analyze(str(root), conf=60, grep_cache=False))


def _reported(result: dict, root: Path) -> set[tuple[str, str, str]]:
    found = set()
    for key in ("unused_functions", "unused_variables", "unused_classes", "unused_imports", "unused_files", "unused_exports"):
        for item in result.get(key) or []:
            rel = Path(item["file"]).resolve().relative_to(root.resolve()).as_posix()
            found.add((key, rel, item.get("name") or ""))
    return found


def _project(root: Path, config_name: str | None, config: str | None) -> None:
    _write(root / "package.json", '{"name": "app", "private": true}')
    _write(root / "src/index.ts", "export const used = 1;\n")
    _write(root / "tools/gen.ts", "export function gen() { return 1; }\n")
    _write(root / "legacy/old.ts", "export const old = 1;\n")
    _write(root / "src/orphan.ts", "export const orphan = 1;\n")
    if config_name:
        _write(root / config_name, config)


def test_entry_and_ignore_remove_findings(tmp_path):
    _project(tmp_path, "knip.json", '{"entry": ["tools/gen.ts!"], "ignore": ["legacy/**"]}')
    result = _scan(tmp_path)
    reported = _reported(result, tmp_path)
    files = {rel for key, rel, _ in reported if key == "unused_files"}
    assert "tools/gen.ts" not in files
    assert not any(rel == "tools/gen.ts" for _k, rel, _n in reported)  # entry exports are public
    assert not any(rel == "legacy/old.ts" for _k, rel, _n in reported)
    assert "src/orphan.ts" in files  # untouched by the config
    assert {item["reason"] for item in result["suppressed"]} >= {"knip ignore"}
    assert result["analysis_summary"]["knip_config"]["honoured_keys"] == ["entry", "ignore"]


def test_without_a_config_nothing_changes(tmp_path):
    _project(tmp_path, None, None)
    files = {rel for key, rel, _ in _reported(_scan(tmp_path), tmp_path) if key == "unused_files"}
    assert {"tools/gen.ts", "legacy/old.ts", "src/orphan.ts"} <= files


@pytest.mark.parametrize(
    "name, text",
    [
        ("knip.ts", "import { list } from './list'\nexport default { entry: list(), ignore: compute() }\n"),
        ("knip.json", "{ not json"),
        ("knip.ts", "export default async () => { const x = await load(); return { ignore: x } }\n"),
    ],
)
def test_unreadable_config_never_adds_or_removes(tmp_path, name, text):
    _project(tmp_path, name, text)
    files = {rel for key, rel, _ in _reported(_scan(tmp_path), tmp_path) if key == "unused_files"}
    assert {"tools/gen.ts", "legacy/old.ts", "src/orphan.ts"} <= files


def test_literal_parts_of_a_typescript_config_are_honoured(tmp_path):
    _project(
        tmp_path,
        "knip.ts",
        "import type { KnipConfig } from 'knip'\n"
        "const extra = compute()\n"
        "export default { ignore: ['legacy/**', ...extra], ignoreDependencies: [/^@types\\//] } satisfies KnipConfig\n",
    )
    config = load_knip_config(str(tmp_path))
    assert "ignore" in config.unread  # partly literal: only the literal item applies
    assert config.root_workspace.ignore.matches("legacy/old.ts")
    assert config.root_workspace.ignore_dependencies.matches("@types/node")


def test_workspaces_scope_entries_and_ignores(tmp_path):
    _write(tmp_path / "package.json", '{"name": "root", "private": true, "workspaces": ["packages/*"]}')
    _write(tmp_path / "packages/a/package.json", '{"name": "a"}')
    _write(tmp_path / "packages/b/package.json", '{"name": "b"}')
    schematic = _write(tmp_path / "packages/a/schematics/ng-add/index.ts", "export function ngAdd() {}\n")
    same_path_b = _write(tmp_path / "packages/b/schematics/ng-add/index.ts", "export function ngAdd() {}\n")
    root_like = _write(tmp_path / "schematics/ng-add/index.ts", "export function ngAdd() {}\n")
    _write(
        tmp_path / "knip.json",
        json.dumps({"workspaces": {"packages/a": {"entry": ["schematics/*/index.ts"]}}}),
    )
    assert knip_entry(schematic)
    assert not knip_entry(same_path_b)
    assert not knip_entry(root_like)


def test_package_json_knip_key(tmp_path):
    _write(tmp_path / "package.json", '{"name": "p", "knip": {"entry": ["bin/run.ts"]}}')
    run = _write(tmp_path / "bin/run.ts", "export {};\n")
    assert knip_entry(run)


def _result(root: Path) -> dict:
    manifest = str(root / "package.json")
    return {
        "unused_files": [
            {"rule_id": "SKY-E003", "file": str(root / "examples/demo/x.ts")},
            {"rule_id": "SKY-E003", "file": str(root / "src/gen/types.ts")},
            {"rule_id": "SKY-E003", "file": str(root / "src/real.ts")},
        ],
        "unused_exports": [
            {"rule_id": "SKY-E004", "file": str(root / "src/a.ts"), "name": "a", "type": "variable"},
        ],
        "quality": [
            {"rule_id": "SKY-U005", "name": "lodash", "file": manifest, "metadata": {"ecosystem": "npm", "package_name": "lodash"}},
            {"rule_id": "SKY-U005", "name": "@acme/eslint-config", "file": manifest, "metadata": {"ecosystem": "npm", "package_name": "@acme/eslint-config"}},
            {"rule_id": "SKY-U005", "name": "react", "file": manifest, "metadata": {"ecosystem": "npm", "package_name": "react"}},
            {"rule_id": "SKY-Q409", "name": "gh", "file": manifest, "metadata": {}},
            {"rule_id": "SKY-Q408", "name": "chalk", "file": str(root / "src/real.ts"), "metadata": {"ecosystem": "npm", "package_name": "chalk"}},
            {"rule_id": "SKY-C304", "name": "complex", "file": str(root / "src/gen/types.ts")},
        ],
        "analysis_summary": {},
    }


def test_ignore_keys_move_matching_findings_to_suppressed(tmp_path):
    _write(tmp_path / "package.json", '{"name": "p"}')
    _write(
        tmp_path / "knip.json",
        json.dumps(
            {
                "ignoreFiles": ["src/gen/**"],
                "ignoreDependencies": ["lodash", "@acme/.+"],
                "ignoreBinaries": ["gh"],
                "ignoreExportsUsedInFile": True,
                "ignoreWorkspaces": ["examples/*"],
            }
        ),
    )
    result = _result(tmp_path)
    summary = apply_knip_config(result, str(tmp_path))
    assert "ignoreWorkspaces" not in summary["honoured_keys"]  # opt-in, off
    assert [item["file"] for item in result["unused_files"]] == [
        str(tmp_path / "examples/demo/x.ts"),  # ignoreWorkspaces is opt-in
        str(tmp_path / "src/real.ts"),
    ]
    assert result["unused_exports"] == []
    assert {item["name"] for item in result["quality"]} == {"react", "chalk", "complex"}
    assert summary["suppressed"] == {
        "knip ignoreFiles": 1,
        "knip ignoreDependencies": 2,
        "knip ignoreBinaries": 1,
        "knip ignoreExportsUsedInFile": 1,
    }
    # Quality findings outside Knip's issue types are never touched.
    assert any(item["rule_id"] == "SKY-C304" for item in result["quality"])


def test_ignore_workspaces_is_opt_in(tmp_path):
    _write(tmp_path / "package.json", '{"name": "p"}')
    _write(tmp_path / "examples/demo/package.json", '{"name": "demo"}')
    _write(tmp_path / "knip.json", json.dumps({"ignoreWorkspaces": ["examples/*"]}))
    knip_config.configure(ignore_workspaces=True)
    result = _result(tmp_path)
    apply_knip_config(result, str(tmp_path))
    assert str(tmp_path / "examples/demo/x.ts") not in [item["file"] for item in result["unused_files"]]


def test_project_patterns_limit_reported_files(tmp_path):
    _write(tmp_path / "package.json", '{"name": "p"}')
    _write(tmp_path / "knip.json", json.dumps({"project": ["src/**/*.ts"]}))
    result = _result(tmp_path)
    apply_knip_config(result, str(tmp_path))
    files = [item["file"] for item in result["unused_files"]]
    assert str(tmp_path / "examples/demo/x.ts") not in files
    assert str(tmp_path / "src/real.ts") in files


def test_disabled_by_the_skylos_config(tmp_path):
    _write(tmp_path / "package.json", '{"name": "p"}')
    _write(tmp_path / "knip.json", json.dumps({"ignoreDependencies": ["lodash"], "entry": ["src/real.ts"]}))
    knip_config.configure(enabled=False)
    result = _result(tmp_path)
    assert apply_knip_config(result, str(tmp_path)) == {}
    assert len(result["quality"]) == 6
    assert not knip_entry(tmp_path / "src/real.ts")
