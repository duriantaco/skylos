"""Convention roots use native path separators; source fixtures never execute."""

import ntpath
import posixpath
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript import analysis


@pytest.fixture(params=[posixpath, ntpath], ids=["posix", "windows"])
def path_style(request, monkeypatch):
    path_module = request.param
    # Change only this module's path operations, not the host OS or filesystem.
    monkeypatch.setattr(
        analysis, "os", SimpleNamespace(path=path_module, sep=path_module.sep)
    )
    root = "C:\\repo" if path_module is ntpath else "/repo"
    return lambda relative: path_module.join(root, *relative.split("/"))


@pytest.mark.parametrize("extension", ["js", "ts", "mjs", "mts"])
@pytest.mark.parametrize("config", ["config", "config/index"])
@pytest.mark.parametrize("prefix", ["", "docs/", "packages/docs/"])
def test_vitepress_configs_are_dev_roots(path_style, extension, config, prefix):
    path = path_style(f"{prefix}.vitepress/{config}.{extension}")
    assert analysis._is_ts_entry_or_infra(path)
    assert analysis._is_ts_dev_or_test_root(path)
    assert analysis._classify_entry_scope(path, "heuristic", "default-root") == "dev"


@pytest.mark.parametrize(
    "relative",
    [
        "scripts/check.js",
        "scripts/verify-tarball.js",
        "tools/scripts/check.mts",
        "__tests__/helper.ts",
        "test/helper.ts",
        "tests/helper.ts",
        "testdata/helper.ts",
        "integration/helper.ts",
        "_static/client.js",
        "static/client.js",
        "public/client.js",
        "bench/helper.ts",
        "benchmarks/helper.ts",
        "perf/helper.ts",
        "perf-measures/helper.ts",
        "performance/helper.ts",
        "example/helper.ts",
        "examples/helper.ts",
        "vite.config.mts",
    ],
)
def test_existing_infrastructure_conventions_use_native_separators(
    path_style, relative
):
    path = path_style(relative)
    assert analysis._is_ts_entry_or_infra(path)
    assert analysis._is_ts_dev_or_test_root(path)


@pytest.mark.parametrize(
    "relative",
    [
        "src/config.mts",
        "config.mts",
        "docs/vitepress/config.mts",
        "docs/.vitepress-old/config.mts",
        "docs/.vitepress/config-helper.ts",
        "docs/.vitepress/nested/config.mts",
        "docs/.vitepress/config/helpers.ts",
        "docs/.vitepress/config.cts",
        "docs/.vitepress/config.cjs",
        "docs/.vitepress/config.tsx",
        "docs/.vitepress/config/index.cts",
        "docs/.vitepress/theme/index.ts",
        "scripts-helper/check.js",
        "src/orphan.ts",
    ],
)
def test_lookalikes_are_not_infrastructure_roots(path_style, relative):
    path = path_style(relative)
    # Generic index.* roots are separate; do not assert those are dead files.
    assert not analysis._is_ts_entry_or_infra(path)
    assert not analysis._is_ts_dev_or_test_root(path)


def test_dev_roots_do_not_become_production_api_roots(path_style):
    config = path_style("docs/.vitepress/config.mts")
    config_index = path_style("docs/.vitepress/config/index.ts")
    script = path_style("scripts/check.js")
    production = path_style("src/index.ts")
    files = [config, config_index, script, production]
    assert analysis._discover_ts_reachability_entry_files(files) == set(files)
    assert analysis._discover_ts_reachability_entry_files(
        files, include_dev_roots=False
    ) == {production}


def test_conventions_keep_imported_helpers_live(path_style):
    config = path_style("docs/.vitepress/config.mts")
    script = path_style("scripts/check.js")
    config_helper = path_style("docs/.vitepress/sidebar.mts")
    script_helper = path_style("src/task-helper.js")
    orphan = path_style("src/orphan.ts")
    findings = analysis.find_dead_ts_files(
        [config, script, config_helper, script_helper, orphan],
        [],
        {config_helper: {config}, script_helper: {script}},
        {},
    )
    assert {finding["file"] for finding in findings} == {orphan}


def test_literal_backslashes_are_not_posix_separators(monkeypatch):
    monkeypatch.setattr(analysis, "os", SimpleNamespace(path=posixpath, sep="/"))
    for path in (
        r"/repo/notes\scripts\check.js",
        r"/repo/notes\.vitepress\config.mts",
    ):
        assert not analysis._is_ts_entry_or_infra(path)
        assert not analysis._is_ts_dev_or_test_root(path)


def _write(root, relative, content):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(content)
    return path


@pytest.mark.parametrize("config_name", ["config.mts", "config/index.mts"])
def test_native_import_graph_keeps_only_referenced_convention_helpers(
    tmp_path, config_name
):
    config = _write(
        tmp_path,
        f"docs/.vitepress/{config_name}",
        "import { title } from './sidebar.mjs';\nexport default { title };\n",
    )
    sidebar = _write(
        tmp_path,
        str(config.parent.relative_to(tmp_path) / "sidebar.mts"),
        "export const title = 'Docs';\n",
    )
    script = _write(
        tmp_path,
        "scripts/check.js",
        "import { run } from '../src/task-helper.js';\nrun();\n",
    )
    script_helper = _write(tmp_path, "src/task-helper.js", "export function run() {}\n")
    orphan = _write(tmp_path, "src/orphan.ts", "console.log('unused');\n")
    unrelated_config = _write(tmp_path, "src/config.mts", "export default {};\n")
    unrelated_sidebar = _write(
        tmp_path, "docs/.vitepress/unused.mts", "export const unused = 'unused';\n"
    )
    files = [
        config,
        sidebar,
        script,
        script_helper,
        orphan,
        unrelated_config,
        unrelated_sidebar,
    ]
    raw_imports = {str(path): scan_typescript_file(str(path))[12] for path in files}
    _, wildcards, importers = analysis.build_ts_import_graph(raw_imports, {})
    findings = analysis.find_dead_ts_files(
        files, [], importers, wildcards, project_root=str(tmp_path)
    )
    assert {Path(finding["file"]) for finding in findings} == {
        orphan,
        unrelated_config,
        unrelated_sidebar,
    }
    assert (
        analysis._discover_ts_reachability_entry_files(
            files, project_root=str(tmp_path), include_dev_roots=False
        )
        == set()
    )
    assert analysis._discover_ts_reachability_entry_files(
        files, project_root=str(tmp_path), exclude_folders=["docs/.vitepress"]
    ) == {str(script.resolve())}
