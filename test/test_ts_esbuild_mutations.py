from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript.analysis import (
    _discover_esbuild_config_entries,
)


def _entries(tmp_path: Path, code: str) -> set[str]:
    source = tmp_path / "src" / "worker.js"
    source.parent.mkdir()
    assert write_text_no_symlink(source, "export {};\n", encoding="utf-8")
    config = tmp_path / "build.mjs"
    assert write_text_no_symlink(
        config, "import { build } from 'esbuild';\n" + code, encoding="utf-8"
    )
    return _discover_esbuild_config_entries(
        str(config), {str(source.resolve())}, str(tmp_path)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "const alias = entries; alias[0] = 'src/other.js';",
        "let alias = entries; alias.pop();",
        "const first = entries; const second = first; second.splice(0, 1);",
        "const options = {entryPoints: entries}; options.entryPoints.pop();",
        "const holder = [entries]; holder[0][0] = 'src/other.js';",
        "const holder = {entries}; holder.entries.pop();",
        "entries[0] += '.other';",
        "entries.length--;",
        "delete entries[0];",
        "(entries)[0] = 'src/other.js';",
        "entries['pop']();",
    ],
)
def test_esbuild_does_not_fold_stale_array_initializers(tmp_path, mutation):
    assert not _entries(
        tmp_path,
        "const entries = ['src/worker.js'];\n"
        f"{mutation}\n"
        "build({entryPoints: entries});\n",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "options.entryPoints[0] = 'src/other.js';",
        "options.entryPoints.splice(0, 1);",
        "delete options.entryPoints[0];",
        "const alias = options.entryPoints; alias.pop();",
        "const alias = options; alias.entryPoints.pop();",
        "const copy = {...options}; copy.entryPoints.pop();",
    ],
)
def test_esbuild_does_not_fold_stale_nested_options(tmp_path, mutation):
    assert not _entries(
        tmp_path,
        "const options = {entryPoints: ['src/worker.js']};\n"
        f"{mutation}\n"
        "build(options);\n",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "path.join = () => 'src/other.js';",
        "const alias = path; alias.join = () => 'src/other.js';",
        "delete path.join;",
    ],
)
def test_esbuild_does_not_trust_modified_path_helpers(tmp_path, mutation):
    assert not _entries(
        tmp_path,
        "import path from 'node:path';\n"
        f"{mutation}\n"
        "build({entryPoints: [path.join('src', 'worker.js')]});\n",
    )


def test_esbuild_does_not_trust_modified_build_namespace(tmp_path):
    assert not _entries(
        tmp_path,
        "import * as esbuild from 'esbuild';\n"
        "esbuild.build = () => {};\n"
        "esbuild.build({entryPoints: ['src/worker.js']});\n",
    )


@pytest.mark.parametrize(
    "setup",
    [
        "const alias = entries;",
        "const options = {entryPoints: entries};",
        "const other = ['src/other.js']; other.pop();",
        "const copied = [...entries];",
        "const mapped = entries.map(name => name); mapped.pop();",
    ],
)
def test_esbuild_keeps_unchanged_entry_arrays(tmp_path, setup):
    matches = _entries(
        tmp_path,
        "const entries = ['src/worker.js'];\n"
        f"{setup}\n"
        "build({entryPoints: entries});\n",
    )
    assert {Path(path).name for path in matches} == {"worker.js"}


@pytest.mark.parametrize(
    "setup",
    [
        "const root = 'src';",
        "const original = 'src'; const root = original;",
        "const root = `src`;",
    ],
)
def test_esbuild_container_writes_do_not_mutate_primitive_constants(tmp_path, setup):
    matches = _entries(
        tmp_path,
        f"{setup}\n"
        "const settings = {root}; settings.verbose = true;\n"
        "build({entryPoints: [`${root}/worker.js`]});\n",
    )
    assert {Path(path).name for path in matches} == {"worker.js"}


@pytest.mark.parametrize(
    "unrelated",
    [
        "function other(build) { build = () => {}; }",
        "const other = (build) => { build = () => {}; };",
        "function other(entries) { entries.pop(); }",
        "function other({entries}) { entries.pop(); }",
        "function other() { let build; build = () => {}; }",
        "{ const entries = []; entries.pop(); }",
        "function other() { const entries = []; const alias = entries; alias.pop(); }",
    ],
)
def test_esbuild_ignores_writes_to_explicitly_shadowed_bindings(tmp_path, unrelated):
    matches = _entries(
        tmp_path,
        "const entries = ['src/worker.js'];\n"
        f"{unrelated}\n"
        "build({entryPoints: entries});\n",
    )
    assert {Path(path).name for path in matches} == {"worker.js"}


def test_esbuild_shadowed_path_parameter_does_not_change_module_import(tmp_path):
    matches = _entries(
        tmp_path,
        "import path from 'node:path';\n"
        "function other(path) { path.join = () => 'other'; }\n"
        "build({entryPoints: [path.join('src', 'worker.js')]});\n",
    )
    assert {Path(path).name for path in matches} == {"worker.js"}


@pytest.mark.parametrize(
    "mutation",
    [
        "function change() { entries.pop(); } change();",
        "function change() { const alias = entries; alias.pop(); } change();",
        "{ const alias = entries; alias.pop(); }",
        "function change(build) { const alias = entries; alias.pop(); } change();",
    ],
)
def test_esbuild_retains_mutation_tracking_for_captured_module_bindings(
    tmp_path, mutation
):
    assert not _entries(
        tmp_path,
        "const entries = ['src/worker.js'];\n"
        f"{mutation}\n"
        "build({entryPoints: entries});\n",
    )
