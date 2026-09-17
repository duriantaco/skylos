from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.typescript import esbuild_static
from skylos.visitors.languages.typescript.analysis import (
    _discover_esbuild_config_entries,
)


def _entries(tmp_path: Path, code: str) -> set[str]:
    sources = [
        tmp_path / "src" / "old.js",
        tmp_path / "src" / "new.js",
        tmp_path / "src" / "worker.js",
        tmp_path / "src" / "w.js",
    ]
    sources[0].parent.mkdir()
    for source in sources:
        assert write_text_no_symlink(source, "export {};\n", encoding="utf-8")
    config = tmp_path / "build.mts"
    assert write_text_no_symlink(
        config, "import { build } from 'esbuild';\n" + code, encoding="utf-8"
    )
    found = _discover_esbuild_config_entries(
        str(config), {str(source.resolve()) for source in sources}, str(tmp_path)
    )
    return {Path(path).name for path in found}


@pytest.mark.parametrize(
    "receiver",
    ["(custom).path", "getCustom().path", "custom['tools'].path"],
)
def test_esbuild_does_not_trust_an_import_name_in_a_member_chain_suffix(
    tmp_path, receiver
):
    code = (
        "import path from 'node:path';\n"
        "const tools = {path: {join: () => 'src/new.js'}};\n"
        "const custom = {...tools, tools};\n"
        "function getCustom() { return custom; }\n"
        f"build({{entryPoints: [{receiver}.join('src', 'old.js')]}});\n"
    )

    assert _entries(tmp_path, code) == set()


@pytest.mark.parametrize(
    ("path_import", "parameter", "call"),
    [
        ("import { join } from 'node:path';", "join", "join('src', 'old.js')"),
        (
            "import { join as combine } from 'node:path';",
            "combine",
            "combine('src', 'old.js')",
        ),
        ("import path from 'node:path';", "path", "path.join('src', 'old.js')"),
        (
            "import * as paths from 'node:path';",
            "paths",
            "paths.join('src', 'old.js')",
        ),
    ],
)
def test_esbuild_map_parameter_shadows_imported_helpers(
    tmp_path, path_import, parameter, call
):
    code = (
        f"{path_import}\n"
        f"build({{entryPoints: ['worker'].map({parameter} => {call})}});\n"
    )

    assert _entries(tmp_path, code) == set()


@pytest.mark.parametrize(
    "callback",
    [
        "([name]) => `src/${name}.js`",
        "({length: name}) => `src/${name}.js`",
        "(...name) => `src/${name}.js`",
        "async name => `src/${name}.js`",
        "async (name: string) => `src/${name}.js`",
        "(name = 'other') => `src/${name}.js`",
        "(name, index) => `src/${name}.js`",
    ],
)
def test_esbuild_abstains_on_unsupported_map_parameter_or_async_shapes(
    tmp_path, callback
):
    code = f"build({{entryPoints: ['worker'].map({callback})}});\n"

    assert _entries(tmp_path, code) == set()


@pytest.mark.parametrize(
    "parameter",
    [
        "name",
        "(name)",
        "(name: string)",
        "(name?: string)",
        "(/* before */ name /* after */)",
    ],
)
def test_esbuild_accepts_simple_map_parameters(tmp_path, parameter):
    code = (
        f"build({{entryPoints: ['worker'].map({parameter} => `src/${{name}}.js`)}});\n"
    )

    assert _entries(tmp_path, code) == {"worker.js"}


@pytest.mark.parametrize(
    ("path_import", "call"),
    [
        ("import { join } from 'node:path';", "join('src', `${name}.js`)"),
        ("import path from 'node:path';", "path.join('src', `${name}.js`)"),
        (
            "import * as paths from 'node:path';",
            "paths.join('src', `${name}.js`)",
        ),
    ],
)
def test_esbuild_preserves_unshadowed_imported_helpers(tmp_path, path_import, call):
    code = f"{path_import}\nbuild({{entryPoints: ['worker'].map(name => {call})}});\n"

    assert _entries(tmp_path, code) == {"worker.js"}


def test_esbuild_callback_shadow_does_not_change_a_module_binding(tmp_path):
    code = (
        "import { join } from 'node:path';\n"
        "const entry = join('src', 'worker.js');\n"
        "build({entryPoints: ['unused'].map(join => entry)});\n"
    )

    assert _entries(tmp_path, code) == {"worker.js"}


@pytest.mark.parametrize(
    "source",
    [
        "({label: 'worker'})",
        "[{in: 'worker', out: 'bundle'}]",
        "['new', {in: 'worker', out: 'bundle'}]",
    ],
)
def test_esbuild_map_does_not_normalize_entry_objects_into_strings(tmp_path, source):
    code = (
        f"const values = {source};\n"
        "const alias = values;\n"
        "build({entryPoints: alias.map(name => `src/${name}.js`)});\n"
    )

    assert _entries(tmp_path, code) == set()


@pytest.mark.parametrize(
    "source",
    [
        "['worker']",
        "(['worker'] as const)",
        "['worker'].map(name => `${name}`)",
        "['worker'].map(name => `${name}`).map(name => `${name}`)",
    ],
)
def test_esbuild_map_preserves_string_arrays_aliases_and_nested_maps(tmp_path, source):
    code = (
        f"const values = {source};\n"
        "const alias = values;\n"
        "build({entryPoints: alias.map(name => `src/${name}.js`)});\n"
    )

    assert _entries(tmp_path, code) == {"worker.js"}


def test_esbuild_map_source_alias_cycle_abstains(tmp_path):
    code = (
        "const first = second; const second = first;\n"
        "build({entryPoints: first.map(name => `src/${name}.js`)});\n"
    )

    assert _entries(tmp_path, code) == set()


def test_esbuild_nested_maps_share_the_static_depth_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(esbuild_static, "_MAX_DEPTH", 4)
    code = (
        "build({entryPoints: ['worker'].map(name => `${name}`)"
        ".map(name => `${name}`).map(name => `src/${name}.js`)});\n"
    )

    assert _entries(tmp_path, code) == set()
