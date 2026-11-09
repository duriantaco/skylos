"""Generic function values are runtime references, without invoking the function."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript import scan_typescript_file
from test.fixture_paths import write_fixture


@pytest.mark.parametrize("extension", ["ts", "tsx"])
def test_instantiated_callback_is_a_reference(tmp_path, extension):
    path = tmp_path / ("app." + extension)
    path.write_text(
        'import { helper, retired } from "./utils";\nexport const reducers = { active: helper<State, Action> };\n'
    )
    result = scan_typescript_file(str(path))
    assert "helper" in {name for name, _file in result[1]}
    assert "retired" not in {name for name, _file in result[1]}


@pytest.mark.parametrize("extension", ["ts", "tsx"])
def test_instantiated_generic_import_is_live_and_neighbor_remains_unused(
    tmp_path, extension
):
    write_fixture(
        tmp_path,
        "utils.ts",
        "export function helper<T, U>(state: T, action: U) { return state; }\nexport function retired() { return 1; }\n",
    )
    write_fixture(
        tmp_path,
        "app." + extension,
        'import { helper, retired } from "./utils";\nexport const reducers = { active: helper<State, Action> };\n',
    )
    result = json.loads(analyze(str(tmp_path), grep_verify=False, grep_cache=False))
    names = {item["simple_name"] for item in result.get("unused_imports", [])}
    assert "helper" not in names
    assert "retired" in names
