"""Actual value reads and default import bindings, without public-API guesses."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.typescript import scan_typescript_file
from skylos.visitors.languages.typescript.analysis import build_ts_import_graph
from test.fixture_paths import write_fixture


@pytest.mark.parametrize("extension", ["ts", "tsx"])
@pytest.mark.parametrize(
    "signature,body",
    [
        ("value: number = fallback", "return value;"),
        ("{ value = fallback }: { value?: number }", "return value;"),
        ("{ value: renamed = fallback }: { value?: number }", "return renamed;"),
    ],
)
def test_only_parameter_default_value_is_a_read(tmp_path, extension, signature, body):
    path = write_fixture(
        tmp_path,
        "app." + extension,
        "const fallback = 1; const retired = 2;\n"
        + f"function run({signature}, unusedParameter = 0) {{ {body} }}\nrun({{}});\n",
    )
    result = scan_typescript_file(str(path))
    refs = [name for name, _ in result[1]]
    assert refs.count("fallback") == 1
    assert "retired" not in refs
    assert "unusedParameter" not in refs


@pytest.mark.parametrize("extension", ["ts", "tsx"])
def test_destructured_default_uses_import_but_preserves_unused_neighbor(
    tmp_path, monkeypatch, extension
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(
        tmp_path, "values.ts", "export const fallback = 1; export const retired = 2;\n"
    )
    write_fixture(
        tmp_path,
        "app." + extension,
        'import { fallback, retired } from "./values";\nfunction run({ value = fallback }: { value?: number }) { return value; }\nrun({});\n',
    )
    result = json.loads(analyze(str(tmp_path), grep_verify=False, grep_cache=False))
    assert not result.get("analysis_errors")
    names = {row["simple_name"] for row in result.get("unused_imports", [])}
    assert "fallback" not in names
    assert "retired" in names


def _graph(tmp_path, clause, body, extension):
    provider = write_fixture(
        tmp_path,
        "provider.ts",
        "export default function ActualDefault() { return 1; }\nexport function unusedNamed() { return 2; }\n",
    )
    orphan = write_fixture(
        tmp_path, "orphan.ts", "export default function OrphanDefault() { return 3; }\n"
    )
    app = write_fixture(
        tmp_path, "app." + extension, f'import {clause} from "./provider";\n' + body
    )
    definitions, imports = {}, {}
    for path in [provider, orphan, app]:
        scanned = scan_typescript_file(str(path))
        imports[str(path)] = scanned[12]
        for index, definition in enumerate(scanned[0]):
            definitions[f"{path}:{index}"] = definition
    consumed, _, _ = build_ts_import_graph(imports, definitions)
    by_name = {d.simple_name: d for d in definitions.values() if d.type != "import"}
    return by_name, consumed, provider


@pytest.mark.parametrize("extension", ["ts", "tsx"])
@pytest.mark.parametrize(
    "body", ["", "function local(view: number) { return view; }\nlocal(1);\n"]
)
def test_unread_or_shadowed_default_alias_does_not_rescue_target(
    tmp_path, body, extension
):
    definitions, _, _ = _graph(tmp_path, "view", body, extension)
    assert definitions["ActualDefault"].references == 0
    assert definitions["unusedNamed"].references == 0
    assert definitions["OrphanDefault"].references == 0


def test_unread_default_import_remains_an_unused_import(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    _graph(tmp_path, "view", "export const alive = 1;\n", "ts")
    result = json.loads(analyze(str(tmp_path), grep_verify=False, grep_cache=False))
    assert "view" in {row["simple_name"] for row in result.get("unused_imports", [])}
