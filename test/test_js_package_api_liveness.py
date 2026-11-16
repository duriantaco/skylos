"""Package entry interfaces apply equally to JavaScript and TypeScript."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(root, name, source):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


@pytest.mark.parametrize("extension", ["js", "jsx", "mjs", "ts", "mts"])
@pytest.mark.parametrize("private", [True, False])
@pytest.mark.parametrize("field", ["main", "exports"])
def test_explicit_package_interface_preserves_only_its_exported_bindings(tmp_path, extension, private, field):
    _write(tmp_path, "package.json", json.dumps({
        "name": "format-package", "type": "module", "private": private,
        field: f"./src/index.{extension}",
    }))
    entry = _write(tmp_path, f"src/index.{extension}", "export const value = 1;\nconst hidden = 2;\n")
    orphan = _write(tmp_path, f"src/orphan.{extension}", "export const spare = 3;\n")
    report = json.loads(analyze(
        str(tmp_path), conf=0, grep_verify=False,
        enable_quality=False, enable_danger=False, enable_secrets=False,
        enable_dependency_hallucinations=False,
    ))
    assert not report.get("analysis_errors"), report.get("analysis_errors")
    variables = {(Path(row["file"]), row["simple_name"]) for row in report.get("unused_variables", [])}
    assert (entry, "value") not in variables
    assert (entry, "hidden") in variables
    assert (orphan, "spare") in variables


def test_public_javascript_barrel_preserves_exact_forwarded_binding(tmp_path):
    _write(tmp_path, "package.json", '{"name":"format-package","type":"module","exports":"./src/index.js"}')
    _write(tmp_path, "src/index.js", "export { format as display } from './helpers.js';\n")
    helper = _write(tmp_path, "src/helpers.js", "export const format = () => 'ok';\nexport const expanded = () => 'details';\n")
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False, enable_dependency_hallucinations=False))
    unused = {
        row["simple_name"]
        for key in ["unused_variables", "unused_functions", "unused_exports"]
        for row in report.get(key, [])
        if Path(row["file"]) == helper
    }
    assert "format" not in unused
    assert "expanded" in unused
