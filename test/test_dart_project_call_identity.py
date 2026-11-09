import json

import pytest

from skylos.analyzer import analyze


def test_imported_callee_does_not_inherit_deadness_from_an_unrelated_caller(tmp_path):
    pytest.importorskip("tree_sitter_dart_orchard")
    (tmp_path / "main.dart").write_text(
        "import 'provider.dart' as api;\n"
        "void caller() { api.used(); }\n"
        "void main() { caller(); }\n"
    )
    (tmp_path / "provider.dart").write_text("void caller() {}\nvoid used() {}\n")
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, grep_cache=False)
    )
    unused = {
        (item["basename"], item["full_name"])
        for item in result.get("unused_functions", [])
    }
    assert ("provider.dart", "caller") in unused
    assert ("provider.dart", "used") not in unused
