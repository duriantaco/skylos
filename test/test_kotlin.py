from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze, proc_file
from skylos.visitors.languages.kotlin import scan_kotlin_file


def _scan_kotlin(tmp_path: Path, code: str, filename: str = "src/main/App.kt") -> tuple:
    file_path = tmp_path / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(code, encoding="utf-8")
    return scan_kotlin_file(str(file_path), {})


def test_kotlin_scanner_collects_defs_refs_and_raw_imports(tmp_path):
    defs, refs, _, _, visitor, _, quality, danger, _, _, _, _, raw_imports = (
        _scan_kotlin(
            tmp_path,
            """
package demo

import com.acme.Service
import com.acme.Legacy as OldService

class Controller {
    fun publicApi() {
        privateUsed()
    }

    private fun privateUsed() {}
    private fun privateDead() {}
}

fun main() {
    Controller().publicApi()
    topUsed()
}

private fun topUsed() {}
private fun topDead() {}
""",
        )
    )

    def_names = {definition.name for definition in defs}
    ref_names = {ref[0] for ref in refs}
    exported = {definition.name for definition in defs if definition.is_exported}

    assert "Service" in def_names
    assert "OldService" in def_names
    assert "Controller" in def_names
    assert "Controller.publicApi" in def_names
    assert "Controller.privateUsed" in def_names
    assert "Controller.privateDead" in def_names
    assert "main" in def_names
    assert "topUsed" in def_names
    assert "topDead" in def_names

    assert "Controller" in ref_names
    assert "publicApi" in ref_names
    assert "privateUsed" in ref_names
    assert "topUsed" in ref_names

    assert "Controller" in exported
    assert "Controller.publicApi" in exported
    assert "main" in exported
    assert "Controller.privateDead" not in exported
    assert "topDead" not in exported

    assert visitor.is_test_file is False
    assert quality == []
    assert danger == []
    assert raw_imports == [
        {"source": "com.acme.Service", "names": ["Service"], "line": 3},
        {"source": "com.acme.Legacy", "names": ["OldService"], "line": 5},
    ]


def test_kotlin_test_annotation_marks_function_as_test_entrypoint(tmp_path):
    defs, refs, _, _, visitor, _, _, _, _, _, _, _, _ = _scan_kotlin(
        tmp_path,
        """
import kotlin.test.Test

class ControllerTest {
    @Test
    fun loadsUser() {}
}
""",
        filename="src/test/ControllerTest.kt",
    )

    test_method = next(definition for definition in defs if _is_loads_user(definition))

    assert test_method.is_exported is True
    assert visitor.is_test_file is True
    assert visitor.test_decorated_lines == {test_method.line}
    assert ("Test", str(tmp_path / "src/test/ControllerTest.kt")) in refs


def test_proc_file_dispatches_kotlin_to_kotlin_scanner(tmp_path):
    file_path = tmp_path / "Main.kt"
    file_path.write_text("fun main() {}\n", encoding="utf-8")

    out = proc_file(str(file_path))
    defs = out[0]

    assert any(definition.name == "main" for definition in defs)


def test_analyze_kotlin_reports_language_summary_and_dead_code(tmp_path):
    file_path = tmp_path / "Main.kt"
    file_path.write_text(
        """
fun main() {
    used()
}

private fun used() {}
private fun unusedPrivate() {}
""",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=False))
    unused = {item["full_name"] for item in result["unused_functions"]}

    assert result["analysis_summary"]["languages"] == {"Kotlin": 1}
    assert "unusedPrivate" in unused
    assert "used" not in unused


def _is_loads_user(definition) -> bool:
    return definition.name == "ControllerTest.loadsUser"
