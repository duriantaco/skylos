"""Swift discovery, ownership and analysis-completeness contracts."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import Skylos, analyze


def _scan(root, **options):
    return json.loads(
        analyze(
            str(root),
            conf=0,
            grep_verify=True,
            grep_cache=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_dependency_hallucinations=False,
            **options,
        )
    )


def test_directory_discovery_includes_swift(tmp_path):
    source = tmp_path / "Sources" / "Worker.swift"
    source.parent.mkdir()
    source.write_text("public struct Worker {}\n")
    files, _root = Skylos()._get_python_files(str(tmp_path))
    assert source in files


def test_swift_package_cache_is_not_scanned_as_application_source(tmp_path):
    source = tmp_path / "Sources" / "Worker.swift"
    source.parent.mkdir()
    source.write_text("public struct Worker {}\n")
    generated = tmp_path / ".build" / "checkouts" / "Dependency.swift"
    generated.parent.mkdir(parents=True)
    generated.write_text("private func generatedHelper() {}\n")
    files, _root = Skylos()._get_python_files(str(tmp_path))
    assert source in files
    assert generated not in files
    # An explicit target remains an explicit request to inspect that file.
    explicit, _root = Skylos()._get_python_files(str(generated))
    assert explicit == [generated]


def test_swift_language_summary_and_private_findings(tmp_path):
    (tmp_path / "Worker.swift").write_text(
        "private func spare() {}\npublic func entry() {}\n"
    )
    result = _scan(tmp_path)
    assert result["analysis_summary"]["languages"] == {"Swift": 1}
    assert not result.get("analysis_errors")
    assert [item["simple_name"] for item in result["unused_functions"]] == ["spare"]


def test_public_swift_type_does_not_export_its_private_methods(tmp_path):
    (tmp_path / "Worker.swift").write_text(
        "public struct Worker {\n"
        "    private func spare() {}\n"
        "    public func entry() {}\n"
        "}\n"
    )
    result = _scan(tmp_path)
    assert {item["name"] for item in result["unused_functions"]} == {"Worker.spare"}


def test_another_language_cannot_keep_a_swift_function_alive(tmp_path):
    (tmp_path / "Worker.swift").write_text("private func spare() {}\n")
    (tmp_path / "script.py").write_text("def spare(): pass\nspare()\n")
    result = _scan(tmp_path)
    assert any(
        Path(item["file"]).suffix == ".swift" and item["simple_name"] == "spare"
        for item in result["unused_functions"]
    )


def test_private_functions_in_different_swift_files_keep_their_owners(tmp_path):
    (tmp_path / "First.swift").write_text("private func spare() {}\n")
    (tmp_path / "Second.swift").write_text(
        "private func spare() {}\npublic func entry() { spare() }\n"
    )
    result = _scan(tmp_path)
    assert {
        (Path(item["file"]).name, item["simple_name"])
        for item in result.get("unused_functions", [])
    } == {("First.swift", "spare")}


@pytest.mark.parametrize("content", [b"func broken( {", b"public func x() {}\xff"])
def test_invalid_swift_source_reports_incomplete_analysis(tmp_path, content):
    path = tmp_path / "Broken.swift"
    path.write_bytes(content)
    result = _scan(tmp_path)
    assert result.get("analysis_errors")
    assert any(Path(item["file"]) == path for item in result["analysis_errors"])


def test_swift_rule_scoped_suppression_keeps_other_findings(tmp_path):
    (tmp_path / "Worker.swift").write_text(
        "private func preserved() {} // skylos: ignore[SKY-U001] deliberately retained\n"
        "private func spare() {}\n"
    )
    result = _scan(tmp_path)
    assert {item["simple_name"] for item in result["unused_functions"]} == {"spare"}
