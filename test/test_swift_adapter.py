"""Swift adapter errors and limits must remain visible to every caller."""

import pytest

from skylos.visitors.languages.swift import scan_swift_file
from skylos.visitors.languages.swift.core import SwiftCore, SwiftScanError


def test_unreadable_path_is_incomplete_even_without_metadata_opt_in(tmp_path):
    result = scan_swift_file(str(tmp_path / "Missing.swift"))
    assert result[25]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert result[25]["kind"] == "source_read_error"
    assert not result[0]


def test_missing_grammar_is_incomplete(tmp_path, monkeypatch):
    import skylos.visitors.languages.swift.core as module

    path = tmp_path / "Probe.swift"
    path.write_text("public func entry() {}\n")
    monkeypatch.setattr(module, "tree_sitter_swift", None)
    result = scan_swift_file(str(path))
    assert result[25]["kind"] == "parser_unavailable"
    assert not result[0]


@pytest.mark.parametrize("source", [b"func broken( {", b"public func entry() {}\xff"])
def test_invalid_source_is_not_a_clean_empty_scan(tmp_path, source):
    path = tmp_path / "Probe.swift"
    path.write_bytes(source)
    result = scan_swift_file(str(path))
    assert result[25]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert not result[0]


def test_symlink_source_is_not_followed(tmp_path):
    path = tmp_path / "Actual.swift"
    path.write_text("private func spare() {}")
    link = tmp_path / "Link.swift"
    link.symlink_to(path)
    result = scan_swift_file(str(link))
    assert result[25]["kind"] == "source_read_error"


def test_source_size_limit_is_an_analysis_error(tmp_path, monkeypatch):
    import skylos.visitors.languages.swift as module

    path = tmp_path / "Probe.swift"
    path.write_text("private func spare() {}")
    monkeypatch.setattr(module, "MAX_SWIFT_SOURCE_BYTES", 10)
    assert scan_swift_file(str(path))[25]["kind"] == "source_read_error"


def test_syntax_node_limit_is_an_analysis_error(tmp_path, monkeypatch):
    import skylos.visitors.languages.swift.core as module

    path = tmp_path / "Probe.swift"
    path.write_text("private func spare() {}")
    monkeypatch.setattr(module, "MAX_SWIFT_NODES", 2)
    assert scan_swift_file(str(path))[25]["kind"] == "source_complexity"


def test_ambiguous_overload_resolution_has_a_deterministic_work_limit(monkeypatch):
    import skylos.visitors.languages.swift.core as module

    count = 60
    control = "\n".join(f"private func f{i}(_ value: Int) {{}}" for i in range(count))
    control += (
        "\npublic func entry() { " + "; ".join(f"f{i}(1)" for i in range(count)) + " }"
    )
    ambiguous = "\n".join("private func shared(_ value: Int) {}" for _ in range(count))
    ambiguous += (
        "\npublic func entry() { " + "; ".join("shared(1)" for _ in range(count)) + " }"
    )
    monkeypatch.setattr(module, "MAX_SWIFT_RESOLUTION_WORK", 4_000)
    ordinary = SwiftCore("Control.swift", control.encode())
    ordinary.scan()
    assert not ordinary.root_node.has_error
    assert ordinary.resolution_work <= 4_000
    core = SwiftCore("Ambiguous.swift", ambiguous.encode())
    # Repeated same-label declarations are intentionally semantic-invalid but
    # parser-valid input. A source scanner must bound that input too.
    assert not core.root_node.has_error
    with pytest.raises(SwiftScanError, match="work limit"):
        core.scan()
    assert core.resolution_work <= 4_060


def test_ambiguous_work_limit_reaches_standard_adapter_metadata(tmp_path, monkeypatch):
    import skylos.visitors.languages.swift.core as module

    path = tmp_path / "Probe.swift"
    path.write_text("private func spare() {}\npublic func entry() { spare() }\n")
    monkeypatch.setattr(module, "MAX_SWIFT_RESOLUTION_WORK", 1)
    result = scan_swift_file(str(path), _include_analysis_metadata=True)
    assert result[25]["kind"] == "source_complexity"
    assert not result[0]


def test_directive_text_inside_string_does_not_hide_a_finding(tmp_path):
    path = tmp_path / "Probe.swift"
    path.write_text(
        'public let note = "// skylos: ignore[SKY-U001]"\nprivate func spare() {}\n'
    )
    result = scan_swift_file(str(path), _include_analysis_metadata=True)
    assert not result[13]
    assert not result[26]
    assert any(d.name == "spare" and d.references == 0 for d in result[0])
