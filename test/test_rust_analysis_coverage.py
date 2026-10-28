import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.analysis.errors import analysis_result_incomplete
from skylos.visitors.languages.rust import _parse_error, scan_rust_file


def test_rust_recovery_is_reported_as_incomplete(tmp_path):
    path = tmp_path / "main.rs"
    path.write_text("fn main() {\n    let value = ;\n}\n")
    result = scan_rust_file(str(path), {}, _include_analysis_metadata=True)
    assert result[25]["kind"] == "syntax_error"
    assert result[25]["line"] == 2
    assert result[6] == []
    report = json.loads(analyze(str(tmp_path), enable_quality=True))
    assert analysis_result_incomplete(report)
    assert any(error["file"] == str(path) for error in report["analysis_errors"])


def test_valid_rust_keeps_complete_coverage_and_public_tuple(tmp_path):
    path = tmp_path / "main.rs"
    path.write_text("fn main() {}\n")
    assert len(scan_rust_file(str(path), {})) == 13
    result = scan_rust_file(str(path), {}, _include_analysis_metadata=True)
    assert result[25] is None
    assert not analysis_result_incomplete(json.loads(analyze(str(tmp_path))))


def test_unavailable_rust_parser_cannot_claim_complete_analysis():
    error = _parse_error("example.rs", None)
    assert error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert error["kind"] == "parser_unavailable"


def test_missing_rust_source_returns_error_metadata(tmp_path):
    path = tmp_path / "missing.rs"
    assert len(scan_rust_file(str(path), {})) == 13
    result = scan_rust_file(str(path), {}, _include_analysis_metadata=True)
    assert result[25]["kind"] == "source_read_error"
    assert result[25]["file"] == str(path)


def test_rust_source_read_failure_makes_analyzer_incomplete(tmp_path, monkeypatch):
    path = tmp_path / "main.rs"
    path.write_text("fn main() {}\n")
    original = Path.read_bytes

    def read_bytes(file):
        if file.resolve() == path.resolve():
            raise OSError("source became unreadable")
        return original(file)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    report = json.loads(analyze(str(tmp_path)))
    assert analysis_result_incomplete(report)
    assert any(
        error["kind"] == "source_read_error" for error in report["analysis_errors"]
    )
