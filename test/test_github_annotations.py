"""Tests for GitHub Actions annotation output format (--github flag)."""
from skylos.cli import _emit_github_annotations
import io
import sys


def _capture_annotations(result):
    old = sys.stdout
    sys.stdout = buf = io.StringIO()
    _emit_github_annotations(result)
    sys.stdout = old
    return buf.getvalue().strip().splitlines()


class TestGitHubAnnotations:
    def test_danger_findings(self):
        result = {
            "danger": [
                {
                    "rule_id": "SKY-D211",
                    "severity": "HIGH",
                    "file": "app.py",
                    "line": 10,
                    "message": "SQL injection detected",
                }
            ],
        }
        lines = _capture_annotations(result)
        assert len(lines) == 1
        assert lines[0] == "::error file=app.py,line=10,title=Skylos SKY-D211::SQL injection detected"

    def test_severity_mapping(self):
        result = {
            "quality": [
                {"rule_id": "SKY-Q301", "severity": "MEDIUM", "file": "a.py", "line": 5, "message": "Complex"},
                {"rule_id": "SKY-Q302", "severity": "LOW", "file": "b.py", "line": 8, "message": "Long func"},
            ],
        }
        lines = _capture_annotations(result)
        assert "::warning" in lines[0]
        assert "::notice" in lines[1]

    def test_dead_code_annotations(self):
        result = {
            "unused_functions": [
                {"name": "old_func", "file": "app.py", "line": 42},
            ],
            "unused_imports": [
                {"name": "os", "file": "app.py", "line": 1},
            ],
        }
        lines = _capture_annotations(result)
        assert len(lines) == 2
        assert "::warning" in lines[0]
        assert "Unused function: old_func" in lines[0]
        assert "Unused import: os" in lines[1]

    def test_empty_result(self):
        result = {}
        lines = _capture_annotations(result)
        assert lines == [""] or lines == []

    def test_mixed_categories(self):
        result = {
            "danger": [
                {"rule_id": "SKY-D501", "severity": "CRITICAL", "file": "x.py", "line": 1, "message": "eval"},
            ],
            "secrets": [
                {"rule_id": "SKY-S101", "severity": "HIGH", "file": "y.py", "line": 2, "message": "API key"},
            ],
            "unused_classes": [
                {"name": "OldClass", "file": "z.py", "line": 3},
            ],
        }
        lines = _capture_annotations(result)
        assert len(lines) == 3
        # CRITICAL maps to error
        assert lines[0].startswith("::error")
        assert lines[1].startswith("::error")  # HIGH -> error
        assert "Unused class: OldClass" in lines[2]
