import pytest
from unittest.mock import patch, Mock

from skylos.tui import (
    _shorten,
    _loc,
    prepare_category_data,
    CATEGORIES,
    DEAD_CODE_KEYS,
    SEVERITY_COLORS,
    SkylosApp,
    run_tui,
)


class TestShorten:
    def test_none_returns_question_mark(self):
        assert _shorten(None) == "?"

    def test_empty_string_returns_question_mark(self):
        assert _shorten("") == "?"

    def test_relative_to_root(self, tmp_path):
        f = tmp_path / "src" / "app.py"
        f.parent.mkdir(parents=True)
        f.write_text("x=1")
        result = _shorten(str(f), root_path=str(tmp_path))
        assert result.replace("\\", "/") == "src/app.py"

    def test_relative_to_cwd(self, tmp_path, monkeypatch):
        f = tmp_path / "mod.py"
        f.write_text("x=1")
        monkeypatch.chdir(tmp_path)
        result = _shorten(str(f))
        assert result == "mod.py"

    def test_outside_root_returns_full_path(self, tmp_path):
        root = tmp_path / "project"
        root.mkdir()
        outside = tmp_path / "other" / "x.py"
        outside.parent.mkdir()
        outside.write_text("x=1")
        result = _shorten(str(outside), root_path=str(root))
        assert str(outside.resolve()) in result or "other" in result


class TestLoc:
    def test_basic(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        f = tmp_path / "a.py"
        f.write_text("x=1")
        result = _loc({"file": str(f), "line": 42})
        assert ":42" in result

    def test_missing_line(self):
        result = _loc({"file": "a.py"})
        assert ":?" in result

    def test_missing_file(self):
        result = _loc({})
        assert result.startswith("?")


class TestPrepareCategoryData:
    @pytest.fixture
    def sample_result(self):
        return {
            "analysis_summary": {"total_files": 5},
            "unused_functions": [
                {"name": "dead_func", "file": "a.py", "line": 10, "confidence": 95},
            ],
            "unused_imports": [
                {"name": "os", "file": "b.py", "line": 1, "confidence": 80},
            ],
            "unused_classes": [],
            "unused_variables": [
                {"name": "x", "file": "c.py", "line": 3},
            ],
            "unused_parameters": [],
            "danger": [
                {
                    "rule_id": "SKY-D211",
                    "severity": "HIGH",
                    "message": "SQL injection",
                    "file": "d.py",
                    "line": 7,
                    "symbol": "query",
                },
            ],
            "secrets": [
                {
                    "provider": "aws",
                    "message": "AWS key found",
                    "file": "e.py",
                    "line": 2,
                },
            ],
            "quality": [
                {
                    "kind": "complexity",
                    "name": "big_func",
                    "value": 15,
                    "threshold": 10,
                    "file": "f.py",
                    "line": 20,
                },
            ],
            "dependency_vulnerabilities": [],
            "suppressed": [],
        }

    def test_returns_all_category_keys(self, sample_result):
        data = prepare_category_data(sample_result)
        assert "dead_code" in data
        assert "security" in data
        assert "secrets" in data
        assert "quality" in data
        assert "dependencies" in data
        assert "suppressed" in data

    def test_dead_code_aggregates_all_types(self, sample_result):
        data = prepare_category_data(sample_result)
        cols, rows, raw = data["dead_code"]
        assert len(rows) == 3
        assert cols == ["Type", "Name", "File:Line", "Confidence"]

    def test_dead_code_type_labels(self, sample_result):
        data = prepare_category_data(sample_result)
        _, rows, _ = data["dead_code"]
        type_labels = [r[0] for r in rows]
        assert "Function" in type_labels
        assert "Import" in type_labels
        assert "Variable" in type_labels

    def test_dead_code_confidence_formatting(self, sample_result):
        data = prepare_category_data(sample_result)
        _, rows, _ = data["dead_code"]
        assert rows[0][3] == "95%"

    def test_dead_code_missing_confidence(self):
        result = {
            "unused_functions": [{"name": "f", "file": "a.py", "line": 1}],
        }
        data = prepare_category_data(result)
        _, rows, _ = data["dead_code"]
        assert rows[0][3] == "?"

    def test_security_rows(self, sample_result):
        data = prepare_category_data(sample_result)
        cols, rows, raw = data["security"]
        assert len(rows) == 1
        assert rows[0][0] == "SKY-D211"
        assert rows[0][1] == "HIGH"
        assert "SQL injection" in rows[0][2]
        assert cols[0] == "Rule"

    def test_secrets_rows(self, sample_result):
        data = prepare_category_data(sample_result)
        _, rows, _ = data["secrets"]
        assert len(rows) == 1
        assert rows[0][0] == "aws"
        assert "AWS key found" in rows[0][1]

    def test_quality_rows_with_threshold(self, sample_result):
        data = prepare_category_data(sample_result)
        _, rows, _ = data["quality"]
        assert len(rows) == 1
        assert rows[0][0] == "Complexity"
        assert rows[0][1] == "big_func"
        assert "15" in rows[0][2]
        assert "limit 10" in rows[0][2]

    def test_quality_includes_custom_rules(self):
        result = {
            "custom_rules": [
                {
                    "rule_id": "CUSTOM-1",
                    "message": "Bad pattern",
                    "file": "g.py",
                    "line": 5,
                },
            ],
        }
        data = prepare_category_data(result)
        _, rows, _ = data["quality"]
        assert len(rows) == 1
        assert rows[0][0] == "Custom"

    def test_quality_includes_circular_deps(self):
        result = {
            "circular_dependencies": [
                {
                    "cycle": ["a", "b", "a"],
                    "suggested_break": "b",
                    "severity": "MEDIUM",
                },
            ],
        }
        data = prepare_category_data(result)
        _, rows, _ = data["quality"]
        assert len(rows) == 1
        assert rows[0][0] == "Circular Dep"
        assert "a" in rows[0][1]

    def test_dependencies_rows(self):
        result = {
            "dependency_vulnerabilities": [
                {
                    "rule_id": "CVE-2024-1234",
                    "severity": "CRITICAL",
                    "message": "RCE vuln",
                    "metadata": {
                        "package_name": "requests",
                        "package_version": "2.25.0",
                        "display_id": "CVE-2024-1234",
                        "fixed_version": "2.31.0",
                    },
                },
            ],
        }
        data = prepare_category_data(result)
        _, rows, _ = data["dependencies"]
        assert len(rows) == 1
        assert "requests@2.25.0" in rows[0][0]
        assert rows[0][1] == "CVE-2024-1234"
        assert rows[0][2] == "CRITICAL"
        assert rows[0][4] == "2.31.0"

    def test_suppressed_rows(self):
        result = {
            "suppressed": [
                {
                    "category": "dead_code",
                    "name": "old_func",
                    "reason": "whitelisted",
                    "file": "h.py",
                    "line": 9,
                },
            ],
        }
        data = prepare_category_data(result)
        _, rows, _ = data["suppressed"]
        assert len(rows) == 1
        assert rows[0][0] == "Dead Code"  # category title-cased
        assert rows[0][1] == "old_func"
        assert rows[0][2] == "whitelisted"

    def test_empty_result(self):
        data = prepare_category_data({})
        for key in (
            "dead_code",
            "security",
            "secrets",
            "quality",
            "dependencies",
            "suppressed",
        ):
            cols, rows, raw = data[key]
            assert rows == []
            assert raw == []

    def test_root_path_shortens_file_paths(self, tmp_path):
        f = tmp_path / "src" / "main.py"
        f.parent.mkdir(parents=True)
        f.write_text("x=1")
        result = {
            "unused_functions": [
                {"name": "f", "file": str(f), "line": 1, "confidence": 90},
            ],
        }
        data = prepare_category_data(result, root_path=str(tmp_path))
        _, rows, _ = data["dead_code"]
        loc = rows[0][2]
        assert "src/main.py" in loc.replace("\\", "/")

    def test_raw_items_preserved(self, sample_result):
        data = prepare_category_data(sample_result)
        _, _, raw = data["dead_code"]
        assert raw[0]["name"] == "dead_func"
        assert raw[0]["_type_label"] == "Function"

    def test_security_missing_symbol_defaults(self):
        result = {
            "danger": [
                {
                    "rule_id": "R1",
                    "severity": "LOW",
                    "message": "msg",
                    "file": "a.py",
                    "line": 1,
                },
            ],
        }
        data = prepare_category_data(result)
        _, rows, _ = data["security"]
        assert rows[0][4] == "<module>"

    def test_secrets_defaults(self):
        result = {
            "secrets": [{"file": "a.py", "line": 1}],
        }
        data = prepare_category_data(result)
        _, rows, _ = data["secrets"]
        assert rows[0][0] == "generic"
        assert rows[0][1] == "Secret detected"

    def test_dependencies_missing_metadata(self):
        result = {
            "dependency_vulnerabilities": [
                {"severity": "HIGH", "message": "vuln"},
            ],
        }
        data = prepare_category_data(result)
        _, rows, _ = data["dependencies"]
        assert rows[0][0] == "?@?"
        assert rows[0][4] == "-"


class TestSkylosAppInit:
    @pytest.fixture
    def sample_result(self):
        return {
            "analysis_summary": {"total_files": 2},
            "unused_functions": [
                {"name": "f1", "file": "a.py", "line": 1, "confidence": 90},
                {"name": "f2", "file": "b.py", "line": 5, "confidence": 70},
            ],
            "unused_imports": [],
            "unused_classes": [],
            "unused_variables": [],
            "unused_parameters": [],
            "danger": [
                {
                    "rule_id": "SKY-D211",
                    "severity": "HIGH",
                    "message": "x",
                    "file": "c.py",
                    "line": 1,
                },
            ],
            "secrets": [],
            "quality": [],
            "dependency_vulnerabilities": [],
            "suppressed": [],
        }

    def test_category_counts(self, sample_result):
        app = SkylosApp(sample_result)
        assert app.category_counts["dead_code"] == 2
        assert app.category_counts["security"] == 1
        assert app.category_counts["secrets"] == 0
        assert app.category_counts["quality"] == 0
        # overview = sum of all non-overview counts
        assert app.category_counts["overview"] == 3

    def test_root_path_stored(self, sample_result, tmp_path):
        app = SkylosApp(sample_result, root_path=tmp_path)
        assert app.root_path == str(tmp_path)

    def test_root_path_none(self, sample_result):
        app = SkylosApp(sample_result)
        assert app.root_path is None

    def test_category_data_prepared(self, sample_result):
        app = SkylosApp(sample_result)
        assert "dead_code" in app.category_data
        assert "security" in app.category_data

    def test_initial_reactive_values(self, sample_result):
        app = SkylosApp(sample_result)
        assert app.active_category == "overview"
        assert app.severity_filter is None
        assert app.search_query == ""


class TestRunTui:
    def test_run_tui_creates_and_runs_app(self):
        result = {"analysis_summary": {"total_files": 0}}
        with patch("skylos.tui.SkylosApp") as MockApp:
            mock_instance = Mock()
            MockApp.return_value = mock_instance
            run_tui(result, root_path="/tmp")
            MockApp.assert_called_once_with(result, root_path="/tmp")
            mock_instance.run.assert_called_once()


class TestConstants:
    def test_categories_has_overview_first(self):
        assert CATEGORIES[0][0] == "overview"

    def test_all_severity_colors_defined(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert sev in SEVERITY_COLORS

    def test_dead_code_keys_match_expected(self):
        keys = [k for k, _ in DEAD_CODE_KEYS]
        assert "unused_functions" in keys
        assert "unused_imports" in keys
        assert "unused_classes" in keys
        assert "unused_variables" in keys
        assert "unused_parameters" in keys
