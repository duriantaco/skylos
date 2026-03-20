from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from skylos.llm.cleanup_orchestrator import (
    CleanupItem,
    CleanupResult,
    CleanupOrchestrator,
    _load_standards,
    _build_analysis_system_prompt,
    _build_analysis_user_prompt,
    _build_fix_system_prompt,
    _build_fix_user_prompt,
)


class TestLoadStandards:
    def test_load_builtin(self):
        text = _load_standards(None)
        assert "Constants" in text
        assert "Exception" in text

    def test_load_custom(self, tmp_path):
        custom = tmp_path / "my_standards.md"
        custom.write_text("# Custom\n- Rule 1\n")
        text = _load_standards(custom)
        assert "Custom" in text
        assert "Rule 1" in text

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            _load_standards(tmp_path / "nonexistent.md")


class TestPromptBuilding:
    def test_analysis_system_has_standards(self):
        prompt = _build_analysis_system_prompt("# My Standards\n- no magic numbers")
        assert "My Standards" in prompt
        assert "no magic numbers" in prompt
        assert "JSON" in prompt

    def test_analysis_user_has_line_numbers(self):
        source = "x = 1\ny = 2\n"
        prompt = _build_analysis_user_prompt(source, "test.py")
        assert "test.py" in prompt
        assert "   1 | x = 1" in prompt
        assert "   2 | y = 2" in prompt

    def test_fix_system_has_standards(self):
        prompt = _build_fix_system_prompt("# Standards\n- be clean")
        assert "Standards" in prompt
        assert "be clean" in prompt

    def test_fix_user_has_item_details(self):
        item = CleanupItem(
            file="foo.py",
            line=5,
            category="constants",
            description="magic number 42",
            suggestion="extract to constant",
        )
        source = "a = 1\nb = 2\nc = 3\nd = 4\ne = 42\nf = 6\n"
        prompt = _build_fix_user_prompt(source, "foo.py", item)
        assert "foo.py" in prompt
        assert "constants" in prompt
        assert "magic number 42" in prompt
        assert "extract to constant" in prompt
        # Line 5 should be marked
        assert " >>> " in prompt


class TestDataclasses:
    def test_cleanup_item_defaults(self):
        item = CleanupItem(
            file="a.py", line=1, category="c", description="d", suggestion="s"
        )
        assert item.status == "pending"
        assert item.severity == "medium"
        assert item.skip_reason == ""

    def test_cleanup_result_summary(self):
        result = CleanupResult(
            items=[
                CleanupItem(
                    file="a.py",
                    line=1,
                    category="naming",
                    description="bad name",
                    suggestion="rename",
                    status="applied",
                )
            ],
            applied=1,
            reverted=0,
            skipped=0,
            total_analyzed_files=1,
        )
        s = result.summary()
        assert s["total_items"] == 1
        assert s["applied"] == 1
        assert s["total_analyzed_files"] == 1
        assert s["items"][0]["status"] == "applied"


class TestFileCollection:
    def _make_orchestrator(self):
        with patch(
            "skylos.llm.cleanup_orchestrator._load_standards", return_value="# test"
        ):
            return CleanupOrchestrator(model="test", api_key="test")

    def test_single_file(self, tmp_path):
        f = tmp_path / "hello.py"
        f.write_text("x = 1\n")
        orch = self._make_orchestrator()
        files = orch._collect_files(f)
        assert files == [f]

    def test_single_non_code_file(self, tmp_path):
        f = tmp_path / "readme.md"
        f.write_text("hello\n")
        orch = self._make_orchestrator()
        files = orch._collect_files(f)
        assert files == []

    def test_directory_collects_code(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.ts").write_text("const x = 1;\n")
        (tmp_path / "c.txt").write_text("hello\n")
        orch = self._make_orchestrator()
        files = orch._collect_files(tmp_path)
        names = {f.name for f in files}
        assert "a.py" in names
        assert "b.ts" in names
        assert "c.txt" not in names

    def test_skips_excluded_dirs(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "dep.js").write_text("var x = 1;\n")
        (tmp_path / "app.js").write_text("var y = 2;\n")
        orch = self._make_orchestrator()
        files = orch._collect_files(tmp_path)
        names = {f.name for f in files}
        assert "app.js" in names
        assert "dep.js" not in names

    def test_skips_large_files(self, tmp_path):
        big = tmp_path / "big.py"
        big.write_text("x = 1\n" * 20000)
        small = tmp_path / "small.py"
        small.write_text("x = 1\n")
        orch = self._make_orchestrator()
        files = orch._collect_files(tmp_path)
        names = {f.name for f in files}
        assert "small.py" in names
        assert "big.py" not in names


class TestAnalysis:
    def _make_orchestrator(self):
        with patch(
            "skylos.llm.cleanup_orchestrator._load_standards", return_value="# test"
        ):
            return CleanupOrchestrator(model="test", api_key="test")

    def test_parse_analysis_response(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 42\n")

        mock_response = json.dumps(
            {
                "items": [
                    {
                        "line": 1,
                        "category": "constants",
                        "description": "magic number 42",
                        "suggestion": "extract to ANSWER constant",
                        "severity": "medium",
                    }
                ]
            }
        )

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = mock_response

        items = orch._analyze_file(f, lambda *a, **kw: None)
        assert len(items) == 1
        assert items[0].category == "constants"
        assert items[0].line == 1

    def test_empty_analysis(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("x: int = 1\n")

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = json.dumps({"items": []})

        items = orch._analyze_file(f, lambda *a, **kw: None)
        assert items == []

    def test_invalid_json_returns_empty(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = "not json"

        items = orch._analyze_file(f, lambda *a, **kw: None)
        assert items == []

    def test_skips_large_line_count(self, tmp_path):
        f = tmp_path / "huge.py"
        f.write_text("\n".join(f"x{i} = {i}" for i in range(2500)))

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()

        items = orch._analyze_file(f, lambda *a, **kw: None)
        assert items == []
        orch._adapter.complete.assert_not_called()


class TestFixApplication:
    def _make_orchestrator(self):
        with patch(
            "skylos.llm.cleanup_orchestrator._load_standards", return_value="# test"
        ):
            return CleanupOrchestrator(model="test", api_key="test")

    def test_apply_fix_success(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 42\n")

        item = CleanupItem(
            file=str(f),
            line=1,
            category="constants",
            description="magic number",
            suggestion="extract",
        )

        fix_response = json.dumps(
            {
                "code_lines": ["ANSWER = 42", "x = ANSWER"],
                "confidence": "high",
                "change_description": "extracted constant",
            }
        )

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = fix_response

        mock_executor = MagicMock()
        mock_executor.apply_fix.return_value = True
        mock_executor.run_tests.return_value = MagicMock(passed=True)

        orch._apply_single_fix(item, mock_executor, lambda *a, **kw: None)
        assert item.status == "applied"
        mock_executor.apply_fix.assert_called_once()

    def test_revert_on_test_failure(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 42\n")

        item = CleanupItem(
            file=str(f),
            line=1,
            category="constants",
            description="magic number",
            suggestion="extract",
        )

        fix_response = json.dumps(
            {
                "code_lines": ["BROKEN = 42"],
                "confidence": "high",
                "change_description": "broke it",
            }
        )

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = fix_response

        mock_executor = MagicMock()
        mock_executor.apply_fix.return_value = True
        mock_executor.run_tests.return_value = MagicMock(
            passed=False, output="AssertionError"
        )

        orch._apply_single_fix(item, mock_executor, lambda *a, **kw: None)
        assert item.status == "reverted"
        mock_executor.revert_fix.assert_called_once()

    def test_skip_low_confidence(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 42\n")

        item = CleanupItem(
            file=str(f),
            line=1,
            category="constants",
            description="magic number",
            suggestion="extract",
        )

        fix_response = json.dumps(
            {
                "code_lines": ["ANSWER = 42"],
                "confidence": "low",
                "change_description": "risky change",
            }
        )

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = fix_response

        mock_executor = MagicMock()
        orch._apply_single_fix(item, mock_executor, lambda *a, **kw: None)
        assert item.status == "skipped"
        assert "low confidence" in item.skip_reason
        mock_executor.apply_fix.assert_not_called()

    def test_skip_no_change(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 42\n")

        item = CleanupItem(
            file=str(f),
            line=1,
            category="constants",
            description="magic number",
            suggestion="extract",
        )

        fix_response = json.dumps(
            {
                "code_lines": ["x = 42"],
                "confidence": "high",
                "change_description": "no change",
            }
        )

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = fix_response

        mock_executor = MagicMock()
        orch._apply_single_fix(item, mock_executor, lambda *a, **kw: None)
        assert item.status == "skipped"
        assert "no change" in item.skip_reason

    def test_skip_file_not_found(self):
        item = CleanupItem(
            file="/nonexistent/path.py",
            line=1,
            category="c",
            description="d",
            suggestion="s",
        )

        orch = self._make_orchestrator()
        mock_executor = MagicMock()
        orch._apply_single_fix(item, mock_executor, lambda *a, **kw: None)
        assert item.status == "skipped"
        assert "file not found" in item.skip_reason


class TestOrchestration:
    def _make_orchestrator(self):
        with patch(
            "skylos.llm.cleanup_orchestrator._load_standards", return_value="# test"
        ):
            return CleanupOrchestrator(model="test", api_key="test")

    def test_dry_run(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 42\n")

        analysis = json.dumps(
            {
                "items": [
                    {
                        "line": 1,
                        "category": "constants",
                        "description": "magic number 42",
                        "suggestion": "extract to constant",
                        "severity": "medium",
                    }
                ]
            }
        )

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = analysis

        summary = orch.run(str(f), dry_run=True, quiet=True)
        assert summary["total_items"] == 1
        assert summary["applied"] == 0
        assert summary["skipped"] == 1

    def test_max_fixes_cap(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("a = 1\nb = 2\nc = 3\n")

        analysis = json.dumps(
            {
                "items": [
                    {
                        "line": i,
                        "category": "c",
                        "description": f"issue {i}",
                        "suggestion": "fix",
                        "severity": "medium",
                    }
                    for i in range(1, 4)
                ]
            }
        )

        orch = self._make_orchestrator()
        orch._adapter = MagicMock()
        orch._adapter.complete.return_value = analysis

        summary = orch.run(str(f), max_fixes=1, dry_run=True, quiet=True)
        # 1 in dry-run skipped + 2 from max_fixes cap
        assert summary["skipped"] == 3

    def test_no_files(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()

        orch = self._make_orchestrator()
        summary = orch.run(str(d), quiet=True)
        assert summary["total_items"] == 0
        assert summary["applied"] == 0

    def test_summary_structure(self):
        result = CleanupResult(
            items=[],
            applied=2,
            reverted=1,
            skipped=3,
            total_analyzed_files=5,
        )
        s = result.summary()
        assert set(s.keys()) == {
            "total_items",
            "applied",
            "reverted",
            "skipped",
            "total_analyzed_files",
            "items",
        }
