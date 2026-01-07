#!/usr/bin/env python3
import pytest
import json
import logging
from unittest.mock import Mock, patch
import sys
import types
from rich.table import Table
from rich.tree import Tree as RichTree
import skylos.cli as cli

from skylos.cli import (
    CleanFormatter,
    setup_logger,
    remove_unused_import,
    remove_unused_function,
    interactive_selection,
    print_badge,
    main,
)


class TestCleanFormatter:
    def test_clean_formatter_removes_metadata(self):
        """Test that CleanFormatter only returns the message."""
        formatter = CleanFormatter()

        record = Mock()
        record.getMessage.return_value = "Test message"

        result = formatter.format(record)
        assert result == "Test message"

        record.getMessage.assert_called_once()


class TestSetupLogger:
    @patch("skylos.cli.logging.FileHandler")
    @patch("skylos.cli.RichHandler")
    def test_setup_logger_console_only(self, mock_rich_handler, mock_file_handler):
        """Test logger setup without output file."""
        mock_handler = Mock()
        mock_rich_handler.return_value = mock_handler

        logger = setup_logger()

        mock_rich_handler.assert_called_once()
        mock_file_handler.assert_not_called()

    @patch("skylos.cli.logging.FileHandler")
    @patch("skylos.cli.RichHandler")
    def test_setup_logger_with_output_file(self, mock_rich_handler, mock_file_handler):
        """Test logger setup with output file."""
        mock_rich_handler.return_value = Mock()
        mock_file_handler.return_value = Mock()

        logger = setup_logger("output.log")

        mock_rich_handler.assert_called_once()
        mock_file_handler.assert_called_once_with("output.log")

    def test_remove_simple_import(self):
        """Test removing a simple import statement."""
        content = """import os
import sys
import json

def main():
    print(sys.version)
"""

        with (
            patch("pathlib.Path.read_text", return_value=content) as mock_read,
            patch("pathlib.Path.write_text") as mock_write,
            patch(
                "skylos.cli.remove_unused_import_cst", return_value=("NEW_CODE", True)
            ) as mock_codemod,
        ):
            result = remove_unused_import("test.py", "os", 1)

            assert result is True
            mock_read.assert_called_once()
            mock_codemod.assert_called_once()
            mock_write.assert_called_once_with("NEW_CODE", encoding="utf-8")

    def test_remove_from_multi_import(self):
        content = "import os, sys, json\n"

        with (
            patch("pathlib.Path.read_text", return_value=content),
            patch("pathlib.Path.write_text") as mock_write,
            patch("skylos.cli.remove_unused_import_cst", return_value=("X", True)),
        ):
            result = remove_unused_import("test.py", "os", 1)

            assert result is True
            mock_write.assert_called_once()

    def test_remove_from_import_statement(self):
        content = "from collections import defaultdict, Counter\n"

        with (
            patch("pathlib.Path.read_text", return_value=content),
            patch("pathlib.Path.write_text") as mock_write,
            patch("skylos.cli.remove_unused_import_cst", return_value=("X", True)),
        ):
            result = remove_unused_import("test.py", "Counter", 1)

            assert result is True
            mock_write.assert_called_once()

    def test_remove_entire_from_import(self):
        content = "from collections import defaultdict\n"

        with (
            patch("pathlib.Path.read_text", return_value=content),
            patch("pathlib.Path.write_text") as mock_write,
            patch("skylos.cli.remove_unused_import_cst", return_value=("", True)),
        ):
            result = remove_unused_import("test.py", "defaultdict", 1)

            assert result is True
            mock_write.assert_called_once_with("", encoding="utf-8")

    def test_remove_import_file_error(self):
        """handling file errors when removing imports."""
        with patch(
            "pathlib.Path.read_text", side_effect=FileNotFoundError("File not found")
        ):
            result = remove_unused_import("nonexistent.py", "os", 1)
            assert result is False


class TestRemoveUnusedFunction:
    def test_remove_simple_function(self):
        """test remove a simple function."""
        content = """def used_function():
    return "used"

def unused_function():
    return "unused"

def another_function():
    return "another"
"""

        with (
            patch("pathlib.Path.read_text", return_value=content),
            patch("pathlib.Path.write_text") as mock_write,
            patch(
                "skylos.cli.remove_unused_function_cst",
                return_value=("NEW_FUNC_CODE", True),
            ),
        ):
            result = remove_unused_function("test.py", "unused_function", 4)

        assert result is True
        mock_write.assert_called_once_with("NEW_FUNC_CODE", encoding="utf-8")

    def test_remove_function_with_decorators(self):
        """removing function with decorators."""
        content = """@property
@decorator
def unused_function():
    return "unused"
"""

        with (
            patch("pathlib.Path.read_text", return_value=content),
            patch("pathlib.Path.write_text") as mock_write,
            patch("skylos.cli.remove_unused_function_cst", return_value=("X", True)),
        ):
            result = remove_unused_function("test.py", "unused_function", 3)

        assert result is True
        mock_write.assert_called_once()

    def test_remove_function_file_error(self):
        with patch(
            "pathlib.Path.read_text", side_effect=FileNotFoundError("File not found")
        ):
            result = remove_unused_function("nonexistent.py", "func", 1)
            assert result is False

    def test_remove_function_parse_error(self):
        with patch("pathlib.Path.read_text", side_effect=SyntaxError("Invalid syntax")):
            result = remove_unused_function("test.py", "func", 1)
            assert result is False


class TestInteractiveSelection:
    @pytest.fixture
    def mock_console(self):
        return Mock()

    @pytest.fixture
    def sample_unused_items(self):
        """create fake sample unused items for testing"""
        functions = [
            {"name": "unused_func1", "file": "test1.py", "line": 10},
            {"name": "unused_func2", "file": "test2.py", "line": 20},
        ]
        imports = [
            {"name": "unused_import1", "file": "test1.py", "line": 1},
            {"name": "unused_import2", "file": "test2.py", "line": 2},
        ]
        return functions, imports

    def test_interactive_selection_unavailable(self, mock_console, sample_unused_items):
        functions, imports = sample_unused_items

        with patch("skylos.cli.INTERACTIVE_AVAILABLE", False):
            selected_functions, selected_imports = interactive_selection(
                mock_console, functions, imports
            )

        assert selected_functions == []
        assert selected_imports == []
        mock_console.print.assert_called_once()

    @patch("skylos.cli.inquirer")
    def test_interactive_selection_with_selections(
        self, mock_inquirer, mock_console, sample_unused_items
    ):
        functions, imports = sample_unused_items

        mock_inquirer.prompt.side_effect = [
            {"functions": [functions[0]]},
            {"imports": [imports[1]]},
        ]

        with patch("skylos.cli.INTERACTIVE_AVAILABLE", True):
            selected_functions, selected_imports = interactive_selection(
                mock_console, functions, imports
            )

            assert selected_functions == [functions[0]]
            assert selected_imports == [imports[1]]
            assert mock_inquirer.prompt.call_count == 2
            assert mock_console.print.call_count >= 1
            printed_messages = [
                str(call.args[0]) for call in mock_console.print.call_args_list
            ]

            assert any("Select" in msg for msg in printed_messages)

    @patch("skylos.cli.inquirer")
    def test_interactive_selection_no_selections(
        self, mock_inquirer, mock_console, sample_unused_items
    ):
        functions, imports = sample_unused_items

        mock_inquirer.prompt.return_value = None

        with patch("skylos.cli.INTERACTIVE_AVAILABLE", True):
            selected_functions, selected_imports = interactive_selection(
                mock_console, functions, imports
            )

        assert selected_functions == []
        assert selected_imports == []

    def test_interactive_selection_empty_lists(self, mock_console):
        selected_functions, selected_imports = interactive_selection(
            mock_console, [], []
        )

        assert selected_functions == []
        assert selected_imports == []


class TestPrintBadge:
    @pytest.fixture
    def mock_logger(self):
        logger = Mock()
        logger.console = Mock()
        return logger

    def test_print_badge_zero_dead_code(self, mock_logger):
        """Test badge printing with zero dead code."""
        print_badge(0, mock_logger)

        calls = [c.args[0] for c in mock_logger.console.print.call_args_list]
        badge_call = next(
            (c for c in calls if isinstance(c, str) and "Dead_Code-Free" in c),
            None,
        )
        assert badge_call is not None
        assert "brightgreen" in badge_call

    def test_print_badge_with_dead_code(self, mock_logger):
        print_badge(5, mock_logger)

        calls = [c.args[0] for c in mock_logger.console.print.call_args_list]
        badge_call = next(
            (c for c in calls if isinstance(c, str) and "Dead_Code-5" in c),
            None,
        )
        assert badge_call is not None
        assert "orange" in badge_call


class TestMainFunction:
    @pytest.fixture
    def mock_skylos_result(self):
        return {
            "unused_functions": [
                {"name": "unused_func", "file": "test.py", "line": 10}
            ],
            "unused_imports": [{"name": "unused_import", "file": "test.py", "line": 1}],
            "unused_parameters": [],
            "unused_variables": [],
            "analysis_summary": {"total_files": 2, "excluded_folders": []},
        }

    def test_main_json_output(self, mock_skylos_result):
        """testing main function with JSON output"""
        test_args = ["cli.py", "test_path", "--json"]

        with (
            patch("sys.argv", test_args),
            patch("skylos.cli.run_analyze") as mock_analyze,
            patch("builtins.print") as mock_print,
            patch("skylos.cli.setup_logger"),
            patch("skylos.cli.Progress") as mock_progress,
        ):
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
            mock_analyze.return_value = json.dumps(mock_skylos_result)

            main()

            mock_analyze.assert_called_once()
            mock_print.assert_called_once_with(json.dumps(mock_skylos_result))

    def test_main_verbose_output(self, mock_skylos_result):
        """with verbose"""
        test_args = ["cli.py", "test_path", "--verbose"]

        with (
            patch("sys.argv", test_args),
            patch("skylos.cli.run_analyze") as mock_analyze,
            patch("skylos.cli.setup_logger") as mock_setup_logger,
            patch("skylos.cli.Progress") as mock_progress,
        ):
            mock_logger = Mock()
            mock_logger.console = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_analyze.return_value = json.dumps(mock_skylos_result)
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())

            main()

            mock_logger.setLevel.assert_called_with(logging.DEBUG)

    def test_main_analysis_error(self):
        test_args = ["cli.py", "test_path"]

        with (
            patch("sys.argv", test_args),
            patch("skylos.cli.run_analyze", side_effect=Exception("Analysis failed")),
            patch("skylos.cli.setup_logger") as mock_setup_logger,
            patch("skylos.cli.parse_exclude_folders", return_value=set()),
            patch("skylos.cli.Progress") as mock_progress,
        ):
            mock_logger = Mock()
            mock_logger.console = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())

            with pytest.raises(SystemExit):
                main()

            mock_logger.error.assert_called_with(
                "Error during analysis: Analysis failed"
            )


def _progress_ctx():
    cm = Mock()
    cm.__enter__ = Mock(
        return_value=Mock(add_task=Mock(return_value="t"), update=Mock())
    )
    cm.__exit__ = Mock(return_value=False)
    return cm


def test_shorten_path_non_pathlike_returns_str():
    assert cli._shorten_path(123) == "123"


def test_comment_out_unused_import_handles_exception_and_returns_false():
    with (
        patch("pathlib.Path.read_text", return_value="import os\n"),
        patch("skylos.cli.comment_out_unused_import_cst", side_effect=RuntimeError("boom")),
        patch("pathlib.Path.write_text") as w,
        patch("skylos.cli.logging.error") as logerr,
    ):
        ok = cli.comment_out_unused_import("x.py", "os", 1, marker="M")

    assert ok is False
    w.assert_not_called()
    assert logerr.called


def test_comment_out_unused_function_handles_exception_and_returns_false():
    with (
        patch("pathlib.Path.read_text", return_value="def f():\n    pass\n"),
        patch("skylos.cli.comment_out_unused_function_cst", side_effect=RuntimeError("boom")),
        patch("pathlib.Path.write_text") as w,
        patch("skylos.cli.logging.error") as logerr,
    ):
        ok = cli.comment_out_unused_function("x.py", "f", 1, marker="M")

    assert ok is False
    w.assert_not_called()
    assert logerr.called


def test_render_results_unused_table_includes_confidence_column_and_formats():
    console = Mock()

    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [
            {"name": "hi", "file": "/root/a.py", "line": 10, "confidence": 95},  # red
            {"name": "mid", "file": "/root/a.py", "line": 20, "confidence": 80},  # yellow
            {"name": "lo", "file": "/root/a.py", "line": 30, "confidence": 50},  # dim
        ],
        "unused_imports": [],
        "unused_parameters": [],
        "unused_variables": [],
        "unused_classes": [],
        "quality": [],
        "danger": [],
        "secrets": [],
    }

    cli.render_results(console, result, tree=False, root_path="/root")

    tables = []
    for call in console.print.call_args_list:
        if not call.args:
            continue
        arg0 = call.args[0]
        if isinstance(arg0, Table):
            tables.append(arg0)

    assert tables, "Expected at least one Table printed by render_results()"

    t = tables[0]

    headers = []
    for col in t.columns:
        headers.append(col.header)

    assert "Conf" in headers, "Expected a confidence column in unused table"

    conf_col = None
    for col in t.columns:
        if col.header == "Conf":
            conf_col = col
            break

    assert conf_col is not None, "Conf column not found"

    conf_cells = list(conf_col._cells)

    assert conf_cells[0] == "[red]95%[/red]"
    assert conf_cells[1] == "[yellow]80%[/yellow]"
    assert conf_cells[2] == "[dim]50%[/dim]"


def test_render_results_tree_mode_groups_by_file_and_sorts_by_line():
    console = Mock()

    result = {
        "analysis_summary": {"total_files": 2},
        "unused_functions": [{"name": "u1", "file": "/p/a.py", "line": 20}],
        "unused_imports": [{"name": "os", "file": "/p/a.py", "line": 5}],
        "unused_parameters": [{"name": "p", "file": "/p/b.py", "line": 1}],
        "unused_variables": [],
        "unused_classes": [],
        "danger": [
            {
                "rule_id": "SKY-D211",
                "severity": "high",
                "message": "SQLi",
                "file": "/p/b.py",
                "line": 9,
            }
        ],
        "secrets": [],
        "quality": [],
    }

    cli.render_results(console, result, tree=True, root_path="/p")

    trees = []
    for call in console.print.call_args_list:
        if not call.args:
            continue
        arg0 = call.args[0]
        if isinstance(arg0, RichTree):
            trees.append(arg0)

    assert trees, "Expected a Tree printed in tree mode"

    tree = trees[0]
    assert "/p" in str(tree.label)

    child_labels = []
    for ch in tree.children:
        child_labels.append(str(ch.label))

    has_a = False
    has_b = False
    for s in child_labels:
        if "a.py" in s:
            has_a = True
        if "b.py" in s:
            has_b = True

    assert has_a is True
    assert has_b is True

    a_node = None
    for ch in tree.children:
        if "a.py" in str(ch.label):
            a_node = ch
            break

    assert a_node is not None, "Expected a.py node in tree"

    a_msgs = []
    for gc in a_node.children:
        a_msgs.append(str(gc.label))

    idx5 = None
    idx20 = None
    for i, s in enumerate(a_msgs):
        if idx5 is None and "L5" in s:
            idx5 = i
        if idx20 is None and "L20" in s:
            idx20 = i

    assert idx5 is not None, "Expected L5 entry under a.py"
    assert idx20 is not None, "Expected L20 entry under a.py"
    assert idx5 < idx20


def test_main_init_subcommand_calls_run_init_and_exits(monkeypatch):
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "init"])
    with patch("skylos.cli.run_init") as r:
        with pytest.raises(SystemExit) as e:
            cli.main()
    assert e.value.code == 0
    r.assert_called_once()


def test_main_whitelist_subcommand_calls_run_whitelist_and_exits(monkeypatch):
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "whitelist", "handle_*", "--reason", "x"])
    with patch("skylos.cli.run_whitelist") as w:
        with pytest.raises(SystemExit) as e:
            cli.main()
    assert e.value.code == 0
    w.assert_called_once()
    kwargs = w.call_args.kwargs
    assert kwargs["pattern"] == "handle_*"
    assert kwargs["reason"] == "x"
    assert kwargs["show"] is False


def test_main_sync_subcommand_calls_sync_main_and_exits(monkeypatch):
    fake_sync = types.SimpleNamespace(main=Mock())
    monkeypatch.setitem(sys.modules, "skylos.sync", fake_sync)

    monkeypatch.setattr(cli.sys, "argv", ["skylos", "sync", "--pull"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 0
    fake_sync.main.assert_called_once_with(["--pull"])


def test_main_sarif_maps_categories_rule_ids_and_lines(monkeypatch, tmp_path):
    result = {
        "analysis_summary": {"total_files": 1},
        "danger": [
            {
                "rule_id": "SKY-D211",
                "file": "a.py",
                "line": "7",
                "message": "SQLi",
                "severity": "HIGH",
            }
        ],
        "quality": [
            {
                "kind": "nesting",
                "file": "b.py",
                "line": 0,
                "value": 9,
                "threshold": 3,
            }
        ],
        "secrets": [{"provider": "generic", "file": "c.py", "line": None, "message": "Secret"}],
        "unused_functions": [{"name": "u", "file": "d.py", "line": -5}],
        "unused_imports": [{"name": "os", "file": "e.py", "line": "not-an-int"}],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
    }

    sarif_path = tmp_path / "out.sarif.json"
    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--sarif", str(sarif_path), "--json"])

    captured = {}

    def fake_exporter_ctor(findings, tool_name=None):
        captured["findings"] = findings
        exp = Mock()
        exp.write = Mock()
        return exp

    with (
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.SarifExporter", side_effect=fake_exporter_ctor),
        patch("builtins.print"),
    ):
        cli.main()

    findings = captured.get("findings")
    assert findings, "Expected SARIF exporter to receive findings"

    cats = set()
    for f in findings:
        cats.add(f["category"])

    assert "SECURITY" in cats
    assert "QUALITY" in cats
    assert "SECRET" in cats
    assert "DEAD_CODE" in cats

    dead_rules = set()
    for f in findings:
        if f["category"] == "DEAD_CODE":
            dead_rules.add(f["rule_id"])

    assert "SKYLOS-DEADCODE-UNUSED_FUNCTION" in dead_rules
    assert "SKYLOS-DEADCODE-UNUSED_IMPORT" in dead_rules

    for f in findings:
        assert isinstance(f["line_number"], int)
        assert f["line_number"] >= 1


def test_main_upload_gate_failed_exits_when_not_forced(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    monkeypatch.setattr(cli.sys, "argv", ["skylos", "."])

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results"),
        patch("skylos.cli.print_badge"),
        patch(
            "skylos.cli.upload_report",
            return_value={
                "success": True,
                "scan_id": "scan123",
                "quality_gate": {"passed": False, "message": "Too many issues"},
            },
        ),
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 1


def test_main_upload_gate_failed_does_not_exit_when_forced(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--force"])

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results"),
        patch("skylos.cli.print_badge"),
        patch(
            "skylos.cli.upload_report",
            return_value={
                "success": True,
                "scan_id": "scan123",
                "quality_gate": {"passed": False, "message": "Too many issues"},
            },
        ),
        patch("skylos.cli.sys.exit") as sx,
    ):
        cli.main()

    sx.assert_not_called()


def test_main_command_exec_success_exits_zero(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--", "echo", "hi"])

    fake_logger = Mock()
    fake_logger.console = Mock()

    proc = Mock()
    proc.stdout = iter(["line1\n", "line2\n"])
    proc.wait = Mock()
    proc.returncode = 0

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results"),
        patch("skylos.cli.print_badge"),
        patch("skylos.cli.upload_report", return_value={"success": False, "error": "No token found"}),
        patch("skylos.cli.subprocess.Popen", return_value=proc) as popen,
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 0
    popen.assert_called_once()
    called_cmd = popen.call_args.args[0]
    assert called_cmd == ["echo", "hi"]


def test_main_command_exec_failure_exits_with_code(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--", "false"])

    fake_logger = Mock()
    fake_logger.console = Mock()

    proc = Mock()
    proc.stdout = iter(["oops\n"])
    proc.wait = Mock()
    proc.returncode = 7

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results"),
        patch("skylos.cli.print_badge"),
        patch("skylos.cli.upload_report", return_value={"success": False, "error": "No token found"}),
        patch("skylos.cli.subprocess.Popen", return_value=proc),
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 7

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
