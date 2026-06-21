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
    def teardown_method(self):
        logger = logging.getLogger("skylos")
        logger.handlers.clear()
        logger.propagate = True

    @patch("skylos.cli.logging.FileHandler")
    @patch("skylos.cli.RichHandler")
    def test_setup_logger_console_only(self, mock_rich_handler, mock_file_handler):
        """Test logger setup without output file."""
        mock_handler = Mock()
        mock_rich_handler.return_value = mock_handler

        logger = setup_logger()

        assert logger.name == "skylos"
        mock_rich_handler.assert_called_once()
        mock_file_handler.assert_not_called()

    @patch("skylos.cli.logging.FileHandler")
    @patch("skylos.cli.RichHandler")
    def test_setup_logger_with_output_file(self, mock_rich_handler, mock_file_handler):
        """Test logger setup with output file."""
        mock_rich_handler.return_value = Mock()
        mock_file_handler.return_value = Mock()

        logger = setup_logger("output.log")

        assert logger.name == "skylos"
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
        test_args = ["cli.py", "test_path", "--json", "--no-provenance"]

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

    def test_main_config_file_is_loaded_and_forwarded(
        self, mock_skylos_result, tmp_path, monkeypatch
    ):
        config_dir = tmp_path / "quality"
        config_dir.mkdir()
        config_path = config_dir / "skylos.toml"
        config_path.write_text("[skylos]\nquality_enabled = true", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        test_args = [
            "cli.py",
            ".",
            "--json",
            "--config-file",
            "quality/skylos.toml",
            "--no-provenance",
        ]

        with (
            patch("sys.argv", test_args),
            patch("skylos.cli.run_analyze") as mock_analyze,
            patch("builtins.print"),
            patch("skylos.cli.setup_logger"),
            patch("skylos.cli.Progress") as mock_progress,
        ):
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
            mock_analyze.return_value = json.dumps(mock_skylos_result)

            main()

            assert mock_analyze.call_args.kwargs["enable_quality"] is True
            assert mock_analyze.call_args.kwargs["config_file"] == config_path.resolve()

    def test_main_verbose_output(self, mock_skylos_result):
        """with verbose"""
        test_args = ["cli.py", "test_path", "--verbose"]

        with (
            patch("sys.argv", test_args),
            patch("skylos.cli.run_analyze") as mock_analyze,
            patch("skylos.cli.setup_logger") as mock_setup_logger,
            patch("skylos.cli.Progress") as mock_progress,
            patch("skylos.cli.upload_report") as mock_upload,
        ):
            mock_logger = Mock()
            mock_logger.console = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_analyze.return_value = json.dumps(mock_skylos_result)
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
            mock_upload.return_value = {"success": True, "quality_gate_passed": True}

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

    def test_main_auto_enables_danger_for_security_contracts(self, mock_skylos_result):
        test_args = ["cli.py", "test_path", "--json", "--no-provenance"]

        with (
            patch("sys.argv", test_args),
            patch("skylos.cli.run_analyze") as mock_analyze,
            patch("builtins.print"),
            patch("skylos.cli.setup_logger") as mock_setup_logger,
            patch("skylos.cli.load_config") as mock_load_config,
            patch("skylos.cli.Progress") as mock_progress,
        ):
            mock_logger = Mock()
            mock_logger.console = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_load_config.return_value = {
                "exclude": [],
                "security_contracts": [
                    {
                        "framework": "fastapi",
                        "file": "app/api/routes.py",
                        "handler": "list_users",
                        "guards": ["require_admin"],
                    }
                ],
            }
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
            mock_analyze.return_value = json.dumps(mock_skylos_result)

            main()

            assert mock_analyze.call_args.kwargs["enable_danger"] is True

    def test_main_uses_policy_enabled_categories_when_no_flags(
        self, mock_skylos_result
    ):
        test_args = ["cli.py", "test_path", "--json", "--no-provenance"]

        with (
            patch("sys.argv", test_args),
            patch("skylos.cli.run_analyze") as mock_analyze,
            patch("builtins.print"),
            patch("skylos.cli.setup_logger") as mock_setup_logger,
            patch("skylos.cli.load_config") as mock_load_config,
            patch("skylos.cli.Progress") as mock_progress,
        ):
            mock_logger = Mock()
            mock_logger.console = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_load_config.return_value = {
                "exclude": [],
                "security_enabled": True,
                "secrets_enabled": True,
                "quality_enabled": True,
            }
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
            mock_analyze.return_value = json.dumps(mock_skylos_result)

            main()

            assert mock_analyze.call_args.kwargs["enable_danger"] is True
            assert mock_analyze.call_args.kwargs["enable_secrets"] is True
            assert mock_analyze.call_args.kwargs["enable_quality"] is True


def _progress_ctx():
    cm = Mock()
    cm.__enter__ = Mock(
        return_value=Mock(add_task=Mock(return_value="t"), update=Mock())
    )
    cm.__exit__ = Mock(return_value=False)
    return cm


def test_shorten_path_non_pathlike_returns_str():
    assert cli._shorten_path(123) == "123"


def test_apply_display_filters_severity_filters_without_crashing():
    result = {
        "analysis_summary": {"total_files": 1},
        "quality": [
            {"severity": "LOW", "file": "src/a.py", "message": "low"},
            {"severity": "MEDIUM", "file": "src/b.py", "message": "medium"},
            {"severity": "HIGH", "file": "src/c.py", "message": "high"},
        ],
        "danger": [],
        "secrets": [],
        "unused_functions": [{"name": "unused", "file": "src/a.py", "line": 1}],
    }

    filtered = cli._apply_display_filters(result, severity="medium")

    assert filtered["quality"] == [
        {"severity": "MEDIUM", "file": "src/b.py", "message": "medium"},
        {"severity": "HIGH", "file": "src/c.py", "message": "high"},
    ]
    assert filtered["unused_functions"] == result["unused_functions"]
    assert filtered["analysis_summary"] == result["analysis_summary"]


def test_apply_display_filters_combines_category_file_and_severity():
    result = {
        "analysis_summary": {"total_files": 1},
        "quality": [
            {"severity": "HIGH", "file": "src/keep.py", "message": "keep"},
            {"severity": "LOW", "file": "src/keep.py", "message": "drop severity"},
            {"severity": "HIGH", "file": "src/drop.py", "message": "drop file"},
        ],
        "danger": [
            {"severity": "HIGH", "file": "src/keep.py", "message": "drop category"}
        ],
        "secrets": [],
        "unused_functions": [],
    }

    filtered = cli._apply_display_filters(
        result, severity="medium", category="quality", file_filter="keep.py"
    )

    assert filtered["quality"] == [
        {"severity": "HIGH", "file": "src/keep.py", "message": "keep"}
    ]
    assert filtered["danger"] == []


def test_comment_out_unused_import_handles_exception_and_returns_false():
    with (
        patch("pathlib.Path.read_text", return_value="import os\n"),
        patch(
            "skylos.cli.comment_out_unused_import_cst", side_effect=RuntimeError("boom")
        ),
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
        patch(
            "skylos.cli.comment_out_unused_function_cst",
            side_effect=RuntimeError("boom"),
        ),
        patch("pathlib.Path.write_text") as w,
        patch("skylos.cli.logging.error") as logerr,
    ):
        ok = cli.comment_out_unused_function("x.py", "f", 1, marker="M")

    assert ok is False
    w.assert_not_called()
    assert logerr.called


def test_comment_out_unused_function_refuses_symlink_outside_root(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("def unused():\n    return 1\n", encoding="utf-8")
    link = repo / "link.py"
    link.symlink_to(outside)

    ok = cli.comment_out_unused_function(link, "unused", 1, root_path=repo)

    assert ok is False
    assert outside.read_text(encoding="utf-8") == "def unused():\n    return 1\n"


def test_remove_unused_import_refuses_file_outside_root(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("import os\n", encoding="utf-8")

    ok = cli.remove_unused_import(outside, "os", 1, root_path=repo)

    assert ok is False
    assert outside.read_text(encoding="utf-8") == "import os\n"


def test_generate_llm_report_formats_findings_and_defaults_dead_code(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "\n".join(
            [
                "def live():",
                "    value = input()",
                "    eval(value)",
                "    return value",
                "",
                "def unused():",
                "    return 2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    result = {
        "danger": [
            {
                "rule_id": "SKY-D201",
                "severity": "HIGH",
                "message": "eval used",
                "file": str(src),
                "line": 3,
                "name": "live",
            }
        ],
        "secrets": [],
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "severity": "MEDIUM",
                "message": "complex",
                "file": str(src),
                "line": 1,
                "name": "live",
            }
        ],
        "custom_rules": [],
        "unused_functions": [
            {"name": "unused", "file": str(src), "line": 6, "why_unused": ["no refs"]}
        ],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
        "unused_files": [],
    }

    report = cli._generate_llm_report(result, tmp_path)

    assert report.startswith("# Skylos Report — 3 findings\n\n")
    assert "## 1. SKY-D201 | HIGH | Security\n" in report
    assert "## 2. SKY-Q301 | MEDIUM | Quality\n" in report
    assert "## 3. SKY-DC001 | MEDIUM | Dead Code\n" in report
    assert ">>>    3 |     eval(value)" in report
    assert "Unused function 'unused' is never used (no refs)" in report
    assert result["unused_functions"][0]["rule_id"] == "SKY-DC001"
    assert result["unused_functions"][0]["severity"] == "MEDIUM"


def test_generate_llm_report_uses_secret_preview_without_source_context(tmp_path):
    raw_secret = "ghp_" + "1234567890" + "abcdefghijklmnop" + "qrstuvwxyzABCD"
    src = tmp_path / "settings.py"
    src.write_text(f'TOKEN = "{raw_secret}"\n', encoding="utf-8")
    result = {
        "danger": [],
        "secrets": [
            {
                "rule_id": "SKY-S101",
                "severity": "CRITICAL",
                "provider": "github",
                "message": "Potential github secret detected",
                "file": str(src),
                "line": 1,
                "preview": "ghp_…ABCD",
            }
        ],
        "quality": [],
        "custom_rules": [],
    }

    report = cli._generate_llm_report(result, tmp_path)

    assert "## 1. SKY-S101 | CRITICAL | Secrets" in report
    assert "ghp_…ABCD" in report
    assert raw_secret not in report
    assert 'TOKEN = "' not in report


def test_llm_report_code_block_returns_empty_for_invalid_line(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("print('ok')\n", encoding="utf-8")

    assert cli._llm_report_code_block(str(src), "bad", tmp_path, {}) == ""


def test_llm_report_code_block_handles_unreadable_file(tmp_path, monkeypatch):
    src = tmp_path / "app.py"
    src.write_text("print('ok')\n", encoding="utf-8")

    def fail_read_text(self, *args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(cli.pathlib.Path, "read_text", fail_read_text)

    assert cli._llm_report_code_block(str(src), 1, tmp_path, {}) == ""


def test_render_results_unused_table_includes_confidence_column_and_formats():
    console = Mock()

    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [
            {"name": "hi", "file": "/root/a.py", "line": 10, "confidence": 95},  # red
            {
                "name": "mid",
                "file": "/root/a.py",
                "line": 20,
                "confidence": 80,
            },  # yellow
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


def test_render_results_unused_table_includes_compact_dead_code_reason():
    console = Mock()

    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [
            {
                "name": "old_helper",
                "file": "/root/a.py",
                "line": 10,
                "confidence": 95,
                "dead_code_reason_tags": [
                    "uncertainty",
                    "no_refs",
                    "not_exported",
                    "no_entrypoint",
                    "confidence_ge_threshold",
                ],
            }
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

    tables = [
        call.args[0]
        for call in console.print.call_args_list
        if call.args and isinstance(call.args[0], Table)
    ]
    assert tables

    table = tables[0]
    headers = [column.header for column in table.columns]
    assert "Why" in headers

    why_col = next(column for column in table.columns if column.header == "Why")
    assert list(why_col._cells) == ["uncertain · no refs · not exported · +1"]


def test_render_results_shows_grep_verify_summary():
    console = Mock()
    result = {
        "analysis_summary": {
            "total_files": 1,
            "grep_verify": {"enabled": True, "rescued_count": 3},
        },
        "unused_functions": [],
        "unused_imports": [],
        "unused_parameters": [],
        "unused_variables": [],
        "unused_classes": [],
        "quality": [],
        "danger": [],
        "secrets": [],
    }

    cli.render_results(console, result, tree=False, root_path="/root")

    printed = "\n".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Grep verify: on" in printed
    assert "rescued 3" in printed


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
    with patch("skylos.commands.init_cmd.run_init_command", return_value=0) as r:
        with pytest.raises(SystemExit) as e:
            cli.main()
    assert e.value.code == 0
    r.assert_called_once()


def test_main_whitelist_subcommand_calls_run_whitelist_and_exits(monkeypatch):
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", "whitelist", "handle_*", "--reason", "x"]
    )
    with patch(
        "skylos.commands.whitelist_cmd.run_whitelist_command", return_value=0
    ) as w:
        with pytest.raises(SystemExit) as e:
            cli.main()
    assert e.value.code == 0
    w.assert_called_once()
    assert w.call_args.args == (["handle_*", "--reason", "x"],)


def test_main_sync_subcommand_calls_sync_main_and_exits(monkeypatch):
    fake_sync = types.SimpleNamespace(main=Mock())
    monkeypatch.setitem(sys.modules, "skylos.cloud.sync", fake_sync)

    monkeypatch.setattr(cli.sys, "argv", ["skylos", "sync", "--pull"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 0
    fake_sync.main.assert_called_once_with(["--pull"])


def test_main_project_subcommand_calls_project_main_and_exits(monkeypatch):
    fake_project = types.SimpleNamespace(run_project_command=Mock(return_value=0))
    monkeypatch.setitem(sys.modules, "skylos.commands.project_cmd", fake_project)

    monkeypatch.setattr(cli.sys, "argv", ["skylos", "project", "status"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 0
    fake_project.run_project_command.assert_called_once_with(["status"])


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
        "secrets": [
            {"provider": "generic", "file": "c.py", "line": None, "message": "Secret"}
        ],
        "unused_functions": [{"name": "u", "file": "d.py", "line": -5}],
        "unused_imports": [{"name": "os", "file": "e.py", "line": "not-an-int"}],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
    }

    sarif_path = tmp_path / "out.sarif.json"
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", ".", "--sarif", str(sarif_path), "--json"]
    )

    captured = {}

    def fake_exporter_ctor(findings, tool_name=None):
        captured["findings"] = findings
        exp = Mock()
        exp.write = Mock()
        exp.generate = Mock(return_value={"runs": [{}]})
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

    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--upload", "--strict"])

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results"),
        patch("skylos.cli.print_badge"),
        patch("skylos.cli._print_upload_destination", return_value=(True, False)),
        patch(
            "skylos.cli.upload_report",
            return_value={
                "success": True,
                "scan_id": "scan123",
                "quality_gate_passed": False,
            },
        ),
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

        assert e.value.code == 1


def test_main_json_upload_calls_upload_report_quiet(monkeypatch):
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

    monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--json", "--upload"])

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch(
            "skylos.cli.upload_report",
            return_value={"success": True, "quality_gate_passed": True},
        ) as mock_upload,
        patch("builtins.print") as mock_print,
    ):
        cli.main()

    mock_upload.assert_called_once()
    upload_result = mock_upload.call_args.args[0]
    assert upload_result["project_root"] == ""
    assert upload_result["analysis_summary"] == {
        "total_files": 1,
        "project_root": "",
    }
    assert upload_result["danger"] == []
    assert upload_result["quality"] == []
    assert upload_result["secrets"] == []
    assert "provenance_summary" in upload_result
    assert mock_upload.call_args.kwargs == {
        "is_forced": False,
        "strict": False,
        "quiet": True,
    }
    mock_print.assert_called_once()
    printed_payload = json.loads(mock_print.call_args.args[0])
    assert printed_payload["analysis_summary"] == {"total_files": 1}
    assert printed_payload["danger"] == []
    assert printed_payload["quality"] == []
    assert printed_payload["secrets"] == []
    assert "provenance_summary" in printed_payload


def test_main_linked_repo_does_not_upload_without_upload_flag(monkeypatch):
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
    monkeypatch.setenv("SKYLOS_TOKEN", "token")

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results"),
        patch("skylos.cli.print_badge"),
        patch("skylos.cli._detect_link_file", return_value=".skylos/link.json"),
        patch("skylos.cli.upload_report") as mock_upload,
    ):
        cli.main()

    mock_upload.assert_not_called()


def test_main_json_gate_failure_exits_nonzero(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [
            {
                "rule_id": "SKY-Q001",
                "file": "app.py",
                "line": 1,
                "severity": "LOW",
                "message": "quality issue",
            }
        ],
        "secrets": [],
    }

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", ".", "--json", "--gate", "--strict", "--no-provenance"],
    )

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("builtins.print") as mock_print,
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 1
    mock_print.assert_called_once_with(json.dumps(result))


def test_main_concise_outputs_clickable_dead_code_and_exits_nonzero(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [
            {"name": "unused_function", "file": "src/test.py", "line": 1}
        ],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [{"name": "UnusedClass", "file": "src/test.py", "line": 5}],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", "--format", "concise", "--no-provenance", "src/test.py"],
    )

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress") as progress,
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results") as render_results,
        patch("skylos.cli.print_badge") as print_badge,
        patch("builtins.print") as mock_print,
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 1
    mock_print.assert_called_once_with(
        "src/test.py:1  unused function\nsrc/test.py:5  unused class\n",
        end="",
    )
    progress.assert_not_called()
    render_results.assert_not_called()
    print_badge.assert_not_called()


@pytest.mark.parametrize(
    ("category", "finding", "expected_line"),
    [
        (
            "dependency_vulnerabilities",
            {
                "package": "badpkg",
                "file": "requirements.txt",
                "line": 1,
                "message": "CVE-TEST vulnerable dependency",
            },
            "requirements.txt:1  CVE-TEST vulnerable dependency\n",
        ),
        (
            "custom_rules",
            {
                "rule_id": "CUSTOM-001",
                "file": "src/test.py",
                "line": 3,
                "message": "custom rule hit",
            },
            "src/test.py:3  custom rule hit\n",
        ),
    ],
)
def test_main_concise_exits_nonzero_for_reported_extra_categories(
    monkeypatch, category, finding, expected_line
):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "unused_files": [],
        "unused_fixtures": [],
        "danger": [],
        "quality": [],
        "secrets": [],
        "custom_rules": [],
        "dependency_vulnerabilities": [],
    }
    result[category] = [finding]

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", "--format", "concise", "--no-provenance", "--sca", "src/test.py"],
    )

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress") as progress,
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results") as render_results,
        patch("skylos.cli.print_badge") as print_badge,
        patch("builtins.print") as mock_print,
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 1
    mock_print.assert_called_once_with(expected_line, end="")
    progress.assert_not_called()
    render_results.assert_not_called()
    print_badge.assert_not_called()


def test_main_concise_clean_output_prints_nothing(monkeypatch):
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

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", "--format", "concise", "--no-provenance", "src/test.py"],
    )

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress") as progress,
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("builtins.print") as mock_print,
    ):
        cli.main()

    mock_print.assert_not_called()
    progress.assert_not_called()


def test_main_rich_output_writes_report_file(monkeypatch, tmp_path):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": "dead", "file": "app.py", "line": 1}],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }
    output_path = tmp_path / "skylos.txt"

    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            ".",
            "--output",
            str(output_path),
            "--no-provenance",
            "--no-upload",
        ],
    )

    with (
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
    ):
        cli.main()

    output = output_path.read_text(encoding="utf-8")
    assert "Python Static Analysis Results" in output
    assert "Unused Functions" in output
    assert "dead" in output


def test_main_ignores_pyproject_addopts_output_clobber(monkeypatch, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("KEEP\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        f"""
[tool.skylos]
addopts = ["--output", "{victim}"]
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": "dead", "file": "app.py", "line": 1}],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", ".", "--no-provenance", "--no-upload"],
    )

    with (
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
    ):
        cli.main()

    assert victim.read_text(encoding="utf-8") == "KEEP\n"


def test_main_json_strict_failure_exits_nonzero(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": "dead", "file": "app.py", "line": 1}],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", ".", "--json", "--strict", "--no-provenance"],
    )

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("builtins.print") as mock_print,
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 1
    mock_print.assert_called_once_with(json.dumps(result))


def test_main_strict_failure_renders_results_then_exits_nonzero(monkeypatch):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [{"name": "dead", "file": "app.py", "line": 1}],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
    }

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", ".", "--strict", "--no-provenance"],
    )

    fake_logger = Mock()
    fake_logger.console = Mock()

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress", return_value=_progress_ctx()),
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results") as render_results,
        patch("skylos.cli.print_badge") as badge,
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 1
    render_results.assert_called_once()
    badge.assert_called_once()


@pytest.mark.parametrize("llm_args", (["--llm"], ["--format", "llm"]))
def test_main_llm_output_is_quiet_and_gate_failure_exits_nonzero(monkeypatch, llm_args):
    result = {
        "analysis_summary": {"total_files": 1},
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [
            {
                "rule_id": "SKY-Q001",
                "file": "app.py",
                "line": 1,
                "severity": "LOW",
                "message": "quality issue",
            }
        ],
        "secrets": [],
    }

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", ".", *llm_args, "--gate", "--strict", "--no-provenance"],
    )

    fake_logger = Mock()
    fake_logger.console = Mock()
    analyzer_logger = logging.getLogger("Skylos")
    original_level = analyzer_logger.level
    observed = {}

    def fake_analyze(*args, **kwargs):
        observed["analyzer_level"] = analyzer_logger.level
        return json.dumps(result)

    with (
        patch("skylos.cli.setup_logger", return_value=fake_logger),
        patch("skylos.cli.Progress") as progress,
        patch("skylos.cli.run_analyze", side_effect=fake_analyze),
        patch("skylos.cli.load_config", return_value={}),
        patch("builtins.print") as mock_print,
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 1
    assert mock_print.call_args.args[0].startswith("# Skylos Report")
    assert observed["analyzer_level"] == logging.WARNING
    assert analyzer_logger.level == original_level
    fake_logger.console.print.assert_not_called()
    progress.assert_not_called()


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
        patch(
            "skylos.cli.upload_report",
            return_value={"success": False, "error": "No token found"},
        ),
        patch("skylos.cli.subprocess.Popen", return_value=proc) as popen,
        patch("skylos.api.get_project_token", return_value=None),
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 0

    echo_calls = [c for c in popen.call_args_list if c.args[0] == ["echo", "hi"]]
    assert len(echo_calls) == 1


def test_main_ignores_pyproject_addopts_deployment_command(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.skylos]
addopts = [".", "--", "sh", "-c", "touch SHOULD_NOT_RUN"]
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

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
            return_value={"success": False, "error": "No token found"},
        ),
        patch("skylos.cli.subprocess.Popen") as popen,
        patch("skylos.api.get_project_token", return_value=None),
    ):
        cli.main()

    dangerous_calls = [
        call
        for call in popen.call_args_list
        if call.args and call.args[0] == ["sh", "-c", "touch SHOULD_NOT_RUN"]
    ]
    assert dangerous_calls == []


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
        patch(
            "skylos.cli.upload_report",
            return_value={"success": False, "error": "No token found"},
        ),
        patch("skylos.cli.subprocess.Popen", return_value=proc),
        patch("skylos.api.get_project_token", return_value=None),
    ):
        with pytest.raises(SystemExit) as e:
            cli.main()

    assert e.value.code == 7


def test_render_upload_failure_shows_large_upload_guidance():
    console = Mock()

    cli._render_upload_failure(
        console,
        {
            "success": False,
            "code": "UPLOAD_PROTOCOL_UNSUPPORTED",
            "error": "protocol mismatch",
        },
    )

    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Upload unavailable:" in printed
    assert "only supports inline scan uploads right now" in printed
    assert "/api/report/init and /api/report/complete" in printed


def test_render_upload_failure_shows_generic_error_for_other_failures():
    console = Mock()

    cli._render_upload_failure(
        console,
        {
            "success": False,
            "error": "network timeout",
        },
    )

    printed = " ".join(
        str(call.args[0]) for call in console.print.call_args_list if call.args
    )
    assert "Upload failed:" in printed
    assert "network timeout" in printed


class TestDiffFlag:
    """Tests for --diff line-level filtering."""

    def test_diff_flag_parses_with_explicit_ref(self, monkeypatch):
        """--diff origin/main sets args.diff to 'origin/main'."""
        monkeypatch.setattr(
            cli.sys, "argv", ["skylos", ".", "--diff", "origin/develop"]
        )

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

        with (
            patch("skylos.cli.Progress", return_value=_progress_ctx()),
            patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
            patch("skylos.cli.load_config", return_value={}),
            patch("skylos.cli.render_results"),
            patch("skylos.cli.print_badge"),
            patch(
                "skylos.cli.upload_report",
                return_value={"success": False, "error": "No token found"},
            ),
            patch("skylos.cicd.review.subprocess.run") as mock_git,
            patch("skylos.api.get_project_token", return_value=None),
        ):
            mock_git.return_value = Mock(returncode=0, stdout="")
            cli.main()
            diff_calls = [
                c for c in mock_git.call_args_list if c.args[0][:2] == ["git", "diff"]
            ]
            assert len(diff_calls) == 1
            assert diff_calls[0].args[0] == [
                "git",
                "diff",
                "--unified=0",
                "origin/develop...HEAD",
            ]

    def test_diff_flag_without_value_defaults_to_auto(self, monkeypatch):
        """--diff without value uses 'auto' which resolves to origin/main."""
        monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--diff"])
        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)

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

        with (
            patch("skylos.cli.Progress", return_value=_progress_ctx()),
            patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
            patch("skylos.cli.load_config", return_value={}),
            patch("skylos.cli.render_results"),
            patch("skylos.cli.print_badge"),
            patch(
                "skylos.cli.upload_report",
                return_value={"success": False, "error": "No token found"},
            ),
            patch("skylos.cicd.review.subprocess.run") as mock_git,
            patch("skylos.api.get_project_token", return_value=None),
        ):
            mock_git.return_value = Mock(returncode=0, stdout="")
            cli.main()
            diff_calls = [
                c for c in mock_git.call_args_list if c.args[0][:2] == ["git", "diff"]
            ]
            assert len(diff_calls) == 1
            assert diff_calls[0].args[0] == [
                "git",
                "diff",
                "--unified=0",
                "origin/main...HEAD",
            ]

    def test_diff_auto_uses_github_base_ref(self, monkeypatch):
        """--diff auto-detection picks up GITHUB_BASE_REF env var."""
        monkeypatch.setattr(cli.sys, "argv", ["skylos", ".", "--diff"])
        monkeypatch.setenv("GITHUB_BASE_REF", "develop")

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

        with (
            patch("skylos.cli.Progress", return_value=_progress_ctx()),
            patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
            patch("skylos.cli.load_config", return_value={}),
            patch("skylos.cli.render_results"),
            patch("skylos.cli.print_badge"),
            patch(
                "skylos.cli.upload_report",
                return_value={"success": False, "error": "No token found"},
            ),
            patch("skylos.cicd.review.subprocess.run") as mock_git,
            patch("skylos.api.get_project_token", return_value=None),
        ):
            mock_git.return_value = Mock(returncode=0, stdout="")
            cli.main()
            diff_calls = [
                c for c in mock_git.call_args_list if c.args[0][:2] == ["git", "diff"]
            ]
            assert len(diff_calls) == 1
            assert diff_calls[0].args[0] == [
                "git",
                "diff",
                "--unified=0",
                "origin/develop...HEAD",
            ]

    def test_diff_filters_findings_to_changed_lines(self, monkeypatch):
        """--diff filters findings to only those in changed line ranges."""
        monkeypatch.setattr(
            cli.sys, "argv", ["skylos", ".", "--diff", "origin/main", "--json"]
        )

        result = {
            "analysis_summary": {"total_files": 1},
            "unused_functions": [
                {"name": "foo", "file": "src/app.py", "line": 10},
                {"name": "bar", "file": "src/app.py", "line": 50},
            ],
            "unused_imports": [],
            "unused_variables": [],
            "unused_classes": [],
            "unused_parameters": [],
            "danger": [
                {
                    "rule_id": "SKY-D201",
                    "file": "src/app.py",
                    "line": 12,
                    "message": "eval",
                },
            ],
            "quality": [],
            "secrets": [],
        }

        diff_output = (
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -8,5 +8,7 @@ some context\n"
            "+new line\n"
        )

        git_result = Mock(returncode=0, stdout=diff_output)

        captured_output = []

        with (
            patch("skylos.cli.Progress", return_value=_progress_ctx()),
            patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
            patch("skylos.cli.load_config", return_value={}),
            patch("skylos.cicd.review.subprocess.run", return_value=git_result),
            patch("builtins.print", side_effect=lambda x: captured_output.append(x)),
        ):
            cli.main()

        assert len(captured_output) == 1
        output = json.loads(captured_output[0])
        assert len(output["unused_functions"]) == 1
        assert output["unused_functions"][0]["name"] == "foo"
        assert len(output["danger"]) == 1
        assert output["danger"][0]["line"] == 12


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
