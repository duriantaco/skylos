#!/usr/bin/env python3
import pytest
import json
import sys
import logging
from unittest.mock import Mock, patch, mock_open

from skylos.cli import Colors, CleanFormatter, setup_logger, remove_unused_import, remove_unused_function, interactive_selection, print_badge, main

class TestColors:
    def test_colors_defined(self):
        """Test that all color constants are defined."""
        assert hasattr(Colors, 'RED')
        assert hasattr(Colors, 'GREEN')
        assert hasattr(Colors, 'RESET')
        assert hasattr(Colors, 'BOLD')
        
        assert Colors.RED.startswith('\033[')
        assert Colors.RESET == '\033[0m'

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
    
    @patch('skylos.cli.logging.FileHandler')
    @patch('skylos.cli.RichHandler')
    def test_setup_logger_console_only(self, mock_rich_handler, mock_file_handler):
        """Test logger setup without output file."""
        mock_handler = Mock()
        mock_rich_handler.return_value = mock_handler

        logger = setup_logger()

        mock_rich_handler.assert_called_once()
        mock_file_handler.assert_not_called()
    
    @patch('skylos.cli.logging.FileHandler')
    @patch('skylos.cli.RichHandler')
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
        
        with patch('pathlib.Path.read_text', return_value=content) as mock_read, \
             patch('pathlib.Path.write_text') as mock_write, \
             patch('skylos.cli.remove_unused_import_cst', return_value=("NEW_CODE", True)) as mock_codemod:
            result = remove_unused_import("test.py", "os", 1)
            
            assert result is True
            mock_read.assert_called_once()
            mock_codemod.assert_called_once()
            mock_write.assert_called_once_with("NEW_CODE", encoding="utf-8")
    
    def test_remove_from_multi_import(self):
        content = "import os, sys, json\n"
        
        with patch('pathlib.Path.read_text', return_value=content), \
             patch('pathlib.Path.write_text') as mock_write, \
             patch('skylos.cli.remove_unused_import_cst', return_value=("X", True)):
            result = remove_unused_import("test.py", "os", 1)
            
            assert result is True
            mock_write.assert_called_once()
    
    def test_remove_from_import_statement(self):
        content = "from collections import defaultdict, Counter\n"
        
        with patch('pathlib.Path.read_text', return_value=content), \
             patch('pathlib.Path.write_text') as mock_write, \
             patch('skylos.cli.remove_unused_import_cst', return_value=("X", True)):
            result = remove_unused_import("test.py", "Counter", 1)
            
            assert result is True
            mock_write.assert_called_once()

    def test_remove_entire_from_import(self):
        content = "from collections import defaultdict\n"
        
        with patch('pathlib.Path.read_text', return_value=content), \
             patch('pathlib.Path.write_text') as mock_write, \
             patch('skylos.cli.remove_unused_import_cst', return_value=("", True)):
            result = remove_unused_import("test.py", "defaultdict", 1)
            
            assert result is True
            mock_write.assert_called_once_with("", encoding="utf-8")
    
    def test_remove_import_file_error(self):
        """handling file errors when removing imports."""
        with patch('pathlib.Path.read_text', side_effect=FileNotFoundError("File not found")):
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
        
        with patch('pathlib.Path.read_text', return_value=content), \
             patch('pathlib.Path.write_text') as mock_write, \
             patch('skylos.cli.remove_unused_function_cst', return_value=("NEW_FUNC_CODE", True)):
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
        
        with patch('pathlib.Path.read_text', return_value=content), \
             patch('pathlib.Path.write_text') as mock_write, \
             patch('skylos.cli.remove_unused_function_cst', return_value=("X", True)):
            result = remove_unused_function("test.py", "unused_function", 3)
        
        assert result is True
        mock_write.assert_called_once()

    
    def test_remove_function_file_error(self):
        with patch('pathlib.Path.read_text', side_effect=FileNotFoundError("File not found")):
            result = remove_unused_function("nonexistent.py", "func", 1)
            assert result is False
    
    def test_remove_function_parse_error(self):
        with patch('pathlib.Path.read_text', side_effect=SyntaxError("Invalid syntax")):
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
            {"name": "unused_func2", "file": "test2.py", "line": 20}
        ]
        imports = [
            {"name": "unused_import1", "file": "test1.py", "line": 1},
            {"name": "unused_import2", "file": "test2.py", "line": 2}
        ]
        return functions, imports
    
    def test_interactive_selection_unavailable(self, mock_console, sample_unused_items):
        functions, imports = sample_unused_items
        
        with patch('skylos.cli.INTERACTIVE_AVAILABLE', False):
            selected_functions, selected_imports = interactive_selection(
                mock_console, functions, imports
            )
        
        assert selected_functions == []
        assert selected_imports == []
        mock_console.print.assert_called_once()
    
    @patch('skylos.cli.inquirer')
    def test_interactive_selection_with_selections(self, mock_inquirer, mock_console, sample_unused_items):
        functions, imports = sample_unused_items
        
        mock_inquirer.prompt.side_effect = [
            {'functions': [functions[0]]},
            {'imports': [imports[1]]}
        ]
        
        with patch('skylos.cli.INTERACTIVE_AVAILABLE', True):
            selected_functions, selected_imports = interactive_selection(
                mock_console, functions, imports
            )
    
    @patch('skylos.cli.inquirer')
    def test_interactive_selection_no_selections(self, mock_inquirer, mock_console, sample_unused_items):
        functions, imports = sample_unused_items
        
        mock_inquirer.prompt.return_value = None
        
        with patch('skylos.cli.INTERACTIVE_AVAILABLE', True):
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
            "unused_imports": [
                {"name": "unused_import", "file": "test.py", "line": 1}
            ],
            "unused_parameters": [],
            "unused_variables": [],
            "analysis_summary": {
                "total_files": 2,
                "excluded_folders": []
            }
        }
    
    def test_main_json_output(self, mock_skylos_result):
        """testing main function with JSON output"""
        test_args = ["cli.py", "test_path", "--json"]
        
        with patch('sys.argv', test_args), \
             patch('skylos.cli.run_analyze') as mock_analyze, \
             patch('builtins.print') as mock_print, \
             patch('skylos.cli.setup_logger'), \
             patch('skylos.cli.Progress') as mock_progress:
            
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
            mock_analyze.return_value = json.dumps(mock_skylos_result)
            
            main()
            
            mock_analyze.assert_called_once()
            mock_print.assert_called_once_with(json.dumps(mock_skylos_result))
    
    def test_main_verbose_output(self, mock_skylos_result):
        """ with verbose"""
        test_args = ["cli.py", "test_path", "--verbose"]
        
        with patch('sys.argv', test_args), \
             patch('skylos.cli.run_analyze') as mock_analyze, \
             patch('skylos.cli.setup_logger') as mock_setup_logger, \
             patch('skylos.cli.Progress') as mock_progress:
            
            mock_logger = Mock()
            mock_logger.console = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_analyze.return_value = json.dumps(mock_skylos_result)
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
            
            main()
            
            mock_logger.setLevel.assert_called_with(logging.DEBUG)

    def test_main_analysis_error(self):
        test_args = ["cli.py", "test_path"]
        
        with patch('sys.argv', test_args), \
            patch('skylos.cli.run_analyze', side_effect=Exception("Analysis failed")), \
            patch('skylos.cli.setup_logger') as mock_setup_logger, \
            patch('skylos.cli.parse_exclude_folders', return_value=set()), \
            patch('skylos.cli.Progress') as mock_progress:
            
            mock_logger = Mock()
            mock_logger.console = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_progress.return_value.__enter__.return_value = Mock(add_task=Mock())
            
            with pytest.raises(SystemExit):
                main()
            
            mock_logger.error.assert_called_with("Error during analysis: Analysis failed")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])