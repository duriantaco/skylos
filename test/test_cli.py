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
    @patch('skylos.cli.logging.StreamHandler')
    def test_setup_logger_console_only(self, mock_stream_handler, mock_file_handler):
        """Test logger setup without output file."""
        mock_handler = Mock()
        mock_stream_handler.return_value = mock_handler
        
        logger = setup_logger()
        
        assert logger.name == 'skylos'
        assert logger.level == logging.INFO
        assert not logger.propagate
        
        mock_stream_handler.assert_called_once_with(sys.stdout)
        mock_file_handler.assert_not_called()
    
    @patch('skylos.cli.logging.FileHandler')
    @patch('skylos.cli.logging.StreamHandler')
    def test_setup_logger_with_output_file(self, mock_stream_handler, mock_file_handler):
        """Test logger setup with output file."""
        mock_stream_handler.return_value = Mock()
        mock_file_handler.return_value = Mock()
        
        logger = setup_logger("output.log")
        
        mock_stream_handler.assert_called_once_with(sys.stdout)
        mock_file_handler.assert_called_once_with("output.log")


class TestRemoveUnusedImport:
    """Test unused import removal functionality."""
    
    def test_remove_simple_import(self):
        """Test removing a simple import statement."""
        content = """import os
import sys
import json

def main():
    print(sys.version)
"""
        
        with patch('builtins.open', mock_open(read_data=content)) as mock_file:
            result = remove_unused_import("test.py", "os", 1)
            
            assert result is True
            handle = mock_file()
            written_content = ''.join(call.args[0] for call in handle.write.call_args_list)
            assert "import os" not in written_content
    
    def test_remove_from_multi_import(self):
        content = "import os, sys, json\n"
        
        with patch('builtins.open', mock_open(read_data=content)) as mock_file:
            result = remove_unused_import("test.py", "os", 1)
            
            assert result is True
    
    def test_remove_from_import_statement(self):
        content = "from collections import defaultdict, Counter\n"
        
        with patch('builtins.open', mock_open(read_data=content)) as mock_file:
            result = remove_unused_import("test.py", "Counter", 1)
            
            assert result is True
            handle = mock_file()
            written_lines = handle.writelines.call_args[0][0]
            written_content = ''.join(written_lines)
            assert "defaultdict" in written_content
            assert "Counter" not in written_content

    def test_remove_entire_from_import(self):
        content = "from collections import defaultdict\n"
        
        with patch('builtins.open', mock_open(read_data=content)) as mock_file:
            result = remove_unused_import("test.py", "defaultdict", 1)
            
            assert result is True
            handle = mock_file()
            written_content = ''.join(call.args[0] for call in handle.write.call_args_list)
            # line should be empty
            assert written_content.strip() == ""
    
    def test_remove_import_file_error(self):
        """handling file errors when removing imports."""
        with patch('builtins.open', side_effect=FileNotFoundError("File not found")):
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
        
        with patch('skylos.cli.ast.parse') as mock_parse, \
             patch('builtins.open', mock_open(read_data=content)) as mock_file:
            
            mock_func_node = Mock()
            mock_func_node.name = "unused_function"
            mock_func_node.lineno = 4
            mock_func_node.end_lineno = 5
            mock_func_node.decorator_list = []
            
            with patch('skylos.cli.ast.walk', return_value=[mock_func_node]):
                with patch('skylos.cli.ast.FunctionDef', mock_func_node.__class__):
                    result = remove_unused_function("test.py", "unused_function", 4)
            
            assert result is True
    
    def test_remove_function_with_decorators(self):
        """removing function with decorators."""
        content = """@property
@decorator
def unused_function():
    return "unused"
"""
        
        with patch('skylos.cli.ast.parse') as mock_parse, \
             patch('builtins.open', mock_open(read_data=content)) as mock_file:
            
            mock_decorator = Mock()
            mock_decorator.lineno = 1
            
            mock_func_node = Mock()
            mock_func_node.name = "unused_function"
            mock_func_node.lineno = 3
            mock_func_node.end_lineno = 4
            mock_func_node.decorator_list = [mock_decorator]
            
            with patch('skylos.cli.ast.walk', return_value=[mock_func_node]):
                with patch('skylos.cli.ast.FunctionDef', mock_func_node.__class__):
                    result = remove_unused_function("test.py", "unused_function", 3)
            
            assert result is True
    
    def test_remove_function_file_error(self):
        with patch('builtins.open', side_effect=FileNotFoundError("File not found")):
            result = remove_unused_function("nonexistent.py", "func", 1)
            assert result is False
    
    def test_remove_function_parse_error(self):
        with patch('builtins.open', mock_open(read_data="invalid python code")), \
             patch('skylos.cli.ast.parse', side_effect=SyntaxError("Invalid syntax")):
            result = remove_unused_function("test.py", "func", 1)
            assert result is False

class TestInteractiveSelection:
    @pytest.fixture
    def mock_logger(self):
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
    
    def test_interactive_selection_unavailable(self, mock_logger, sample_unused_items):
        """interactive selection when inquirer is not available."""
        functions, imports = sample_unused_items
        
        with patch('skylos.cli.INTERACTIVE_AVAILABLE', False):
            selected_functions, selected_imports = interactive_selection(
                mock_logger, functions, imports
            )
        
        assert selected_functions == []
        assert selected_imports == []
        mock_logger.error.assert_called_once()
    
    @patch('skylos.cli.inquirer')
    def test_interactive_selection_with_selections(self, mock_inquirer, mock_logger, sample_unused_items):
        functions, imports = sample_unused_items
        
        mock_inquirer.prompt.side_effect = [
            {'functions': [functions[0]]},
            {'imports': [imports[1]]}
        ]
        
        with patch('skylos.cli.INTERACTIVE_AVAILABLE', True):
            selected_functions, selected_imports = interactive_selection(
                mock_logger, functions, imports
            )
        
        assert selected_functions == [functions[0]]
        assert selected_imports == [imports[1]]
        assert mock_inquirer.prompt.call_count == 2
    
    @patch('skylos.cli.inquirer')
    def test_interactive_selection_no_selections(self, mock_inquirer, mock_logger, sample_unused_items):
        functions, imports = sample_unused_items
        
        mock_inquirer.prompt.return_value = None
        
        with patch('skylos.cli.INTERACTIVE_AVAILABLE', True):
            selected_functions, selected_imports = interactive_selection(
                mock_logger, functions, imports
            )
        
        assert selected_functions == []
        assert selected_imports == []
    
    def test_interactive_selection_empty_lists(self, mock_logger):
        selected_functions, selected_imports = interactive_selection(
            mock_logger, [], []
        )
        
        assert selected_functions == []
        assert selected_imports == []


class TestPrintBadge:    
    @pytest.fixture
    def mock_logger(self):
        return Mock()
    
    def test_print_badge_zero_dead_code(self, mock_logger):
        """Test badge printing with zero dead code."""
        print_badge(0, mock_logger)
        
        calls = [call.args[0] for call in mock_logger.info.call_args_list]
        badge_call = next((call for call in calls if "Dead_Code-Free" in call), None)
        assert badge_call is not None
        assert "brightgreen" in badge_call
    
    def test_print_badge_with_dead_code(self, mock_logger):
        print_badge(5, mock_logger)
        
        calls = [call.args[0] for call in mock_logger.info.call_args_list]
        badge_call = next((call for call in calls if "Dead_Code-5" in call), None)
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
             patch('skylos.cli.skylos.analyze') as mock_analyze, \
             patch('skylos.cli.setup_logger') as mock_setup_logger:
            
            mock_logger = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_analyze.return_value = json.dumps(mock_skylos_result)
            
            main()
            
            mock_analyze.assert_called_once()
            mock_logger.info.assert_called_with(json.dumps(mock_skylos_result))
    
    def test_main_verbose_output(self, mock_skylos_result):
        """ with verbose"""
        test_args = ["cli.py", "test_path", "--verbose"]
        
        with patch('sys.argv', test_args), \
             patch('skylos.cli.skylos.analyze') as mock_analyze, \
             patch('skylos.cli.setup_logger') as mock_setup_logger:
            
            mock_logger = Mock()
            mock_setup_logger.return_value = mock_logger
            mock_analyze.return_value = json.dumps(mock_skylos_result)
            
            main()
            
            mock_logger.setLevel.assert_called_with(logging.DEBUG)
    
    def test_main_analysis_error(self):
        test_args = ["cli.py", "test_path"]
        
        with patch('sys.argv', test_args), \
            patch('skylos.cli.skylos.analyze', side_effect=Exception("Analysis failed")), \
            patch('skylos.cli.setup_logger') as mock_setup_logger, \
            patch('skylos.cli.parse_exclude_folders', return_value=set()):
            
            mock_logger = Mock()
            mock_setup_logger.return_value = mock_logger
            
            with pytest.raises(SystemExit):
                main()
            
            mock_logger.error.assert_called_with("Error during analysis: Analysis failed")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])