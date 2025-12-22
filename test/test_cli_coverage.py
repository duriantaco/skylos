# tests/test_cli_coverage.py
import pytest
from unittest.mock import patch, MagicMock
import subprocess
import sys


class TestCoverageFlag:
    """Tests for the --coverage CLI flag."""
    
    @patch('skylos.cli.subprocess.run')
    @patch('skylos.cli.run_analyze')
    def test_coverage_runs_pytest_first(self, mock_analyze, mock_run):
        """--coverage should run pytest with coverage before analysis."""
        from skylos.cli import main
        
        # Mock successful pytest run
        mock_run.return_value = MagicMock(returncode=0)
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'
        
        with patch.object(sys, 'argv', ['skylos', '.', '--coverage', '--json']):
            try:
                main()
            except SystemExit:
                pass
        
        # Verify coverage run was called
        calls = mock_run.call_args_list
        assert any(
            'coverage' in str(call) and 'pytest' in str(call)
            for call in calls
        )
    
    @patch('skylos.cli.subprocess.run')
    @patch('skylos.cli.run_analyze')
    def test_coverage_falls_back_to_unittest(self, mock_analyze, mock_run):
        """If pytest fails, should fall back to unittest."""
        from skylos.cli import main
        
        # First call (pytest) fails, second call (unittest) succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1),  # pytest fails
            MagicMock(returncode=0),  # unittest succeeds
        ]
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'
        
        with patch.object(sys, 'argv', ['skylos', '.', '--coverage', '--json']):
            try:
                main()
            except SystemExit:
                pass
        
        # Should have called both pytest and unittest
        assert mock_run.call_count == 2
        
        calls = [str(c) for c in mock_run.call_args_list]
        assert any('pytest' in c for c in calls)
        assert any('unittest' in c for c in calls)
    
    @patch('skylos.cli.subprocess.run')
    @patch('skylos.cli.run_analyze')
    def test_coverage_runs_before_analysis(self, mock_analyze, mock_run):
        """Coverage collection must happen BEFORE analysis."""
        from skylos.cli import main
        
        call_order = []
        
        def track_subprocess(*args, **kwargs):
            call_order.append('coverage')
            return MagicMock(returncode=0)
        
        def track_analyze(*args, **kwargs):
            call_order.append('analyze')
            return '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'
        
        mock_run.side_effect = track_subprocess
        mock_analyze.side_effect = track_analyze
        
        with patch.object(sys, 'argv', ['skylos', '.', '--coverage', '--json']):
            try:
                main()
            except SystemExit:
                pass
        
        # Coverage must come before analyze
        assert call_order.index('coverage') < call_order.index('analyze')
    
    @patch('skylos.cli.subprocess.run')
    @patch('skylos.cli.run_analyze')
    def test_coverage_uses_project_root_cwd(self, mock_analyze, mock_run):
        """Coverage should run in the project root directory."""
        from skylos.cli import main
        
        mock_run.return_value = MagicMock(returncode=0)
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'
        
        with patch.object(sys, 'argv', ['skylos', '/some/project', '--coverage', '--json']):
            try:
                main()
            except SystemExit:
                pass
        
        # Check that cwd was passed to subprocess.run
        call_kwargs = mock_run.call_args_list[0][1]
        assert 'cwd' in call_kwargs
    
    @patch('skylos.cli.run_analyze')
    def test_no_coverage_flag_skips_coverage(self, mock_analyze):
        """Without --coverage flag, coverage should not run."""
        from skylos.cli import main
        
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'
        
        with patch('skylos.cli.subprocess.run') as mock_run:
            with patch.object(sys, 'argv', ['skylos', '.', '--json']):
                try:
                    main()
                except SystemExit:
                    pass
            
            # subprocess.run should not be called for coverage
            coverage_calls = [
                c for c in mock_run.call_args_list
                if 'coverage' in str(c)
            ]
            assert len(coverage_calls) == 0
    
    @patch('skylos.cli.subprocess.run')
    @patch('skylos.cli.run_analyze')
    def test_coverage_with_other_flags(self, mock_analyze, mock_run):
        """--coverage should work with other flags like --danger."""
        from skylos.cli import main
        
        mock_run.return_value = MagicMock(returncode=0)
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "danger": [], "analysis_summary": {"total_files": 1}}'
        
        with patch.object(sys, 'argv', ['skylos', '.', '--coverage', '--danger', '--json']):
            try:
                main()
            except SystemExit:
                pass
        
        # Coverage should still run
        assert mock_run.called
        
        # Analysis should include danger flag
        mock_analyze.assert_called_once()
        call_kwargs = mock_analyze.call_args[1]
        assert call_kwargs.get('enable_danger') is True


class TestCoverageIntegration:
    """Integration tests for coverage + analysis flow."""
    
    @patch('skylos.implicit_refs.pattern_tracker')
    @patch('skylos.cli.subprocess.run')
    @patch('skylos.cli.run_analyze')
    def test_coverage_data_loaded_before_analysis(self, mock_analyze, mock_run, mock_tracker):
        """After coverage runs, the .coverage file should be loaded."""
        from skylos.cli import main
        from pathlib import Path
        
        mock_run.return_value = MagicMock(returncode=0)
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'
        
        # Simulate .coverage file existing after coverage run
        with patch.object(Path, 'exists', return_value=True):
            with patch.object(sys, 'argv', ['skylos', '.', '--coverage', '--json']):
                try:
                    main()
                except SystemExit:
                    pass
        
        # Analysis should have been called (which loads coverage internally)
        assert mock_analyze.called