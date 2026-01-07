import pytest
import tempfile
from pathlib import Path
from textwrap import dedent
from skylos.tracer import CallTracer


@pytest.fixture(scope="session")
def sample_project():
    with tempfile.TemporaryDirectory() as temp_dir:
        project_path = Path(temp_dir)

        create_sample_project(project_path)
        yield project_path


def create_sample_project(base_path: Path):
    (base_path / "app").mkdir()

    app_init = base_path / "app" / "__init__.py"
    app_init.write_text(
        dedent("""
        from .core import main_function
        from .utils import helper_function
        
        __all__ = ['main_function', 'helper_function']
    """)
    )

    core_py = base_path / "app" / "core.py"
    core_py.write_text(
        dedent("""
        import os
        import sys
        from typing import Dict, List  # List is unused here
        from collections import defaultdict
        
        def main_function():
            '''Main entry point - should not be flagged'''
            data = defaultdict(list)
            return process_data(data)
        
        def process_data(data: Dict):
            '''Used by main_function'''
            return len(data)
        
        def deprecated_function():
            '''This function is never called'''
            unused_var = "should be flagged"
            return unused_var
        
        def _private_helper():
            '''Private function, might be unused'''
            return "private"
    """)
    )

    utils_py = base_path / "app" / "utils.py"
    utils_py.write_text(
        dedent("""
        import json  # unused
        import re
        
        def helper_function():
            '''Exported function'''
            return validate_input("test")
        
        def validate_input(text: str):
            '''Used by helper_function'''
            return re.match(r"^[a-z]+$", text) is not None
        
        def unused_utility():
            '''Never called utility'''
            return "utility"
        
        class ConfigManager:
            '''Used class'''
            def __init__(self):
                self.config = {}
            
            def get(self, key):
                return self.config.get(key)
        
        class LegacyProcessor:
            '''Unused class'''
            def process(self, data):
                return data
    """)
    )

    tests_dir = base_path / "tests"
    tests_dir.mkdir()

    test_core = tests_dir / "test_core.py"
    test_core.write_text(
        dedent("""
        import unittest
        from app.core import main_function, process_data
        
        class TestCore(unittest.TestCase):
            def test_main_function(self):
                result = main_function()
                self.assertIsInstance(result, int)
            
            def test_process_data(self):
                data = {'key': ['value']}
                result = process_data(data)
                self.assertEqual(result, 1)
            
            def test_edge_case(self):
                '''Test methods should not be flagged'''
                pass
    """)
    )

    config_dir = base_path / "config"
    config_dir.mkdir()

    config_py = config_dir / "settings.py"
    config_py.write_text(
        dedent("""
        # Configuration file with potentially unused imports
        import os
        import logging
        
        DEBUG = True
        DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
        
        def setup_logging():
            '''Might be called externally'''
            logging.basicConfig(level=logging.INFO)
    """)
    )

    pycache_dir = base_path / "__pycache__"
    pycache_dir.mkdir()

    cache_file = pycache_dir / "cached.pyc"
    cache_file.write_bytes(b"fake compiled python")


@pytest.fixture
def simple_python_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(
            dedent("""
            import os  # unused
            import sys
            
            def used_function():
                print("Hello", file=sys.stderr)
            
            def unused_function():
                return "never called"
            
            if __name__ == "__main__":
                used_function()
        """)
        )
        f.flush()
        yield Path(f.name)
        Path(f.name).unlink()


@pytest.fixture
def empty_project():
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def project_with_syntax_error():
    with tempfile.TemporaryDirectory() as temp_dir:
        project_path = Path(temp_dir)

        valid_py = project_path / "valid.py"
        valid_py.write_text("def valid_function():\n    return True\n")

        invalid_py = project_path / "invalid.py"
        invalid_py.write_text(
            "def invalid_function(\n    # Missing closing parenthesis\n    return False\n"
        )

        yield project_path


@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """auto cleanup any temporary files after each test"""
    yield


pytest_plugins = []


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "cli: mark test as CLI interface test")


@pytest.fixture
def mock_git_repo():
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = Path(temp_dir)

        try:
            import subprocess

            subprocess.run(
                ["git", "init"], cwd=repo_path, check=True, capture_output=True
            )
            subprocess.run(
                ["git", "config", "user.email", "test@example.com"],
                cwd=repo_path,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test User"], cwd=repo_path, check=True
            )

            test_file = repo_path / "test.py"
            test_file.write_text("def test(): pass\n")
            subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
            subprocess.run(
                ["git", "commit", "-m", "Initial commit"], cwd=repo_path, check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        yield repo_path


_tracer = None


def pytest_addoption(parser):
    parser.addoption(
        "--skylos-trace",
        action="store_true",
        default=False,
        help="Enable Skylos call tracing to capture dynamic function calls",
    )
    parser.addoption(
        "--skylos-trace-include",
        action="store",
        default=None,
        help="Comma-separated path patterns to include (e.g., 'skylos/,myproject/')",
    )
    parser.addoption(
        "--skylos-trace-output",
        action="store",
        default=".skylos_trace",
        help="Output file for trace data (default: .skylos_trace)",
    )


def pytest_configure(config):
    global _tracer

    if config.getoption("--skylos-trace"):
        include = config.getoption("--skylos-trace-include")
        include_patterns = include.split(",") if include else None

        _tracer = CallTracer(include_patterns=include_patterns)
        _tracer.start()
        print("\nSkylos call tracing enabled")


def pytest_unconfigure(config):
    global _tracer

    if _tracer is not None:
        _tracer.stop()
        output_path = config.getoption("--skylos-trace-output", ".skylos_trace")
        _tracer.save(output_path)

        stats = _tracer.get_stats()
        print(
            f"\nSkylos trace: {stats['unique_functions']} functions across {stats['files_traced']} files"
        )
