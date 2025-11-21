import pytest
import tempfile
import json
from pathlib import Path
from skylos.analyzer import Skylos


class TestChangeAnalyzer:
    def test_future_annotations_not_flagged(self):
        """from __future__ import annotations should not be flagged as unused"""
        code = """
from __future__ import annotations
import ast  # should be flagged

def func(x: int) -> int:
    return x * 2
"""
        result = self._analyze(code)
        import_names = [i["simple_name"] for i in result["unused_imports"]]

        assert "annotations" not in import_names, (
            "__future__ annotations wrongly flagged"
        )
        assert "ast" in import_names, "Regular unused import should also be flagged"

    def test_underscore_items_not_flagged(self):
        """items starting with _ should not be reported as unused"""
        code = """
_private_var = "private"

def _private_func():
    return "private"

def regular_func(_private_param):
    return "test"

class Example:
    def _private_method(self):
        return "private"
"""
        result = self._analyze(code)

        function_names = [f["name"] for f in result["unused_functions"]]
        underscore_funcs = [name for name in function_names if name.startswith("_")]
        assert len(underscore_funcs) == 0, (
            f"Underscore functions incorrectly flagged: {underscore_funcs}"
        )

        variable_names = [v["name"] for v in result["unused_variables"]]
        underscore_vars = [name for name in variable_names if name.startswith("_")]
        assert len(underscore_vars) == 0, (
            f"Underscore variables incorrectly flagged: {underscore_vars}"
        )

        param_names = [p["name"] for p in result["unused_parameters"]]
        underscore_params = [name for name in param_names if name.startswith("_")]
        assert len(underscore_params) == 0, (
            f"Underscore parameters incorrectly flagged: {underscore_params}"
        )

    def test_unittest_magic_methods_not_flagged(self):
        """setUp, tearDown, setUpClass should not be flagged as unused"""
        code = """
import unittest

class TestCase(unittest.TestCase):
    def setUp(self):
        self.data = "test"
    
    def tearDown(self):
        pass
    
    @classmethod
    def setUpClass(cls):
        pass
    
    @classmethod
    def tearDownClass(cls):
        pass
    
    def test_example(self):
        pass

def setUpModule():
    pass

def tearDownModule():
    pass
"""
        result = self._analyze(code, "test_magic.py")
        function_names = [f["name"] for f in result["unused_functions"]]

        magic_methods = [
            "setUp",
            "tearDown",
            "setUpClass",
            "tearDownClass",
            "setUpModule",
            "tearDownModule",
        ]
        flagged_magic = [method for method in magic_methods if method in function_names]

        assert len(flagged_magic) == 0, (
            f"unittest/pytest methods incorrectly flagged: {flagged_magic}"
        )

    def test_all_edge_cases_together(self):
        code = """
from __future__ import annotations
import unused_import

_private_var = "private"

class TestExample:
    def setUp(self):
        self._data = "test"
    
    def tearDown(self):
        pass
    
    def test_something(self):
        return self._data
    
    def _helper_method(self):
        return "helper"

def _private_func() -> str:
    return "private"

def regular_func(_param: str):
    return "test"
"""
        result = self._analyze(code, "test_comprehensive.py")

        # should not flag __future__ imports
        import_names = [i["simple_name"] for i in result["unused_imports"]]
        assert "annotations" not in import_names, "__future__ annotations flagged"
        assert "unused_import" in import_names, (
            "Regular unused import should be flagged"
        )

        # should not flag _ items
        function_names = [f["name"] for f in result["unused_functions"]]
        underscore_funcs = [name for name in function_names if name.startswith("_")]
        assert len(underscore_funcs) == 0, (
            f"Underscore functions flagged: {underscore_funcs}"
        )

        # should not flag test methods
        magic_methods = ["setUp", "tearDown", "test_something"]
        flagged_magic = [method for method in magic_methods if method in function_names]
        assert len(flagged_magic) == 0, f"Test methods flagged: {flagged_magic}"

        # should not flag _ param
        param_names = [p["name"] for p in result["unused_parameters"]]
        underscore_params = [name for name in param_names if name.startswith("_")]
        assert len(underscore_params) == 0, (
            f"Underscore parameters flagged: {underscore_params}"
        )

    def _analyze(self, code: str, filename: str = "example.py") -> dict:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(code)

            skylos = Skylos()
            result_json = skylos.analyze(str(temp_dir), thr=60)
            return json.loads(result_json)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
