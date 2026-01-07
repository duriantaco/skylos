import pytest
import json
import tempfile
from pathlib import Path
from textwrap import dedent

import skylos
from skylos.analyzer import Skylos
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS


class TestSkylosIntegration:
    @pytest.fixture
    def temp_project(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)

            pyproject = project_path / "pyproject.toml"
            pyproject.write_text("[tool.skylos]\n")

            main_py = project_path / "main.py"
            main_py.write_text(
                dedent("""
                import os  # unused import
                import sys
                from typing import List  # unused import
                from collections import defaultdict
                from utils import UsedClass, exported_function
                
                def used_function(x):
                    '''This function is called and should not be flagged'''
                    return x * 2
                
                def unused_function(a, b):
                    '''This function is never called'''
                    unused_var = a + b  # unused variable
                    return unused_var
                
                def main():
                    result = used_function(5)
                    print(result, file=sys.stderr)
                    data = defaultdict(list)
                    
                    obj = UsedClass()
                    obj.get_value()
                    exported_function()
                    
                    return data
                
                if __name__ == "__main__":
                    main()
            """)
            )

            utils_py = project_path / "utils.py"
            utils_py.write_text(
                dedent("""
                import json  # unused import
                
                class UsedClass:
                    '''This class is imported and used'''
                    def __init__(self):
                        self.value = 42
                    
                    def get_value(self):
                        return self.value
                
                class UnusedClass:
                    '''This class is never used'''
                    def __init__(self):
                        self.data = {}
                    
                    def unused_method(self, param):  # unused parameter
                        return "never called"
                
                def exported_function():
                    '''This function is used by main.py'''
                    return "exported"
            """)
            )

            package_dir = project_path / "mypackage"
            package_dir.mkdir()

            init_py = package_dir / "__init__.py"
            init_py.write_text(
                dedent("""
                from .submodule import PublicClass
                
                __all__ = ['PublicClass', 'public_function']
                
                def public_function():
                    return "public"
                
                def _private_function():
                    return "private"
            """)
            )

            sub_py = package_dir / "submodule.py"
            sub_py.write_text(
                dedent("""
                class PublicClass:
                    '''Exported via __init__.py'''
                    def method(self):
                        return "method"
                
                class InternalClass:
                    '''Not exported, should be flagged'''
                    pass
            """)
            )

            test_py = project_path / "test_example.py"
            test_py.write_text(
                dedent("""
                import unittest
                from main import used_function
                
                class TestExample(unittest.TestCase):
                    def test_used_function(self):
                        result = used_function(3)
                        self.assertEqual(result, 6)
                    
                    def test_unused_method(self):
                        pass
            """)
            )

            yield project_path

    def test_basic_analysis(self, temp_project):
        """Test basic unused code detection"""
        result_json = skylos.analyze(
            str(temp_project), exclude_folders=list(DEFAULT_EXCLUDE_FOLDERS)
        )
        result = json.loads(result_json)

        assert "unused_functions" in result
        assert "unused_imports" in result
        assert "unused_variables" in result
        assert "unused_parameters" in result
        assert "unused_classes" in result

        assert len(result["unused_functions"]) > 0
        assert len(result["unused_imports"]) > 0

        unused_function_names = [f["name"] for f in result["unused_functions"]]
        assert "unused_function" in unused_function_names

        assert "used_function" not in unused_function_names
        assert "main" not in unused_function_names

    def test_unused_imports_detection(self, temp_project):
        """Test detection of unused imports"""
        result_json = skylos.analyze(str(temp_project))
        result = json.loads(result_json)

        unused_imports = result["unused_imports"]
        import_names = [imp["name"] for imp in unused_imports]

        assert any("os" in name for name in import_names)
        assert any("typing.List" in name or "List" in name for name in import_names)

        used_imports = ["sys", "defaultdict"]
        for used_import in used_imports:
            assert not any(used_import in name for name in import_names)

    def test_class_detection(self, temp_project):
        """test detection of unused classes"""
        result_json = skylos.analyze(str(temp_project))
        result = json.loads(result_json)

        unused_classes = result["unused_classes"]
        class_names = [cls["name"] for cls in unused_classes]

        assert any("UnusedClass" in name for name in class_names), (
            f"UnusedClass not found in {class_names}"
        )

        used_classes_flagged = [name for name in class_names if "UsedClass" in name]
        assert len(used_classes_flagged) == 0, (
            f"UsedClass was incorrectly flagged as unused: {used_classes_flagged}"
        )

        # publicclass should not be flagged because it's exported via __init__.py
        public_classes_flagged = [name for name in class_names if "PublicClass" in name]
        assert len(public_classes_flagged) == 0, (
            f"PublicClass was incorrectly flagged as unused: {public_classes_flagged}"
        )

    def test_exclude_folders(self, temp_project):
        result1 = skylos.analyze(str(temp_project))

        # exclude the mypackage folder
        result2 = skylos.analyze(str(temp_project), exclude_folders=["mypackage"])

        # it'll find fewer items when excluding a folder
        data1 = json.loads(result1)
        data2 = json.loads(result2)

        total1 = sum(len(items) for items in data1.values() if isinstance(items, list))
        total2 = sum(len(items) for items in data2.values() if isinstance(items, list))

        assert total2 <= total1

    def test_custom_exclude_folders(self, temp_project):
        custom_dir = temp_project / "custom_exclude"
        custom_dir.mkdir()

        custom_file = custom_dir / "custom.py"
        custom_file.write_text(
            dedent("""
            def custom_function():
                return "should be excluded"
        """)
        )

        result_json = skylos.analyze(
            str(temp_project), exclude_folders=["custom_exclude"]
        )
        result = json.loads(result_json)

        all_files = []
        for category in [
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
        ]:
            for item in result[category]:
                all_files.append(item["file"])

        excluded_files = [f for f in all_files if "custom_exclude" in f]
        assert len(excluded_files) == 0, f"Found excluded files: {excluded_files}"

    def test_magic_methods_excluded(self, temp_project):
        magic_py = temp_project / "magic.py"
        magic_py.write_text(
            dedent("""
            class MagicClass:
                def __init__(self):
                    self.value = 0
                
                def __str__(self):
                    return str(self.value)
                
                def __len__(self):
                    return self.value
                
                def regular_method(self):
                    return "regular"
        """)
        )

        result_json = skylos.analyze(str(temp_project))
        result = json.loads(result_json)

        unused_functions = result["unused_functions"]
        function_names = [f["name"] for f in unused_functions]

        magic_methods = ["__init__", "__str__", "__len__"]
        for magic_method in magic_methods:
            assert not any(magic_method in name for name in function_names)

    def test_test_methods_excluded(self, temp_project):
        """Test that test methods are not flagged as unused"""
        result_json = skylos.analyze(str(temp_project))
        result = json.loads(result_json)

        unused_functions = result["unused_functions"]
        function_names = [f["name"] for f in unused_functions]

        test_methods = ["test_used_function", "test_unused_method"]
        for test_method in test_methods:
            assert not any(test_method in name for name in function_names)

    def test_exported_functions_excluded(self, temp_project):
        result_json = skylos.analyze(str(temp_project))
        result = json.loads(result_json)

        unused_functions = result["unused_functions"]
        function_names = [f["name"] for f in unused_functions]

        assert not any("public_function" in name for name in function_names)

    def test_single_file_analysis(self, temp_project):
        main_file = temp_project / "main.py"

        result_json = skylos.analyze(str(main_file))
        result = json.loads(result_json)

        # should still detect unused items in the single file
        assert len(result["unused_functions"]) > 0
        assert len(result["unused_imports"]) > 0

        all_files = set()
        for category in ["unused_functions", "unused_imports", "unused_variables"]:
            for item in result[category]:
                all_files.add(Path(item["file"]).name)

        assert "main.py" in all_files
        assert "utils.py" not in all_files

    def test_confidence_levels(self, temp_project):
        result_json = skylos.analyze(str(temp_project))
        result = json.loads(result_json)

        for category in ["unused_functions", "unused_imports", "unused_variables"]:
            for item in result[category]:
                assert "confidence" in item
                assert isinstance(item["confidence"], (int, float))
                assert 0 <= item["confidence"] <= 100

    def test_analyzer_class_direct(self, temp_project):
        analyzer = Skylos()
        result_json = analyzer.analyze(str(temp_project), thr=50)
        result = json.loads(result_json)

        expected_keys = [
            "unused_functions",
            "unused_imports",
            "unused_classes",
            "unused_variables",
            "unused_parameters",
            "analysis_summary",
        ]

        for key in expected_keys:
            assert key in result

    def test_empty_project(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result_json = skylos.analyze(temp_dir)
            result = json.loads(result_json)

            assert result["unused_functions"] == []
            assert result["unused_imports"] == []
            assert result["analysis_summary"]["total_files"] == 0

    def test_threshold_filtering(self, temp_project):
        """Test that confidence threshold filtering works"""
        # high threshold = find fewer items
        result_high = json.loads(skylos.analyze(str(temp_project), conf=95))

        # low threshold = should find more items
        result_low = json.loads(skylos.analyze(str(temp_project), conf=10))

        assert len(result_high["unused_functions"]) <= len(
            result_low["unused_functions"]
        )
        assert len(result_high["unused_imports"]) <= len(result_low["unused_imports"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
