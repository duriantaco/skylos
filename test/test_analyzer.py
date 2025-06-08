#!/usr/bin/env python3
import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from collections import defaultdict

try:
    from skylos.analyzer import (
        Skylos, 
        parse_exclude_folders, 
        proc_file, 
        analyze,
        DEFAULT_EXCLUDE_FOLDERS,
        AUTO_CALLED,
        MAGIC_METHODS,
        TEST_METHOD_PATTERN
    )
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from skylos.analyzer import (
        Skylos, 
        parse_exclude_folders, 
        proc_file, 
        analyze,
        DEFAULT_EXCLUDE_FOLDERS,
        AUTO_CALLED,
        MAGIC_METHODS,
        TEST_METHOD_PATTERN
    )

class TestParseExcludeFolders:
    
    def test_default_exclude_folders_included(self):
        """default folders are included by default."""
        result = parse_exclude_folders(None, use_defaults=True)
        assert DEFAULT_EXCLUDE_FOLDERS.issubset(result)
    
    def test_default_exclude_folders_disabled(self):
        """default folders can be disabled."""
        result = parse_exclude_folders(None, use_defaults=False)
        assert not DEFAULT_EXCLUDE_FOLDERS.intersection(result)
    
    def test_user_exclude_folders_added(self):
        """user-specified folders are added."""
        user_folders = {"custom_folder", "another_folder"}
        result = parse_exclude_folders(user_folders, use_defaults=True)
        assert user_folders.issubset(result)
        assert DEFAULT_EXCLUDE_FOLDERS.issubset(result)
    
    def test_include_folders_override_defaults(self):
        """include_folders can override defaults."""
        include_folders = {"__pycache__", ".git"}
        result = parse_exclude_folders(None, use_defaults=True, include_folders=include_folders)
        for folder in include_folders:
            assert folder not in result
    
    def test_include_folders_override_user_excludes(self):
        """include_folders can override user excludes."""
        user_excludes = {"custom_folder", "another_folder"}
        include_folders = {"custom_folder"}
        result = parse_exclude_folders(user_excludes, use_defaults=False, include_folders=include_folders)
        assert "custom_folder" not in result
        assert "another_folder" in result


class TestSkylos:
    
    @pytest.fixture
    def skylos(self):
        return Skylos()
    
    def test_init(self, skylos):
        assert skylos.defs == {}
        assert skylos.refs == []
        assert skylos.dynamic == set()
        assert isinstance(skylos.exports, defaultdict)
    
    def test_module_name_generation(self, skylos):
        """Test module name generation from file paths."""
        root = Path("/project")
        
        # test a regular Python file
        file_path = Path("/project/src/module.py")
        result = skylos._module(root, file_path)
        assert result == "src.module"
        
        # test __init__.py file
        file_path = Path("/project/src/__init__.py")
        result = skylos._module(root, file_path)
        assert result == "src"
        
        # nested module
        file_path = Path("/project/src/package/submodule.py")
        result = skylos._module(root, file_path)
        assert result == "src.package.submodule"
        
        # root level file
        file_path = Path("/project/main.py")
        result = skylos._module(root, file_path)
        assert result == "main"
    
    def test_should_exclude_file(self, skylos):
        """
        should exclude pycache, build, egg-info and whatever is in exclude_folders
        """
        root = Path("/project")
        exclude_folders = {"__pycache__", "build", "*.egg-info"}
        
        file_path = Path("/project/src/__pycache__/module.pyc")
        assert skylos._should_exclude_file(file_path, root, exclude_folders)
        
        file_path = Path("/project/build/lib/module.py")
        assert skylos._should_exclude_file(file_path, root, exclude_folders)
        
        file_path = Path("/project/mypackage.egg-info/PKG-INFO")
        assert skylos._should_exclude_file(file_path, root, exclude_folders)
        
        file_path = Path("/project/src/module.py")
        assert not skylos._should_exclude_file(file_path, root, exclude_folders)
        
        assert not skylos._should_exclude_file(file_path, root, None)
    
    @patch('skylos.analyzer.Path')
    def test_get_python_files_single_file(self, mock_path, skylos):
        mock_file = Mock()
        mock_file.is_file.return_value = True
        mock_file.parent = Path("/project")
        mock_path.return_value.resolve.return_value = mock_file
        
        files, root = skylos._get_python_files("/project/test.py")
        assert files == [mock_file]
        assert root == Path("/project")
    
    @patch('skylos.analyzer.Path')
    def test_get_python_files_directory(self, mock_path, skylos):
        mock_dir = Mock()
        mock_dir.is_file.return_value = False
        mock_files = [Path("/project/file1.py"), Path("/project/file2.py")]
        mock_dir.glob.return_value = mock_files
        mock_path.return_value.resolve.return_value = mock_dir
        
        files, root = skylos._get_python_files("/project")
        assert files == mock_files
        assert root == mock_dir
    
    def test_mark_exports_in_init(self, skylos):
        mock_def1 = Mock()
        mock_def1.in_init = True
        mock_def1.simple_name = "public_function"
        mock_def1.is_exported = False
        
        mock_def2 = Mock()
        mock_def2.in_init = True
        mock_def2.simple_name = "_private_function"
        mock_def2.is_exported = False
        
        skylos.defs = {
            "module.public_function": mock_def1,
            "module._private_function": mock_def2
        }
        
        skylos._mark_exports()
        
        assert mock_def1.is_exported == True
        assert mock_def2.is_exported == False
    
    def test_mark_exports_explicit_exports(self, skylos):
        mock_def = Mock()
        mock_def.simple_name = "my_function"
        mock_def.type = "function"
        mock_def.is_exported = False
        
        skylos.defs = {"module.my_function": mock_def}
        skylos.exports = {"module": {"my_function"}}
        
        skylos._mark_exports()
        
        assert mock_def.is_exported == True
    
    def test_mark_refs_direct_reference(self, skylos):
        mock_def = Mock()
        mock_def.references = 0
        
        skylos.defs = {"module.function": mock_def}
        skylos.refs = [("module.function", None)]
        
        skylos._mark_refs()
        
        assert mock_def.references == 1
    
    def test_mark_refs_import_reference(self, skylos):
        mock_import = Mock()
        mock_import.type = "import"
        mock_import.simple_name = "imported_func"
        mock_import.references = 0
        
        mock_original = Mock()
        mock_original.type = "function"
        mock_original.simple_name = "imported_func"
        mock_original.references = 0
        
        skylos.defs = {
            "module.imported_func": mock_import,
            "other_module.imported_func": mock_original
        }
        skylos.refs = [("module.imported_func", None)]
        
        skylos._mark_refs()
        
        assert mock_import.references == 1
        assert mock_original.references == 1


class TestHeuristics:
    
    @pytest.fixture
    def skylos_with_class_methods(self, mock_definition):
        skylos = Skylos()
        
        mock_class = mock_definition(
            name="MyClass", 
            simple_name="MyClass", 
            type="class", 
            references=1
        )
        
        mock_init = mock_definition(
            name="MyClass.__init__",
            simple_name="__init__",
            type="method",
            references=0
        )
        
        mock_enter = mock_definition(
            name="MyClass.__enter__",
            simple_name="__enter__",
            type="method",
            references=0
        )
        
        skylos.defs = {
            "MyClass": mock_class,
            "MyClass.__init__": mock_init,
            "MyClass.__enter__": mock_enter
        }
        
        return skylos, mock_class, mock_init, mock_enter
    
    def test_auto_called_methods_get_references(self, skylos_with_class_methods):
        """auto-called methods get reference counts when class is used."""
        skylos, mock_class, mock_init, mock_enter = skylos_with_class_methods
        
        skylos._apply_heuristics()
        
        assert mock_init.references == 1
        assert mock_enter.references == 1
    
    def test_magic_methods_confidence_zero(self, mock_definition):
        """magic methods get confidence of 0."""
        skylos = Skylos()
        
        mock_magic = mock_definition(
            name="MyClass.__str__",
            simple_name="__str__",
            type="method",
            confidence=100
        )
        
        skylos.defs = {"MyClass.__str__": mock_magic}
        skylos._apply_heuristics()
        
        assert mock_magic.confidence == 0
    
    def test_self_cls_parameters_confidence_zero(self, mock_definition):
        """self/cls parameters get confidence of 0"""
        skylos = Skylos()
        
        mock_self = mock_definition(
            name="self",
            simple_name="self",
            type="parameter",
            confidence=100
        )
        
        mock_cls = mock_definition(
            name="cls",
            simple_name="cls",
            type="parameter",
            confidence=100
        )
        
        skylos.defs = {"self": mock_self, "cls": mock_cls}
        skylos._apply_heuristics()
        
        assert mock_self.confidence == 0
        assert mock_cls.confidence == 0
    
    def test_test_methods_confidence_zero(self, mock_definition):
        """test methods in test classes get confidence of 0"""
        skylos = Skylos()
        
        mock_test_method = mock_definition(
            name="TestMyClass.test_something",
            simple_name="test_something",
            type="method",
            confidence=100
        )
        
        skylos.defs = {"TestMyClass.test_something": mock_test_method}
        skylos._apply_heuristics()
        
        assert mock_test_method.confidence == 0
    
    def test_underscore_variable_confidence_zero(self, mock_definition):
        """underscore variables get confidence of 0."""
        skylos = Skylos()
        
        mock_underscore = mock_definition(
            name="_",
            simple_name="_",
            type="variable",
            confidence=100
        )
        
        skylos.defs = {"_": mock_underscore}
        skylos._apply_heuristics()
        
        assert mock_underscore.confidence == 0


class TestAnalyze:
    
    @pytest.fixture
    def temp_python_project(self):
        """Create a temp Python project for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            main_py = temp_path / "main.py"
            main_py.write_text("""
def used_function():
    return "used"

def unused_function():
    return "unused"

class UsedClass:
    def method(self):
        pass

class UnusedClass:
    def method(self):
        pass

result = used_function()
instance = UsedClass()
""")
            
            package_dir = temp_path / "mypackage"
            package_dir.mkdir()
            
            init_py = package_dir / "__init__.py"
            init_py.write_text("""
from .module import exported_function

def internal_function():
    pass
""")
            
            module_py = package_dir / "module.py"
            module_py.write_text("""
def exported_function():
    return "exported"

def internal_function():
    return "internal"
""")
            
            test_dir = temp_path / "__pycache__"
            test_dir.mkdir()
            
            test_file = test_dir / "cached.pyc"
            test_file.write_text("# This should be excluded")
            
            yield temp_path
    
    @patch('skylos.analyzer.proc_file')
    def test_analyze_basic(self, mock_proc_file, temp_python_project):
        mock_def = Mock()
        mock_def.name = "test.unused_function"
        mock_def.references = 0
        mock_def.is_exported = False
        mock_def.confidence = 80
        mock_def.type = "function"
        mock_def.to_dict.return_value = {
            "name": "test.unused_function",
            "type": "function",
            "file": "test.py",
            "line": 1
        }
        
        mock_proc_file.return_value = ([mock_def], [], set(), set())
        
        result_json = analyze(str(temp_python_project), conf=60)
        result = json.loads(result_json)
        
        assert "unused_functions" in result
        assert "unused_imports" in result
        assert "unused_classes" in result
        assert "unused_variables" in result
        assert "unused_parameters" in result
        assert "analysis_summary" in result
    
    def test_analyze_with_exclusions(self, temp_python_project):
        """analyze with folder exclusions."""
        exclude_dir = temp_python_project / "build"
        exclude_dir.mkdir()
        exclude_file = exclude_dir / "generated.py"
        exclude_file.write_text("def generated_function(): pass")
        
        result_json = analyze(str(temp_python_project), exclude_folders=["build"])  # Use list instead of set
        result = json.loads(result_json)
        
        assert result["analysis_summary"]["excluded_folders"] == ["build"]
    
    def test_analyze_empty_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result_json = analyze(temp_dir, conf=60)
            result = json.loads(result_json)
            
            assert result["analysis_summary"]["total_files"] == 0
            assert all(len(result[key]) == 0 for key in [
                "unused_functions", "unused_imports", "unused_classes",
                "unused_variables", "unused_parameters"
            ])
    
    def test_confidence_threshold_filtering(self, mock_definition):
        """confidence threshold properly filters results."""
        skylos = Skylos()
        
        high_conf = mock_definition(
            name="high_conf",
            simple_name="high_conf",
            type="function",
            references=0,
            is_exported=False,
            confidence=80
        )
        
        low_conf = mock_definition(
            name="low_conf",
            simple_name="low_conf",
            type="function",
            references=0,
            is_exported=False,
            confidence=40
        )
        
        skylos.defs = {"high_conf": high_conf, "low_conf": low_conf}
        
        with patch.object(skylos, '_get_python_files') as mock_get_files:
            mock_get_files.return_value = ([Path("/fake/file.py")], Path("/"))
            
            with patch('skylos.analyzer.proc_file') as mock_proc_file:
                mock_proc_file.return_value = ([], [], set(), set())
                
                result_json = skylos.analyze("/fake/path", thr=60)
                result = json.loads(result_json)
                
                # include only high confidence 
                assert len(result["unused_functions"]) == 1
                assert result["unused_functions"][0]["name"] == "high_conf"


class TestProcFile:
    
    def test_proc_file_with_valid_python(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
def test_function():
    pass

class TestClass:
    def method(self):
        pass
""")
            f.flush()
            
            try:
                with patch('skylos.analyzer.Visitor') as mock_visitor_class:
                    mock_visitor = Mock()
                    mock_visitor.defs = []
                    mock_visitor.refs = []
                    mock_visitor.dyn = set()
                    mock_visitor.exports = set()
                    mock_visitor_class.return_value = mock_visitor
                    
                    defs, refs, dyn, exports = proc_file(f.name, "test_module")
                    
                    mock_visitor_class.assert_called_once_with("test_module", f.name)
                    mock_visitor.visit.assert_called_once()
                    
                    assert defs == []
                    assert refs == []
                    assert dyn == set()
                    assert exports == set()
            finally:
                Path(f.name).unlink()
    
    def test_proc_file_with_invalid_python(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def invalid_syntax(:\npass") 
            f.flush()
            
            try:
                defs, refs, dyn, exports = proc_file(f.name, "test_module")
                
                assert defs == []
                assert refs == []
                assert dyn == set()
                assert exports == set()
            finally:
                Path(f.name).unlink()
    
    def test_proc_file_with_tuple_args(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def test(): pass")
            f.flush()
            
            try:
                with patch('skylos.analyzer.Visitor') as mock_visitor_class:
                    mock_visitor = Mock()
                    mock_visitor.defs = []
                    mock_visitor.refs = []
                    mock_visitor.dyn = set()
                    mock_visitor.exports = set()
                    mock_visitor_class.return_value = mock_visitor
                    
                    defs, refs, dyn, exports = proc_file((f.name, "test_module"))
                    
                    mock_visitor_class.assert_called_once_with("test_module", f.name)
            finally:
                Path(f.name).unlink()


class TestConstants:
    
    def test_auto_called_contains_expected_methods(self):
        """ AUTO_CALLED contains expected magic methods."""
        assert "__init__" in AUTO_CALLED
        assert "__enter__" in AUTO_CALLED
        assert "__exit__" in AUTO_CALLED
    
    def test_magic_methods_contains_common_methods(self):
        """ MAGIC_METHODS contains common magic methods."""
        assert "__str__" in MAGIC_METHODS
        assert "__repr__" in MAGIC_METHODS
        assert "__eq__" in MAGIC_METHODS
        assert "__len__" in MAGIC_METHODS
    
    def test_test_method_pattern_matches_correctly(self):
        """ TEST_METHOD_PATTERN matches test methods correctly."""
        assert TEST_METHOD_PATTERN.match("test_something")
        assert TEST_METHOD_PATTERN.match("test_another_thing")
        assert TEST_METHOD_PATTERN.match("test_123")
        assert not TEST_METHOD_PATTERN.match("not_a_test")
        assert not TEST_METHOD_PATTERN.match("test")  # no underscore
        assert not TEST_METHOD_PATTERN.match("testing_something")  # doesnt start with test_
    
    def test_default_exclude_folders_contains_expected(self):
        """ DEFAULT_EXCLUDE_FOLDERS contains expected directories."""
        expected_folders = {
            "__pycache__", ".git", ".pytest_cache", ".mypy_cache",
            ".tox", "htmlcov", ".coverage", "build", "dist",
            "*.egg-info", "venv", ".venv"
        }
        assert expected_folders.issubset(DEFAULT_EXCLUDE_FOLDERS)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])