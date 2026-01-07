import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from collections import defaultdict
from skylos.visitors.test_aware import TestAwareVisitor
from skylos.visitors.framework_aware import FrameworkAwareVisitor

from skylos.analyzer import Skylos, proc_file, analyze


@pytest.fixture
def mock_definition():
    def _create_mock_def(
        name,
        simple_name,
        type,
        references=0,
        is_exported=False,
        confidence=100,
        in_init=False,
        line=1,
    ):
        mock = Mock()
        mock.name = name
        mock.simple_name = simple_name
        mock.type = type
        mock.references = references
        mock.is_exported = is_exported
        mock.confidence = confidence
        mock.in_init = in_init
        mock.line = line
        mock.filename = Path("test.py")
        mock.skip_reason = None
        mock.to_dict.return_value = {
            "name": name,
            "type": type,
            "file": "test.py",
            "line": line,
        }
        return mock

    return _create_mock_def


@pytest.fixture
def mock_test_aware_visitor():
    mock = Mock(spec=TestAwareVisitor)
    mock.is_test_file = False
    mock.test_decorated_lines = set()
    return mock


@pytest.fixture
def mock_framework_aware_visitor():
    mock = Mock(spec=FrameworkAwareVisitor)
    mock.framework_decorated_lines = set()
    return mock


@pytest.fixture
def temp_python_project():
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

        yield temp_path


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

    @patch("skylos.analyzer.Path")
    def test_get_python_files_single_file(self, mock_path, skylos):
        mock_file = Mock()
        mock_file.is_file.return_value = True
        mock_file.parent = Path("/project")
        mock_path.return_value.resolve.return_value = mock_file

        files, root = skylos._get_python_files("/project/test.py")
        assert files == [mock_file]
        assert root == Path("/project")

    @patch("skylos.analyzer.Path")
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
            "module._private_function": mock_def2,
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
            "other_module.imported_func": mock_original,
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
            name="MyClass", simple_name="MyClass", type="class", references=1
        )

        mock_init = mock_definition(
            name="MyClass.__init__", simple_name="__init__", type="method", references=0
        )

        mock_enter = mock_definition(
            name="MyClass.__enter__",
            simple_name="__enter__",
            type="method",
            references=0,
        )

        skylos.defs = {
            "MyClass": mock_class,
            "MyClass.__init__": mock_init,
            "MyClass.__enter__": mock_enter,
        }

        return skylos, mock_class, mock_init, mock_enter

    def test_auto_called_methods_get_references(self, skylos_with_class_methods):
        """auto-called methods get reference counts when class is used."""
        skylos, _, mock_init, mock_enter = skylos_with_class_methods

        skylos._apply_heuristics()

        assert mock_init.references == 1
        assert mock_enter.references == 1


class TestAnalyze:
    @patch("skylos.analyzer.proc_file")
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
            "line": 1,
        }

        mock_def.line = 1
        mock_def.filename = "test.py"
        mock_def.simple_name = "unused_function"
        mock_def.in_init = False
        mock_def.skip_reason = None
        mock_def.filename = Path("test.py")

        mock_test_visitor = Mock(spec=TestAwareVisitor)
        mock_test_visitor.is_test_file = False
        mock_test_visitor.test_decorated_lines = set()

        mock_framework_visitor = Mock(spec=FrameworkAwareVisitor)
        mock_framework_visitor.framework_decorated_lines = set()
        mock_framework_visitor.is_framework_file = False

        mock_proc_file.return_value = (
            [mock_def],
            [],
            set(),
            set(),
            mock_test_visitor,
            mock_framework_visitor,
            [],
            [],
            [],
            None,
            None,
            None,
        )

        result_json = analyze(str(temp_python_project), conf=60)
        result = json.loads(result_json)

        assert "unused_functions" in result
        assert "unused_imports" in result
        assert "unused_classes" in result
        assert "unused_variables" in result
        assert "unused_parameters" in result
        assert "unused_files" in result
        assert "analysis_summary" in result

    def test_analyze_with_exclusions(self, temp_python_project):
        """analyze with folder exclusions."""
        exclude_dir = temp_python_project / "build"
        exclude_dir.mkdir()
        exclude_file = exclude_dir / "generated.py"
        exclude_file.write_text("def generated_function(): pass")

        result_json = analyze(str(temp_python_project), exclude_folders=["build"])
        result = json.loads(result_json)

        assert result["analysis_summary"]["excluded_folders"] == ["build"]

    def test_analyze_empty_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result_json = analyze(temp_dir, conf=60)
            result = json.loads(result_json)

            assert result["analysis_summary"]["total_files"] == 0
            assert all(
                len(result[key]) == 0
                for key in [
                    "unused_functions",
                    "unused_imports",
                    "unused_classes",
                    "unused_variables",
                    "unused_parameters",
                ]
            )

    def test_confidence_threshold_filtering(self, mock_definition):
        """confidence threshold properly filters results."""
        skylos = Skylos()

        high_conf = mock_definition(
            name="high_conf",
            simple_name="high_conf",
            type="function",
            references=0,
            is_exported=False,
            confidence=80,
        )

        low_conf = mock_definition(
            name="low_conf",
            simple_name="low_conf",
            type="function",
            references=0,
            is_exported=False,
            confidence=40,
        )

        skylos.defs = {"high_conf": high_conf, "low_conf": low_conf}

        with patch.object(skylos, "_get_python_files") as mock_get_files:
            mock_get_files.return_value = ([Path("/fake/file.py")], Path("/"))

            with patch("skylos.analyzer.proc_file") as mock_proc_file:
                mock_proc_file.return_value = (
                    [],
                    [],
                    set(),
                    set(),
                    Mock(spec=TestAwareVisitor),
                    Mock(spec=FrameworkAwareVisitor),
                    [],
                    [],
                    [],
                    None,
                    None,
                    None,
                )

                result_json = skylos.analyze("/fake/path", thr=60)
                result = json.loads(result_json)

                # include only high confidence
                assert len(result["unused_functions"]) == 1
                assert result["unused_functions"][0]["name"] == "high_conf"


class TestProcFile:
    def test_proc_file_with_valid_python(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
def test_function():
    pass

class TestClass:
    def method(self):
        pass
""")
            f.flush()

            try:
                with (
                    patch("skylos.analyzer.Visitor") as mock_visitor_class,
                    patch(
                        "skylos.analyzer.TestAwareVisitor"
                    ) as mock_test_visitor_class,
                    patch(
                        "skylos.analyzer.FrameworkAwareVisitor"
                    ) as mock_framework_visitor_class,
                ):
                    mock_visitor = Mock()
                    mock_visitor.defs = []
                    mock_visitor.refs = []
                    mock_visitor.dyn = set()
                    mock_visitor.exports = set()
                    mock_visitor.pattern_tracker = None
                    mock_visitor_class.return_value = mock_visitor

                    mock_test_visitor = Mock(spec=TestAwareVisitor)
                    mock_test_visitor_class.return_value = mock_test_visitor

                    mock_framework_visitor = Mock(spec=FrameworkAwareVisitor)
                    mock_framework_visitor_class.return_value = mock_framework_visitor

                    (
                        defs,
                        refs,
                        dyn,
                        exports,
                        test_flags,
                        framework_flags,
                        quality_findings,
                        danger_findings,
                        pro_findings,
                        pattern_tracker,
                        empty_file_finding,
                        cfg,
                    ) = proc_file(f.name, "test_module")

                    mock_visitor_class.assert_called_once_with("test_module", f.name)
                    mock_visitor.visit.assert_called_once()

                    assert defs == []
                    assert refs == []
                    assert dyn == set()
                    assert exports == set()
                    assert test_flags == mock_test_visitor
                    assert framework_flags == mock_framework_visitor
                    assert quality_findings == []
                    assert danger_findings == []
                    assert pro_findings == []
                    assert pattern_tracker is None
                    assert empty_file_finding is None
            finally:
                Path(f.name).unlink()

    def test_proc_file_with_invalid_python(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("def invalid_syntax(:\npass")
            f.flush()

            try:
                (
                    defs,
                    refs,
                    dyn,
                    exports,
                    test_flags,
                    framework_flags,
                    quality_findings,
                    danger_findings,
                    pro_findings,
                    pattern_tracker,
                    empty_file_finding,
                    cfg,
                ) = proc_file(f.name, "test_module")

                assert defs == []
                assert refs == []
                assert dyn == set()
                assert exports == set()
                assert isinstance(test_flags, TestAwareVisitor)
                assert isinstance(framework_flags, FrameworkAwareVisitor)
                assert quality_findings == []
                assert danger_findings == []
                assert pro_findings == []
                assert pattern_tracker is None
                assert empty_file_finding is None
                assert isinstance(test_flags, TestAwareVisitor)
                assert isinstance(framework_flags, FrameworkAwareVisitor)
            finally:
                Path(f.name).unlink()

    def test_proc_file_with_tuple_args(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("def test(): pass")
            f.flush()

            try:
                with (
                    patch("skylos.analyzer.Visitor") as mock_visitor_class,
                    patch(
                        "skylos.analyzer.TestAwareVisitor"
                    ) as mock_test_visitor_class,
                    patch(
                        "skylos.analyzer.FrameworkAwareVisitor"
                    ) as mock_framework_visitor_class,
                ):
                    mock_visitor = Mock()
                    mock_visitor.defs = []
                    mock_visitor.refs = []
                    mock_visitor.dyn = set()
                    mock_visitor.exports = set()
                    mock_visitor.pattern_tracker = None
                    mock_visitor_class.return_value = mock_visitor

                    mock_test_visitor = Mock(spec=TestAwareVisitor)
                    mock_test_visitor_class.return_value = mock_test_visitor

                    mock_framework_visitor = Mock(spec=FrameworkAwareVisitor)
                    mock_framework_visitor_class.return_value = mock_framework_visitor

                    (
                        defs,
                        refs,
                        dyn,
                        exports,
                        test_flags,
                        framework_flags,
                        quality_findings,
                        danger_findings,
                        pro_findings,
                        pattern_tracker,
                        empty_file_finding,
                        cfg,
                    ) = proc_file((f.name, "test_module"))

                    mock_visitor_class.assert_called_once_with("test_module", f.name)
            finally:
                Path(f.name).unlink()

    def test_empty_file_reporting(self, tmp_path):
        # should be reported
        empty = tmp_path / "empty_module.py"
        empty.write_text("")

        # should be skipped
        (tmp_path / "main.py").write_text("")  # skip main.py
        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        # skip __init__.py
        (pkg / "__init__.py").write_text('"""package init docstring"""')

        result_json = analyze(str(tmp_path), conf=0)
        result = json.loads(result_json)

        assert "unused_files" in result
        files = result["unused_files"]

        flagged = {Path(f["file"]).name for f in files}
        assert "empty_module.py" in flagged
        assert "main.py" not in flagged
        assert "__init__.py" not in flagged

        item = next(f for f in files if Path(f["file"]).name == "empty_module.py")
        assert item["rule_id"] == "SKY-E002"
        assert item["category"] == "DEAD_CODE"
        assert item["severity"] == "LOW"


class TestApplyPenalties:
    @patch("skylos.analyzer.detect_framework_usage")
    def test_private_name_penalty(
        self,
        mock_detect_framework,
        mock_definition,
        mock_test_aware_visitor,
        mock_framework_aware_visitor,
    ):
        """private names get penalized."""
        mock_detect_framework.return_value = (
            None  # or whatever confidence value here that can change later on
        )

        skylos = Skylos()
        mock_def = mock_definition(
            name="_private_func",
            simple_name="_private_func",
            type="function",
            confidence=100,
        )

        skylos._apply_penalties(
            mock_def, mock_test_aware_visitor, mock_framework_aware_visitor
        )
        assert mock_def.confidence < 100

    @patch("skylos.analyzer.detect_framework_usage")
    def test_magic_methods_confidence_zero(
        self,
        mock_detect_framework,
        mock_definition,
        mock_test_aware_visitor,
        mock_framework_aware_visitor,
    ):
        """magic methods get confidence of 0."""
        mock_detect_framework.return_value = None
        skylos = Skylos()
        mock_def = mock_definition(
            name="MyClass.__str__", simple_name="__str__", type="method", confidence=100
        )

        skylos._apply_penalties(
            mock_def, mock_test_aware_visitor, mock_framework_aware_visitor
        )
        assert mock_def.confidence == 0

    @patch("skylos.analyzer.detect_framework_usage")
    def test_self_cls_parameters_confidence_zero(
        self,
        mock_detect_framework,
        mock_definition,
        mock_test_aware_visitor,
        mock_framework_aware_visitor,
    ):
        mock_detect_framework.return_value = None
        skylos = Skylos()

        mock_self = mock_definition(
            name="MyClass.method.self",
            simple_name="self",
            type="parameter",
            confidence=100,
        )

        mock_cls = mock_definition(
            name="MyClass.classmethod.cls",
            simple_name="cls",
            type="parameter",
            confidence=100,
        )

        skylos._apply_penalties(
            mock_self, mock_test_aware_visitor, mock_framework_aware_visitor
        )
        skylos._apply_penalties(
            mock_cls, mock_test_aware_visitor, mock_framework_aware_visitor
        )

        assert mock_self.confidence == 0
        assert mock_cls.confidence == 0

    @patch("skylos.analyzer.detect_framework_usage")
    def test_test_methods_confidence_zero(
        self, mock_detect_framework, mock_definition, mock_framework_aware_visitor
    ):
        """test methods get confidence of 0"""
        mock_detect_framework.return_value = None

        skylos = Skylos()

        test_visitor = Mock(spec=TestAwareVisitor)
        test_visitor.is_test_file = True
        test_visitor.test_decorated_lines = set()

        mock_def = mock_definition(
            name="TestMyClass.test_something",
            simple_name="test_something",
            type="method",
            confidence=100,
        )

        skylos._apply_penalties(mock_def, test_visitor, mock_framework_aware_visitor)
        assert mock_def.confidence == 0

    @patch("skylos.analyzer.detect_framework_usage")
    def test_underscore_variable_confidence_zero(
        self,
        mock_detect_framework,
        mock_definition,
        mock_test_aware_visitor,
        mock_framework_aware_visitor,
    ):
        """underscore variables get confidence of 0."""
        mock_detect_framework.return_value = None

        skylos = Skylos()

        mock_def = mock_definition(
            name="_", simple_name="_", type="variable", confidence=100
        )

        skylos._apply_penalties(
            mock_def, mock_test_aware_visitor, mock_framework_aware_visitor
        )
        assert mock_def.confidence == 0


class TestIgnorePragmas:
    def test_analyze_respects_ignore_pragmas(self, tmp_path):
        src = tmp_path / "demo.py"
        src.write_text(
            """
def used():
    pass

def unused_no_ignore():
    pass

def unused_ignore():   # pragma: no skylos
    pass

used()
"""
        )

        result_json = analyze(str(tmp_path), conf=0)
        result = json.loads(result_json)

        # collect names of functions flagged as unreachable
        unreachable = {
            item["name"].split(".")[-1] for item in result["unused_functions"]
        }

        # expectations
        assert "unused_no_ignore" in unreachable
        assert "unused_ignore" not in unreachable
        assert "used" not in unreachable


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
