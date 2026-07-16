import pytest
import json
import tempfile
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch
from collections import defaultdict
from skylos.visitors.test_aware import TestAwareVisitor
from skylos.visitors.framework_aware import FrameworkAwareVisitor
from skylos.analysis.penalties import apply_penalties
from skylos.deadcode.config_entrypoints import configured_entrypoint_reason

from skylos.analyzer import (
    Skylos,
    proc_file,
    analyze,
    _architecture_iad_strict,
    _go_engine_analysis_report,
    _resolve_analysis_root,
)
from skylos.visitors.languages.shell import SHELL_SOURCE_EXTS


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
        mock.node = None
        mock.calls = []
        mock.called_by = []
        mock.complexity = 1
        mock.why_confidence_reduced = []
        mock.conditional_import = False
        mock.base_classes = []
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

        file_path = Path("/project/src/module.py")
        result = skylos._module(root, file_path)
        assert result == "module"

        file_path = Path("/project/src/__init__.py")
        result = skylos._module(root, file_path)
        assert result == ""

        file_path = Path("/project/src/package/submodule.py")
        result = skylos._module(root, file_path)
        assert result == "package.submodule"

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

    def test_trace_file_false_ignores_existing_project_root_trace(self, tmp_path):
        module = tmp_path / "app.py"
        module.write_text(
            "def root_traced():\n    return 1\n\ndef unused():\n    return 2\n",
            encoding="utf-8",
        )
        (tmp_path / ".skylos_trace").write_text(
            json.dumps(
                {
                    "version": 1,
                    "calls": [
                        {
                            "file": str(module),
                            "function": "root_traced",
                            "line": 1,
                            "count": 1,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = json.loads(
            analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
        )
        names = {item.get("name") for item in result.get("unused_functions", [])}

        assert "root_traced" in names
        assert "unused" in names

    def test_analysis_summary_includes_directory_rollups(self, tmp_path):
        source = tmp_path / "src" / "api" / "views.py"
        source.parent.mkdir(parents=True)
        source.write_text(
            "def used():\n"
            "    return 1\n\n"
            "def unused_handler():\n"
            "    return 2\n\n"
            "def very_long():\n"
            + "".join(f"    value_{i} = {i}\n" for i in range(55))
            + "    return value_0\n\n"
            "used()\n",
            encoding="utf-8",
        )

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_quality=True,
                grep_verify=False,
                trace_file=False,
            )
        )

        rollups = result["analysis_summary"]["by_directory"]
        api_rollup = next(item for item in rollups if item["path"] == "src/api")
        assert api_rollup["total"] >= 2
        assert api_rollup["files"] == 1
        assert api_rollup["dead_code"] >= 1
        assert api_rollup["quality"] >= 1
        assert api_rollup["rules"]["SKY-C304"] == 1

    @patch("skylos.analyzer.Path")
    def test_get_python_files_single_file(self, mock_path, skylos):
        mock_file = Mock()
        mock_file.is_file.return_value = True
        mock_file.parent = Path("/project")
        mock_path.return_value.resolve.return_value = mock_file

        files, root = skylos._get_python_files("/project/test.py")
        assert files == [mock_file]
        assert root == Path("/project")

    @patch("skylos.analyzer.discover_source_files")
    @patch("skylos.analyzer.Path")
    def test_get_python_files_directory(self, mock_path, mock_discover, skylos):
        mock_dir = Mock()
        mock_dir.is_file.return_value = False
        mock_files = [Path("/project/file1.py"), Path("/project/file2.py")]

        mock_path.return_value.resolve.return_value = mock_dir
        mock_discover.return_value = mock_files

        files, root = skylos._get_python_files("/project")

        mock_discover.assert_called_once_with(
            mock_dir,
            {
                ".py",
                ".pyi",
                ".pyw",
                ".go",
                ".ts",
                ".tsx",
                ".js",
                ".jsx",
                ".mts",
                ".cts",
                ".mjs",
                ".cjs",
                ".java",
                ".php",
                ".rs",
                ".dart",
                ".cs",
                ".kt",
                ".kts",
                *SHELL_SOURCE_EXTS,
            },
            exclude_folders=None,
        )
        assert files == mock_files
        assert root == mock_dir

    def test_get_python_files_fallback_honors_gitignore(
        self, skylos, tmp_path, monkeypatch
    ):
        if shutil.which("git") is None:
            pytest.skip("git is required for this test")

        project = tmp_path / "proj"
        ignored_dir = project / "customenv"
        kept_dir = project / "src"
        ignored_dir.mkdir(parents=True)
        kept_dir.mkdir(parents=True)
        (project / ".gitignore").write_text("customenv/\n", encoding="utf-8")
        (ignored_dir / "ghost.py").write_text(
            "def ghost():\n    pass\n", encoding="utf-8"
        )
        keep_file = kept_dir / "keep.py"
        keep_file.write_text("def keep():\n    return 1\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=project, check=True)

        monkeypatch.setattr("skylos.analyzer._fast_discover", None)

        files, root = skylos._get_python_files(project)

        assert root == project.resolve()
        assert files == [keep_file.resolve()]

    def test_get_python_files_fast_discovery_honors_nested_excludes(
        self, skylos, tmp_path, monkeypatch
    ):
        project = tmp_path / "proj"
        legacy_dir = project / "src" / "legacy"
        modern_dir = project / "src" / "modern"
        legacy_dir.mkdir(parents=True)
        modern_dir.mkdir(parents=True)
        legacy_file = legacy_dir / "old.py"
        legacy_file.write_text("def old_dead():\n    pass\n", encoding="utf-8")
        keep_file = modern_dir / "keep.py"
        keep_file.write_text("def keep():\n    return 1\n", encoding="utf-8")

        def fake_fast_discover(root, extensions, excludes):
            return [str(legacy_file), str(keep_file)]

        monkeypatch.setattr("skylos.analyzer._fast_discover", fake_fast_discover)

        files, root = skylos._get_python_files(project, exclude_folders=["src/legacy"])

        assert root == project.resolve()
        assert files == [keep_file]

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

        assert mock_def1.is_exported
        assert not mock_def2.is_exported

    def test_mark_exports_explicit_exports(self, skylos):
        mock_def = Mock()
        mock_def.simple_name = "my_function"
        mock_def.type = "function"
        mock_def.is_exported = False
        mock_def.references = 0

        skylos.defs = {"module.my_function": mock_def}
        skylos.exports = {"module": {"my_function"}}

        skylos._mark_exports()

        assert mock_def.is_exported

    def test_mark_refs_direct_reference(self, skylos):
        mock_def = Mock()
        mock_def.type = "function"
        mock_def.simple_name = "function"
        mock_def.name = "module.function"
        mock_def.references = 0

        skylos.defs = {"module.function": mock_def}
        skylos.refs = [("module.function", None)]

        skylos._mark_refs()

        assert mock_def.references == 1

    def test_mark_refs_import_reference(self, skylos):
        mock_import = Mock()
        mock_import.type = "import"
        mock_import.simple_name = "imported_func"
        mock_import.name = "other_module.imported_func"
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
        assert mock_original.references == 2


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

    def test_visitor_alias_hooks_get_references(self, mock_definition):
        """class-level NodeVisitor aliases are dispatch hooks, not dead variables."""
        skylos = Skylos()
        mock_class = mock_definition(
            name="ScopeCollector",
            simple_name="ScopeCollector",
            type="class",
            references=1,
        )
        mock_alias = mock_definition(
            name="ScopeCollector._collect_scope_info.visit_AsyncFor",
            simple_name="visit_AsyncFor",
            type="variable",
            references=0,
        )
        mock_method = mock_definition(
            name="ScopeCollector._collect_scope_info.visit_Import",
            simple_name="visit_Import",
            type="method",
            references=0,
        )
        skylos.defs = {
            "ScopeCollector": mock_class,
            "ScopeCollector._collect_scope_info.visit_AsyncFor": mock_alias,
            "ScopeCollector._collect_scope_info.visit_Import": mock_method,
        }

        skylos._apply_heuristics()

        assert mock_alias.references == 1
        assert mock_method.references == 1

    def test_http_handler_metadata_gets_references(self, mock_definition):
        """BaseHTTPRequestHandler reads metadata attributes dynamically."""
        skylos = Skylos()
        mock_class = mock_definition(
            name="AgentServiceHandler",
            simple_name="AgentServiceHandler",
            type="class",
            references=0,
        )
        mock_class.base_classes = ["http.server.BaseHTTPRequestHandler"]
        mock_variable = mock_definition(
            name="AgentServiceHandler.server_version",
            simple_name="server_version",
            type="variable",
            references=0,
        )
        skylos.defs = {
            "AgentServiceHandler": mock_class,
            "AgentServiceHandler.server_version": mock_variable,
        }

        skylos._apply_heuristics()

        assert mock_variable.references == 1

    def test_http_handler_override_methods_get_references(self, mock_definition):
        """SimpleHTTPRequestHandler calls override methods dynamically."""
        skylos = Skylos()
        mock_class = mock_definition(
            name="NoCacheHandler",
            simple_name="NoCacheHandler",
            type="class",
            references=0,
        )
        mock_class.base_classes = ["http.server.SimpleHTTPRequestHandler"]
        mock_method = mock_definition(
            name="NoCacheHandler.log_message",
            simple_name="log_message",
            type="method",
            references=0,
        )
        skylos.defs = {
            "NoCacheHandler": mock_class,
            "NoCacheHandler.log_message": mock_method,
        }

        skylos._apply_heuristics()

        assert mock_method.references == 1

    def test_html_parser_callbacks_get_references(self, mock_definition):
        """HTMLParser.feed() dispatches handle_* callbacks dynamically."""
        skylos = Skylos()
        mock_class = mock_definition(
            name="HtmlRouteExtractor",
            simple_name="HtmlRouteExtractor",
            type="class",
            references=1,
        )
        mock_class.base_classes = ["html.parser.HTMLParser"]
        mock_start = mock_definition(
            name="HtmlRouteExtractor.handle_starttag",
            simple_name="handle_starttag",
            type="method",
            references=0,
        )
        mock_data = mock_definition(
            name="HtmlRouteExtractor.handle_data",
            simple_name="handle_data",
            type="method",
            references=0,
        )
        mock_helper = mock_definition(
            name="HtmlRouteExtractor.helper",
            simple_name="helper",
            type="method",
            references=0,
        )
        skylos.defs = {
            "HtmlRouteExtractor": mock_class,
            "HtmlRouteExtractor.handle_starttag": mock_start,
            "HtmlRouteExtractor.handle_data": mock_data,
            "HtmlRouteExtractor.helper": mock_helper,
        }

        skylos._apply_heuristics()

        assert mock_start.references == 1
        assert mock_data.references == 1
        assert mock_helper.references == 0

    def test_urllib_request_handler_hooks_get_references(self, mock_definition):
        """urllib opener dispatches protocol hook methods by naming convention."""
        skylos = Skylos()
        mock_class = mock_definition(
            name="_PinnedHTTPHandler",
            simple_name="_PinnedHTTPHandler",
            type="class",
            references=1,
        )
        mock_class.base_classes = ["urllib.request.HTTPHandler"]
        mock_open = mock_definition(
            name="_PinnedHTTPHandler.http_open",
            simple_name="http_open",
            type="method",
            references=0,
        )
        mock_helper = mock_definition(
            name="_PinnedHTTPHandler.connection_factory",
            simple_name="connection_factory",
            type="method",
            references=0,
        )
        skylos.defs = {
            "_PinnedHTTPHandler": mock_class,
            "_PinnedHTTPHandler.http_open": mock_open,
            "_PinnedHTTPHandler.connection_factory": mock_helper,
        }

        skylos._apply_heuristics()

        assert mock_open.references == 1
        assert mock_helper.references == 0

    def test_textual_app_runtime_hooks_get_references(self, mock_definition):
        """Textual App subclasses consume metadata and action methods dynamically."""
        skylos = Skylos()
        mock_class = mock_definition(
            name="SkylosApp",
            simple_name="SkylosApp",
            type="class",
            references=0,
        )
        mock_class.base_classes = ["textual.app.App"]
        mock_binding = mock_definition(
            name="SkylosApp.BINDINGS",
            simple_name="BINDINGS",
            type="variable",
            references=0,
        )
        mock_action = mock_definition(
            name="SkylosApp.action_go_category",
            simple_name="action_go_category",
            type="method",
            references=0,
        )
        skylos.defs = {
            "SkylosApp": mock_class,
            "SkylosApp.BINDINGS": mock_binding,
            "SkylosApp.action_go_category": mock_action,
        }

        skylos._apply_heuristics()

        assert mock_binding.references == 1
        assert mock_action.references == 1


class TestAnalyze:
    def test_architecture_iad_strict_requires_explicit_iad_opt_in(self):
        assert _architecture_iad_strict({"strict": True}) is False
        assert _architecture_iad_strict({"enforce_iad": True}) is True
        assert _architecture_iad_strict({"strict_iad": True}) is True

    def test_package_subdir_scan_keeps_absolute_imports_live(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "api.py").write_text(
            "from pkg.payload import action as _action\n\n"
            "def action():\n"
            "    return _action()\n",
            encoding="utf-8",
        )
        (package / "payload.py").write_text(
            "def action():\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        (package / "consumer.py").write_text(
            "from pkg.api import action\n\n"
            "def run():\n"
            "    return action()\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(package), conf=0, grep_verify=False))
        unused = {
            (Path(item["file"]).name, item["simple_name"])
            for item in result.get("unused_functions", [])
        }

        assert ("api.py", "action") not in unused
        assert ("payload.py", "action") not in unused

    def test_cast_string_type_reference_keeps_import_live(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "from typing import cast\n"
            "from models import AgentActionName\n\n"
            "def normalize(action):\n"
            "    return cast(\"AgentActionName\", action)\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
        unused_imports = {
            item["simple_name"] for item in result.get("unused_imports", [])
        }

        assert "AgentActionName" not in unused_imports

    def test_noqa_f401_suppresses_only_matching_unused_import(self, tmp_path):
        (tmp_path / "constants.py").write_text(
            "USED_FOR_COMPAT = 1\n"
            "PLAIN_UNUSED = 2\n",
            encoding="utf-8",
        )
        (tmp_path / "facade.py").write_text(
            "from constants import (\n"
            "    USED_FOR_COMPAT,  # noqa: F401 - compatibility re-export\n"
            "    PLAIN_UNUSED,\n"
            ")\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
        unused_imports = {
            item["simple_name"] for item in result.get("unused_imports", [])
        }
        suppressed = {
            item["name"]
            for item in result.get("suppressed", [])
            if item.get("suppression_code") == "noqa:F401"
        }

        assert "USED_FOR_COMPAT" not in unused_imports
        assert "PLAIN_UNUSED" in unused_imports
        assert "USED_FOR_COMPAT" in suppressed

    def test_noqa_f401_on_multiline_import_statement_suppresses_aliases(
        self, tmp_path
    ):
        (tmp_path / "constants.py").write_text(
            "COMPAT_ONE = 1\n"
            "COMPAT_TWO = 2\n",
            encoding="utf-8",
        )
        (tmp_path / "facade.py").write_text(
            "from constants import (  # noqa: F401 - compatibility re-export\n"
            "    COMPAT_ONE,\n"
            "    COMPAT_TWO,\n"
            ")\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
        unused_imports = {
            item["simple_name"] for item in result.get("unused_imports", [])
        }

        assert "COMPAT_ONE" not in unused_imports
        assert "COMPAT_TWO" not in unused_imports

    def test_noqa_f401_on_multiline_import_close_suppresses_aliases(
        self, tmp_path
    ):
        (tmp_path / "constants.py").write_text(
            "COMPAT_ONE = 1\n"
            "COMPAT_TWO = 2\n",
            encoding="utf-8",
        )
        (tmp_path / "facade.py").write_text(
            "from constants import (\n"
            "    COMPAT_ONE,\n"
            "    COMPAT_TWO,\n"
            ")  # noqa: F401 - compatibility re-export\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
        unused_imports = {
            item["simple_name"] for item in result.get("unused_imports", [])
        }

        assert "COMPAT_ONE" not in unused_imports
        assert "COMPAT_TWO" not in unused_imports

    def test_noqa_f401_on_second_import_does_not_suppress_first_import(
        self, tmp_path
    ):
        (tmp_path / "app.py").write_text(
            "import os\n"
            "import sys  # noqa: F401 - compatibility re-export\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
        unused_imports = {
            item["simple_name"] for item in result.get("unused_imports", [])
        }
        suppressed = {item["name"] for item in result.get("suppressed", [])}

        assert "os" in unused_imports
        assert "sys" in suppressed

    def test_noqa_f401_does_not_suppress_unused_variable(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "unused_value = 1  # noqa: F401\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
        unused_variables = {
            item["simple_name"] for item in result.get("unused_variables", [])
        }

        assert "unused_value" in unused_variables

    def test_mcp_decorated_tools_and_resources_are_live(self, tmp_path):
        (tmp_path / "server.py").write_text(
            "class FakeMCP:\n"
            "    def tool(self):\n"
            "        def decorate(fn):\n"
            "            return fn\n"
            "        return decorate\n\n"
            "    def resource(self, _uri):\n"
            "        def decorate(fn):\n"
            "            return fn\n"
            "        return decorate\n\n"
            "mcp = FakeMCP()\n\n"
            "@mcp.tool()\n"
            "def registered_tool():\n"
            "    return 'tool'\n\n"
            "@mcp.resource('skylos://latest')\n"
            "def registered_resource():\n"
            "    return 'resource'\n\n"
            "def plain_dead():\n"
            "    return 'dead'\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
        unused = {
            (Path(item["file"]).name, item["simple_name"])
            for item in result.get("unused_functions", [])
        }

        assert ("server.py", "registered_tool") not in unused
        assert ("server.py", "registered_resource") not in unused
        assert ("server.py", "plain_dead") in unused

    def test_package_scan_resolves_relative_and_module_import_styles(self, tmp_path):
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "api.py").write_text(
            "from .payload import action as _action\n\n"
            "def action():\n"
            "    return _action()\n",
            encoding="utf-8",
        )
        (package / "payload.py").write_text(
            "def action():\n"
            "    return 'ok'\n\n"
            "def side():\n"
            "    return 'side'\n\n"
            "def unused():\n"
            "    return 'dead'\n",
            encoding="utf-8",
        )
        (package / "consumer.py").write_text(
            "import pkg.api as api\n"
            "from pkg import payload\n\n"
            "def run():\n"
            "    return api.action(), payload.side()\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(package), conf=0, grep_verify=False))
        unused = {
            (Path(item["file"]).name, item["simple_name"])
            for item in result.get("unused_functions", [])
        }

        assert ("api.py", "action") not in unused
        assert ("payload.py", "action") not in unused
        assert ("payload.py", "side") not in unused
        assert ("payload.py", "unused") in unused

    def test_project_scan_strips_common_python_source_root(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        package = tmp_path / "lib" / "pkg"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "api.py").write_text(
            "from pkg.payload import action as _action\n\n"
            "def action():\n"
            "    return _action()\n",
            encoding="utf-8",
        )
        (package / "payload.py").write_text(
            "def action():\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        (package / "consumer.py").write_text(
            "from pkg.api import action\n\n"
            "def run():\n"
            "    return action()\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
        unused = {
            (Path(item["file"]).name, item["simple_name"])
            for item in result.get("unused_functions", [])
        }

        assert ("api.py", "action") not in unused
        assert ("payload.py", "action") not in unused

    def test_package_scan_without_project_root_matches_package_import_prefix(
        self, tmp_path
    ):
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "api.py").write_text(
            "from pkg.payload import action as _action\n\n"
            "def action():\n"
            "    return _action()\n",
            encoding="utf-8",
        )
        (package / "payload.py").write_text(
            "def action():\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        (package / "consumer.py").write_text(
            "from pkg.api import action\n\n"
            "def run():\n"
            "    return action()\n",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(package), conf=0, grep_verify=False))
        unused = {
            (Path(item["file"]).name, item["simple_name"])
            for item in result.get("unused_functions", [])
        }

        assert ("api.py", "action") not in unused
        assert ("payload.py", "action") not in unused

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
        mock_def.node = None
        mock_def.calls = []
        mock_def.called_by = []
        mock_def.complexity = 1
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

    @patch("skylos.analyzer.logger.info")
    def test_analyze_mixed_languages_includes_java_in_summary(self, mock_log_info):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "main.py").write_text(
                "def hello():\n    return 1\n", encoding="utf-8"
            )
            (root / "main.go").write_text(
                "package main\nfunc main() {}\n", encoding="utf-8"
            )
            (root / "Hello.java").write_text(
                "public class Hello {\n"
                "    public static void main(String[] args) {\n"
                '        System.out.println("hi");\n'
                "    }\n"
                "}\n",
                encoding="utf-8",
            )

            result_json = analyze(str(root), conf=0)

        result = json.loads(result_json)

        assert result["analysis_summary"]["total_files"] == 3
        assert result["analysis_summary"]["languages"] == {
            "Go": 1,
            "Java": 1,
            "Python": 1,
        }
        mock_log_info.assert_any_call("Analyzing 3 files...")
        assert not any(
            "Python files" in call.args[0] for call in mock_log_info.call_args_list
        )

    @patch("skylos.analyzer.logger.info")
    def test_analyze_mixed_languages_includes_javascript_in_summary(
        self, mock_log_info
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "main.py").write_text(
                "def hello():\n    return 1\n", encoding="utf-8"
            )
            (root / "app.mjs").write_text(
                "export function runUnsafe(input) {\n"
                "  eval(input);\n"
                "}\n"
                "runUnsafe('hi');\n",
                encoding="utf-8",
            )

            result_json = analyze(str(root), conf=0)

        result = json.loads(result_json)

        assert result["analysis_summary"]["total_files"] == 2
        assert result["analysis_summary"]["languages"] == {
            "JavaScript": 1,
            "Python": 1,
        }
        mock_log_info.assert_any_call("Analyzing 2 files...")

    @patch("skylos.analyzer.logger.info")
    def test_analyze_mixed_languages_includes_php_in_summary(self, mock_log_info):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "main.py").write_text(
                "def hello():\n    return 1\n", encoding="utf-8"
            )
            (root / "index.php").write_text(
                "<?php\nfunction helper($x) { return trim($x); }\nhelper('hi');\n",
                encoding="utf-8",
            )

            result_json = analyze(str(root), conf=0)

        result = json.loads(result_json)

        assert result["analysis_summary"]["total_files"] == 2
        assert result["analysis_summary"]["languages"] == {
            "PHP": 1,
            "Python": 1,
        }
        mock_log_info.assert_any_call("Analyzing 2 files...")

    @patch("skylos.analyzer.logger.info")
    def test_analyze_mixed_languages_includes_rust_in_summary(self, mock_log_info):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "main.py").write_text(
                "def hello():\n    return 1\n", encoding="utf-8"
            )
            (root / "lib.rs").write_text(
                "pub fn run() { helper(); }\nfn helper() {}\n",
                encoding="utf-8",
            )

            result_json = analyze(str(root), conf=0)

        result = json.loads(result_json)

        assert result["analysis_summary"]["total_files"] == 2
        assert result["analysis_summary"]["languages"] == {
            "Python": 1,
            "Rust": 1,
        }
        mock_log_info.assert_any_call("Analyzing 2 files...")

    def test_analyze_rust_public_reexports_stay_live(self, tmp_path):
        (tmp_path / "lib.rs").write_text(
            """
mod internal {
    pub fn public_api() {}
    pub fn stale_api() {}
}

pub use crate::internal::public_api;
use crate::internal::stale_api;
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unused_imports = {item["simple_name"] for item in result["unused_imports"]}

        assert "public_api" not in unused_imports
        assert "stale_api" in unused_imports

    def test_analyze_rust_namespaced_associated_constructor_is_live(self, tmp_path):
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "tls.rs").write_text(
            """
struct VerifyCaCertVerifier;

impl VerifyCaCertVerifier {
    fn new() -> Self { Self }
}

fn build_verifier() {
    VerifyCaCertVerifier::new();
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(src_dir), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["full_name"] for item in result["unused_functions"]}

        assert "tls.VerifyCaCertVerifier.new" not in unreachable
        assert "tls.build_verifier" in unreachable

    def test_analyze_rust_external_trait_import_methods_are_live(self, tmp_path):
        (tmp_path / "lib.rs").write_text(
            """
use futures::StreamExt;
use crate::traits::WidgetExt;

fn run(stream: StreamLike, widget: Widget) {
    stream.next();
    widget.next();
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unused_imports = {item["simple_name"] for item in result["unused_imports"]}

        assert "StreamExt" not in unused_imports
        assert "WidgetExt" in unused_imports

    @patch("skylos.analyzer.logger.info")
    def test_analyze_mixed_languages_includes_csharp_in_summary(self, mock_log_info):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "main.py").write_text(
                "def hello():\n    return 1\n", encoding="utf-8"
            )
            (root / "Program.cs").write_text(
                "public class Program {\n"
                "    public static void Main(string[] args) {\n"
                '        System.Console.WriteLine("hi");\n'
                "    }\n"
                "}\n",
                encoding="utf-8",
            )

            result_json = analyze(str(root), conf=0)

        result = json.loads(result_json)

        assert result["analysis_summary"]["total_files"] == 2
        assert result["analysis_summary"]["languages"] == {
            "C#": 1,
            "Python": 1,
        }
        mock_log_info.assert_any_call("Analyzing 2 files...")

    def test_analyze_csharp_unused_private_method_without_using_noise(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "Demo.cs").write_text(
                "using System;\n"
                "\n"
                "public class Demo {\n"
                "    private void DeadHelper() { }\n"
                "    public void Alive() {\n"
                "        Used();\n"
                "    }\n"
                "    private void Used() { }\n"
                "}\n",
                encoding="utf-8",
            )

            result_json = analyze(str(root), conf=0)

        result = json.loads(result_json)

        assert result["analysis_summary"]["languages"] == {"C#": 1}
        assert {item["name"] for item in result["unused_functions"]} == {
            "Demo.DeadHelper"
        }
        assert result["unused_imports"] == []

    def test_analyze_malformed_pyproject_config_does_not_suppress_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pyproject.toml").write_text(
                """
[tool.skylos]
ignore = 1
complexity = "boom"
max_args = false
""".strip(),
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                'def unused_func(a, b, c, d, e, f):\n'
                '    return eval("1+1")\n',
                encoding="utf-8",
            )

            result_json = analyze(
                str(root), conf=0, enable_danger=True, grep_verify=False
            )

        result = json.loads(result_json)

        assert result["unused_functions"]
        assert "SKY-D201" in {f.get("rule_id") for f in result.get("danger", [])}

    @patch("skylos.analysis.file_processing.scan_typescript_file")
    def test_proc_file_dispatches_js_to_typescript_scanner(self, mock_scan):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write("export function run() { return 1; }\n")
            f.flush()

            mock_scan.return_value = tuple(range(13))

            try:
                result = proc_file(f.name, "test_module")
            finally:
                Path(f.name).unlink()

        mock_scan.assert_called_once()
        assert result == tuple(range(13))

    def test_analyze_quality_includes_architecture_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "abstract_mod.py").write_text(
                "from abc import ABC\n"
                "import concrete_mod\n"
                "class Base(ABC):\n"
                "    pass\n"
                "class Base2(ABC):\n"
                "    pass\n",
                encoding="utf-8",
            )
            (root / "concrete_mod.py").write_text("VALUE = 1\n", encoding="utf-8")

            result_json = analyze(str(root), enable_quality=True, grep_verify=False)

        result = json.loads(result_json)
        assert result.get("architecture_metrics")
        assert any(
            f.get("rule_id") in {"SKY-Q802", "SKY-Q803", "SKY-Q804"}
            for f in result.get("quality", [])
        )
        assert result["analysis_summary"]["quality_count"] == len(
            result.get("quality", [])
        )

    def test_analyze_architecture_metrics_preserve_dotted_submodule_imports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package_a").mkdir()
            (root / "package_b").mkdir()
            (root / "package_a" / "__init__.py").write_text("", encoding="utf-8")
            (root / "package_a" / "cli.py").write_text(
                "import sync_common\ndef main():\n    return sync_common.VALUE\n",
                encoding="utf-8",
            )
            (root / "package_b" / "__init__.py").write_text("", encoding="utf-8")
            (root / "package_b" / "cli.py").write_text(
                "from package_a.cli import main as run_a\n"
                "import sync_common\n"
                "def main():\n"
                "    return run_a() + sync_common.VALUE\n",
                encoding="utf-8",
            )
            (root / "sync_common.py").write_text("VALUE = 1\n", encoding="utf-8")

            result_json = analyze(str(root), enable_quality=True, grep_verify=False)

        result = json.loads(result_json)
        metrics = result["architecture_metrics"]["module_metrics"]
        assert metrics["package_a"]["ca"] == 0
        assert metrics["package_a.cli"]["ca"] == 1
        assert metrics["package_a.cli"]["zone"] != "zone_of_uselessness"

    def test_analyze_architecture_metrics_preserve_resolved_relative_imports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app" / "package_a").mkdir(parents=True)
            (root / "app" / "package_b").mkdir()
            (root / "app" / "__init__.py").write_text("", encoding="utf-8")
            (root / "app" / "package_a" / "__init__.py").write_text(
                "", encoding="utf-8"
            )
            (root / "app" / "package_a" / "cli.py").write_text(
                "def main():\n    return 1\n",
                encoding="utf-8",
            )
            (root / "app" / "package_b" / "__init__.py").write_text(
                "", encoding="utf-8"
            )
            (root / "app" / "package_b" / "cli.py").write_text(
                "from ..package_a.cli import main as run_a\n"
                "def main():\n"
                "    return run_a()\n",
                encoding="utf-8",
            )

            result_json = analyze(str(root), enable_quality=True, grep_verify=False)

        result = json.loads(result_json)
        metrics = result["architecture_metrics"]["module_metrics"]
        assert metrics["app.package_a"]["ca"] == 0
        assert metrics["app.package_a.cli"]["ca"] == 1
        assert metrics["app.package_a.cli"]["zone"] != "zone_of_uselessness"

    def test_analyze_applies_configured_architecture_layer_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pyproject.toml").write_text(
                "[tool.skylos.architecture]\n"
                "strict = false\n\n"
                "[[tool.skylos.architecture.layers]]\n"
                'name = "api"\n'
                'patterns = ["app.api"]\n\n'
                "[[tool.skylos.architecture.layers]]\n"
                'name = "domain"\n'
                'patterns = ["app.domain"]\n\n'
                "[[tool.skylos.architecture.rules]]\n"
                'from = "domain"\n'
                'deny = ["api"]\n',
                encoding="utf-8",
            )
            (root / "app" / "api").mkdir(parents=True)
            (root / "app" / "domain").mkdir(parents=True)
            (root / "app" / "__init__.py").write_text("", encoding="utf-8")
            (root / "app" / "api" / "__init__.py").write_text("", encoding="utf-8")
            (root / "app" / "domain" / "__init__.py").write_text("", encoding="utf-8")
            (root / "app" / "api" / "routes.py").write_text(
                "API_VALUE = 1\n",
                encoding="utf-8",
            )
            (root / "app" / "domain" / "model.py").write_text(
                "from app.api.routes import API_VALUE\n"
                "def model_value():\n"
                "    return API_VALUE\n",
                encoding="utf-8",
            )

            result_json = analyze(str(root), enable_quality=True, grep_verify=False)

        result = json.loads(result_json)
        policy_findings = [
            f for f in result.get("quality", []) if f.get("rule_id") == "SKY-Q805"
        ]
        assert len(policy_findings) == 1
        assert policy_findings[0]["from_layer"] == "domain"
        assert policy_findings[0]["to_layer"] == "api"
        assert result["architecture_metrics"]["layer_policy"]["violation_count"] == 1

    def test_analyze_architecture_filters_cli_entrypoint_and_private_helper_noise(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pkg = root / "mypkg"
            pkg.mkdir()
            (root / "pyproject.toml").write_text(
                "[project]\n"
                'name = "issue300-repro"\n'
                'version = "0.1.0"\n\n'
                "[project.scripts]\n"
                'mypkg = "mypkg:main"\n',
                encoding="utf-8",
            )
            (pkg / "__init__.py").write_text(
                'from .cli import main\n__all__ = ["main"]\n',
                encoding="utf-8",
            )
            (pkg / "cli.py").write_text(
                "from .flow_a import run_a\n"
                "from .flow_b import run_b\n"
                "from .flow_c import run_c\n\n"
                "def main():\n"
                "    run_a()\n"
                "    run_b()\n"
                "    run_c()\n",
                encoding="utf-8",
            )
            (pkg / "_helpers.py").write_text(
                "def normalize(value):\n"
                "    return value.strip().lower()\n\n"
                "def emit(value):\n"
                "    print(normalize(value))\n",
                encoding="utf-8",
            )
            for suffix in ("a", "b", "c"):
                (pkg / f"flow_{suffix}.py").write_text(
                    "from ._helpers import emit\n\n"
                    f"def run_{suffix}():\n"
                    f'    emit("{suffix}")\n',
                    encoding="utf-8",
                )

            result_json = analyze(str(root), enable_quality=True, grep_verify=False)

        result = json.loads(result_json)
        metrics = result["architecture_metrics"]["module_metrics"]
        assert metrics["mypkg"]["zone"] == "main_sequence"
        assert metrics["mypkg.cli"]["zone"] == "off_main_sequence"
        assert metrics["mypkg._helpers"]["distance"] == 1.0

        architecture_rules = {
            (f.get("rule_id"), f.get("name"))
            for f in result.get("quality", [])
            if f.get("rule_id") in {"SKY-Q802", "SKY-Q803"}
        }
        assert ("SKY-Q803", "mypkg") not in architecture_rules
        assert ("SKY-Q803", "mypkg.cli") not in architecture_rules
        assert ("SKY-Q802", "mypkg._helpers") not in architecture_rules

    def test_pyproject_gui_script_entrypoint_is_not_reported_dead(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pkg = root / "mypkg"
            pkg.mkdir()
            (root / "pyproject.toml").write_text(
                "[project]\n"
                'name = "gui-entrypoint-repro"\n'
                'version = "0.1.0"\n\n'
                "[project.gui-scripts]\n"
                'mypkg-gui = "mypkg.gui:launch"\n',
                encoding="utf-8",
            )
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "gui.py").write_text(
                'def launch():\n    print("hello")\n',
                encoding="utf-8",
            )

            result_json = analyze(str(root), conf=0, grep_verify=False)

        result = json.loads(result_json)
        unused_functions = {
            item["full_name"] for item in result.get("unused_functions", [])
        }
        assert "mypkg.gui.launch" not in unused_functions

    def test_analyze_architecture_filters_low_fan_in_private_helper_q803(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pkg = root / "mypkg"
            pkg.mkdir()
            (root / "pyproject.toml").write_text(
                "[project]\n"
                'name = "q803-private-helper-repro"\n'
                'version = "0.1.0"\n\n'
                "[project.scripts]\n"
                'mypkg = "mypkg.cli:main"\n',
                encoding="utf-8",
            )
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "cli.py").write_text(
                "from ._banner import print_banner\n\n"
                "def main():\n"
                "    print_banner()\n",
                encoding="utf-8",
            )
            (pkg / "_banner.py").write_text(
                'def print_banner():\n    print("hello")\n',
                encoding="utf-8",
            )

            result_json = analyze(str(root), enable_quality=True, grep_verify=False)

        result = json.loads(result_json)
        metrics = result["architecture_metrics"]["module_metrics"]
        assert metrics["mypkg._banner"]["ca"] == 1
        assert metrics["mypkg._banner"]["ce"] == 0
        assert metrics["mypkg._banner"]["zone"] == "zone_of_pain"

        architecture_rules = {
            (f.get("rule_id"), f.get("name"))
            for f in result.get("quality", [])
            if f.get("rule_id") in {"SKY-Q802", "SKY-Q803"}
        }
        assert ("SKY-Q803", "mypkg._banner") not in architecture_rules

    def test_analyze_architecture_labels_empty_package_disconnected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pkg = root / "mypkg"
            pkg.mkdir()
            (root / "pyproject.toml").write_text(
                '[project]\nname = "disconnected-package-repro"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (pkg / "__init__.py").write_text("", encoding="utf-8")

            result_json = analyze(str(root), enable_quality=True, grep_verify=False)

        result = json.loads(result_json)
        metrics = result["architecture_metrics"]["module_metrics"]
        distribution = result["architecture_metrics"]["system_metrics"][
            "zone_distribution"
        ]
        assert metrics["mypkg"]["ca"] == 0
        assert metrics["mypkg"]["ce"] == 0
        assert metrics["mypkg"]["zone"] == "disconnected"
        assert distribution["disconnected"] == 1
        assert distribution["zone_of_pain"] == 0

        architecture_rules = {
            (f.get("rule_id"), f.get("name"))
            for f in result.get("quality", [])
            if f.get("rule_id") in {"SKY-Q802", "SKY-Q803"}
        }
        assert ("SKY-Q802", "mypkg") not in architecture_rules
        assert ("SKY-Q803", "mypkg") not in architecture_rules

    def test_analyze_architecture_filters_library_reexport_and_test_leaf_noise(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pkg = root / "src" / "mini_pkg"
            tests = root / "tests"
            pkg.mkdir(parents=True)
            tests.mkdir()
            (root / "pyproject.toml").write_text(
                "[project]\n"
                'name = "mini-pkg"\n'
                'version = "0.1.0"\n'
                'requires-python = ">=3.10"\n\n'
                "[build-system]\n"
                'requires = ["setuptools>=68"]\n'
                'build-backend = "setuptools.build_meta"\n\n'
                "[tool.setuptools]\n"
                'package-dir = {"" = "src"}\n',
                encoding="utf-8",
            )
            (pkg / "__init__.py").write_text(
                '"""Minimal library entry point that re-exports core symbols."""\n'
                "from .core import Greeter, greet\n\n"
                '__all__ = ["Greeter", "greet"]\n',
                encoding="utf-8",
            )
            (pkg / "core.py").write_text(
                '"""Concrete library implementation."""\n'
                "from dataclasses import dataclass\n\n\n"
                "@dataclass(frozen=True)\n"
                "class Greeter:\n"
                "    name: str\n\n"
                "    def hello(self) -> str:\n"
                '        return f"Hello, {self.name}!"\n\n\n'
                "def greet(name: str) -> str:\n"
                "    return Greeter(name=name).hello()\n",
                encoding="utf-8",
            )
            (tests / "__init__.py").write_text("", encoding="utf-8")
            (tests / "test_core.py").write_text(
                "from mini_pkg import greet\n\n\n"
                "def test_greet():\n"
                '    assert greet("world") == "Hello, world!"\n',
                encoding="utf-8",
            )

            result_json = analyze(str(root), enable_quality=True, grep_verify=False)

        result = json.loads(result_json)
        metrics = result["architecture_metrics"]["module_metrics"]
        assert metrics["mini_pkg.core"]["distance"] == 1.0
        assert metrics["mini_pkg.core"]["zone"] == "zone_of_pain"
        assert metrics["tests.test_core"]["zone"] == "main_sequence"

        architecture_rules = {
            (f.get("rule_id"), f.get("name"))
            for f in result.get("quality", [])
            if f.get("rule_id") in {"SKY-Q802", "SKY-Q803"}
        }
        assert ("SKY-Q802", "mini_pkg.core") not in architecture_rules
        assert ("SKY-Q803", "mini_pkg.core") not in architecture_rules
        assert ("SKY-Q803", "tests.test_core") not in architecture_rules

    @patch("skylos.analysis.file_processing.scan_typescript_file")
    def test_proc_file_dispatches_mjs_to_typescript_scanner(self, mock_scan):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mjs", delete=False) as f:
            f.write("export function run() { return 1; }\n")
            f.flush()

            mock_scan.return_value = tuple(range(13))

            try:
                result = proc_file(f.name, "test_module")
            finally:
                Path(f.name).unlink()

        mock_scan.assert_called_once()
        assert result == tuple(range(13))

    @patch("skylos.analysis.file_processing.scan_php_file")
    def test_proc_file_dispatches_php_to_php_scanner(self, mock_scan):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".php", delete=False) as f:
            f.write("<?php function run() { return 1; }\n")
            f.flush()

            mock_scan.return_value = tuple(range(13))

            try:
                result = proc_file(f.name, "test_module")
            finally:
                Path(f.name).unlink()

        mock_scan.assert_called_once()
        assert result == tuple(range(13))

    @patch("skylos.analysis.file_processing.scan_rust_file")
    def test_proc_file_dispatches_rust_to_rust_scanner(self, mock_scan):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rs", delete=False) as f:
            f.write("pub fn run() { }\n")
            f.flush()

            mock_scan.return_value = tuple(range(13))

            try:
                result = proc_file(f.name, "test_module")
            finally:
                Path(f.name).unlink()

        mock_scan.assert_called_once()
        assert result == tuple(range(13))

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

                assert len(result["unused_functions"]) == 1
                assert result["unused_functions"][0]["name"] == "high_conf"


class TestProcFile:
    def test_proc_file_with_valid_python(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
def test_function():
    return 42

class TestClass:
    def method(self):
        return "ok"
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
                        raw_imports,
                        ignore_lines,
                        suppressed_findings,
                        inferred_types,
                        instance_attr_types,
                        used_attr_names,
                        used_attr_context,
                        source_lines,
                        *_extra,
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
                    raw_imports,
                    ignore_lines,
                    suppressed_findings,
                    inferred_types,
                    instance_attr_types,
                    used_attr_names,
                    used_attr_context,
                    source_lines,
                    *_extra,
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

    def test_proc_file_keeps_findings_when_dynamic_fstring_pattern_has_regex_chars(
        self, tmp_path
    ):
        file_path = tmp_path / "dynamic_pattern.py"
        file_path.write_text(
            'def hidden(name, obj):\n'
            '    eval("1+1")\n'
            '    return getattr(obj, f"bad({name}", None)\n',
            encoding="utf-8",
        )

        out = proc_file(str(file_path), "dynamic_pattern")
        danger_findings = out[7]
        pattern_tracker = out[9]

        assert "SKY-D201" in {f.get("rule_id") for f in danger_findings}
        assert pattern_tracker is not None

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
                        raw_imports,
                        ignore_lines,
                        suppressed_findings,
                        inferred_types,
                        instance_attr_types,
                        used_attr_names,
                        used_attr_context,
                        source_lines,
                        *_extra,
                    ) = proc_file((f.name, "test_module"))

                    mock_visitor_class.assert_called_once_with("test_module", f.name)
            finally:
                Path(f.name).unlink()

    def test_empty_file_reporting(self, tmp_path):
        empty = tmp_path / "empty_module.py"
        empty.write_text("")

        (tmp_path / "main.py").write_text("")
        pkg = tmp_path / "mypkg"
        pkg.mkdir()
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
    @pytest.mark.parametrize(
        ("filename", "def_type", "expected_reason"),
        [
            ("tests/test_api.py", "function", "test-only path"),
            ("examples/demo.py", "function", "standalone example path"),
            ("benchmarks/bench_api.py", "class", "benchmark entrypoint path"),
        ],
    )
    @patch("skylos.analysis.penalties.detect_framework_usage")
    def test_non_library_paths_suppress_dead_code_callables(
        self,
        mock_detect_framework,
        filename,
        def_type,
        expected_reason,
        mock_definition,
        mock_test_aware_visitor,
        mock_framework_aware_visitor,
    ):
        mock_detect_framework.return_value = None

        skylos = Skylos()
        mock_def = mock_definition(
            name="demo.symbol",
            simple_name="symbol",
            type=def_type,
            confidence=100,
        )
        mock_def.filename = Path(filename)

        apply_penalties(
            skylos, mock_def, mock_test_aware_visitor, mock_framework_aware_visitor
        )

        assert mock_def.confidence == 0
        assert mock_def.skip_reason == expected_reason

    @patch("skylos.analysis.penalties.detect_framework_usage")
    def test_private_name_penalty(
        self,
        mock_detect_framework,
        mock_definition,
        mock_test_aware_visitor,
        mock_framework_aware_visitor,
    ):
        mock_detect_framework.return_value = None

        skylos = Skylos()
        mock_def = mock_definition(
            name="_private_func",
            simple_name="_private_func",
            type="function",
            confidence=100,
        )

        apply_penalties(
            skylos, mock_def, mock_test_aware_visitor, mock_framework_aware_visitor
        )
        assert mock_def.confidence < 100

    @patch("skylos.analysis.penalties.detect_framework_usage")
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

        apply_penalties(
            skylos, mock_def, mock_test_aware_visitor, mock_framework_aware_visitor
        )
        assert mock_def.confidence == 0

    @patch("skylos.analysis.penalties.detect_framework_usage")
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

        apply_penalties(
            skylos, mock_self, mock_test_aware_visitor, mock_framework_aware_visitor
        )
        apply_penalties(
            skylos, mock_cls, mock_test_aware_visitor, mock_framework_aware_visitor
        )

        assert mock_self.confidence == 0
        assert mock_cls.confidence == 0

    @patch("skylos.analysis.penalties.detect_framework_usage")
    def test_conditional_import_penalty_reduces_confidence(
        self,
        mock_detect_framework,
        mock_definition,
        mock_test_aware_visitor,
        mock_framework_aware_visitor,
    ):
        mock_detect_framework.return_value = None
        skylos = Skylos()

        mock_def = mock_definition(
            name="brotli",
            simple_name="brotli",
            type="import",
            confidence=100,
        )
        mock_def.conditional_import = True

        apply_penalties(
            skylos, mock_def, mock_test_aware_visitor, mock_framework_aware_visitor
        )

        assert mock_def.confidence == 40
        assert "conditional_import_fallback" in mock_def.why_confidence_reduced

    @patch("skylos.analysis.penalties.detect_framework_usage")
    def test_test_methods_confidence_zero(
        self, mock_detect_framework, mock_definition, mock_framework_aware_visitor
    ):
        """test methods get confidence of 0"""
        mock_detect_framework.return_value = None

        skylos = Skylos()

        mock_def = mock_definition(
            name="TestMyClass.test_something",
            simple_name="test_something",
            type="method",
            confidence=100,
        )

        test_visitor = Mock(spec=TestAwareVisitor)
        test_visitor.is_test_file = True
        test_visitor.test_decorated_lines = {mock_def.line}

        apply_penalties(skylos, mock_def, test_visitor, mock_framework_aware_visitor)
        assert mock_def.confidence == 0

    @patch("skylos.analysis.penalties.detect_framework_usage")
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

        apply_penalties(
            skylos, mock_def, mock_test_aware_visitor, mock_framework_aware_visitor
        )
        assert mock_def.confidence == 0


class TestConfiguredDeadCodeEntrypoints:
    @patch("skylos.analysis.penalties.detect_framework_usage")
    def test_configured_class_entrypoint_matches_path_and_base(
        self,
        mock_detect_framework,
        mock_definition,
        mock_test_aware_visitor,
        mock_framework_aware_visitor,
    ):
        mock_detect_framework.return_value = None
        skylos = Skylos()
        skylos._project_root = Path("/repo")
        cfg = {
            "dead_code": {
                "entrypoints": [
                    {
                        "type": "class",
                        "name": "_Main",
                        "path": "app/main.py",
                        "base_classes": ["Application"],
                        "reason": "custom app entrypoint",
                    }
                ]
            }
        }
        mock_def = mock_definition(
            name="app.main._Main",
            simple_name="_Main",
            type="class",
            confidence=100,
        )
        mock_def.filename = Path("/repo/app/main.py")
        mock_def.base_classes = ["framework.Application"]

        apply_penalties(
            skylos,
            mock_def,
            mock_test_aware_visitor,
            mock_framework_aware_visitor,
            cfg,
        )

        assert mock_def.confidence == 0
        assert mock_def.skip_reason == "custom app entrypoint"
        assert mock_def.suppression_code == "configured_entrypoint"

    def test_configured_method_entrypoint_matches_parent_base(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            """
[tool.skylos]
ignore = []

[[tool.skylos.dead_code.entrypoints]]
type = "method"
name = ["create"]
parent = { name = "Main", base_classes = ["Application"] }
reason = "custom framework lifecycle method"
""",
            encoding="utf-8",
        )
        (tmp_path / "main.py").write_text(
            """
class Application:
    pass

class Main(Application):
    def create(self):
        return None

    def stale(self):
        return None

app = Main()
""",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0))
        unused_methods = {
            item["full_name"].rsplit(".", 1)[-1]
            for item in result["unused_functions"]
        }

        assert "create" not in unused_methods
        assert "stale" in unused_methods

    def test_configured_function_entrypoint_matches_decorator(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            """
[tool.skylos]
ignore = []

[[tool.skylos.dead_code.entrypoints]]
type = "function"
decorators = ["runtime_hook"]
reason = "custom decorator entrypoint"
""",
            encoding="utf-8",
        )
        (tmp_path / "hooks.py").write_text(
            """
def runtime_hook(fn):
    return fn

@runtime_hook
def boot():
    return None

def orphan():
    return None
""",
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0))
        unused_functions = {
            item["simple_name"] for item in result["unused_functions"]
        }

        assert "boot" not in unused_functions
        assert "orphan" in unused_functions

    def test_malformed_entrypoint_rule_does_not_suppress_broadly(
        self, mock_definition
    ):
        skylos = Skylos()
        skylos._project_root = Path("/repo")
        cfg = {
            "dead_code": {
                "entrypoints": [
                    {
                        "type": "function",
                        "path": "main.py",
                        "reason": "too broad",
                    }
                ]
            }
        }
        mock_def = mock_definition(
            name="main.orphan",
            simple_name="orphan",
            type="function",
            confidence=100,
        )
        mock_def.filename = Path("/repo/main.py")

        assert configured_entrypoint_reason(mock_def, skylos, cfg) is None


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

        unreachable = {
            item["name"].split(".")[-1] for item in result["unused_functions"]
        }

        assert "unused_no_ignore" in unreachable
        assert "unused_ignore" not in unreachable
        assert "used" not in unreachable

    def test_analyze_suppresses_pytest_plugin_hook_methods(self, tmp_path):
        src = tmp_path / "plugin.py"
        src.write_text(
            """
import pytest

class UnusedFixturesPlugin:
    def pytest_collection_finish(self, session):
        return None

    def pytest_fixture_setup(self, fixturedef, request):
        return None

    def pytest_sessionfinish(self, session, exitstatus):
        return None
"""
        )

        result_json = analyze(str(tmp_path), conf=0)
        result = json.loads(result_json)

        unreachable = {
            item["name"].split(".")[-1] for item in result["unused_functions"]
        }

        assert "pytest_collection_finish" not in unreachable
        assert "pytest_fixture_setup" not in unreachable
        assert "pytest_sessionfinish" not in unreachable

    def test_analyze_suppresses_additional_pytest_plugin_hooks(self, tmp_path):
        src = tmp_path / "plugin.py"
        src.write_text(
            """
import pytest

def pytest_addhooks(pluginmanager):
    return None

def pytest_cmdline_main(config):
    return 0

def pytest_assertrepr_compare(config, op, left, right):
    return []
"""
        )

        result_json = analyze(str(tmp_path), conf=0)
        result = json.loads(result_json)

        unreachable = {
            item["name"].split(".")[-1] for item in result["unused_functions"]
        }

        assert "pytest_addhooks" not in unreachable
        assert "pytest_cmdline_main" not in unreachable
        assert "pytest_assertrepr_compare" not in unreachable

    def test_analyze_suppresses_pytest_hook_parameters(self, tmp_path):
        src = tmp_path / "plugin.py"
        src.write_text(
            """
import pytest

def pytest_assertrepr_compare(config, op, left, right):
    return []
"""
        )

        result_json = analyze(str(tmp_path), conf=0)
        result = json.loads(result_json)

        unused_parameters = {
            item["simple_name"] for item in result["unused_parameters"]
        }

        assert "config" not in unused_parameters
        assert "op" not in unused_parameters
        assert "left" not in unused_parameters
        assert "right" not in unused_parameters

    def test_analyze_suppresses_override_method_parameters(self, tmp_path):
        src = tmp_path / "models.py"
        src.write_text(
            """
from typing import override
import typing_extensions

class Base:
    def render(self, value, context, unused_base):
        return value + context + unused_base

class TypedChild(Base):
    @override
    def render(self, value, context, compat):
        return value + context

class ExtensionChild(Base):
    @typing_extensions.override()
    def render(self, value, context, compat_ext):
        return value + context

class PlainChild(Base):
    def render(self, value, context, plain_unused):
        return value + context
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unused_parameters = {item["full_name"] for item in result["unused_parameters"]}

        assert "models.TypedChild.render.compat" not in unused_parameters
        assert "models.ExtensionChild.render.compat_ext" not in unused_parameters
        assert "models.PlainChild.render.plain_unused" in unused_parameters

    def test_analyze_suppresses_sqlalchemy_listener_parameters(self, tmp_path):
        src = tmp_path / "listener.py"
        src.write_text(
            """
from sqlalchemy import event

class Engine:
    pass

def on_connect(dbapi_connection, connection_record):
    return None

event.listens_for(Engine, "connect")(on_connect)
"""
        )

        result_json = analyze(str(tmp_path), conf=0)
        result = json.loads(result_json)

        unused_parameters = {
            item["simple_name"] for item in result["unused_parameters"]
        }

        assert "dbapi_connection" not in unused_parameters
        assert "connection_record" not in unused_parameters

    def test_analyze_marks_private_helper_dead_when_only_called_by_dead_method(
        self, tmp_path
    ):
        src = tmp_path / "helper.py"
        src.write_text(
            """
class Helper:
    def run(self):
        return self._helper()

    def _helper(self):
        return 1


HELPER = Helper()
"""
        )

        result_json = analyze(str(tmp_path), conf=0)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}

        assert "Helper.run" in unreachable
        assert "Helper._helper" in unreachable

    def test_analyze_keeps_method_refs_receiver_specific(self, tmp_path):
        src = tmp_path / "plugins.py"
        src.write_text(
            """
class LivePlugin:
    def process(self, event):
        return event["id"]

    def cleanup(self):
        return "unused"


class RemovedPlugin:
    def process(self, event):
        return event["legacy"]


LIVE_PLUGIN = LivePlugin()
BOOTSTRAP_RESULT = LIVE_PLUGIN.process({"id": "boot"})
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}
        unreachable_classes = {item["name"] for item in result["unused_classes"]}

        assert "LivePlugin.process" not in unreachable
        assert "LivePlugin.cleanup" in unreachable
        assert "RemovedPlugin" in unreachable_classes
        assert "RemovedPlugin.process" not in unreachable

    def test_analyze_protocol_methods_only_live_for_reachable_implementers(
        self, tmp_path
    ):
        src = tmp_path / "service.py"
        src.write_text(
            """
from typing import Protocol


class Handler(Protocol):
    def handle(self, payload: str) -> str:
        ...


class EmailHandler:
    def handle(self, payload: str) -> str:
        return payload.upper()


def dispatch(handler: Handler) -> str:
    return handler.handle("welcome")


LIVE_RESULT = dispatch(EmailHandler())


class LegacyHandler:
    def handle(self, payload: str) -> str:
        return payload.lower()


def unused_factory():
    return LegacyHandler()
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}
        unreachable_classes = {item["name"] for item in result["unused_classes"]}

        assert "EmailHandler.handle" not in unreachable
        assert "LegacyHandler" in unreachable_classes
        assert "LegacyHandler.handle" not in unreachable

    def test_analyze_bound_dispatch_receiver_refs_stay_callsite_specific(
        self, tmp_path
    ):
        src = tmp_path / "service.py"
        src.write_text(
            """
from typing import Protocol


class Handler(Protocol):
    def handle(self, payload: str) -> str:
        ...


class EmailHandler:
    def handle(self, payload: str) -> str:
        return payload.upper()


class LegacyHandler:
    def handle(self, payload: str) -> str:
        return payload.lower()


class Processor:
    def dispatch(self, handler: Handler) -> str:
        return handler.handle("welcome")


PROCESSOR = Processor()
LIVE_RESULT = PROCESSOR.dispatch(EmailHandler())
email = EmailHandler()
LIVE_RESULT_2 = PROCESSOR.dispatch(email)
LIVE_RESULT_3 = PROCESSOR.dispatch(handler=EmailHandler())
LEGACY_REGISTRY = {"legacy": LegacyHandler}


def stale_path():
    return PROCESSOR.dispatch(LegacyHandler())
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}
        unreachable_classes = {item["name"] for item in result["unused_classes"]}

        assert "EmailHandler.handle" not in unreachable
        assert "LegacyHandler" not in unreachable_classes
        assert "LegacyHandler.handle" in unreachable
        assert "stale_path" in unreachable

    def test_analyze_explicit_protocol_implementer_method_can_be_dead(self, tmp_path):
        src = tmp_path / "service.py"
        src.write_text(
            """
from typing import Protocol


class Handler(Protocol):
    def handle(self, payload: str) -> str:
        ...


class LegacyHandler(Handler):
    def handle(self, payload: str) -> str:
        return payload.lower()


LEGACY_REGISTRY = {"legacy": LegacyHandler}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}
        unreachable_classes = {item["name"] for item in result["unused_classes"]}

        assert "LegacyHandler" not in unreachable_classes
        assert "LegacyHandler.handle" in unreachable

    def test_analyze_dead_class_suppresses_owned_method_duplicates(self, tmp_path):
        src = tmp_path / "service.py"
        src.write_text(
            """
class Dead:
    def a(self):
        return 1

    def b(self):
        return 2
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}
        unreachable_classes = {item["name"] for item in result["unused_classes"]}

        assert "Dead" in unreachable_classes
        assert "Dead.a" not in unreachable
        assert "Dead.b" not in unreachable

    def test_analyze_js_package_route_attachment_export_is_live(self, tmp_path):
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (tmp_path / "package.json").write_text(
            '{"name":"app","type":"module","main":"src/app.js"}',
            encoding="utf-8",
        )
        (src_dir / "app.js").write_text(
            """
const routes = new Map();

function register(path, handler) {
  routes.set(path, handler);
}

export function healthHandler(req, res) {
  res.end("ok");
}

register("/health", healthHandler);

export function attachRoutes(server) {
  for (const [path, handler] of routes) {
    server.get(path, handler);
  }
}

export function orphanHandler(req, res) {
  res.end("orphan");
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(src_dir), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}
        unused_files = {Path(item["file"]).name for item in result["unused_files"]}

        assert "attachRoutes" not in unreachable
        assert "orphanHandler" in unreachable
        assert "app.js" not in unused_files

    def test_analyze_js_route_attachment_uses_route_shape_not_name_tokens(
        self, tmp_path
    ):
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (tmp_path / "package.json").write_text(
            '{"name":"app","type":"module","main":"src/app.js"}',
            encoding="utf-8",
        )
        (src_dir / "app.js").write_text(
            """
export function healthHandler(req, res) {
  res.end("ok");
}

export function configure(api) {
  api.get("/health", healthHandler);
}

export const attachRoutes = (server) => {
  server.post("/orders", healthHandler);
};

export function applyConfig(config) {
  const key = "theme";
  return config.get(key, defaultHandler);
}

function defaultHandler() {
  return "light";
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(src_dir), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}

        assert "configure" not in unreachable
        assert "attachRoutes" not in unreachable
        assert "applyConfig" in unreachable

    def test_analyze_java_public_static_helper_not_auto_exported(self, tmp_path):
        (tmp_path / "App.java").write_text(
            """
public class App {
    public static void main(String[] args) {
        LiveJob job = new LiveJob();
        System.out.println(job.run());
    }

    public static String staleFormat(String value) {
        return value.trim().toLowerCase();
    }
}

class LiveJob {
    String run() {
        return "ok";
    }
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}

        assert "App.staleFormat" in unreachable

    def test_analyze_java_library_public_method_stays_exported(self, tmp_path):
        (tmp_path / "Api.java").write_text(
            """
public class Api {
    public static void main(String[] args) {
        System.out.println("demo");
    }

    public String main() {
        return "not an entrypoint";
    }

    public String publicEndpoint(String value) {
        return value.trim();
    }

    private String privateHelper(String value) {
        return value.toLowerCase();
    }
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}

        assert "Api.publicEndpoint" not in unreachable
        assert "Api.privateHelper" in unreachable

    def test_analyze_java_serialization_hooks_stay_live(self, tmp_path):
        (tmp_path / "SerializableValue.java").write_text(
            """
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;

public class SerializableValue {
    private Object writeReplace() throws ObjectStreamException {
        return this;
    }

    private void readObject(ObjectInputStream in) throws IOException {
        throw new InvalidObjectException("unsupported");
    }

    private String staleHelper() {
        return "stale";
    }
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}

        assert "SerializableValue.writeReplace" not in unreachable
        assert "SerializableValue.readObject" not in unreachable
        assert "SerializableValue.staleHelper" in unreachable

    def test_analyze_java_abstract_methods_stay_live(self, tmp_path):
        (tmp_path / "RecordStrategy.java").write_text(
            """
public abstract class RecordStrategy {
    abstract String componentName(Class<?> raw);

    private String staleHelper() {
        return "stale";
    }
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}

        assert "RecordStrategy.componentName" not in unreachable
        assert "RecordStrategy.staleHelper" in unreachable

    def test_analyze_java_method_call_disambiguates_field_with_same_name(
        self, tmp_path
    ):
        (tmp_path / "Adapter.java").write_text(
            """
public class Adapter {
    public static void main(String[] args) {
        new Worker().read();
    }
}

class Worker {
    private String delegate;

    void read() {
        delegate();
    }

    private String delegate() {
        return delegate;
    }

    private String staleHelper() {
        return "stale";
    }
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}

        assert "Worker.delegate" not in unreachable
        assert "Worker.staleHelper" in unreachable

    def test_analyze_java_class_for_name_marks_literal_class_live(self, tmp_path):
        (tmp_path / "App.java").write_text(
            """
public class App {
    public static void main(String[] args) throws Exception {
        Class.forName("com.example.Plugin");
    }
}

class Plugin {
    void run() {
    }
}

class StalePlugin {
    void run() {
    }
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable_classes = {item["name"] for item in result["unused_classes"]}

        assert "Plugin" not in unreachable_classes
        assert "StalePlugin" in unreachable_classes

    def test_analyze_java_qualified_call_does_not_rescue_same_class_method(
        self, tmp_path
    ):
        (tmp_path / "App.java").write_text(
            """
public class App {
    public static void main(String[] args) {
        new Worker().read();
    }
}

class Other {
    static void delegate() {
    }
}

class Worker {
    void read() {
        Other.delegate();
    }

    private void delegate() {
    }
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable = {item["name"] for item in result["unused_functions"]}

        assert "Worker.delegate" in unreachable

    def test_analyze_java_framework_annotations_mark_classes_live(self, tmp_path):
        (tmp_path / "Components.java").write_text(
            """
import jakarta.persistence.Entity;
import jakarta.ws.rs.Path;
import org.springframework.stereotype.Service;

@Service
class PackagePrivateService {
    void staleHelper() {
    }
}

@Entity
class AuditRecord {
    private Long id;
}

@Path("/orders")
class OrderResource {
}

class TrulyUnused {
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable_classes = {item["name"] for item in result["unused_classes"]}
        unreachable_functions = {
            item["name"] for item in result["unused_functions"]
        }

        assert "PackagePrivateService" not in unreachable_classes
        assert "AuditRecord" not in unreachable_classes
        assert "OrderResource" not in unreachable_classes
        assert "TrulyUnused" in unreachable_classes
        assert "PackagePrivateService.staleHelper" in unreachable_functions

    def test_analyze_java_junit5_annotations_mark_tests_live(self, tmp_path):
        (tmp_path / "BillingTest.java").write_text(
            """
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class BillingTest {
    @ParameterizedTest
    @ValueSource(strings = {"basic", "pro"})
    void acceptsPlan(String plan) {
        plan.trim();
    }

    @AfterAll
    static void cleanup() {
    }
}

class LegacySuite {
    void stale() {
    }
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unreachable_classes = {item["name"] for item in result["unused_classes"]}
        unreachable_functions = {
            item["name"] for item in result["unused_functions"]
        }

        assert "BillingTest" not in unreachable_classes
        assert "BillingTest.acceptsPlan" not in unreachable_functions
        assert "BillingTest.cleanup" not in unreachable_functions
        assert "LegacySuite" in unreachable_classes

    def test_analyze_typescript_transitive_dead_uses_file_scoped_callers(
        self, tmp_path
    ):
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (tmp_path / "package.json").write_text(
            '{"name":"app","type":"module","main":"src/live.ts"}',
            encoding="utf-8",
        )
        (src_dir / "live.ts").write_text(
            """
function helper() {
  return 1;
}

export function foo() {
  return helper();
}

foo();
""",
            encoding="utf-8",
        )
        (src_dir / "dead.ts").write_text(
            """
function helper() {
  return 2;
}

function foo() {
  return helper();
}
""",
            encoding="utf-8",
        )

        result_json = analyze(str(tmp_path), conf=0, grep_verify=False)
        result = json.loads(result_json)

        unused_by_file = {
            (Path(item["file"]).name, item["name"])
            for item in result["unused_functions"]
        }

        assert ("live.ts", "helper") not in unused_by_file
        assert ("dead.ts", "helper") in unused_by_file
        assert ("dead.ts", "foo") in unused_by_file

    def test_analyze_single_file_skips_project_unused_dependency_rule(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["requests", "rich"]\n',
            encoding="utf-8",
        )
        src = tmp_path / "demo.py"
        src.write_text(
            """
def fake_call():
    print("demo")
""",
            encoding="utf-8",
        )

        result_json = analyze(str(src), conf=0, enable_quality=True)
        result = json.loads(result_json)

        quality = result.get("quality", [])
        dependency_findings = [f for f in quality if f.get("rule_id") == "SKY-U005"]

        assert dependency_findings == []

    def test_analyze_flags_mock_placeholder_data_in_production_file(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text(
            'SUPPORT_EMAIL = "test@example.com"\n'
            'USER_ID = "00000000-0000-0000-0000-000000000000"\n',
            encoding="utf-8",
        )

        result = json.loads(
            analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
        )
        findings = [
            f for f in result.get("quality", []) if f.get("rule_id") == "SKY-L032"
        ]

        assert {f["mock_data_type"] for f in findings} == {
            "placeholder_email",
            "low_entropy_uuid",
        }

    def test_analyze_flags_no_effect_statement(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text(
            """
import uuid

def make_id():
    uuid.uuid4()
    return "ok"
""".strip()
            + "\n",
            encoding="utf-8",
        )

        result = json.loads(
            analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
        )
        findings = [
            f for f in result.get("quality", []) if f.get("rule_id") == "SKY-L033"
        ]

        assert len(findings) == 1
        assert findings[0]["name"] == "uuid.uuid4"
        assert findings[0]["value"] == "discarded_result"

    def test_analyze_flags_unreachable_loop_code(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text(
            """
def poll():
    return None

def run():
    while True:
        poll()
    return "unreachable"
""".strip()
            + "\n",
            encoding="utf-8",
        )

        result = json.loads(
            analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
        )
        findings = [
            f for f in result.get("quality", []) if f.get("rule_id") == "SKY-UC001"
        ]

        assert any(
            f["value"] == "loop that cannot fall through" and f["line"] == 7
            for f in findings
        )

    def test_analyze_repo_rules_use_root_project_ignore_config(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            """
[tool.skylos]
ignore = ["SKY-L021", "SKY-D222", "SKY-D260"]
""".strip(),
            encoding="utf-8",
        )
        root_file = tmp_path / "app.py"
        root_file.write_text("def root_fn():\n    return 1\n", encoding="utf-8")

        nested = tmp_path / "packages" / "nested"
        nested.mkdir(parents=True)
        (nested / "pyproject.toml").write_text(
            """
[tool.skylos]
ignore = []
""".strip(),
            encoding="utf-8",
        )
        nested_file = nested / "module.py"
        nested_file.write_text("def nested_fn():\n    return 2\n", encoding="utf-8")

        diff_result = Mock(returncode=0, stdout="diff")
        real_subprocess_run = subprocess.run

        def selective_subprocess_run(*args, **kwargs):
            if args:
                cmd = args[0]
            else:
                cmd = kwargs.get("args")
            if cmd[:4] == ["git", "diff", "HEAD", "--"]:
                return diff_result
            return real_subprocess_run(*args, **kwargs)

        with (
            patch(
                "subprocess.run",
                side_effect=selective_subprocess_run,
            ),
            patch(
                "skylos.rules.quality.regression.detect_security_regressions",
                return_value=[
                    {
                        "rule_id": "SKY-L021",
                        "file": str(root_file),
                        "line": 1,
                        "message": "regression",
                    }
                ],
            ),
            patch(
                "skylos.rules.ai_defect.dependency_hallucination.scan_python_dependency_hallucinations",
                return_value=[
                    {
                        "rule_id": "SKY-D222",
                        "file": str(root_file),
                        "line": 1,
                        "message": "dependency hallucination",
                    }
                ],
            ),
            patch(
                "skylos.security.injection_scanner.scan_file",
                return_value=[
                    {
                        "rule_id": "SKY-D260",
                        "file": str(root_file),
                        "line": 1,
                        "message": "prompt injection",
                    }
                ],
            ),
        ):
            result = json.loads(
                analyze(
                    [str(root_file), str(nested_file)],
                    conf=0,
                    enable_danger=True,
                    enable_quality=True,
                    enable_ai_defects=True,
                    changed_files={str(root_file.resolve())},
                    grep_verify=False,
                )
            )

        assert "error" not in result
        quality_rule_ids = {
            finding.get("rule_id") for finding in result.get("quality", [])
        }
        danger_rule_ids = {
            finding.get("rule_id") for finding in result.get("danger", [])
        }
        ai_defect_rule_ids = {
            finding.get("rule_id") for finding in result.get("ai_defects", [])
        }

        assert "SKY-L021" not in quality_rule_ids
        assert "SKY-D222" not in danger_rule_ids
        assert "SKY-D222" not in ai_defect_rule_ids
        assert "SKY-D260" not in danger_rule_ids


def test_changed_files_only_scans_changed_config_files_for_secrets(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    changed_cfg = tmp_path / "settings.toml"
    changed_cfg.write_text('token = "abc"\n', encoding="utf-8")
    unchanged_cfg = tmp_path / "secrets.yaml"
    unchanged_cfg.write_text("token: xyz\n", encoding="utf-8")

    scanned = []

    def fake_secret_scan(ctx):
        scanned.append(ctx["relpath"])
        return []

    with patch("skylos.analyzer._secrets_scan_ctx", side_effect=fake_secret_scan):
        json.loads(
            analyze(
                str(tmp_path),
                enable_secrets=True,
                changed_files={str(changed_cfg.resolve())},
                grep_verify=False,
            )
        )

    assert "settings.toml" in scanned
    assert "secrets.yaml" not in scanned


def test_changed_files_scans_dotenv_for_secrets(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    dotenv = tmp_path / ".env"
    dotenv.write_text("API_KEY=test\n", encoding="utf-8")

    scanned = []

    def fake_secret_scan(ctx):
        scanned.append(ctx["relpath"])
        return []

    with patch("skylos.analyzer._secrets_scan_ctx", side_effect=fake_secret_scan):
        json.loads(
            analyze(
                str(tmp_path),
                enable_secrets=True,
                changed_files={str(dotenv.resolve())},
                grep_verify=False,
            )
        )

    assert ".env" in scanned


def test_config_secret_scan_skips_symlink_targets_outside_root(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    outside_secret = tmp_path.parent / "outside_secret"
    outside_secret.write_text("AWS_SECRET_ACCESS_KEY=OUTSIDE\n", encoding="utf-8")
    link = tmp_path / "config.yaml"
    try:
        link.symlink_to(outside_secret)
    except OSError:
        pytest.skip("symlinks are not supported on this filesystem")

    scanned = []

    def fake_secret_scan(ctx):
        scanned.append((ctx["relpath"], "".join(ctx["lines"])))
        return []

    with patch("skylos.analyzer._secrets_scan_ctx", side_effect=fake_secret_scan):
        json.loads(analyze(str(tmp_path), enable_secrets=True, grep_verify=False))

    assert all(rel != "config.yaml" for rel, _ in scanned)
    assert all("OUTSIDE" not in text for _, text in scanned)


def test_changed_files_secret_scan_skips_symlink_targets_outside_root(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    outside_secret = tmp_path.parent / "outside_changed_secret"
    outside_secret.write_text("AWS_SECRET_ACCESS_KEY=OUTSIDE_CHANGED\n", encoding="utf-8")
    link = tmp_path / "config.yaml"
    try:
        link.symlink_to(outside_secret)
    except OSError:
        pytest.skip("symlinks are not supported on this filesystem")

    scanned = []

    def fake_secret_scan(ctx):
        scanned.append((ctx["relpath"], "".join(ctx["lines"])))
        return []

    with patch("skylos.analyzer._secrets_scan_ctx", side_effect=fake_secret_scan):
        json.loads(
            analyze(
                str(tmp_path),
                enable_secrets=True,
                changed_files={str(link)},
                grep_verify=False,
            )
        )

    assert scanned == []


class TestRepoPhantomReferences:
    def test_resolve_analysis_root_stops_at_nested_javascript_package(
        self, tmp_path
    ):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        package_root = tmp_path / "benchmarks" / "typescript-case"
        source_root = package_root / "src"
        source_root.mkdir(parents=True)
        (package_root / "package.json").write_text(
            '{"name": "typescript-case", "private": true}\n',
            encoding="utf-8",
        )

        assert _resolve_analysis_root(source_root) == package_root

    def test_go_engine_report_marks_engine_checks_partial(self):
        with patch(
            "skylos.engines.go_runner.get_go_engine_status",
            return_value={
                "status": "unavailable",
                "reason": "Go engine binary not found",
                "configured_by": "discovery",
            },
        ):
            report = _go_engine_analysis_report([Path("main.go"), Path("helper.py")])

        assert report["status"] == "partial"
        assert report["completed_checks"] == ["quality"]
        assert report["skipped_checks"] == ["dead_code", "security"]

    def test_analyze_reports_unavailable_go_engine_in_summary(self, tmp_path):
        source = tmp_path / "main.go"
        source.write_text("package main\n\nfunc main() {}\n", encoding="utf-8")

        with (
            patch(
                "skylos.engines.go_runner.get_go_engine_status",
                return_value={
                    "status": "unavailable",
                    "reason": "Go engine binary not found",
                    "configured_by": "discovery",
                },
            ),
            patch(
                "skylos.visitors.languages.go.go.run_go_engine_for_module",
                side_effect=RuntimeError("Go engine binary not found"),
            ),
        ):
            result = json.loads(analyze(str(tmp_path), grep_verify=False))

        report = result["analysis_summary"]["language_engines"]["go"]
        assert report["status"] == "partial"
        assert report["skipped_checks"] == ["dead_code", "security"]
        assert result["analysis_summary"]["incomplete_languages"] == ["go"]

    def test_resolve_analysis_root_ignores_home_git_root_without_project_marker(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / ".git").mkdir()
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        case_root = tmp_path / "benchmarks" / "case"
        case_root.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        assert _resolve_analysis_root(case_root) == case_root

    def test_analyze_flags_imported_local_module_member_call(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        pkg = tmp_path / "app"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "security.py").write_text(
            """
def authenticate(request):
    return request
""".strip(),
            encoding="utf-8",
        )
        (pkg / "views.py").write_text(
            """
from app import security

def handler(request):
    return security.require_auth(request)
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, enable_ai_defects=True))
        ai_defects = [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ]

        assert len(ai_defects) == 1
        assert ai_defects[0]["name"] == "security.require_auth"
        assert ai_defects[0]["vibe_category"] == "hallucinated_reference"

    def test_quality_scan_does_not_run_ai_defect_phantom_scan(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        pkg = tmp_path / "app"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "security.py").write_text(
            """
def authenticate(request):
    return request
""".strip(),
            encoding="utf-8",
        )
        (pkg / "views.py").write_text(
            """
from app import security

def handler(request):
    return security.require_auth(request)
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, enable_quality=True))

        assert [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ] == []

    def test_analyze_single_file_runs_repo_phantom_reference_scan(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        pkg = tmp_path / "app"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "security.py").write_text(
            """
def authenticate(request):
    return request
""".strip(),
            encoding="utf-8",
        )
        views = pkg / "views.py"
        views.write_text(
            """
from app import security

def handler(request):
    return security.require_auth(request)
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(views), conf=0, enable_ai_defects=True))
        ai_defects = [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ]

        assert len(ai_defects) == 1
        assert ai_defects[0]["name"] == "security.require_auth"

    def test_analyze_subdirectory_uses_repo_root_for_phantom_scan(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        pkg = tmp_path / "app"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "security.py").write_text(
            """
def authenticate(request):
    return request
""".strip(),
            encoding="utf-8",
        )
        (pkg / "views.py").write_text(
            """
from app import security

def handler(request):
    return security.require_auth(request)
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(pkg), conf=0, enable_ai_defects=True))
        ai_defects = [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ]

        assert len(ai_defects) == 1
        assert ai_defects[0]["name"] == "security.require_auth"

    def test_analyze_nested_subproject_uses_nearest_project_root(self, tmp_path):
        backend = tmp_path / "backend"
        backend.mkdir()
        (backend / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")

        pkg = backend / "app"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "security.py").write_text(
            """
def authenticate(request):
    return request
""".strip(),
            encoding="utf-8",
        )
        (pkg / "views.py").write_text(
            """
from app import security

def handler(request):
    return security.require_auth(request)
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(pkg), conf=0, enable_ai_defects=True))
        ai_defects = [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ]

        assert len(ai_defects) == 1
        assert ai_defects[0]["name"] == "security.require_auth"

    def test_analyze_nested_subproject_ignore_applies_to_repo_phantom_scan(
        self, tmp_path
    ):
        backend = tmp_path / "backend"
        backend.mkdir()
        (backend / "pyproject.toml").write_text(
            """
[tool.skylos]
ignore = ["SKY-L012"]
""".strip(),
            encoding="utf-8",
        )

        pkg = backend / "app"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "security.py").write_text(
            """
def authenticate(request):
    return request
""".strip(),
            encoding="utf-8",
        )
        (pkg / "views.py").write_text(
            """
from app import security

def handler(request):
    return security.require_auth(request)
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(backend), conf=0, enable_ai_defects=True))
        ai_defects = [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ]

        assert ai_defects == []

    def test_analyze_repo_phantom_respects_inline_ignore_pragmas(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        pkg = tmp_path / "app"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "security.py").write_text(
            """
def authenticate(request):
    return request
""".strip(),
            encoding="utf-8",
        )
        (pkg / "views.py").write_text(
            """
from app import security

def handler(request):
    return security.require_auth(request)  # skylos: ignore
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, enable_ai_defects=True))
        ai_defects = [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ]
        suppressed = [
            f for f in result.get("suppressed", []) if f.get("rule_id") == "SKY-L012"
        ]

        assert ai_defects == []
        assert len(suppressed) == 1
        assert suppressed[0]["reason"] == "inline ignore comment"
        check = next(
            item
            for item in result["analysis_summary"]["ai_verification"]["checks"]
            if item["id"] == "python_local_api_reference"
        )
        assert check["outcome"] == "pass"
        assert check["suppressed_findings"] == 1
        assert {reason["code"] for reason in check["reasons"]} >= {"finding_suppressed"}

    def test_analyze_subtree_marks_repo_local_modules_outside_selection_incomplete(
        self, tmp_path
    ):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")

        common = tmp_path / "common"
        common.mkdir()
        (common / "__init__.py").write_text("", encoding="utf-8")
        (common / "security.py").write_text(
            """
def authenticate(request):
    return request
""".strip(),
            encoding="utf-8",
        )

        app = tmp_path / "app"
        app.mkdir()
        (app / "__init__.py").write_text("", encoding="utf-8")
        (app / "views.py").write_text(
            """
from common import security

def handler(request):
    return security.require_auth(request)
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(app), conf=0, enable_ai_defects=True))
        ai_defects = [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ]

        assert ai_defects == []
        check = next(
            item
            for item in result["analysis_summary"]["ai_verification"]["checks"]
            if item["id"] == "python_local_api_reference"
        )
        assert check["outcome"] == "incomplete"
        assert check["reasons"] == [{"code": "local_import_outside_scan", "count": 1}]

    def test_analyze_flags_stale_bare_call_resembling_local_symbol(self, tmp_path):
        pkg = tmp_path / "billing"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "totals.py").write_text(
            """
def calculate_total(items):
    return sum(items)
""".strip(),
            encoding="utf-8",
        )
        (pkg / "workflow.py").write_text(
            """
from billing.totals import calculate_total

def create_invoice(order):
    return compute_total(order["items"])
""".strip(),
            encoding="utf-8",
        )

        result = json.loads(analyze(str(tmp_path), conf=0, enable_ai_defects=True))
        ai_defects = [
            f for f in result.get("ai_defects", []) if f.get("rule_id") == "SKY-L012"
        ]

        assert len(ai_defects) == 1
        assert ai_defects[0]["name"] == "compute_total"
        assert ai_defects[0]["vibe_category"] == "hallucinated_reference"

    def test_danger_scan_does_not_run_sca_without_enable_sca(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        (tmp_path / "app.py").write_text("def handler():\n    return 1\n")

        from skylos.rules.sca import vulnerability_scanner

        def fail_scan_dependencies(*args, **kwargs):
            raise AssertionError("SCA should only run when enable_sca=True")

        monkeypatch.setattr(
            vulnerability_scanner,
            "scan_dependencies",
            fail_scan_dependencies,
        )

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_danger=True,
                grep_verify=False,
            )
        )

        assert "dependency_vulnerabilities" not in result
        assert "sca_count" not in result.get("analysis_summary", {})

    def test_enable_sca_runs_dependency_vulnerability_scan(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        (tmp_path / "app.py").write_text("def handler():\n    return 1\n")

        from skylos.rules.sca import vulnerability_scanner

        monkeypatch.setattr(
            vulnerability_scanner,
            "scan_dependencies",
            lambda root: [{"rule_id": "CVE-TEST", "file": str(root), "line": 1}],
        )

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_sca=True,
                grep_verify=False,
            )
        )

        assert result["analysis_summary"]["sca_count"] == 1
        assert result["dependency_vulnerabilities"][0]["rule_id"] == "CVE-TEST"

    def test_ai_defect_scan_checks_manifest_dependencies_without_python_files(
        self, tmp_path, monkeypatch
    ):
        project = tmp_path / "repo"
        manifest_only = project / "fixtures" / "manifest_only"
        manifest_only.mkdir(parents=True)
        (project / "pyproject.toml").write_text(
            "[tool.skylos]\n",
            encoding="utf-8",
        )
        (project / "package.json").write_text(
            json.dumps({"dependencies": {"parent-only": "99.99.99"}}),
            encoding="utf-8",
        )
        (manifest_only / "package.json").write_text(
            json.dumps({"dependencies": {"child-only": "99.99.99"}}),
            encoding="utf-8",
        )

        from skylos.rules.ai_defect import manifest_dependency_hallucination

        def fake_status_checker(_ecosystem, _name, _version, _cache):
            return manifest_dependency_hallucination.STATUS_MISSING_VERSION

        monkeypatch.setattr(
            manifest_dependency_hallucination,
            "check_dependency_version_status",
            fake_status_checker,
        )

        raw_result = analyze(
            str(manifest_only),
            conf=0,
            enable_ai_defects=True,
            grep_verify=False,
        )
        result = json.loads(raw_result)

        ai_defects = result.get("ai_defects")
        assert isinstance(ai_defects, list)
        assert result["analysis_summary"]["ai_defects_count"] == 1
        assert not result.get("danger")
        assert ai_defects[0]["rule_id"] == "SKY-D225"
        assert ai_defects[0]["metadata"]["package_name"] == "child-only"

    def test_ai_defect_dependency_scan_uses_project_root_for_src_layout(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        pkg = tmp_path / "src" / "my_package"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "module.py").write_text("import requests\n", encoding="utf-8")

        from skylos.rules.ai_defect import dependency_hallucination

        seen = {}

        def fake_scan(repo_root, py_files):
            seen["repo_root"] = Path(repo_root)
            seen["py_files"] = list(py_files)
            cache_path = Path(repo_root) / ".skylos" / "cache" / "pypi_exists.json"
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text("{}", encoding="utf-8")
            return []

        monkeypatch.setattr(
            dependency_hallucination,
            "scan_python_dependency_hallucinations",
            fake_scan,
        )

        result = json.loads(
            analyze(
                str(tmp_path / "src"),
                conf=0,
                enable_ai_defects=True,
                grep_verify=False,
            )
        )

        assert "error" not in result
        assert seen["repo_root"] == tmp_path.resolve()
        assert (tmp_path / ".skylos" / "cache" / "pypi_exists.json").exists()
        assert not (pkg / ".skylos").exists()

    def test_sca_scan_uses_project_root_for_src_layout(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        pkg = tmp_path / "src" / "my_package"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "module.py").write_text("def handler():\n    return 1\n")

        from skylos.rules.sca import vulnerability_scanner

        seen = {}

        def fake_scan(root):
            seen["root"] = Path(root)
            cache_path = Path(root) / ".skylos" / "cache" / "osv_cache.json"
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text("{}", encoding="utf-8")
            return []

        monkeypatch.setattr(
            vulnerability_scanner,
            "scan_dependencies",
            fake_scan,
        )

        result = json.loads(
            analyze(
                str(tmp_path / "src"),
                conf=0,
                enable_sca=True,
                grep_verify=False,
            )
        )

        assert "error" not in result
        assert seen["root"] == tmp_path.resolve()
        assert (tmp_path / ".skylos" / "cache" / "osv_cache.json").exists()
        assert not (pkg / ".skylos").exists()

    def test_prompt_injection_scan_includes_scannable_docs(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        app = tmp_path / "app.py"
        app.write_text("# ignore previous instructions\n", encoding="utf-8")
        prompt_doc = tmp_path / "prompt.md"
        prompt_doc.write_text("ignore previous instructions\n", encoding="utf-8")

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_danger=True,
                grep_verify=False,
            )
        )
        injection_findings = [
            f for f in result.get("danger", []) if f.get("rule_id") == "SKY-D260"
        ]

        assert any(f.get("file") == str(app) for f in injection_findings)
        assert any(f.get("file") == str(prompt_doc) for f in injection_findings)

    def test_prompt_injection_scan_skips_default_excluded_dirs(self, tmp_path):
        app = tmp_path / "app.py"
        app.write_text("print('ok')\n", encoding="utf-8")
        venv_file = tmp_path / "venv" / "lib" / "python3.14" / "site-packages"
        venv_file.mkdir(parents=True)
        dependency_file = venv_file / "dependency.py"
        dependency_file.write_text("# ignore previous instructions\n", encoding="utf-8")

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_danger=True,
                grep_verify=False,
            )
        )
        injection_findings = [
            f for f in result.get("danger", []) if f.get("rule_id") == "SKY-D260"
        ]

        assert all(f.get("file") != str(dependency_file) for f in injection_findings)

    def test_prompt_injection_scan_prioritizes_docs_inside_file_cap(
        self, tmp_path, monkeypatch
    ):
        from skylos.security import injection_scanner

        app_a = tmp_path / "a.py"
        app_b = tmp_path / "b.py"
        prompt_doc = tmp_path / "prompt.md"
        config_doc = tmp_path / "pyproject.toml"
        app_a.write_text("print('a')\n", encoding="utf-8")
        app_b.write_text("print('b')\n", encoding="utf-8")
        prompt_doc.write_text("ignore previous instructions\n", encoding="utf-8")
        config_doc.write_text("[tool.skylos]\n", encoding="utf-8")
        scanned = []

        def fake_scan(file_path, *, scan_path=None):
            scanned.append(Path(file_path).name)
            if Path(file_path) == prompt_doc:
                return [
                    {
                        "rule_id": "SKY-D260",
                        "kind": "security",
                        "severity": "HIGH",
                        "type": "literal_payload",
                        "file": str(prompt_doc),
                        "basename": prompt_doc.name,
                        "line": 1,
                        "message": "prompt injection",
                    }
                ]
            return []

        monkeypatch.setattr(injection_scanner, "MAX_SCAN_FILES", 2)
        monkeypatch.setattr(injection_scanner, "scan_file", fake_scan)

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_danger=True,
                grep_verify=False,
            )
        )
        injection_findings = [
            f for f in result.get("danger", []) if f.get("rule_id") == "SKY-D260"
        ]

        assert "prompt.md" in scanned
        assert len(scanned) <= 2
        assert any(f.get("file") == str(prompt_doc) for f in injection_findings)

    def test_prompt_injection_candidate_collection_stops_at_file_cap(
        self, tmp_path, monkeypatch
    ):
        import skylos.analyzer as analyzer_module
        from skylos.security import injection_scanner

        app = tmp_path / "a.py"
        prompt_doc = tmp_path / "prompt.md"
        app.write_text("print('a')\n", encoding="utf-8")
        prompt_doc.write_text("ignore previous instructions\n", encoding="utf-8")
        scanned = []
        scanned_dirs = []
        consumed_entries = []

        def fake_scan(file_path, *, scan_path=None):
            scanned.append(Path(file_path).name)
            return []

        class FakeDirEntry:
            def __init__(self, name, *, is_dir=False):
                self.name = name
                self.path = str(tmp_path / name)
                self._is_dir = is_dir

            def is_dir(self, *, follow_symlinks=True):
                return self._is_dir

        class FakeScandir:
            def __iter__(self):
                consumed_entries.append("a.py")
                yield FakeDirEntry("a.py")
                for idx in range(1000):
                    name = f"filler_{idx}.md"
                    consumed_entries.append(name)
                    yield FakeDirEntry(name)
                consumed_entries.append("later")
                yield FakeDirEntry("later", is_dir=True)

            def close(self):
                return None

        def fake_scandir(root):
            scanned_dirs.append(Path(root))
            return FakeScandir()

        real_os = analyzer_module.os

        class OsProxy:
            def __getattr__(self, name):
                return getattr(real_os, name)

        monkeypatch.setattr(injection_scanner, "MAX_SCAN_FILES", 2)
        monkeypatch.setattr(injection_scanner, "scan_file", fake_scan)
        monkeypatch.setattr(
            analyzer_module.Skylos,
            "_discover_files",
            lambda self, path, exclude_folders=None: ([app], tmp_path),
        )
        os_proxy = OsProxy()
        os_proxy.scandir = fake_scandir
        monkeypatch.setattr(analyzer_module, "os", os_proxy)

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_danger=True,
                grep_verify=False,
            )
        )

        assert "error" not in result
        assert scanned == ["prompt.md", "a.py"]
        assert scanned_dirs == [tmp_path]
        assert consumed_entries == ["a.py"]

    def test_prompt_injection_scan_caps_reported_findings(
        self, tmp_path, monkeypatch
    ):
        from skylos.security import injection_scanner

        (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        app = tmp_path / "app.py"
        app.write_text("print('ok')\n", encoding="utf-8")
        injected = [
            {
                "rule_id": "SKY-D260",
                "kind": "security",
                "severity": "HIGH",
                "type": "hidden_char",
                "file": str(app),
                "basename": app.name,
                "line": idx + 1,
                "message": "prompt injection",
            }
            for idx in range(injection_scanner.MAX_SCAN_FINDINGS + 5)
        ]

        monkeypatch.setattr(
            injection_scanner, "scan_file", lambda *_args, **_kwargs: injected
        )

        result = json.loads(
            analyze(
                str(tmp_path),
                conf=0,
                enable_danger=True,
                grep_verify=False,
            )
        )
        injection_findings = [
            f for f in result.get("danger", []) if f.get("rule_id") == "SKY-D260"
        ]

        assert len(injection_findings) == injection_scanner.MAX_SCAN_FINDINGS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
