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


class TestMultiPath:
    def test_single_path_string(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "app"
            app.mkdir()
            (app / "main.py").write_text("def used(): pass\ndef dead_func(): pass\nused()\n")

            s = Skylos()
            result = json.loads(s.analyze(str(app), thr=20))
            names = [f["simple_name"] for f in result["unused_functions"]]
            assert "dead_func" in names

    def test_single_path_list(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "app"
            app.mkdir()
            (app / "main.py").write_text("def used(): pass\ndef dead_func(): pass\nused()\n")

            s = Skylos()
            result = json.loads(s.analyze([str(app)], thr=20))
            names = [f["simple_name"] for f in result["unused_functions"]]
            assert "dead_func" in names

    def test_two_disjoint_paths(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "src"
            app.mkdir()
            (app / "main.py").write_text("def app_dead(): pass\n")

            lib = Path(d) / "lib"
            lib.mkdir()
            (lib / "helpers.py").write_text("def lib_dead(): pass\n")

            s = Skylos()
            result = json.loads(s.analyze([str(app), str(lib)], thr=20))
            names = [f["simple_name"] for f in result["unused_functions"]]
            assert "app_dead" in names, "Should find unused func in first path"
            assert "lib_dead" in names, "Should find unused func in second path"

    def test_cross_path_references_resolved(self):
        with tempfile.TemporaryDirectory() as d:
            lib = Path(d) / "lib"
            lib.mkdir()
            (lib / "utils.py").write_text("def helper(): return 1\n")

            app = Path(d) / "app"
            app.mkdir()
            (app / "main.py").write_text("from lib.utils import helper\nhelper()\n")

            s = Skylos()
            result = json.loads(s.analyze([str(lib), str(app)], thr=20))
            func_names = [f["simple_name"] for f in result["unused_functions"]]
            assert "helper" not in func_names, "Cross-path call should resolve"

    def test_duplicate_files_deduplicated(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "app"
            app.mkdir()
            (app / "main.py").write_text("def only_func(): pass\n")

            s = Skylos()
            result = json.loads(s.analyze([str(app), str(app)], thr=20))
            names = [f["simple_name"] for f in result["unused_functions"]]
            assert names.count("only_func") == 1, "Should not duplicate findings"

    def test_parent_and_child_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "project"
            root.mkdir()
            sub = root / "sub"
            sub.mkdir()
            (root / "top.py").write_text("def top_dead(): pass\n")
            (sub / "bot.py").write_text("def bot_dead(): pass\n")

            s = Skylos()
            result = json.loads(s.analyze([str(root), str(sub)], thr=20))
            names = [f["simple_name"] for f in result["unused_functions"]]
            assert "top_dead" in names
            assert "bot_dead" in names
            assert names.count("bot_dead") == 1, "Child path files should be deduplicated"

    def test_empty_path_in_list(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "app"
            app.mkdir()
            (app / "main.py").write_text("def lonely(): pass\n")

            empty = Path(d) / "empty"
            empty.mkdir()

            s = Skylos()
            result = json.loads(s.analyze([str(app), str(empty)], thr=20))
            names = [f["simple_name"] for f in result["unused_functions"]]
            assert "lonely" in names

    def test_file_path_in_multi_list(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "app"
            app.mkdir()
            (app / "main.py").write_text("def dir_func(): pass\n")

            single = Path(d) / "solo.py"
            single.write_text("def file_func(): pass\n")

            s = Skylos()
            result = json.loads(s.analyze([str(app), str(single)], thr=20))
            names = [f["simple_name"] for f in result["unused_functions"]]
            assert "dir_func" in names
            assert "file_func" in names


class TestPrivateNamePenalty:
    def _analyze(self, code, filename="example.py", thr=60):
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / filename
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(code)
            s = Skylos()
            return json.loads(s.analyze(str(d), thr=thr))

    def test_private_func_hidden_at_default_threshold(self):
        result = self._analyze("def _secret(): pass\n", thr=60)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "_secret" not in names

    def test_private_func_visible_at_low_threshold(self):
        result = self._analyze("def _secret(): pass\n", thr=20)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "_secret" in names

    def test_private_var_hidden_at_default_threshold(self):
        result = self._analyze("_hidden = 42\n", thr=60)
        names = [v["simple_name"] for v in result["unused_variables"]]
        assert "_hidden" not in names

    def test_private_var_visible_at_low_threshold(self):
        result = self._analyze("_hidden = 42\n", thr=20)
        names = [v["simple_name"] for v in result["unused_variables"]]
        assert "_hidden" in names

    def test_public_func_visible_at_default_threshold(self):
        result = self._analyze("def obvious_dead(): pass\n", thr=60)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "obvious_dead" in names

    def test_dunder_never_flagged(self):
        code = "class Foo:\n    def __repr__(self): return 'Foo'\n"
        result = self._analyze(code, thr=1)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "__repr__" not in names

    def test_private_confidence_between_20_and_60(self):
        code = "def _internal(): pass\n"
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "mod.py").write_text(code)
            s = Skylos()
            s.analyze(str(d), thr=1)
            for defn in s.defs.values():
                if defn.simple_name == "_internal":
                    assert 20 < defn.confidence < 60, (
                        f"Private confidence should be (20,60), got {defn.confidence}"
                    )
                    break
            else:
                pytest.fail("_internal not found in defs")

    def test_private_with_call_not_flagged(self):
        code = "def _helper(): return 1\nx = _helper()\n"
        result = self._analyze(code, thr=1)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "_helper" not in names


class TestAbstractMethodDeclarations:
    def _analyze(self, code, filename="example.py", thr=60):
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / filename
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(code)
            s = Skylos()
            return json.loads(s.analyze(str(d), thr=thr))

    def test_abstractmethod_not_flagged(self):
        code = """
from abc import ABC, abstractmethod

class Repository(ABC):
    @abstractmethod
    def create(self, data):
        ...

    @abstractmethod
    def delete(self, id):
        ...

class SqlRepository(Repository):
    def create(self, data):
        return data

    def delete(self, id):
        pass
"""
        result = self._analyze(code, thr=1)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "create" not in names, "Abstract/implemented 'create' should not be flagged"
        assert "delete" not in names, "Abstract/implemented 'delete' should not be flagged"

    def test_abstract_class_methods_suppressed(self):
        code = """
from abc import ABC, abstractmethod

class Notifier(ABC):
    @abstractmethod
    def send(self, msg: str) -> None:
        ...

class SlackNotifier(Notifier):
    def send(self, msg: str) -> None:
        print(msg)
"""
        result = self._analyze(code, thr=1)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "send" not in names

    def test_abc_implementer_methods_not_flagged(self):
        code = """
from abc import ABC, abstractmethod

class Handler(ABC):
    @abstractmethod
    def handle(self, request): ...

    @abstractmethod
    def validate(self, data): ...

class UserHandler(Handler):
    def handle(self, request):
        return "handled"

    def validate(self, data):
        return True

class AdminHandler(Handler):
    def handle(self, request):
        return "admin"

    def validate(self, data):
        return data is not None
"""
        result = self._analyze(code, thr=1)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "handle" not in names
        assert "validate" not in names

    def test_non_abstract_unused_method_still_flagged(self):
        code = """
from abc import ABC, abstractmethod

class Base(ABC):
    @abstractmethod
    def required(self): ...

class Impl(Base):
    def required(self):
        return True

    def extra_unused(self):
        return "I am dead code"
"""
        result = self._analyze(code, thr=20)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "required" not in names, "ABC implementation should not be flagged"
        assert "extra_unused" in names, "Non-abstract unused method should be flagged"


class TestPatternTrackerScoping:
    def _analyze(self, files_dict, thr=20):
        with tempfile.TemporaryDirectory() as d:
            for filename, code in files_dict.items():
                fp = Path(d) / filename
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(code)
            s = Skylos()
            return json.loads(s.analyze(str(d), thr=thr))

    def test_fstring_pattern_scoped_to_module(self):
        files = {
            "export.py": """
import sys

def export_csv(data): return "csv"
def export_json(data): return "json"

def run_export(data, fmt):
    handler = getattr(sys.modules[__name__], f"export_{fmt}", None)
    return handler(data)
""",
            "audit.py": """
def export_audit_log(): return "audit data"
""",
        }
        result = self._analyze(files, thr=20)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "export_csv" not in names, "Same-module pattern should match"
        assert "export_json" not in names, "Same-module pattern should match"
        assert "export_audit_log" in names, "Cross-module pattern should NOT match"

    def test_globals_pattern_scoped_to_module(self):
        files = {
            "handlers.py": """
def handle_create(): return "created"
def handle_delete(): return "deleted"

MAP = {a: globals()[f"handle_{a}"] for a in ("create", "delete")}
""",
            "other.py": """
def handle_request(): return "other"
""",
        }
        result = self._analyze(files, thr=20)
        names = [f["simple_name"] for f in result["unused_functions"]]
        assert "handle_create" not in names
        assert "handle_delete" not in names
        assert "handle_request" in names, "Different module should still be flagged"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
