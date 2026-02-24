import json
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from skylos.module_reachability import (
    ModuleReachabilityAnalyzer,
    find_unreachable_modules,
)


def _mock_def(simple_name, def_type="function"):
    m = Mock()
    m.simple_name = simple_name
    m.type = def_type
    return m


def _make_modmap(mapping):
    return {Path(k): v for k, v in mapping.items()}


def _make_raw_imports(mapping):
    return {Path(k): v for k, v in mapping.items()}


class TestLinearChain:
    def test_all_reachable(self):
        modmap = _make_modmap(
            {
                "a/__init__.py": "a",
                "a/b.py": "a.b",
                "a/c.py": "a.c",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "a/__init__.py": [("a.b", 1, "from_import", ["something"])],
                "a/b.py": [("a.c", 1, "from_import", ["something"])],
                "a/c.py": [],
            }
        )
        unreachable = find_unreachable_modules(modmap, raw_imports)
        assert unreachable == set()


class TestOrphanModule:
    def test_orphan_detected(self):
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                "pkg/used.py": "pkg.used",
                "pkg/orphan.py": "pkg.orphan",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [("pkg.used", 1, "from_import", ["x"])],
                "pkg/used.py": [],
                "pkg/orphan.py": [],
            }
        )
        unreachable = find_unreachable_modules(modmap, raw_imports)
        assert "pkg.orphan" in unreachable
        assert "pkg" not in unreachable
        assert "pkg.used" not in unreachable

    def test_orphan_not_detected_if_entry_point(self):
        """conftest.py is always an entry point."""
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                "conftest.py": "conftest",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [],
                "conftest.py": [],
            }
        )
        unreachable = find_unreachable_modules(modmap, raw_imports)
        assert "conftest" not in unreachable


class TestDiamond:
    def test_diamond_all_reachable(self):
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                "pkg/b.py": "pkg.b",
                "pkg/c.py": "pkg.c",
                "pkg/d.py": "pkg.d",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [
                    ("pkg.b", 1, "from_import", ["B"]),
                    ("pkg.c", 2, "from_import", ["C"]),
                ],
                "pkg/b.py": [("pkg.d", 1, "from_import", ["D"])],
                "pkg/c.py": [("pkg.d", 1, "from_import", ["D"])],
                "pkg/d.py": [],
            }
        )
        unreachable = find_unreachable_modules(modmap, raw_imports)
        assert unreachable == set()


class TestGetattrPackage:
    def test_siblings_reachable_via_getattr(self):
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                "pkg/a.py": "pkg.a",
                "pkg/b.py": "pkg.b",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [],
                "pkg/a.py": [],
                "pkg/b.py": [],
            }
        )
        unreachable_without = find_unreachable_modules(modmap, raw_imports)
        assert "pkg.a" in unreachable_without
        assert "pkg.b" in unreachable_without

        file_defs = {
            Path("pkg/__init__.py"): [_mock_def("__getattr__", "function")],
        }
        unreachable_with = find_unreachable_modules(
            modmap, raw_imports, file_defs=file_defs
        )
        assert "pkg.a" not in unreachable_with
        assert "pkg.b" not in unreachable_with

    def test_getattr_only_applies_to_init_py(self):
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                "pkg/a.py": "pkg.a",
                "pkg/b.py": "pkg.b",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [("pkg.a", 1, "from_import", ["x"])],
                "pkg/a.py": [],
                "pkg/b.py": [],
            }
        )
        file_defs = {
            Path("pkg/a.py"): [_mock_def("__getattr__", "function")],
        }
        unreachable = find_unreachable_modules(modmap, raw_imports, file_defs=file_defs)
        assert "pkg.b" in unreachable


class TestConventionEntryPoints:
    @pytest.mark.parametrize(
        "filename,expected_entry",
        [
            ("manage.py", True),
            ("wsgi.py", True),
            ("asgi.py", True),
            ("conftest.py", True),
            ("app.py", True),
            ("random_module.py", False),
        ],
    )
    def test_convention_files(self, filename, expected_entry):
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                filename: filename.replace(".py", ""),
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [],
                filename: [],
            }
        )
        analyzer = ModuleReachabilityAnalyzer()
        analyzer.build(modmap, raw_imports)
        mod_name = filename.replace(".py", "")
        if expected_entry:
            assert mod_name in analyzer.entry_points
        else:
            assert mod_name not in analyzer.entry_points


class TestTestFiles:
    def test_test_file_is_entry_point(self):
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                "test_foo.py": "test_foo",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [],
                "test_foo.py": [],
            }
        )
        analyzer = ModuleReachabilityAnalyzer()
        analyzer.build(modmap, raw_imports)
        assert "test_foo" in analyzer.entry_points


class TestPyprojectEntrypoints:
    def test_pyproject_script_marks_module(self):
        modmap = _make_modmap(
            {
                "myapp/__init__.py": "myapp",
                "myapp/cli.py": "myapp.cli",
                "myapp/utils.py": "myapp.utils",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "myapp/__init__.py": [],
                "myapp/cli.py": [("myapp.utils", 1, "from_import", ["helper"])],
                "myapp/utils.py": [],
            }
        )
        pyproject_eps = {"myapp.cli.main"}
        unreachable = find_unreachable_modules(
            modmap, raw_imports, pyproject_entrypoints=pyproject_eps
        )
        assert "myapp.cli" not in unreachable
        assert "myapp.utils" not in unreachable


class TestDynamicModules:
    def test_dynamic_module_marks_siblings_reachable(self):
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                "pkg/loader.py": "pkg.loader",
                "pkg/hidden.py": "pkg.hidden",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [("pkg.loader", 1, "from_import", ["load"])],
                "pkg/loader.py": [],
                "pkg/hidden.py": [],
            }
        )
        unreachable_no_dyn = find_unreachable_modules(modmap, raw_imports)
        assert "pkg.hidden" in unreachable_no_dyn

        unreachable_dyn = find_unreachable_modules(
            modmap, raw_imports, dynamic_modules={"pkg"}
        )
        assert "pkg.hidden" not in unreachable_dyn


class TestSingleFile:
    def test_single_file(self):
        modmap = _make_modmap({"main.py": "main"})
        raw_imports = _make_raw_imports({"main.py": []})
        unreachable = find_unreachable_modules(modmap, raw_imports)
        assert unreachable == set()


class TestNoEntryPoints:
    def test_no_entry_points_returns_empty(self):
        modmap = _make_modmap(
            {
                "deep/nested/mod.py": "deep.nested.mod",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "deep/nested/mod.py": [],
            }
        )
        unreachable = find_unreachable_modules(modmap, raw_imports)
        assert unreachable == set()


class TestResolveTarget:
    def test_exact_match(self):
        analyzer = ModuleReachabilityAnalyzer()
        analyzer.all_modules = {"foo", "foo.bar", "foo.bar.baz"}
        assert analyzer._resolve_target("foo.bar.baz") == "foo.bar.baz"

    def test_partial_match(self):
        analyzer = ModuleReachabilityAnalyzer()
        analyzer.all_modules = {"foo", "foo.bar"}
        assert analyzer._resolve_target("foo.bar.baz") == "foo.bar"

    def test_root_fallback(self):
        analyzer = ModuleReachabilityAnalyzer()
        analyzer.all_modules = {"foo"}
        assert analyzer._resolve_target("foo.bar.baz") == "foo"

    def test_no_match(self):
        analyzer = ModuleReachabilityAnalyzer()
        analyzer.all_modules = {"bar"}
        assert analyzer._resolve_target("foo.bar.baz") is None


class TestExternalImportsIgnored:
    def test_external_not_in_graph(self):
        modmap = _make_modmap(
            {
                "pkg/__init__.py": "pkg",
                "pkg/core.py": "pkg.core",
            }
        )
        raw_imports = _make_raw_imports(
            {
                "pkg/__init__.py": [("pkg.core", 1, "from_import", ["x"])],
                "pkg/core.py": [
                    ("numpy", 1, "import", ["numpy"]),
                    ("requests", 2, "import", ["requests"]),
                ],
            }
        )
        analyzer = ModuleReachabilityAnalyzer()
        analyzer.build(modmap, raw_imports)
        # numpy and requests should NOT be in the graph
        all_targets = set()
        for targets in analyzer.graph.values():
            all_targets.update(targets)
        assert "numpy" not in all_targets
        assert "requests" not in all_targets


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
