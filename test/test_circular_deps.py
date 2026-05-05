import ast
import pytest
from skylos.architecture import get_architecture_findings
from skylos.circular_deps import (
    CircularDependencyAnalyzer,
    CircularDependencyRule,
    DependencyGraphBuilder,
    analyze_circular_dependencies,
)


class TestDependencyGraphBuilder:
    """Test the AST visitor that extracts imports."""

    def test_simple_import(self):
        code = "import foo"
        tree = ast.parse(code)
        known = {"foo"}

        builder = DependencyGraphBuilder("mymodule", "mymodule.py", known)
        builder.visit(tree)

        assert len(builder.dependencies) == 1
        assert builder.dependencies[0].to_module == "foo"
        assert builder.dependencies[0].import_type == "import"
        assert len(builder.architecture_dependencies) == 1
        assert builder.architecture_dependencies[0].to_module == "foo"

    def test_from_package_import_known_submodule(self):
        code = "from myproject import submodule"
        tree = ast.parse(code)
        known = {"myproject", "myproject.submodule"}

        builder = DependencyGraphBuilder("main", "main.py", known)
        builder.visit(tree)

        assert len(builder.dependencies) == 1
        assert builder.dependencies[0].to_module == "myproject"
        assert len(builder.architecture_dependencies) == 1
        assert builder.architecture_dependencies[0].to_module == "myproject.submodule"

    def test_from_import(self):
        code = "from foo import bar, baz"
        tree = ast.parse(code)
        known = {"foo"}

        builder = DependencyGraphBuilder("mymodule", "mymodule.py", known)
        builder.visit(tree)

        assert len(builder.dependencies) == 1
        assert builder.dependencies[0].to_module == "foo"
        assert builder.dependencies[0].import_type == "from_import"
        assert "bar" in builder.dependencies[0].imported_names
        assert "baz" in builder.dependencies[0].imported_names

    def test_ignores_external_modules(self):
        code = """
import os
import sys
from pathlib import Path
import myproject
"""
        tree = ast.parse(code)
        known = {"myproject"}

        builder = DependencyGraphBuilder("main", "main.py", known)
        builder.visit(tree)

        assert len(builder.dependencies) == 1
        assert builder.dependencies[0].to_module == "myproject"
        assert len(builder.architecture_dependencies) == 1
        assert builder.architecture_dependencies[0].to_module == "myproject"

    def test_dotted_import(self):
        code = "from myproject.submodule import thing"
        tree = ast.parse(code)
        known = {"myproject", "myproject.submodule"}

        builder = DependencyGraphBuilder("main", "main.py", known)
        builder.visit(tree)

        assert len(builder.dependencies) == 1
        assert builder.dependencies[0].to_module == "myproject"
        assert len(builder.architecture_dependencies) == 1
        assert builder.architecture_dependencies[0].to_module == "myproject.submodule"

    def test_tracks_line_number(self):
        code = """# comment
# another comment
import foo
"""
        tree = ast.parse(code)
        known = {"foo"}

        builder = DependencyGraphBuilder("main", "main.py", known)
        builder.visit(tree)

        assert builder.dependencies[0].import_line == 3


class TestCircularDependencyAnalyzer:
    def test_no_cycles_linear(self):
        """A -> B -> C (no cycle)"""
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py", "c": "c.py"}
        analyzer.dependencies = {
            "a": {"b"},
            "b": {"c"},
            "c": set(),
        }

        cycles = analyzer.find_simple_cycles()
        assert len(cycles) == 0

    def test_simple_two_node_cycle(self):
        """A -> B -> A"""
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py"}
        analyzer.dependencies = {
            "a": {"b"},
            "b": {"a"},
        }

        cycles = analyzer.find_simple_cycles()
        assert len(cycles) == 1
        assert set(cycles[0]) == {"a", "b"}

    def test_three_node_cycle(self):
        """A -> B -> C -> A"""
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py", "c": "c.py"}
        analyzer.dependencies = {
            "a": {"b"},
            "b": {"c"},
            "c": {"a"},
        }

        cycles = analyzer.find_simple_cycles()
        assert len(cycles) == 1
        assert set(cycles[0]) == {"a", "b", "c"}

    def test_multiple_separate_cycles(self):
        """A <-> B and C <-> D (two separate cycles)"""
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py", "c": "c.py", "d": "d.py"}
        analyzer.dependencies = {
            "a": {"b"},
            "b": {"a"},
            "c": {"d"},
            "d": {"c"},
        }

        cycles = analyzer.find_simple_cycles()
        assert len(cycles) == 2

    def test_self_loop_no_crash(self):
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py"}
        analyzer.dependencies = {"a": {"a"}}

        cycles = analyzer.find_simple_cycles()
        assert isinstance(cycles, list)

    def test_suggest_break_point_high_efferent(self):
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py", "c": "c.py"}
        analyzer.dependencies = {
            "a": {"b", "c"},
            "b": {"a"},
            "c": set(),
        }

        cycle = ["a", "b"]
        suggestion = analyzer.suggest_break_point(cycle)

        assert suggestion in cycle

    def test_get_core_infrastructure(self):
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py", "c": "c.py"}
        analyzer.dependencies = {
            "a": {"b", "c"},
            "b": {"a"},
            "c": {"a"},
        }

        core = analyzer.get_core_infrastructure()
        assert "a" in core


class TestCircularDependencyRule:
    """Test the Skylos rule interface."""

    def test_empty_project_no_findings(self):
        rule = CircularDependencyRule()
        findings = rule.analyze()
        assert findings == []

    def test_single_file_no_cycle(self):
        code = """
import os
import sys

def main():
    pass
"""
        rule = CircularDependencyRule()
        rule.add_file(ast.parse(code), "main.py", "main")

        findings = rule.analyze()
        assert len(findings) == 0

    def test_detects_two_file_cycle(self):
        code_a = "from b import something"
        code_b = "from a import something_else"

        rule = CircularDependencyRule()
        rule.add_file(ast.parse(code_a), "a.py", "a")
        rule.add_file(ast.parse(code_b), "b.py", "b")

        findings = rule.analyze()

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "SKY-CIRC"
        assert findings[0]["kind"] == "circular_dependency"
        assert set(findings[0]["cycle"]) == {"a", "b"}

    def test_check_fails_when_exceeds_max(self):
        code_a = "from b import x"
        code_b = "from a import y"

        rule = CircularDependencyRule(max_cycles=0)
        rule.add_file(ast.parse(code_a), "a.py", "a")
        rule.add_file(ast.parse(code_b), "b.py", "b")

        passed, message = rule.check()

        assert passed is False

    def test_warning_mode_always_passes(self):
        code_a = "from b import x"
        code_b = "from a import y"

        rule = CircularDependencyRule(max_cycles=-1)
        rule.add_file(ast.parse(code_a), "a.py", "a")
        rule.add_file(ast.parse(code_b), "b.py", "b")

        passed, message = rule.check()

        assert passed is True

    @pytest.mark.parametrize(
        "package_b_import",
        [
            ("package_a.cli", 1, "from_import", ["main"]),
            ("package_a.cli", 1, "import", ["package_a.cli"]),
            ("package_a.cli", 1, "import", ["_mod"]),
        ],
    )
    def test_raw_imports_preserve_precise_architecture_edges_for_dotted_imports(
        self, package_b_import
    ):
        rule = CircularDependencyRule()
        modules = {
            "package_a": ("/project/package_a/__init__.py", []),
            "package_a.cli": (
                "/project/package_a/cli.py",
                [("sync_common", 1, "import", ["sync_common"])],
            ),
            "package_b": ("/project/package_b/__init__.py", []),
            "package_b.cli": (
                "/project/package_b/cli.py",
                [package_b_import, ("sync_common", 2, "import", ["sync_common"])],
            ),
            "sync_common": ("/project/sync_common.py", []),
        }

        for module_name, (file_path, raw_imports) in modules.items():
            rule.add_file_imports(file_path, module_name, raw_imports)

        rule.analyze()

        circular_graph = dict(rule._analyzer.dependencies)
        architecture_graph = dict(rule._analyzer.architecture_dependencies)
        assert circular_graph["package_b.cli"] == {"package_a", "sync_common"}
        assert architecture_graph["package_b.cli"] == {
            "package_a.cli",
            "sync_common",
        }

        _, summary = get_architecture_findings(
            dependency_graph=architecture_graph,
            module_files=dict(rule._analyzer.modules),
        )

        assert summary["module_metrics"]["package_a"]["ca"] == 0
        assert summary["module_metrics"]["package_a.cli"]["ca"] == 1
        assert summary["module_metrics"]["package_a.cli"]["zone"] != (
            "zone_of_uselessness"
        )

    def test_raw_imports_do_not_trace_init_reexports(self):
        rule = CircularDependencyRule()
        modules = {
            "package_a": (
                "/project/package_a/__init__.py",
                [("package_a.cli", 1, "from_import", ["main"])],
            ),
            "package_a.cli": ("/project/package_a/cli.py", []),
            "package_b.cli": (
                "/project/package_b/cli.py",
                [("package_a", 1, "from_import", ["main"])],
            ),
        }

        for module_name, (file_path, raw_imports) in modules.items():
            rule.add_file_imports(file_path, module_name, raw_imports)

        rule.analyze()

        architecture_graph = dict(rule._analyzer.architecture_dependencies)
        assert architecture_graph["package_b.cli"] == {"package_a"}

    def test_raw_imports_keep_circular_cycle_detection_root_collapsed(self):
        rule = CircularDependencyRule()
        modules = {
            "package_a": (
                "/project/package_a/__init__.py",
                [("package_b.cli", 1, "from_import", ["main"])],
            ),
            "package_a.cli": ("/project/package_a/cli.py", []),
            "package_b": (
                "/project/package_b/__init__.py",
                [("package_a.cli", 1, "from_import", ["main"])],
            ),
            "package_b.cli": ("/project/package_b/cli.py", []),
        }

        for module_name, (file_path, raw_imports) in modules.items():
            rule.add_file_imports(file_path, module_name, raw_imports)

        findings = rule.analyze()

        circular_graph = dict(rule._analyzer.dependencies)
        architecture_graph = dict(rule._analyzer.architecture_dependencies)
        assert circular_graph["package_a"] == {"package_b"}
        assert circular_graph["package_b"] == {"package_a"}
        assert architecture_graph["package_a"] == {"package_b.cli"}
        assert architecture_graph["package_b"] == {"package_a.cli"}
        assert len(findings) == 1
        assert set(findings[0]["cycle"]) == {"package_a", "package_b"}


class TestConvenienceFunction:
    def test_analyze_circular_dependencies(self):
        code_a = "from b import x"
        code_b = "from a import y"

        pairs = [
            ("a.py", "a", ast.parse(code_a)),
            ("b.py", "b", ast.parse(code_b)),
        ]

        findings = analyze_circular_dependencies(pairs)

        assert len(findings) == 1
        assert findings[0]["cycle_length"] == 2


class TestSeverity:
    def test_2_node_cycle_low_severity(self):
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py"}
        analyzer.dependencies = {"a": {"b"}, "b": {"a"}}

        findings = analyzer.analyze()
        assert findings[0].severity in ("LOW", "MEDIUM")

    def test_3_node_cycle_medium_severity(self):
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py", "c": "c.py"}
        analyzer.dependencies = {"a": {"b"}, "b": {"c"}, "c": {"a"}}

        findings = analyzer.analyze()
        assert findings[0].severity == "MEDIUM"

    def test_4_plus_node_cycle_high_severity(self):
        analyzer = CircularDependencyAnalyzer()
        analyzer.modules = {"a": "a.py", "b": "b.py", "c": "c.py", "d": "d.py"}
        analyzer.dependencies = {"a": {"b"}, "b": {"c"}, "c": {"d"}, "d": {"a"}}

        findings = analyzer.analyze()
        assert findings[0].severity == "HIGH"


class TestRealWorldPatterns:
    def test_service_repository_cycle(self):
        """Service imports Repository, Repository imports Service."""
        service = """
from repository import UserRepository

class UserService:
    def __init__(self):
        self.repo = UserRepository()
"""
        repo = """
from service import UserService

class UserRepository:
    def get_service(self):
        return UserService()
"""

        rule = CircularDependencyRule()
        rule.add_file(ast.parse(service), "service.py", "service")
        rule.add_file(ast.parse(repo), "repository.py", "repository")

        findings = rule.analyze()
        assert len(findings) == 1

    def test_diamond_dependency_no_cycle(self):
        """
        A -> B -> D
        A -> C -> D
        (Diamond shape, NOT a cycle)
        """
        code_a = "from b import B\nfrom c import C"
        code_b = "from d import D"
        code_c = "from d import D"
        code_d = "class D: pass"

        rule = CircularDependencyRule()
        rule.add_file(ast.parse(code_a), "a.py", "a")
        rule.add_file(ast.parse(code_b), "b.py", "b")
        rule.add_file(ast.parse(code_c), "c.py", "c")
        rule.add_file(ast.parse(code_d), "d.py", "d")

        findings = rule.analyze()
        assert len(findings) == 0

    def test_no_false_positive_stdlib(self):
        """Don't report cycles with stdlib."""
        code = """
import os
import sys
from pathlib import Path
from typing import Optional
"""

        rule = CircularDependencyRule()
        rule.add_file(ast.parse(code), "main.py", "main")

        findings = rule.analyze()
        assert len(findings) == 0


class TestEdgeCases:
    def test_empty_file(self):
        rule = CircularDependencyRule()
        rule.add_file(ast.parse(""), "empty.py", "empty")
        findings = rule.analyze()
        assert findings == []

    def test_no_imports(self):
        code = """
def foo():
    return 42

class Bar:
    pass
"""
        rule = CircularDependencyRule()
        rule.add_file(ast.parse(code), "noImports.py", "noImports")
        findings = rule.analyze()
        assert findings == []

    def test_import_star(self):
        code = "from foo import *"
        known = {"foo"}

        builder = DependencyGraphBuilder("main", "main.py", known)
        builder.visit(ast.parse(code))

        assert len(builder.dependencies) == 1

    def test_conditional_import_detected(self):
        code = """
if TYPE_CHECKING:
    from other import Thing
"""
        builder = DependencyGraphBuilder("main", "main.py", {"other"})
        builder.visit(ast.parse(code))

        assert len(builder.dependencies) == 1

    def test_try_except_imports_detected(self):
        code = """
try:
    from fast import thing
except ImportError:
    from slow import thing
"""
        builder = DependencyGraphBuilder("main", "main.py", {"fast", "slow"})
        builder.visit(ast.parse(code))

        assert len(builder.dependencies) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
