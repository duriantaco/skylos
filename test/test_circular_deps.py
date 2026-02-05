import ast
import pytest
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

    def test_dotted_import(self):
        code = "from myproject.submodule import thing"
        tree = ast.parse(code)
        known = {"myproject", "myproject.submodule"}
        
        builder = DependencyGraphBuilder("main", "main.py", known)
        builder.visit(tree)
        
        assert len(builder.dependencies) == 1

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
        # a is in two cycles: a<->b and a<->c
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


# =============================================================================
# UNIT TESTS - Severity
# =============================================================================

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
        analyzer.modules = {
            "a": "a.py", "b": "b.py", "c": "c.py", "d": "d.py"
        }
        analyzer.dependencies = {
            "a": {"b"}, "b": {"c"}, "c": {"d"}, "d": {"a"}
        }
        
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