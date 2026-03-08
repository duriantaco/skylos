import ast
from skylos.architecture import (
    analyze_architecture,
    get_architecture_findings,
    _compute_abstractness,
    _classify_zone,
)


class TestComputeAbstractness:
    def test_no_abstractions(self):
        tree = ast.parse("""
class Foo:
    def bar(self):
        pass
""")
        result = _compute_abstractness(tree)
        assert result["abstractness"] < 0.1
        assert result["total_classes"] == 1
        assert result["abstract_classes"] == 0

    def test_abc_detected(self):
        tree = ast.parse("""
from abc import ABC, abstractmethod

class Base(ABC):
    @abstractmethod
    def process(self):
        pass
""")
        result = _compute_abstractness(tree)
        assert result["abstract_classes"] == 1
        assert result["abstract_methods"] == 1
        assert result["abstractness"] > 0.0

    def test_protocol_detected(self):
        tree = ast.parse("""
from typing import Protocol

class Sendable(Protocol):
    def send(self, data: bytes) -> None: ...
""")
        result = _compute_abstractness(tree)
        assert result["protocols"] == 1
        assert result["abstract_classes"] >= 1

    def test_typevar_bonus(self):
        tree = ast.parse("""
from typing import TypeVar
T = TypeVar("T")
U = TypeVar("U", bound=int)

class Container:
    pass
""")
        result = _compute_abstractness(tree)
        assert result["type_vars"] == 2
        assert result["abstractness"] > 0.0

    def test_type_checking_bonus(self):
        tree = ast.parse("""
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from foo import Bar

class Baz:
    pass
""")
        result = _compute_abstractness(tree)
        assert result["abstractness"] > 0.0


class TestClassifyZone:
    def test_main_sequence(self):
        assert _classify_zone(0.5, 0.5) == "main_sequence"
        assert _classify_zone(0.4, 0.6) == "main_sequence"
        assert _classify_zone(0.6, 0.4) == "main_sequence"

    def test_zone_of_pain(self):
        assert _classify_zone(0.9, 0.0) == "zone_of_pain"

    def test_zone_of_uselessness(self):
        assert _classify_zone(0.0, 0.9) == "zone_of_uselessness"

    def test_healthy(self):
        assert _classify_zone(0.5, 0.2) == "healthy"


class TestAnalyzeArchitecture:
    def test_empty_project(self):
        result = analyze_architecture({}, {})
        assert result.system_metrics["total_modules"] == 0
        assert result.findings == []

    def test_single_module(self):
        result = analyze_architecture(
            dependency_graph={"app": set()},
            module_files={"app": "/project/app.py"},
        )
        assert "app" in result.modules
        m = result.modules["app"]
        assert m.ca == 0
        assert m.ce == 0
        assert m.instability == 0.0

    def test_simple_dependency(self):
        result = analyze_architecture(
            dependency_graph={
                "app": {"lib"},
                "lib": set(),
            },
            module_files={
                "app": "/project/app.py",
                "lib": "/project/lib.py",
            },
        )
        app = result.modules["app"]
        lib = result.modules["lib"]

        assert app.ce == 1
        assert app.ca == 0
        assert lib.ca == 1  # app depends on lib
        assert lib.ce == 0  # lib depends on nothing

        assert app.instability == 1.0  # fully unstable
        assert lib.instability == 0.0  # fully stable

    def test_dip_violation_detected(self):
        result = analyze_architecture(
            dependency_graph={
                "core": {"utils"},  # core is stable, depends on utils
                "utils": {"core"},
                "app": {"core"},
                "cli": {"core"},  # another dependent of core
                "web": {"utils"},
            },
            module_files={
                "core": "/p/core.py",
                "utils": "/p/utils.py",
                "app": "/p/app.py",
                "cli": "/p/cli.py",
                "web": "/p/web.py",
            },
        )

        core = result.modules["core"]
        assert core.ca >= 2

    def test_package_aggregation(self):
        result = analyze_architecture(
            dependency_graph={
                "pkg.module_a": {"pkg.module_b"},
                "pkg.module_b": set(),
            },
            module_files={
                "pkg.module_a": "/p/pkg/module_a.py",
                "pkg.module_b": "/p/pkg/module_b.py",
            },
        )
        assert "pkg" in result.packages
        pkg = result.packages["pkg"]
        assert pkg["module_count"] == 2

    def test_system_metrics(self):
        result = analyze_architecture(
            dependency_graph={
                "a": {"b"},
                "b": {"c"},
                "c": set(),
            },
            module_files={
                "a": "/p/a.py",
                "b": "/p/b.py",
                "c": "/p/c.py",
            },
        )
        sm = result.system_metrics
        assert sm["total_modules"] == 3
        assert "modularity_index" in sm
        assert "architecture_fitness" in sm
        assert "coupling_health" in sm
        assert "zone_distribution" in sm

    def test_abstractness_from_trees(self):
        tree_a = ast.parse("""
from abc import ABC, abstractmethod
class Base(ABC):
    @abstractmethod
    def process(self): pass
""")
        tree_b = ast.parse("""
class Concrete:
    def process(self):
        return 42
""")
        result = analyze_architecture(
            dependency_graph={"a": set(), "b": {"a"}},
            module_files={"a": "/p/a.py", "b": "/p/b.py"},
            module_trees={"a": tree_a, "b": tree_b},
        )
        a = result.modules["a"]
        b = result.modules["b"]
        assert a.abstractness > b.abstractness


class TestGetArchitectureFindings:
    def test_returns_findings_and_summary(self):
        findings, summary = get_architecture_findings(
            dependency_graph={"a": {"b"}, "b": set()},
            module_files={"a": "/p/a.py", "b": "/p/b.py"},
        )
        assert isinstance(findings, list)
        assert isinstance(summary, dict)
        assert "system_metrics" in summary
        assert "module_metrics" in summary

    def test_high_distance_generates_finding(self):
        tree_a = ast.parse("""
from abc import ABC, abstractmethod
class Base(ABC):
    @abstractmethod
    def p(self): pass
class Base2(ABC):
    @abstractmethod
    def q(self): pass
""")
        findings, _ = get_architecture_findings(
            dependency_graph={"a": {"b", "c"}, "b": set(), "c": set()},
            module_files={"a": "/p/a.py", "b": "/p/b.py", "c": "/p/c.py"},
            module_trees={"a": tree_a},
        )
        assert isinstance(findings, list)
