import ast
import itertools
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from skylos.analysis import circular_deps
from skylos.analysis.architecture import get_architecture_findings
from skylos.analysis.file_processing import collect_python_raw_imports
from skylos.analysis.circular_deps import (
    CircularDependencyAnalyzer,
    CircularDependencyRule,
    DependencyGraphBuilder,
    analyze_circular_dependencies,
)


def _rule_for_sources(sources, mode):
    rule = CircularDependencyRule()
    for module, (filename, source) in sources.items():
        tree = ast.parse(source, filename=filename)
        if mode == "raw":
            rule.add_file_imports(
                filename, module, collect_python_raw_imports(tree, filename, module)
            )
        else:
            rule.add_file(tree, filename, module)
    return rule


@pytest.mark.parametrize("mode", ["ast", "raw"])
@pytest.mark.parametrize(
    "source",
    [
        "import package.child",
        "from package import child",
        "from package.child import value",
        "from . import child",
        "from .child import value",
    ],
)
def test_package_child_import_keeps_exact_identity_without_self_cycle(mode, source):
    rule = _rule_for_sources(
        {
            "package": ("/project/package/__init__.py", source),
            "package.child": ("/project/package/child.py", "value = 'label'"),
        },
        mode,
    )

    assert rule.analyze() == []
    assert dict(rule._analyzer.dependencies) == {"package": {"package.child"}}
    assert dict(rule._analyzer.architecture_dependencies) == {
        "package": {"package.child"}
    }
    assert [
        (dep.from_module, dep.to_module, dep.import_line)
        for dep in rule._analyzer.all_deps
    ] == [("package", "package.child", 1)]


@pytest.mark.parametrize("mode", ["ast", "raw"])
@pytest.mark.parametrize(
    ("sources", "cycle", "edges"),
    [
        pytest.param(
            {
                "package": (
                    "/project/package/__init__.py",
                    "from . import child",
                ),
                "package.child": (
                    "/project/package/child.py",
                    "from package import value",
                ),
            },
            {"package", "package.child"},
            {"package": {"package.child"}, "package.child": {"package"}},
            id="child-imports-package-back",
        ),
        pytest.param(
            {
                "package.a": ("/project/package/a.py", "from .b import value"),
                "package.b": ("/project/package/b.py", "from .a import value"),
            },
            {"package.a", "package.b"},
            {"package.a": {"package.b"}, "package.b": {"package.a"}},
            id="relative-sibling-cycle",
        ),
        pytest.param(
            {
                "package.nested": (
                    "/project/package/nested/__init__.py",
                    "from .. import child",
                ),
                "package.child": (
                    "/project/package/child.py",
                    "import package.nested",
                ),
            },
            {"package.nested", "package.child"},
            {
                "package.nested": {"package.child"},
                "package.child": {"package.nested"},
            },
            id="nested-package-parent-relative-cycle",
        ),
    ],
)
def test_real_same_package_cycles_remain_visible(mode, sources, cycle, edges):
    rule = _rule_for_sources(sources, mode)

    findings = rule.analyze()

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-CIRC"
    assert set(findings[0]["cycle"]) == cycle
    assert dict(rule._analyzer.dependencies) == edges
    assert dict(rule._analyzer.architecture_dependencies) == edges


@pytest.mark.parametrize("mode", ["ast", "raw"])
@pytest.mark.parametrize(
    ("source", "targets"),
    [
        ("import package.missing", {"package"}),
        ("from package import missing", {"package"}),
        ("from package import child, missing", {"package", "package.child"}),
    ],
)
def test_unresolved_package_children_and_symbols_remain_conservative(
    mode, source, targets
):
    rule = _rule_for_sources(
        {
            "package": ("/project/package/__init__.py", source),
            "package.child": ("/project/package/child.py", "value = 'label'"),
        },
        mode,
    )

    findings = rule.analyze()

    assert len(findings) == 1
    assert findings[0]["cycle"] == ["package"]
    assert rule._analyzer.dependencies["package"] == targets
    assert rule._analyzer.architecture_dependencies["package"] == targets


@pytest.mark.parametrize("mode", ["ast", "raw"])
def test_direct_module_self_import_is_not_suppressed(mode):
    rule = _rule_for_sources({"module": ("/project/module.py", "import module")}, mode)

    findings = rule.analyze()

    assert len(findings) == 1
    assert findings[0]["cycle"] == ["module"]


@pytest.mark.parametrize("mode", ["ast", "raw"])
def test_absolute_and_relative_package_reexports_match_reported_example(mode):
    rule = _rule_for_sources(
        {
            "demo_pkg": (
                "/project/demo_pkg/__init__.py",
                "from demo_pkg.core import value\n__all__ = ['value']\n",
            ),
            "demo_pkg.core": ("/project/demo_pkg/core.py", "value = 1\n"),
            "relative_pkg": (
                "/project/relative_pkg/__init__.py",
                "from .core import value\n__all__ = ['value']\n",
            ),
            "relative_pkg.core": ("/project/relative_pkg/core.py", "value = 2\n"),
            "consumer": (
                "/project/consumer.py",
                "import demo_pkg\nimport relative_pkg\n",
            ),
        },
        mode,
    )

    assert rule.analyze() == []
    assert dict(rule._analyzer.dependencies) == {
        "demo_pkg": {"demo_pkg.core"},
        "relative_pkg": {"relative_pkg.core"},
        "consumer": {"demo_pkg", "relative_pkg"},
    }


@pytest.mark.parametrize("mode", ["ast", "raw"])
@pytest.mark.parametrize("reverse_files", [False, True])
def test_circular_finding_has_stable_location_on_a_real_cycle_edge(mode, reverse_files):
    sources = {
        "alpha": (
            "/project/alpha.py",
            "import helper\n\nfrom beta import value\nfrom beta import other\n",
        ),
        "beta": ("/project/beta.py", "from alpha import value\n"),
        "helper": ("/project/helper.py", ""),
    }
    if reverse_files:
        sources = dict(reversed(list(sources.items())))
    rule = _rule_for_sources(sources, mode)

    findings = rule.analyze()

    assert len(findings) == 1
    assert set(findings[0]["cycle"]) == {"alpha", "beta"}
    assert findings[0]["file"] == "/project/alpha.py"
    assert findings[0]["line"] == 3


@pytest.mark.parametrize("mode", ["ast", "raw"])
def test_cycle_location_does_not_use_an_edge_from_another_cycle(mode):
    rule = _rule_for_sources(
        {
            "alpha": ("/project/alpha.py", "import gamma\n\nimport beta\n"),
            "beta": ("/project/beta.py", "import gamma\n"),
            "gamma": ("/project/gamma.py", "import alpha\n"),
        },
        mode,
    )

    findings = rule.analyze()
    long_cycle = next(finding for finding in findings if finding["cycle_length"] == 3)

    assert long_cycle["file"] == "/project/alpha.py"
    assert long_cycle["line"] == 3


def test_manual_cycle_graph_does_not_invent_an_import_location():
    analyzer = CircularDependencyAnalyzer()
    analyzer.modules = {"a": "a.py", "b": "b.py"}
    analyzer.dependencies = {"a": {"b"}, "b": {"a"}}

    finding = analyzer.get_findings()[0]

    assert "file" not in finding
    assert "line" not in finding


@pytest.mark.parametrize("child_source", ["value = 'label'", "import package"])
def test_same_package_graph_has_python_native_cycle_parity(child_source):
    if circular_deps._fast_find_cycles is None:
        pytest.skip("optional native cycle detector is unavailable")
    rule = _rule_for_sources(
        {
            "package": ("/project/package/__init__.py", "from package import child"),
            "package.child": ("/project/package/child.py", child_source),
        },
        "raw",
    )
    rule.analyze()

    def normalize(cycles):
        return {tuple(sorted(cycle)) for cycle in cycles}

    assert normalize(rule._analyzer._find_cycles_py()) == normalize(
        rule._analyzer._find_cycles_fast()
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


_ORDER_SENSITIVE_EDGES = (
    ("alpha", "beta"),
    ("alpha", "gamma"),
    ("beta", "alpha"),
    ("beta", "gamma"),
    ("gamma", "alpha"),
    ("gamma", "delta"),
    ("delta", "alpha"),
)
_ORDER_SENSITIVE_MODULES = ("alpha", "beta", "gamma", "delta")
# All five elementary cycles of that graph, in (length, cycle) order. The
# pruned DFS used to report four or five of them depending on which neighbor
# it happened to explore first.
_ORDER_SENSITIVE_CYCLES = [
    ["alpha", "beta"],
    ["alpha", "gamma"],
    ["alpha", "beta", "gamma"],
    ["alpha", "gamma", "delta"],
    ["alpha", "beta", "gamma", "delta"],
]
# A fully bidirectional triangle has two 3-cycles over the same node set
# (a->b->c->a and a->c->b->a). Dedup keeps whichever is found first, so this
# graph is sensitive to root order even once neighbors are sorted.
_TRIANGLE_EDGES = (
    ("a", "b"),
    ("b", "a"),
    ("b", "c"),
    ("c", "b"),
    ("a", "c"),
    ("c", "a"),
)
_TRIANGLE_MODULES = ("a", "b", "c")
_TRIANGLE_CYCLE_SETS = {("a", "b"), ("a", "c"), ("b", "c"), ("a", "b", "c")}


def _adjacency_orderings(edges):
    """Every combination of neighbor list orders, as plain lists.

    Lists rather than sets so the iteration order is exactly what the test
    chose, independent of the hash seed the test process happens to run under.
    """
    by_source = {}
    for frm, to in edges:
        by_source.setdefault(frm, []).append(to)
    sources = sorted(by_source)
    for orders in itertools.product(
        *(itertools.permutations(by_source[source]) for source in sources)
    ):
        yield {source: list(order) for source, order in zip(sources, orders)}


def _python_cycles(adjacency, module_order):
    analyzer = CircularDependencyAnalyzer()
    for module in module_order:
        analyzer.modules[module] = f"/project/{module}.py"
    analyzer.dependencies = dict(adjacency)
    return analyzer._find_cycles_py()


@pytest.mark.parametrize(
    ("edges", "modules", "expected_cycle_sets"),
    [
        pytest.param(
            _ORDER_SENSITIVE_EDGES,
            _ORDER_SENSITIVE_MODULES,
            {tuple(sorted(cycle)) for cycle in _ORDER_SENSITIVE_CYCLES},
            id="pruning-sensitive",
        ),
        pytest.param(
            _TRIANGLE_EDGES,
            _TRIANGLE_MODULES,
            _TRIANGLE_CYCLE_SETS,
            id="bidirectional-triangle",
        ),
    ],
)
def test_python_cycle_search_is_independent_of_adjacency_and_root_order(
    edges, modules, expected_cycle_sets
):
    """Forced-Python: neither neighbor order nor root order may change the
    cycles found, their orientation, or the order they are returned in."""
    reference = _python_cycles(
        {
            source: sorted(order)
            for source, order in next(_adjacency_orderings(edges)).items()
        },
        sorted(modules),
    )
    assert {tuple(sorted(cycle)) for cycle in reference} == expected_cycle_sets
    assert len(reference) == len(expected_cycle_sets)
    for adjacency in _adjacency_orderings(edges):
        for module_order in itertools.permutations(modules):
            found = _python_cycles(adjacency, module_order)
            assert found == reference, (adjacency, module_order, found)


def test_findings_are_ordered_by_length_then_cycle():
    """Display order is canonical, not DFS discovery order within a length."""
    analyzer = CircularDependencyAnalyzer()
    for module in _TRIANGLE_MODULES:
        analyzer.modules[module] = f"/project/{module}.py"
    for frm, to in _TRIANGLE_EDGES:
        analyzer.dependencies[frm].add(to)
    assert [cd.cycle for cd in analyzer.analyze()] == [
        ["a", "b"],
        ["a", "c"],
        ["b", "c"],
        ["a", "b", "c"],
    ]


_HASH_SEED_PROBE = """
import json
from skylos.analysis.circular_deps import CircularDependencyAnalyzer
edges = {edges!r}
modules = {modules!r}
analyzer = CircularDependencyAnalyzer()
for module in modules:
    analyzer.modules[module] = f"/project/{{module}}.py"
for frm, to in edges:
    analyzer.dependencies[frm].add(to)
print(json.dumps([cd.to_dict() for cd in analyzer.analyze()]))
"""


@pytest.mark.parametrize("hash_seed", ["0", "1", "2", "6"])
def test_set_backed_findings_are_identical_across_hash_seeds(hash_seed):
    """End to end through the real set-backed graph under contrasting seeds.

    Seeds 0 and 6 used to yield five cycles while 1 and 2 yielded four.
    """
    env = dict(os.environ, PYTHONHASHSEED=hash_seed)
    env["PYTHONPATH"] = os.pathsep.join(
        part
        for part in (str(Path(__file__).resolve().parents[1]), env.get("PYTHONPATH"))
        if part
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _HASH_SEED_PROBE.format(
                edges=list(_ORDER_SENSITIVE_EDGES),
                modules=list(reversed(_ORDER_SENSITIVE_MODULES)),
            ),
        ],
        capture_output=True,
        check=True,
        env=env,
        text=True,
        timeout=60,
    )
    findings = json.loads(completed.stdout)
    assert [finding["cycle"] for finding in findings] == _ORDER_SENSITIVE_CYCLES
    assert [finding["severity"] for finding in findings] == [
        "LOW",
        "LOW",
        "MEDIUM",
        "MEDIUM",
        "HIGH",
    ]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
