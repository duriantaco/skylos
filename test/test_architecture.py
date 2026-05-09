import ast
from skylos.architecture import (
    analyze_architecture,
    get_architecture_findings,
    get_layer_policy_findings,
    _compute_abstractness,
    _classify_zone,
    _has_main_guard,
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
    def test_canonical_truth_table(self):
        cases = [
            (0.0, 0.0, "zone_of_pain"),
            (1.0, 1.0, "zone_of_uselessness"),
            (0.0, 1.0, "main_sequence"),
            (1.0, 0.0, "main_sequence"),
            (0.0, 0.5, "off_main_sequence"),
            (0.5, 0.0, "off_main_sequence"),
        ]

        for abstractness, instability, expected in cases:
            assert _classify_zone(abstractness, instability) == expected

    def test_main_sequence(self):
        assert _classify_zone(0.5, 0.5) == "main_sequence"
        assert _classify_zone(0.4, 0.6) == "main_sequence"
        assert _classify_zone(0.6, 0.4) == "main_sequence"
        assert _classify_zone(0.0, 0.9) == "main_sequence"

    def test_zone_of_pain(self):
        assert _classify_zone(0.0, 0.0) == "zone_of_pain"

    def test_zone_of_uselessness(self):
        assert _classify_zone(0.9, 0.9) == "zone_of_uselessness"

    def test_off_main_sequence(self):
        assert _classify_zone(0.5, 0.2) == "off_main_sequence"
        assert _classify_zone(0.0, 0.4) == "off_main_sequence"

    def test_disconnected_module_is_not_labeled_pain(self):
        result = analyze_architecture(
            dependency_graph={"mypkg": set()},
            module_files={"mypkg": "/p/mypkg/__init__.py"},
        )

        assert result.modules["mypkg"].total_coupling == 0
        assert result.modules["mypkg"].zone == "disconnected"
        assert result.system_metrics["zone_distribution"]["zone_of_pain"] == 0
        assert result.system_metrics["zone_distribution"]["disconnected"] == 1


class TestArchitectureContext:
    def test_main_guard_detected(self):
        tree = ast.parse("""
def main():
    pass

if __name__ == "__main__":
    main()
""")
        assert _has_main_guard(tree)

    def test_entrypoint_and_private_helpers_filter_contextual_findings(self):
        graph = {
            "mypkg.cli": {"mypkg.flow_a", "mypkg.flow_b", "mypkg.flow_c"},
            "mypkg.flow_a": {"mypkg._helpers"},
            "mypkg.flow_b": {"mypkg._helpers"},
            "mypkg.flow_c": {"mypkg._helpers"},
            "mypkg._helpers": set(),
        }
        module_files = {
            "mypkg.cli": "/p/mypkg/cli.py",
            "mypkg.flow_a": "/p/mypkg/flow_a.py",
            "mypkg.flow_b": "/p/mypkg/flow_b.py",
            "mypkg.flow_c": "/p/mypkg/flow_c.py",
            "mypkg._helpers": "/p/mypkg/_helpers.py",
        }

        raw_findings, _ = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
            module_trees={
                "mypkg.cli": ast.parse("""
from typing import Protocol

class Command(Protocol):
    ...
""")
            },
            private_helper_ce_limit=-1,
        )
        assert ("SKY-Q803", "mypkg.cli") in {
            (f["rule_id"], f["name"]) for f in raw_findings
        }
        assert ("SKY-Q802", "mypkg._helpers") in {
            (f["rule_id"], f["name"]) for f in raw_findings
        }

        findings, summary = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
            module_trees={
                "mypkg.cli": ast.parse("""
from typing import Protocol

class Command(Protocol):
    ...
""")
            },
            entrypoint_modules={"mypkg.cli"},
        )

        rules = {(f["rule_id"], f["name"]) for f in findings}
        assert ("SKY-Q803", "mypkg.cli") not in rules
        assert ("SKY-Q802", "mypkg._helpers") not in rules
        assert summary["module_metrics"]["mypkg.cli"]["zone"] == "zone_of_uselessness"
        assert summary["module_metrics"]["mypkg._helpers"]["distance"] == 1.0

    def test_private_helper_low_fan_in_filters_q803_zone_of_pain(self):
        graph = {
            "mypkg.cli": {"mypkg._banner"},
            "mypkg._banner": set(),
        }
        module_files = {
            "mypkg.cli": "/p/mypkg/cli.py",
            "mypkg._banner": "/p/mypkg/_banner.py",
        }

        raw_findings, _ = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
            private_helper_ca_limit=0,
        )
        assert ("SKY-Q803", "mypkg._banner") in {
            (f["rule_id"], f["name"]) for f in raw_findings
        }

        findings, summary = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
        )

        rules = {(f["rule_id"], f["name"]) for f in findings}
        assert summary["module_metrics"]["mypkg._banner"]["ca"] == 1
        assert summary["module_metrics"]["mypkg._banner"]["zone"] == "zone_of_pain"
        assert ("SKY-Q803", "mypkg._banner") not in rules

    def test_private_helper_three_importers_filters_q803_zone_of_pain(self):
        graph = {
            "consumer_a": {"mypkg._shared"},
            "consumer_b": {"mypkg._shared"},
            "consumer_c": {"mypkg._shared"},
            "mypkg._shared": set(),
        }
        module_files = {
            "consumer_a": "/p/consumer_a.py",
            "consumer_b": "/p/consumer_b.py",
            "consumer_c": "/p/consumer_c.py",
            "mypkg._shared": "/p/mypkg/_shared.py",
        }

        findings, summary = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
        )

        assert summary["module_metrics"]["mypkg._shared"]["ca"] == 3
        assert ("SKY-Q803", "mypkg._shared") not in {
            (f["rule_id"], f["name"]) for f in findings
        }

    def test_private_helper_high_fan_in_keeps_q803_zone_of_pain(self):
        graph = {
            "consumer_a": {"mypkg._shared"},
            "consumer_b": {"mypkg._shared"},
            "consumer_c": {"mypkg._shared"},
            "consumer_d": {"mypkg._shared"},
            "mypkg._shared": set(),
        }
        module_files = {
            "consumer_a": "/p/consumer_a.py",
            "consumer_b": "/p/consumer_b.py",
            "consumer_c": "/p/consumer_c.py",
            "consumer_d": "/p/consumer_d.py",
            "mypkg._shared": "/p/mypkg/_shared.py",
        }

        findings, summary = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
        )

        assert summary["module_metrics"]["mypkg._shared"]["ca"] == 4
        assert ("SKY-Q803", "mypkg._shared") in {
            (f["rule_id"], f["name"]) for f in findings
        }


class TestLayerPolicy:
    def test_layer_policy_deny_rule_reports_violation(self):
        graph = {
            "app.domain.model": {"app.api.routes"},
            "app.api.routes": set(),
        }
        module_files = {
            "app.domain.model": "/p/app/domain/model.py",
            "app.api.routes": "/p/app/api/routes.py",
        }
        policy = {
            "layers": [
                {"name": "domain", "patterns": ["app.domain"]},
                {"name": "api", "patterns": ["app.api"]},
            ],
            "rules": [{"from": "domain", "deny": ["api"]}],
        }

        findings, summary = get_layer_policy_findings(graph, module_files, policy)

        assert summary["violation_count"] == 1
        assert findings[0]["rule_id"] == "SKY-Q805"
        assert findings[0]["from_layer"] == "domain"
        assert findings[0]["to_layer"] == "api"

    def test_layer_policy_allow_rule_accepts_allowed_edges(self):
        graph = {
            "app.api.routes": {"app.domain.model"},
            "app.domain.model": set(),
        }
        module_files = {
            "app.api.routes": "/p/app/api/routes.py",
            "app.domain.model": "/p/app/domain/model.py",
        }
        policy = {
            "layers": [
                {"name": "api", "patterns": ["app.api"]},
                {"name": "domain", "patterns": ["app.domain"]},
            ],
            "rules": [{"from": "api", "allow": ["domain"]}],
        }

        findings, summary = get_layer_policy_findings(graph, module_files, policy)

        assert findings == []
        assert summary["checked_edges"] == 1
        assert summary["module_layers"]["app.api.routes"] == "api"

    def test_private_helper_filters_q803_zone_of_uselessness(self):
        graph = {
            "mypkg._contracts": {"mypkg.impl"},
            "mypkg.impl": set(),
        }
        module_files = {
            "mypkg._contracts": "/p/mypkg/_contracts.py",
            "mypkg.impl": "/p/mypkg/impl.py",
        }
        module_trees = {
            "mypkg._contracts": ast.parse("""
from typing import Protocol
from .impl import build

class Builder(Protocol):
    ...
""")
        }

        findings, summary = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
            module_trees=module_trees,
        )

        assert summary["module_metrics"]["mypkg._contracts"]["zone"] == (
            "zone_of_uselessness"
        )
        assert ("SKY-Q803", "mypkg._contracts") not in {
            (f["rule_id"], f["name"]) for f in findings
        }

    def test_main_guard_module_filters_zone_warning(self):
        tree = ast.parse("""
from typing import Protocol
from worker import run

class CommandA(Protocol):
    ...

class CommandB(Protocol):
    ...

class CommandC(Protocol):
    ...

class CommandD(Protocol):
    ...

def main():
    run()

if __name__ == "__main__":
    main()
""")

        findings, summary = get_architecture_findings(
            dependency_graph={"cli": {"worker"}, "worker": set()},
            module_files={"cli": "/p/cli.py", "worker": "/p/worker.py"},
            module_trees={"cli": tree},
        )

        rules = {(f["rule_id"], f["name"]) for f in findings}
        assert summary["module_metrics"]["cli"]["zone"] == "zone_of_uselessness"
        assert ("SKY-Q803", "cli") not in rules

    def test_reexported_package_boundary_filters_structural_findings(self):
        graph = {
            "mini_pkg": {"mini_pkg.core"},
            "mini_pkg.core": set(),
        }
        module_files = {
            "mini_pkg": "/p/mini_pkg/__init__.py",
            "mini_pkg.core": "/p/mini_pkg/core.py",
        }

        raw_findings, _ = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
        )
        assert ("SKY-Q802", "mini_pkg.core") in {
            (f["rule_id"], f["name"]) for f in raw_findings
        }
        assert ("SKY-Q803", "mini_pkg.core") in {
            (f["rule_id"], f["name"]) for f in raw_findings
        }

        findings, summary = get_architecture_findings(
            dependency_graph=graph,
            module_files=module_files,
            package_boundary_modules={"mini_pkg.core"},
        )

        rules = {(f["rule_id"], f["name"]) for f in findings}
        assert ("SKY-Q802", "mini_pkg.core") not in rules
        assert ("SKY-Q803", "mini_pkg.core") not in rules
        assert summary["module_metrics"]["mini_pkg.core"]["zone"] == "zone_of_pain"

    def test_q803_skips_test_modules(self):
        test_tree = ast.parse("""
from typing import Protocol

class CommandA(Protocol):
    ...

class CommandB(Protocol):
    ...

class CommandC(Protocol):
    ...

class CommandD(Protocol):
    ...

def test_contract():
    assert True
""")

        findings, summary = get_architecture_findings(
            dependency_graph={"tests.test_contract": {"app"}, "app": set()},
            module_files={
                "tests.test_contract": "/p/tests/test_contract.py",
                "app": "/p/app.py",
            },
            module_trees={"tests.test_contract": test_tree},
        )

        assert summary["module_metrics"]["tests.test_contract"]["zone"] == (
            "zone_of_uselessness"
        )
        assert ("SKY-Q803", "tests.test_contract") not in {
            (f["rule_id"], f["name"]) for f in findings
        }


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
        assert "off_main_sequence" in sm["zone_distribution"]
        assert "healthy" not in sm["zone_distribution"]

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

    def test_high_distance_message_does_not_call_fallback_healthy(self):
        result = analyze_architecture(
            dependency_graph={
                "stableish": set(),
                "consumer_a": {"stableish"},
                "consumer_b": {"stableish"},
            },
            module_files={
                "stableish": "/p/stableish.py",
                "consumer_a": "/p/consumer_a.py",
                "consumer_b": "/p/consumer_b.py",
            },
            module_abstractness={
                "stableish": {
                    "abstractness": 0.4,
                    "total_classes": 1,
                    "abstract_classes": 0,
                    "total_functions": 0,
                    "abstract_methods": 0,
                    "type_vars": 0,
                    "protocols": 0,
                },
            },
        )

        q802 = next(
            f
            for f in result.findings
            if f["rule_id"] == "SKY-Q802" and f["name"] == "stableish"
        )
        assert result.modules["stableish"].zone == "off_main_sequence"
        assert "Zone: off main sequence." in q802["message"]
        assert "Zone: healthy." not in q802["message"]

    def test_iad_findings_are_advisory_by_default(self):
        findings, _ = get_architecture_findings(
            dependency_graph={
                "stableish": set(),
                "consumer_a": {"stableish"},
                "consumer_b": {"stableish"},
            },
            module_files={
                "stableish": "/p/stableish.py",
                "consumer_a": "/p/consumer_a.py",
                "consumer_b": "/p/consumer_b.py",
            },
        )

        iad_findings = [
            f for f in findings if f["rule_id"] in {"SKY-Q802", "SKY-Q803"}
        ]

        assert {f["rule_id"] for f in iad_findings} == {"SKY-Q802", "SKY-Q803"}
        assert all(f["advisory"] is True for f in iad_findings)
        assert all(
            f["metric_granularity"] == "file-level heuristic" for f in iad_findings
        )
        assert all("Martin I/A/D" in f["metric_origin"] for f in iad_findings)
        assert all("Advisory:" in f["message"] for f in iad_findings)

    def test_iad_findings_can_be_marked_enforced(self):
        findings, _ = get_architecture_findings(
            dependency_graph={
                "stableish": set(),
                "consumer_a": {"stableish"},
                "consumer_b": {"stableish"},
            },
            module_files={
                "stableish": "/p/stableish.py",
                "consumer_a": "/p/consumer_a.py",
                "consumer_b": "/p/consumer_b.py",
            },
            iad_findings_advisory=False,
        )

        iad_findings = [
            f for f in findings if f["rule_id"] in {"SKY-Q802", "SKY-Q803"}
        ]

        assert {f["rule_id"] for f in iad_findings} == {"SKY-Q802", "SKY-Q803"}
        assert all(f["advisory"] is False for f in iad_findings)
        assert all("enforcement_reason" in f for f in iad_findings)
        assert all("Advisory:" not in f["message"] for f in iad_findings)
