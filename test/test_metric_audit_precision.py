"""Source-backed controls for the remaining metric advice audit."""

import ast
import textwrap

import pytest

from skylos.rules.quality._readability import OpaqueIdentifierRule
from skylos.analysis.architecture import _compute_abstractness, analyze_architecture
from skylos.rules.quality.cohesion import LCOMRule
from skylos.rules.quality.coupling import analyze_coupling, _needs_scope_resolution


def _opaque(source):
    source = textwrap.dedent(source)
    return (
        OpaqueIdentifierRule().visit_node(
            ast.parse(source), {"filename": "/project/app/service.py", "source": source}
        )
        or []
    )


def _long_lived_assignment(name, rhs, prefix=""):
    return f"""\
def consume(payload, audit, choose):
    {prefix or "pass"}
    {name} = {rhs}
    if {name}:
        audit({name})
    audit("continue")
    audit("still working")
    audit("done")
    return {name}
"""


@pytest.mark.parametrize(
    "name,key", [("value", "result"), ("result", "value"), ("tmp", "temp")]
)
def test_opaque_identifier_requires_strictly_clearer_suggestion(name, key):
    assert _opaque(_long_lived_assignment(name, f'payload["{key}"]')) == []


@pytest.mark.parametrize(
    "name,key", [("tmp", "result"), ("value", "user_id"), ("result", "user_id")]
)
def test_opaque_identifier_retains_proven_name_improvements(name, key):
    findings = _opaque(_long_lived_assignment(name, f'payload["{key}"]'))
    assert [(row["name"], row["value"]) for row in findings] == [(name, key)]


def test_opaque_identifier_ambiguous_rhs_does_not_invent_a_name():
    assert (
        _opaque(
            _long_lived_assignment(
                "value", 'payload["user_id"] if choose else payload["order_id"]'
            )
        )
        == []
    )


def test_opaque_identifier_shadowed_function_does_not_leak_uses():
    assert (
        _opaque("""
        def consume(payload):
            value = payload["user_id"]
            def inner(value):
                print(value)
                print(value)
                print("padding")
                print("padding")
                return value
            return inner
    """)
        == []
    )


def test_opaque_identifier_suggestion_is_advisory_when_target_name_exists():
    # The rule proves semantic specificity, not that an automatic rename is safe.
    # An existing user_id binding must not make the generic value name immune.
    findings = _opaque(
        _long_lived_assignment(
            "value", 'payload["user_id"]', prefix='user_id = "existing account"'
        )
    )
    assert [(row["name"], row["value"]) for row in findings] == [("value", "user_id")]
    assert "consider a name like" in findings[0]["message"]


def _architecture(graph, packages=None):
    return analyze_architecture(
        graph,
        {name: "" for name in ("pkg.a", "pkg.b", "other.c", "other.d")},
        module_packages=packages,
    )


def test_architecture_unknown_importers_do_not_create_internal_coupling():
    result = _architecture({"not_scanned": {"pkg.a"}, "pkg.a": {"external"}})
    assert result.modules["pkg.a"].ca == result.modules["pkg.a"].ce == 0
    assert result.modules["pkg.a"].zone == "disconnected"
    assert result.findings == []
    assert result.system_metrics["modularity_index"] == 1


def test_architecture_known_edges_still_create_real_metrics_and_findings():
    result = _architecture({"pkg.b": {"pkg.a"}, "pkg.a": set()})
    assert result.modules["pkg.a"].ca == 1
    assert result.modules["pkg.b"].ce == 1
    assert {row["rule_id"] for row in result.findings if row["name"] == "pkg.a"} == {
        "SKY-Q802",
        "SKY-Q803",
    }


def test_architecture_internal_package_edges_do_not_cross_its_boundary():
    result = _architecture({"pkg.a": {"pkg.b"}})
    assert result.modules["pkg.a"].ce == 1
    assert result.packages["pkg"]["afferent_coupling"] == 0
    assert result.packages["pkg"]["efferent_coupling"] == 0
    assert result.packages["pkg"]["instability"] == 0


def test_architecture_package_coupling_deduplicates_external_modules():
    result = _architecture(
        {
            "pkg.a": {"other.c", "pkg.b"},
            "pkg.b": {"other.c"},
            "other.d": {"pkg.a", "pkg.b"},
        }
    )
    package = result.packages["pkg"]
    assert (package["afferent_coupling"], package["efferent_coupling"]) == (1, 1)
    assert package["instability"] == 0.5


def test_architecture_explicit_package_boundaries_beat_name_lookalikes():
    result = _architecture(
        {"pkg.a": {"pkg.b"}}, {"pkg.a": "api", "pkg.b": "implementation"}
    )
    assert result.packages["api"]["efferent_coupling"] == 1
    assert result.packages["implementation"]["afferent_coupling"] == 1
    assert result.system_metrics["modularity_index"] == 0


def test_stable_dependency_finding_retains_evidence_without_claiming_missing_contract():
    graph = {
        "stable": {"volatile"},
        "caller_one": {"stable"},
        "caller_two": {"stable"},
        "caller_three": {"stable"},
        "volatile": {"one", "two", "three", "four"},
        "one": set(),
        "two": set(),
        "three": set(),
        "four": set(),
    }
    result = analyze_architecture(graph, {name: "" for name in graph})
    rows = [row for row in result.findings if row["rule_id"] == "SKY-Q804"]
    assert len(rows) == 1
    row = rows[0]
    assert row["value"] == "stable -> volatile"
    assert row["severity"] == "MEDIUM"
    assert result.modules["stable"].instability == 0.25
    assert result.modules["volatile"].instability == 0.8
    assert row["metric_granularity"] == "file-level heuristic"
    assert row["message"].startswith("Stable dependency review:")
    assert "alone does not prove" in row["message"]


def _abstractness(source):
    return _compute_abstractness(ast.parse(textwrap.dedent(source)))


def test_abstractness_import_aliases_retain_real_contracts():
    result = _abstractness("""
        from abc import ABC as AbstractBase, abstractmethod as abstract
        from typing import Protocol as Contract, TypeVar as TV, TYPE_CHECKING as TC
        T = TV("T")
        if TC:
            import dependency
        class Interface(Contract):
            def read(self): ...
        class Base(AbstractBase):
            @abstract
            def read(self): ...
    """)
    assert result["abstract_classes"] == 2
    assert result["protocols"] == result["abstract_methods"] == result["type_vars"] == 1
    assert result["abstractness"] == pytest.approx(0.57)


def test_abstractness_local_spelling_does_not_prove_a_contract():
    result = _abstractness("""
        class Protocol: pass
        class ABC: pass
        def abstractmethod(function): return function
        def TypeVar(name): return name
        TYPE_CHECKING = True
        T = TypeVar("T")
        if TYPE_CHECKING: pass
        class Local(Protocol, ABC):
            @abstractmethod
            def run(self): return 42
    """)
    assert result["abstract_classes"] == result["abstract_methods"] == 0
    assert result["protocols"] == result["type_vars"] == 0
    assert result["abstractness"] == 0


def test_abstractness_nested_shadow_does_not_hide_unrelated_real_contract():
    result = _abstractness("""
        from typing import Protocol as Contract
        def local(Contract):
            class Ordinary(Contract): pass
        class Real(Contract): pass
    """)
    assert result["abstract_classes"] == result["protocols"] == 1


def test_abstractness_shadowed_and_mutated_providers_remain_unknown():
    result = _abstractness("""
        import typing as types
        from abc import ABC
        ABC = object
        types.Protocol = object
        class First(ABC): pass
        class Second(types.Protocol): pass
    """)
    assert result["abstract_classes"] == result["protocols"] == 0


def test_abstractness_metaclass_is_not_an_abstract_base_class():
    result = _abstractness("""
        from abc import ABCMeta
        class OrdinaryMeta(ABCMeta): pass
        class Contract(metaclass=ABCMeta): pass
    """)
    assert result["abstract_classes"] == 1


def test_abstractness_class_counts_once_when_bases_have_two_contract_markers():
    result = _abstractness("""
        from abc import ABC
        from typing import Protocol
        class Contract(ABC, Protocol): pass
    """)
    assert result["abstract_classes"] == result["protocols"] == 1
    assert result["abstractness"] == 1


def test_abstractness_compatibility_imports_keep_the_same_contract():
    result = _abstractness("""
        if supports_native:
            from typing import Protocol, TypeVar
        else:
            from typing_extensions import Protocol, TypeVar
        T = TypeVar("T")
        class Contract(Protocol): pass
    """)
    assert result["protocols"] == result["abstract_classes"] == result["type_vars"] == 1


def test_abstractness_mixed_conditional_provider_does_not_prove_contract():
    result = _abstractness("""
        if configured:
            from typing import Protocol
        else:
            from local_library import Protocol
        class Ordinary(Protocol): pass
    """)
    assert result["protocols"] == result["abstract_classes"] == 0


def _cohesion(source, project_root=None):
    tree = ast.parse(textwrap.dedent(source))
    rule = LCOMRule()
    context = {
        "filename": str(project_root / "app/service.py")
        if project_root
        else "/project/app/service.py",
        "project_root": project_root,
    }
    rule.visit_node(tree, context)
    return [
        row
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        for row in rule.visit_node(node, context) or []
    ]


def _disconnected_class(decorator="", base="", method_decorator=""):
    methods = "\n".join(
        f"    {method_decorator}\n    def operation_{index}(self):\n        self.state_{index} = {index}"
        for index in range(3)
    )
    return f"{decorator}\nclass Service{base}:\n{methods}\n"


def test_cohesion_real_imported_contracts_retain_interface_exemptions():
    assert (
        _cohesion(
            "from abc import abstractmethod as contract\n"
            + _disconnected_class(method_decorator="@contract")
        )
        == []
    )
    assert (
        _cohesion(
            "from typing import Protocol as Interface\n"
            + _disconnected_class(base="(Interface)")
        )
        == []
    )


def test_cohesion_ordinary_disconnected_implementation_remains_visible():
    findings = _cohesion(_disconnected_class())
    assert [(row["name"], row["lcom4"]) for row in findings] == [("Service", 3)]


@pytest.mark.parametrize(
    "prefix,base,decorator",
    [
        ("from typing import Protocol\nProtocol = object\n", "(Protocol)", ""),
        (
            "def abstractmethod(f): return f\ndef unrelated():\n    from abc import abstractmethod\n",
            "",
            "@abstractmethod",
        ),
        (
            "from abc import abstractmethod\ndef abstractmethod(f): return f\n",
            "",
            "@abstractmethod",
        ),
    ],
)
def test_cohesion_import_spelling_or_unrelated_scope_cannot_hide_implementation(
    prefix, base, decorator
):
    findings = _cohesion(
        prefix + _disconnected_class(base=base, method_decorator=decorator)
    )
    assert [(row["name"], row["lcom4"]) for row in findings] == [("Service", 3)]


def test_cohesion_actual_container_import_keeps_its_context():
    assert (
        _cohesion(
            "from dataclasses import dataclass as record\n"
            + _disconnected_class(decorator="@record")
        )
        == []
    )


@pytest.mark.parametrize(
    "prefix,decorator,base",
    [
        ("def dataclass(cls): return cls\n", "@dataclass", ""),
        (
            "from dataclasses import dataclass\ndataclass = lambda cls: cls\n",
            "@dataclass",
            "",
        ),
        ("class BaseModel: pass\n", "", "(BaseModel)"),
    ],
)
def test_cohesion_container_lookalike_is_not_a_blanket_exemption(
    prefix, decorator, base
):
    findings = _cohesion(prefix + _disconnected_class(decorator=decorator, base=base))
    assert [(row["name"], row["lcom4"]) for row in findings] == [("Service", 3)]


def test_cohesion_project_local_typing_provider_cannot_hide_implementation(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "typing.py").write_text("class Protocol: pass\n")
    findings = _cohesion(
        "from typing import Protocol\n" + _disconnected_class(base="(Protocol)"),
        project_root=tmp_path,
    )
    assert [(row["name"], row["lcom4"]) for row in findings] == [("Service", 3)]


def _coupling(source, name="Consumer"):
    return analyze_coupling(ast.parse(textwrap.dedent(source)), "service.py")[
        "classes"
    ][name]


def test_coupling_does_not_count_old_class_after_ordinary_rebinding():
    result = _coupling("""
        class Provider: pass
        Provider = external_provider
        class Consumer:
            def run(self): return Provider()
    """)
    assert result["efferent_classes"] == []


def test_coupling_class_definition_overwrites_earlier_unrelated_binding():
    result = _coupling("""
        Provider = external_provider
        class Provider: pass
        class Consumer:
            def run(self): return Provider()
    """)
    assert result["efferent_classes"] == ["Provider"]


def test_coupling_eager_base_keeps_class_before_later_rebinding():
    result = _coupling("""
        class Provider: pass
        class Consumer(Provider): pass
        Provider = external_provider
    """)
    assert result["efferent_classes"] == ["Provider"]


def test_coupling_conditional_provider_rebinding_remains_unknown():
    result = _coupling("""
        class Provider: pass
        if configured:
            Provider = external_provider
        class Consumer:
            def run(self): return Provider()
    """)
    assert result["efferent_classes"] == []


def test_coupling_class_rebinding_cannot_use_older_native_resolution():
    assert _needs_scope_resolution(ast.parse("class A: pass\nA = external\n"))


@pytest.mark.parametrize(
    "transform",
    [
        "Provider = decorate(Provider)",
        "Provider = decorate(target=Provider)",
        "Provider = outer(inner(options=True)(Provider))",
        "Provider = decorate(outer(Provider))",
        "Provider = Provider",
        "Provider: type",
        "Provider: type = decorate(Provider)",
        "Provider = Provider()",
        "Provider = Provider[int]",
    ],
)
def test_coupling_explicit_decorator_application_retains_source_class_family(transform):
    result = _coupling(
        "class Provider: pass\n" + transform + "\n"
        "class Consumer:\n    def run(self): return Provider()\n"
    )
    assert result["efferent_classes"] == ["Provider"]


def test_coupling_source_returning_class_decorator_retains_real_edge():
    result = _coupling("""
        def add_behavior(cls):
            cls.enabled = True
            return cls
        class Provider: pass
        Provider = add_behavior(Provider)
        class Consumer:
            def run(self): return Provider()
    """)
    assert result["efferent_classes"] == ["Provider"]


def test_coupling_conditional_class_family_transforms_retain_real_edge():
    result = _coupling("""
        if configured:
            class Provider: pass
        else:
            class Provider: pass
        if decorated:
            Provider = decorate(Provider)
        class Consumer:
            def run(self): return Provider()
    """)
    assert len(result["efferent_classes"]) == 1
    assert result["efferent_classes"][0].startswith("Provider@")


@pytest.mark.parametrize(
    "value",
    [
        "decorate('Provider')",
        "decorate(other)",
        "unrelated_factory()",
    ],
)
def test_coupling_rebinding_lookalike_does_not_carry_old_source_class(value):
    result = _coupling(
        "class Provider: pass\nProvider = " + value + "\n"
        "class Consumer:\n    def run(self): return Provider()\n"
    )
    assert result["efferent_classes"] == []
