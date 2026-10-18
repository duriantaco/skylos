"""C303 adds evidence without changing the underlying arity findings."""

import ast
import textwrap

import pytest

from skylos.rules.quality.structure import ArgCountRule


def scan(source, *, filename="app.py", project_root=None, source_reader=None, **limits):
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    context = {
        "filename": str(filename),
        "project_root": project_root,
        "source": source,
        "mod": "app",
        "receiver_source_reader": source_reader,
    }
    findings = []
    rule = ArgCountRule(**limits)
    for node in ast.walk(tree):
        findings.extend(rule.visit_node(node, context) or [])
    return findings


def child_evidence(source, **kwargs):
    rows = scan(source, **kwargs)
    assert len(rows) >= 2
    return rows[-1]["argument_evidence"]


def test_required_positional_violation_retains_original_measurement():
    [row] = scan("def target(a, b, c, d, e, f): pass")
    assert row["value"] == 6
    assert row["threshold"] == 5
    assert row["severity"] == "MEDIUM"
    assert row["message"].startswith("Function has 6 required positional arguments")
    assert row["argument_evidence"] == {
        "version": 1,
        "complete": True,
        "metric": "required_positional",
        "source_line": 1,
        "required_positional": 6,
        "optional_positional": 0,
        "positional_only": 0,
        "positional_or_keyword": 6,
        "required_keyword_only": 0,
        "optional_keyword_only": 0,
        "keyword_only": 0,
        "total_parameters": 6,
        "positional_parameters": [
            {"name": name, "kind": "positional_or_keyword", "required": True}
            for name in "abcdef"
        ],
        "keyword_only_parameters": [],
        "variadic_positional": None,
        "variadic_keyword": None,
        "receiver_binding": "function",
        "receiver_parameter": None,
        "limits": {"required_positional": 5, "total_parameters": 10},
    }


def test_direct_function_visit_without_module_keeps_the_raw_finding():
    node = ast.parse("def target(a, b, c, d, e, f): pass").body[0]
    [row] = ArgCountRule().visit_node(node, {"filename": "app.py"})
    assert row["value"] == 6
    assert row["threshold"] == 5
    assert row["argument_evidence"]["complete"] is False
    assert row["argument_evidence"]["receiver_binding"] == "unknown"


def test_known_static_override_does_not_reuse_the_legacy_uncertain_receiver_minimum():
    source = """
        from typing_extensions import override
        class Target:
            @staticmethod
            @override
            def target(a, b, c, d, e, f, *, g=1, h=2, i=3, j=4, k=5, m=6): pass
    """
    [row] = scan(source)
    # Preserve the current detector's uncertain raw measurement and message.
    assert row["value"] == 11
    assert row["required_argument_range"] == [5, 6]
    evidence = row["argument_evidence"]
    assert evidence["complete"] is True
    assert evidence["metric"] == "total_parameters"
    assert evidence["receiver_binding"] == "static"
    assert evidence["required_positional"] == 6
    assert evidence["total_parameters"] == 12
    assert "override_contract" not in evidence


def test_optional_and_keyword_only_breakdown_uses_configured_limits():
    [row] = scan(
        "def target(a, /, b=1, c=2, *, d, e=3, **extras): pass",
        max_required=2,
        max_total=4,
    )
    evidence = row["argument_evidence"]
    assert row["value"] == 5
    assert row["severity"] == "LOW"
    assert evidence["metric"] == "total_parameters"
    assert evidence["required_positional"] == 1
    assert evidence["optional_positional"] == 2
    assert evidence["positional_only"] == 1
    assert evidence["positional_or_keyword"] == 2
    assert evidence["required_keyword_only"] == 1
    assert evidence["optional_keyword_only"] == 1
    assert evidence["variadic_keyword"] == "extras"
    assert evidence["limits"] == {"required_positional": 2, "total_parameters": 4}


@pytest.mark.parametrize(
    ("decorator", "receiver", "binding"),
    [
        ("", "self, ", "instance"),
        ("@classmethod\n", "cls, ", "class"),
        ("@staticmethod\n", "", "static"),
    ],
)
def test_receiver_is_not_counted_as_a_caller_parameter(decorator, receiver, binding):
    [row] = scan(
        "class Target:\n"
        + textwrap.indent(
            decorator + f"def action({receiver}a, b=1, c=2, *, d=3): pass\n", "    "
        ),
        max_total=3,
    )
    evidence = row["argument_evidence"]
    assert row["value"] == 4
    assert evidence["complete"] is True
    assert evidence["receiver_binding"] == binding
    assert evidence["required_positional"] == 1
    assert evidence["optional_positional"] == 2
    assert [parameter["name"] for parameter in evidence["positional_parameters"]] == [
        "a",
        "b",
        "c",
    ]
    assert evidence["receiver_parameter"] == (
        {"instance": "self", "class": "cls"}.get(binding)
    )


def test_defaulted_receiver_is_removed_only_from_the_new_breakdown():
    [row] = scan(
        "class Target:\n    def action(self=None, a=1, b=2, c=3): pass", max_total=2
    )
    assert row["value"] == 3
    # Keep the legacy message stable, even though it counted the receiver default.
    assert "4 optional positional" in row["message"]
    assert row["argument_evidence"]["optional_positional"] == 3


@pytest.mark.parametrize("decorator", ["custom", "staticmethod", "classmethod"])
def test_unknown_or_shadowed_decorators_have_incomplete_evidence(decorator):
    source = f"""
        {decorator} = custom_factory()
        class Target:
            @{decorator}
            def action(self, a, b, c, d, e, f): pass
    """
    [row] = scan(source)
    assert row["value"] == 6
    assert row["required_argument_range"] == [6, 7]
    assert row["argument_evidence"]["complete"] is False
    assert row["argument_evidence"]["receiver_binding"] == "unknown"


def test_exact_local_base_contract_is_additive_and_keeps_both_raw_rows():
    evidence = child_evidence("""
        class Base:
            def action(self, a, b, c, d, e, f, *, flag=False): pass
        class Child(Base):
            def action(this, a, b, c, d, e, f, *, flag=True): pass
    """)
    contract = evidence["override_contract"]
    assert contract["kind"] == "project_base_signature"
    assert contract["base_class"] == "Base"
    assert contract["receiver_binding"] == "instance"
    assert contract["required_positional"] == 6
    assert contract["total_parameters"] == 7
    assert contract["parameter_shape"] == "identical"


@pytest.mark.parametrize(
    "signature",
    [
        "a, b, c, d, e, f, g",  # Independent required positional widening.
        "a, b, c, d, e, f, g=1",  # Independent optional widening.
        "a, b, c, d, e, f, *, flag",  # Added required keyword parameter.
        "a, b, c, d, e, renamed",  # Different accepted keyword interface.
        "a, b, c, d, f, e",  # Changed positional semantics.
        "a, b, c, d, e, f, /",  # Keyword calls no longer accepted.
        "a, b, c, d, e, f=1",  # Different required/defaulted contract.
        "a, b, c, d, e, f, **extra",  # Independently extended interface.
    ],
)
def test_counts_or_same_name_do_not_prove_a_base_contract(signature):
    evidence = child_evidence(
        f"""
        class Base:
            def action(self, a, b, c, d, e, f): pass
        class Child(Base):
            def action(self, {signature}): pass
    """,
        max_total=5,
    )
    assert "override_contract" not in evidence


@pytest.mark.parametrize("binding", ["staticmethod", "classmethod"])
def test_static_and_class_method_contracts_require_matching_binding(binding):
    receiver = "cls, " if binding == "classmethod" else ""
    evidence = child_evidence(f"""
        class Base:
            @{binding}
            def action({receiver}a, b, c, d, e, f): pass
        class Child(Base):
            @{binding}
            def action({receiver}a, b, c, d, e, f): pass
    """)
    assert (
        evidence["override_contract"]["receiver_binding"]
        == {"staticmethod": "static", "classmethod": "class"}[binding]
    )


def test_same_parameter_counts_with_changed_receiver_binding_have_no_contract():
    evidence = child_evidence("""
        class Base:
            @staticmethod
            def action(a, b, c, d, e, f): pass
        class Child(Base):
            def action(self, a, b, c, d, e, f): pass
    """)
    assert "override_contract" not in evidence


@pytest.mark.parametrize(
    "prefix, base, child_prefix, suffix",
    [
        ("", "Unknown", "", ""),
        ("@unknown\n", "Base", "", ""),
        ("", "Base", "@unknown\n", ""),
        ("", "Base", "", "Base = other\n"),
        ("", "Base", "", "Base.action = other\n"),
        ("", "Base", "", "Child.action = other\n"),
        ("", "Base", "", "register(Base)\n"),
    ],
)
def test_unknown_class_construction_and_rebinding_keep_contract_unknown(
    prefix, base, child_prefix, suffix
):
    evidence = child_evidence(
        prefix
        + "class Base:\n    def action(self, a, b, c, d, e, f): pass\n"
        + child_prefix
        + f"class Child({base}):\n    def action(self, a, b, c, d, e, f): pass\n"
        + suffix
    )
    assert "override_contract" not in evidence
    assert evidence["complete"] is False


@pytest.mark.parametrize(
    "class_statement, extra",
    [
        ("class Base(metaclass=Factory):", ""),
        ("class Base:", "    def __init_subclass__(cls): pass\n"),
        ("class Base:", "    def __getattribute__(self, name): pass\n"),
        ("class Base:", "    def __getattr__(self, name): pass\n"),
    ],
)
def test_metaclasses_and_dynamic_attribute_hooks_are_not_contract_proof(
    class_statement, extra
):
    evidence = child_evidence(
        class_statement
        + "\n"
        + extra
        + "    def action(self, a, b, c, d, e, f): pass\n"
        + "class Child(Base):\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    assert "override_contract" not in evidence


def test_import_proven_override_marker_enriches_an_exact_base_contract():
    evidence = child_evidence("""
        from typing_extensions import override as overrides
        class Base:
            def action(self, a, b, c, d, e, f): pass
        class Child(Base):
            @overrides
            def action(self, a, b, c, d, e, f): pass
    """)
    assert evidence["complete"] is True
    assert evidence["override_contract"]["marker"] == "typing.override"


@pytest.mark.parametrize("shadow", ["overrides = custom\n", ""])
def test_override_marker_does_not_establish_an_unresolved_or_shadowed_contract(shadow):
    source = (
        "from typing_extensions import override as overrides\n"
        + shadow
        + """
class Child(External):
    @overrides
    def action(self, a, b, c, d, e, f): pass
"""
    )
    [row] = scan(source)
    assert "override_contract" not in row["argument_evidence"]


def test_local_typing_module_blocks_stdlib_marker_proof(tmp_path):
    (tmp_path / "typing_extensions.py").write_text(
        "def override(function): return wrap(function)\n"
    )
    source = """
        from typing_extensions import override
        class Base:
            def action(self, a, b, c, d, e, f): pass
        class Child(Base):
            @override
            def action(self, a, b, c, d, e, f): pass
    """
    evidence = child_evidence(
        source, filename=tmp_path / "app.py", project_root=tmp_path
    )
    assert "override_contract" not in evidence
    assert evidence["complete"] is False


@pytest.mark.parametrize(
    "import_line, base",
    [
        ("from .base import Base", "Base"),
        ("from . import base", "base.Base"),
        ("import pkg.base as base", "base.Base"),
        ("import pkg.base", "pkg.base.Base"),
    ],
)
def test_project_base_imports_are_read_without_executing_target_code(
    tmp_path, import_line, base
):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "base.py").write_text(
        "raise RuntimeError('never execute')\nclass Base:\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    source = (
        import_line
        + f"\nclass Child({base}):\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    [row] = scan(source, filename=package / "app.py", project_root=tmp_path)
    contract = row["argument_evidence"]["override_contract"]
    assert contract["base_file"] == str(package / "base.py")
    assert contract["base_class"] == "Base"


def test_historical_reader_proof_never_uses_the_current_base_file(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "base.py").write_text(
        "class Base:\n    def action(self, unrelated): pass\n"
    )
    seen = []

    def reader(path):
        seen.append(path.as_posix())
        if path.as_posix() == "pkg/base.py":
            return "class Base:\n    def action(self, a, b, c, d, e, f): pass\n"
        return None

    [row] = scan(
        "from .base import Base\nclass Child(Base):\n    def action(self, a, b, c, d, e, f): pass\n",
        filename=package / "app.py",
        project_root=tmp_path,
        source_reader=reader,
    )
    assert row["argument_evidence"]["override_contract"]["base_class"] == "Base"
    assert "pkg/base.py" in seen


@pytest.mark.parametrize("root", [None, 123])
def test_unavailable_project_root_does_not_lose_the_raw_finding(root):
    node = ast.parse("def target(a, b, c, d, e, f): pass").body[0]
    [row] = ArgCountRule().visit_node(
        node, {"filename": "app.py", "project_root": root}
    )
    assert row["value"] == 6
    assert "override_contract" not in row["argument_evidence"]


def test_unreadable_historical_base_keeps_the_finding_visible(tmp_path):
    def reader(path):
        raise OSError("snapshot unavailable")

    [row] = scan(
        "from .base import Base\nclass Child(Base):\n    def action(self, a, b, c, d, e, f): pass\n",
        filename=tmp_path / "app.py",
        project_root=tmp_path,
        source_reader=reader,
    )
    assert row["value"] == 6
    assert row["argument_evidence"]["complete"] is False


def test_symlinked_project_base_is_not_followed(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (tmp_path / "real.py").write_text(
        "class Base:\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    (package / "base.py").symlink_to(tmp_path / "real.py")
    [row] = scan(
        "from .base import Base\nclass Child(Base):\n    def action(self, a, b, c, d, e, f): pass\n",
        filename=package / "app.py",
        project_root=tmp_path,
    )
    assert "override_contract" not in row["argument_evidence"]
    assert row["argument_evidence"]["complete"] is False


def test_unsafe_package_is_not_permission_to_resolve_another_same_name_module(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "base").mkdir()
    (tmp_path / "unsafe.py").write_text(
        "raise RuntimeError('never read through link')\n"
    )
    (package / "base" / "__init__.py").symlink_to(tmp_path / "unsafe.py")
    (package / "base.py").write_text(
        "class Base:\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    [row] = scan(
        "from .base import Base\nclass Child(Base):\n    def action(self, a, b, c, d, e, f): pass\n",
        filename=package / "app.py",
        project_root=tmp_path,
    )
    assert "override_contract" not in row["argument_evidence"]


def test_base_name_must_be_bound_before_the_class_definition():
    evidence = child_evidence("""
        class Child(Base):
            def action(self, a, b, c, d, e, f): pass
        class Base:
            def action(self, a, b, c, d, e, f): pass
    """)
    # ast.walk emits the child's finding first.
    rows = scan(
        "class Child(Base):\n    def action(self, a, b, c, d, e, f): pass\nclass Base:\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    assert "override_contract" not in rows[0]["argument_evidence"]
    assert "override_contract" not in evidence


def test_import_binding_must_precede_the_base_expression(tmp_path):
    (tmp_path / "base.py").write_text(
        "class Base:\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    [row] = scan(
        "class Child(Base):\n    def action(self, a, b, c, d, e, f): pass\nfrom base import Base\n",
        filename=tmp_path / "app.py",
        project_root=tmp_path,
    )
    assert "override_contract" not in row["argument_evidence"]


def test_relative_source_name_is_resolved_against_project_root(tmp_path):
    (tmp_path / "base.py").write_text(
        "class Base:\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    [row] = scan(
        "from .base import Base\nclass Child(Base):\n    def action(self, a, b, c, d, e, f): pass\n",
        filename="app.py",
        project_root=tmp_path,
    )
    assert row["argument_evidence"]["override_contract"]["base_file"] == str(
        tmp_path / "base.py"
    )


def test_repeated_method_definitions_are_not_an_override_proof():
    rows = scan("""
        class Base:
            def action(self, a, b, c, d, e, f): pass
        class Child(Base):
            def action(self, a, b, c, d, e, f): pass
            def action(self, a, b, c, d, e, f): pass
    """)
    assert len(rows) == 3
    for row in rows[1:]:
        assert "override_contract" not in row["argument_evidence"]
        assert row["argument_evidence"]["complete"] is False


def test_import_search_does_not_bypass_an_unsafe_first_layout(tmp_path):
    (tmp_path / "unsafe.py").write_text("raise RuntimeError('never execute')\n")
    (tmp_path / "base.py").symlink_to(tmp_path / "unsafe.py")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "base.py").write_text(
        "class Base:\n    def action(self, a, b, c, d, e, f): pass\n"
    )
    [row] = scan(
        "from base import Base\nclass Child(Base):\n    def action(self, a, b, c, d, e, f): pass\n",
        filename=tmp_path / "app.py",
        project_root=tmp_path,
    )
    assert "override_contract" not in row["argument_evidence"]


def test_overload_evidence_uses_the_selected_signature_and_keeps_raw_fields():
    [row] = scan("""
        from typing import overload
        @overload
        def target(a, b, c, d, e, f): ...
        @overload
        def target(a, b, c): ...
        def target(*args): return args
    """)
    assert row["value"] == 6
    assert row["line"] == 7
    assert row["overload_metric_source_line"] == 4
    assert row["argument_evidence"]["source_line"] == 4
    assert row["argument_evidence"]["required_positional"] == 6
    assert row["argument_evidence"]["complete"] is True
    assert len(row["overload_signatures"]) == 3


def test_all_over_limit_overloads_need_independent_base_coverage():
    source = """
        from typing import overload
        class Base:
            @overload
            def target(self, a, b, c, d, e, f): ...
            @overload
            def target(self, a, b): ...
            def target(self, *args): return args
        class Child(Base):
            @overload
            def target(self, a, b, c, d, e, f): ...
            @overload
            def target(self, a, b): ...
            def target(self, *args): return args
    """
    evidence = child_evidence(source)
    assert evidence["override_contract"]["covered_source_lines"] == [11]
    # Change only the child's short overload into an independent wider one.
    lines = textwrap.dedent(source).splitlines()
    lines[12] = "    def target(self, a, b, c, d, e, f, g): ..."
    wider = "\n".join(lines)
    assert "override_contract" not in child_evidence(wider)


def test_c3_order_uses_the_actual_first_interface_not_any_matching_base():
    source = """
        class First:
            def target(self, a, b, c, d, e, other): pass
        class Second:
            def target(self, a, b, c, d, e, f): pass
        class Child(First, Second):
            def target(self, a, b, c, d, e, f): pass
    """
    assert "override_contract" not in child_evidence(source)
    assert (
        child_evidence(source.replace("Child(First, Second)", "Child(Second, First)"))[
            "override_contract"
        ]["base_class"]
        == "Second"
    )


def test_inheritance_depth_budget_keeps_unresolved_contract_visible():
    source = "class Base:\n    def target(self, a, b, c, d, e, f): pass\n"
    parent = "Base"
    for index in range(20):
        source += f"class Layer{index}({parent}): pass\n"
        parent = f"Layer{index}"
    source += f"class Child({parent}):\n    def target(self, a, b, c, d, e, f): pass\n"
    assert "override_contract" not in child_evidence(source)
