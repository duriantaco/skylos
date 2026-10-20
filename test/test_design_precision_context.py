"""Design advice measures owned implementation, not data or unrelated scopes."""

import ast
import textwrap

import pytest

from test.fixture_paths import write_fixture
import skylos.rules.quality.coupling as coupling

from skylos.rules.quality.class_size import GodClassRule, GodFileRule
from skylos.rules.quality.coupling import CBORule, analyze_coupling
from skylos.rules.quality.cohesion import LCOMRule, analyze_cohesion
from skylos.analysis.architecture import analyze_architecture


def _findings(rule, source):
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    context = {"filename": "/project/package/design.py", "source": source}
    return [
        row for node in ast.walk(tree) for row in rule.visit_node(node, context) or ()
    ]


def _size(source, **limits):
    return _findings(
        GodFileRule(
            max_lines=10, max_definitions=5, max_top_level_definitions=5, **limits
        ),
        source,
    )


def test_multiline_literal_catalog_is_not_implementation_complexity():
    source = (
        "LABELS = {\n"
        + "".join(f"    'key_{index}': 'label {index}',\n" for index in range(40))
        + "}\n"
    )
    assert _size(source) == []


@pytest.mark.parametrize(
    "expression", ["make_label(1)", "value for value in values", "**other"]
)
def test_catalog_exemption_does_not_cover_computation(expression):
    if expression == "value for value in values":
        source = (
            "LABELS = [\n"
            + "\n".join(f"    func_{index}({expression})," for index in range(15))
            + "\n]\n"
        )
        # Calls in a container still perform real implementation work.
    else:
        source = (
            "LABELS = {\n"
            + "\n".join(
                f"    {index}: {expression},"
                if expression != "**other"
                else "    **other,"
                for index in range(15)
            )
            + "\n}\n"
        )
    assert _size(source)


def test_catalog_does_not_hide_real_implementation_in_same_file():
    source = "LABELS = [\n" + "1,\n" * 30 + "]\n"
    source += "def process(value):\n" + "    value += 1\n" * 11 + "    return value\n"
    (finding,) = _size(source)
    assert finding["code_lines"] > finding["implementation_code_lines"] > 10
    assert finding["value"] == finding["implementation_code_lines"]


def test_literal_closing_line_retains_executable_statement():
    source = "VALUES = [\n" + "1,\n" * 12 + "]; run()\n"
    source += "\n".join(f"run_{index}()" for index in range(9))
    assert _size(source)


def test_behavioral_class_literal_catalog_has_same_weight_as_module_catalog():
    catalog = "VALUES = {\n" + "".join(f"    {index}: 'label {index}',\n" for index in range(40)) + "}\n"
    method = "def lookup(self, key):\n    return self.VALUES[key]\n"
    source = "class Symbols:\n" + textwrap.indent(catalog + method, "    ")
    assert _size(source) == []
    assert _size(catalog + "class Symbols:\n" + textwrap.indent(method, "    ")) == []


def test_class_catalog_does_not_remove_method_implementation_lines():
    catalog = "VALUES = [\n" + "    1,\n" * 40 + "]\n"
    method = "def transform(self, value):\n" + "    value += 1\n" * 11 + "    return value\n"
    source = "class Symbols:\n" + textwrap.indent(catalog + method, "    ")
    (finding,) = _size(source)
    assert finding["implementation_code_lines"] > 10
    assert finding["code_lines"] - finding["implementation_code_lines"] == 40


def test_class_computed_catalog_retains_implementation_weight():
    catalog = "VALUES = {\n" + "".join(f"    {index}: build({index}),\n" for index in range(40)) + "}\n"
    source = "class Symbols:\n" + textwrap.indent(catalog + "def lookup(self, key):\n    return self.VALUES[key]\n", "    ")
    (finding,) = _size(source)
    assert finding["code_lines"] == finding["implementation_code_lines"]


def test_nested_class_literal_closing_line_retains_runtime_statement():
    source = "class Outer:\n    class Symbols:\n        VALUES = [\n" + "            1,\n" * 40 + "        ]; register()\n"
    source += "        def lookup(self, key):\n            return self.VALUES[key]\n"
    source += "\n".join(f"execute_{index}()" for index in range(8))
    assert _size(source)


def test_declaration_catalog_is_not_a_god_file():
    source = "".join(
        f"class Event{index}:\n    code: int\n    label: str\n" for index in range(20)
    )
    assert (
        _findings(
            GodFileRule(max_lines=100, max_definitions=5, max_top_level_definitions=5),
            source,
        )
        == []
    )


def test_runtime_class_catalog_still_reports_independent_implementations():
    source = "".join(
        f"class Handler{index}:\n    def run(self):\n        return process({index})\n"
        for index in range(8)
    )
    assert _findings(
        GodFileRule(max_lines=100, max_definitions=5, max_top_level_definitions=5),
        source,
    )


def test_stub_function_surface_retains_configured_limit():
    source = "".join(f"def hook_{index}(value): ...\n" for index in range(8))
    (finding,) = _findings(
        GodFileRule(max_lines=100, max_definitions=5, max_top_level_definitions=5),
        source,
    )
    assert finding["total_definitions"] == 8


def _record(extra="", decorator=""):
    parameters = ", ".join(f"field_{index}" for index in range(18))
    body = "".join(
        f"        self.field_{index} = field_{index}\n" for index in range(18)
    )
    return f"{decorator}class Record:\n    def __init__(self, {parameters}):\n{body}{extra}"


def test_passive_record_fields_are_not_a_god_class():
    assert _findings(GodClassRule(), _record()) == []


@pytest.mark.parametrize("attribute", ["__class__", "__dict__", "__weakref__"])
def test_record_constructor_magic_attribute_writes_retain_design_checks(attribute):
    source = _record().replace("self.field_0 = field_0", f"self.{attribute} = field_0")
    (finding,) = _findings(GodClassRule(), source)
    assert finding["value"] == 18
    catalog = "".join(source.replace("class Record:", f"class Record{index}:")
                      for index in range(8))
    assert _size(catalog)


@pytest.mark.parametrize(
    "extra",
    [
        "    def save(self):\n        persist(self)\n",
        "    def route(self, flag):\n        if flag:\n            return self.field_0\n",
    ],
)
def test_large_stateful_class_with_real_behavior_still_reports(extra):
    (finding,) = _findings(GodClassRule(), _record(extra))
    assert finding["value"] == 18


def test_unknown_record_decorator_preserves_design_check():
    assert _findings(GodClassRule(), _record(decorator="@register\n"))


@pytest.mark.parametrize(
    "declaration",
    ["    field_0 = external_descriptor\n", "    field_0 = descriptors.value\n"],
)
def test_unknown_record_descriptor_keeps_attribute_warning(declaration):
    source = _record().replace("class Record:\n", "class Record:\n" + declaration)
    assert _findings(GodClassRule(), source)


def test_inherited_record_constructor_is_not_proven_passive():
    assert _findings(
        GodClassRule(), _record().replace("class Record:", "class Record(Behavior):")
    )


def test_nested_field_factory_shadowing_is_not_import_proof():
    # A runtime class with an unknown descriptor initializer stays checked.
    source = "from pydantic import Field\ndef unrelated(Field): pass\n" + "".join(
        f"class Schema{index}:\n    value: str = Field()\n" for index in range(8)
    )
    assert _findings(
        GodFileRule(max_lines=100, max_definitions=5, max_top_level_definitions=5),
        source,
    )


@pytest.mark.parametrize(
    "prefix,field",
    [
        ("", "factory()"),
        ("def Field(*args): return build(*args)\n", "Field()"),
        ("from pydantic import Field\nField = custom\n", "Field()"),
        ("from pydantic import Field\n", "Field(default=build())"),
    ],
)
def test_unknown_declaration_initializers_retain_file_size_check(prefix, field):
    source = prefix + "".join(
        f"class Schema{index}:\n    value = {field}\n" for index in range(8)
    )
    assert _findings(
        GodFileRule(max_lines=100, max_definitions=5, max_top_level_definitions=5),
        source,
    )


def test_import_proven_schema_fields_are_declarations():
    source = "from pydantic import Field as SchemaField\n"
    source += "".join(
        f"class Schema{index}:\n    value: str = SchemaField(default='')\n"
        for index in range(8)
    )
    assert (
        _findings(
            GodFileRule(max_lines=10, max_definitions=5, max_top_level_definitions=5),
            source,
        )
        == []
    )


def test_class_local_field_factory_shadowing_retains_file_check():
    source = "from pydantic import Field\n"
    source += "".join(
        f"class Schema{index}:\n    Field = custom\n    value = Field()\n"
        for index in range(8)
    )
    assert _findings(
        GodFileRule(max_lines=100, max_definitions=5, max_top_level_definitions=5),
        source,
    )


def test_property_getter_and_setter_implementation_count_is_preserved():
    source = "class Service:\n" + "".join(
        f"    def method_{index}(self):\n        return work({index})\n"
        for index in range(19)
    )
    source += "    @property\n    def value(self):\n        return self._value\n    @value.setter\n    def value(self, value):\n        self._value = value\n"
    (finding,) = _findings(GodClassRule(), source)
    assert finding["value"] == 21


def _dependencies(source, name):
    return analyze_coupling(ast.parse(textwrap.dedent(source)), "design.py")["classes"][
        name
    ]


def test_nested_class_implementation_does_not_belong_to_outer():
    source = """
        class Dependency: pass
        class Outer:
            class Inner:
                def run(self):
                    return Dependency()
            def run(self):
                return 1
    """
    assert _dependencies(source, "Outer")["efferent_classes"] == []
    assert _dependencies(source, "Inner")["efferent_classes"] == ["Dependency"]


def test_duplicate_nested_class_names_keep_separate_identities():
    source = """
        class Dependency: pass
        class First:
            class Worker:
                def run(self): return Dependency()
        class Second:
            class Worker:
                def run(self): return 1
    """
    result = analyze_coupling(ast.parse(textwrap.dedent(source)), "design.py")[
        "classes"
    ]
    workers = [row for key, row in result.items() if key.startswith("Worker@")]
    assert len(workers) == 2
    assert sorted(row["efferent_coupling"] for row in workers) == [0, 1]


def test_conditional_class_variants_keep_one_dependency_per_lexical_binding():
    source = ""
    for index in range(6):
        source += f"if feature_{index}:\n    class Part{index}: pass\nelse:\n    class Part{index}: pass\n"
    source += "class Service:\n    def run(self):\n" + "".join(
        f"        Part{index}()\n" for index in range(6)
    )
    result = _dependencies(source, "Service")
    assert result["efferent_coupling"] == 6
    assert len(set(result["efferent_classes"])) == 6
    (finding,) = _findings(CBORule(), source)
    assert finding["value"] == 6


@pytest.mark.parametrize(
    "body",
    ["return other.Dependency()", "return Dependency()", "return Dependency.VALUE"],
)
def test_local_parameter_or_namespace_does_not_prove_a_class_edge(body):
    source = f"class Dependency: pass\nclass Client:\n    def run(self, Dependency, other):\n        {body}\n"
    assert _dependencies(source, "Client")["efferent_coupling"] == 0


def test_real_class_dependency_is_kept_alongside_shadowed_method():
    source = """
        class Dependency: pass
        class Client:
            def shadowed(self, Dependency): return Dependency()
            def actual(self): return Dependency()
    """
    assert _dependencies(source, "Client")["efferent_classes"] == ["Dependency"]


@pytest.mark.parametrize(
    "expression",
    [
        "(lambda Dependency: Dependency())(factory)",
        "[Dependency() for Dependency in factories]",
    ],
)
def test_expression_local_bindings_do_not_invent_dependencies(expression):
    source = f"class Dependency: pass\nclass Client:\n    def run(self): return {expression}\n"
    assert _dependencies(source, "Client")["efferent_coupling"] == 0


@pytest.mark.parametrize(
    "expression",
    [
        "[item for item in Dependency()]",
        "(lambda Dependency=Dependency(): Dependency)()",
    ],
)
def test_expression_outer_evaluation_keeps_real_dependencies(expression):
    source = f"class Dependency: pass\nclass Client:\n    def run(self): return {expression}\n"
    assert _dependencies(source, "Client")["efferent_classes"] == ["Dependency"]


def test_explicit_global_class_reference_is_not_local_shadowing():
    source = "class Dependency: pass\nclass Client:\n    def run(self):\n        global Dependency\n        return Dependency()\n"
    assert _dependencies(source, "Client")["efferent_classes"] == ["Dependency"]


def test_annotation_uses_definition_scope_not_parameter_bindings():
    source = """
        class Dependency: pass
        class Client:
            def run(self, Dependency: Dependency, /): return Dependency()
    """
    assert _dependencies(source, "Client")["breakdown"]["type_hints"] == ["Dependency"]
    assert _dependencies(source, "Client")["breakdown"]["instantiation"] == []


def test_schema_graph_does_not_trigger_behavioral_coupling_advice():
    source = "".join(f"class Part{index}: pass\n" for index in range(6))
    source += "class Schema:\n" + "".join(
        f"    part_{index}: Part{index}\n" for index in range(6)
    )
    assert _dependencies(source, "Schema")["efferent_coupling"] == 6
    assert _findings(CBORule(), source) == []
    source += "    def persist(self):\n        write(self)\n"
    (finding,) = _findings(CBORule(), source)
    assert finding["value"] == 6
    assert finding["coupling_scope"] == "file"
    assert "file-local Ca=" in finding["message"]


def test_real_nested_class_constructor_is_resolved():
    source = """
        class Container:
            class Part: pass
        class Client:
            def run(self): return Container.Part()
    """
    assert "Part" in _dependencies(source, "Client")["efferent_classes"]


def test_rule_cache_is_refreshed_between_source_snapshots():
    rule = CBORule()
    source = "".join(f"class Part{index}: pass\n" for index in range(6))
    source += "class Service:\n    def run(self):\n" + "".join(
        f"        Part{index}()\n" for index in range(6)
    )
    assert len(_findings(rule, source)) == 1
    assert _findings(rule, "class Service:\n    def run(self): return 1\n") == []


def test_native_metric_cannot_omit_positional_only_type_dependencies(monkeypatch):
    monkeypatch.setattr(coupling, "_fast_analyze_coupling", lambda *_: {"classes": {}})
    source = "".join(f"class Part{index}: pass\n" for index in range(6))
    parameters = ", ".join(f"part_{index}: Part{index}" for index in range(6))
    source += f"class Client:\n    def run(self, {parameters}, /): return 1\n"
    (finding,) = _findings(CBORule(), source)
    assert finding["value"] == 6


def test_native_metric_cannot_invent_shadowed_class_decorator_edge(monkeypatch):
    stale = {
        "classes": {
            "Client": {
                "efferent_coupling": 6,
                "afferent_coupling": 0,
                "instability": 1.0,
                "breakdown": {"decorator": [f"Part{index}" for index in range(6)]},
            }
        }
    }
    monkeypatch.setattr(coupling, "_fast_analyze_coupling", lambda *_: stale)
    source = "".join(f"class Part{index}: pass\n" for index in range(6))
    source += "class Client:\n    Part0 = custom\n"
    source += "".join(f"    @Part{index}\n" for index in range(6))
    source += "    def run(self): return 1\n"
    assert _findings(CBORule(low_threshold=5), source) == []


def _dip(source=None, *, filename="/project/public.py"):
    graph = {
        "public": {"implementation"},
        "implementation": {f"leaf_{index}" for index in range(6)},
    }
    graph.update({f"consumer_{index}": {"public"} for index in range(4)})
    graph.update({f"leaf_{index}": set() for index in range(6)})
    files = {name: f"/project/{name}.py" for name in graph}
    files["public"] = filename
    trees = (
        {"public": ast.parse(textwrap.dedent(source))} if source is not None else None
    )
    return analyze_architecture(
        graph, files, module_trees=trees, module_loc={name: 1 for name in graph}
    )


@pytest.mark.parametrize(
    "source",
    [
        "from implementation import Service as Service\n",
        "from implementation import Service\n__all__ = ['Service']\n",
        "from implementation import Debugger as _Debugger\nset_trace = _Debugger.set_trace\n__all__ = ['set_trace']\n",
    ],
)
def test_static_public_export_facade_is_not_a_dependency_inversion(source):
    assert _dip(source).dip_violations == []


@pytest.mark.parametrize(
    "source",
    [
        "from implementation import Service\ndef run(): return Service()\n",
        "from implementation import Service\ninstance = Service()\n__all__ = ['instance']\n",
        "from implementation import Service\n__all__ = discover_exports()\n",
        "from implementation import *\n__all__ = ['Service']\n",
        "from implementation import Service\n__all__ = ['Missing']\n",
        "from implementation import Service as Service\nService = other\n",
        "if enabled:\n    from implementation import Service as Service\n",
        "from implementation import Service\n",
    ],
)
def test_runtime_and_unknown_exports_retain_dependency_inversion(source):
    assert [
        (row.stable_module, row.unstable_module) for row in _dip(source).dip_violations
    ] == [("public", "implementation")]


def test_facade_proof_uses_bounded_source_when_worker_tree_is_cached(tmp_path):
    source = tmp_path / "public.py"
    source.write_text("from implementation import Service as Service\n")
    assert _dip(filename=str(source)).dip_violations == []
    source.write_text(
        "from implementation import Service\ndef run(): return Service()\n"
    )
    assert len(_dip(filename=str(source)).dip_violations) == 1


def test_missing_or_symlinked_facade_source_does_not_hide_violation(tmp_path):
    assert len(_dip(filename=str(tmp_path / "missing.py")).dip_violations) == 1
    source = tmp_path / "public.py"
    source.write_text("from implementation import Service as Service\n")
    link = tmp_path / "alias.py"
    link.symlink_to(source)
    assert len(_dip(filename=str(link)).dip_violations) == 1


def _configuration_hooks(value="False", *, writes=False):
    source = "class BackendHooks:\n" + "".join(
        f"    capability_{index} = {value}\n" for index in range(4)
    )
    for index in range(4):
        source += f"    def hook_{index}(self, value):\n"
        if writes:
            source += f"        self.capability_{index} = value\n"
        source += f"        return self.capability_{index}\n"
    return source


def test_read_only_literal_configuration_hooks_are_not_owned_state_clusters():
    source = _configuration_hooks()
    result = analyze_cohesion(ast.parse(source).body[0])
    assert result["implementation_lcom4_lower_bound"] == 4
    assert result["implementation_state_groups"] == 0
    assert _findings(LCOMRule(), source) == []


@pytest.mark.parametrize(
    "value,writes", [("[]", False), ("build()", False), ("False", True)]
)
def test_mutable_unknown_or_receiver_written_configuration_retains_warning(
    value, writes
):
    (finding,) = _findings(LCOMRule(), _configuration_hooks(value, writes=writes))
    assert finding["value"] == 4


@pytest.mark.parametrize(
    "statement",
    [
        "BackendHooks.capability_{index} = value",
        "BackendHooks.capability_{index} += value",
        "del BackendHooks.capability_{index}",
        "setattr(BackendHooks, 'capability_{index}', value)",
        "delattr(BackendHooks, 'capability_{index}')",
        "owner = BackendHooks; owner.capability_{index} = value",
        "setattr(BackendHooks, name, value)",
        "vars(BackendHooks).update({{'capability_{index}': value}})",
        "BackendHooks.__dict__['capability_{index}'] = value",
        "external_configure(BackendHooks)",
        "external.owner = BackendHooks",
    ],
)
def test_class_name_mutations_keep_literal_defaults_as_owned_state(statement):
    source = _configuration_hooks(value="None")
    for index in range(4):
        source = source.replace(
            f"    def hook_{index}(self, value):\n",
            f"    def hook_{index}(self, value):\n"
            f"        {statement.format(index=index)}\n",
        )
    result = analyze_cohesion(ast.parse(source).body[0])
    assert result["implementation_state_groups"] == 4
    assert _findings(LCOMRule(), source)


def test_local_class_name_shadow_does_not_invent_owned_state():
    source = _configuration_hooks(value="None")
    for index in range(4):
        source = source.replace(
            f"    def hook_{index}(self, value):\n",
            f"    def hook_{index}(self, value, BackendHooks):\n"
            f"        BackendHooks.capability_{index} = value\n",
        )
    result = analyze_cohesion(ast.parse(source).body[0])
    assert result["implementation_state_groups"] == 0
    assert _findings(LCOMRule(), source) == []


def test_global_class_name_write_inside_conditional_retains_owned_state():
    source = _configuration_hooks(value="None")
    for index in range(4):
        source = source.replace(
            f"    def hook_{index}(self, value):\n",
            f"    def hook_{index}(self, value):\n"
            "        if value:\n"
            "            global BackendHooks\n"
            f"            BackendHooks.capability_{index} = value\n",
        )
    assert _findings(LCOMRule(), source)


def test_readonly_class_alias_keeps_configuration_exemption():
    source = _configuration_hooks().replace(
        "        return self.", "        owner = BackendHooks\n        return self."
    )
    result = analyze_cohesion(ast.parse(source).body[0])
    assert result["implementation_state_groups"] == 0
    assert _findings(LCOMRule(), source) == []


@pytest.mark.parametrize(
    "provider,factory", [("pydantic", "Field"), ("dataclasses", "field"),
                         ("attrs", "field"), ("attr", "attrib"), ("enum", "auto")]
)
@pytest.mark.parametrize("import_style", ["symbol", "module"])
@pytest.mark.parametrize("local", [False, True])
def test_project_local_field_factory_retains_runtime_design_checks(
    tmp_path, provider, factory, import_style, local
):
    if local:
        write_fixture(tmp_path, f"{provider}.py",
            f"def {factory}(*args): return install_runtime_descriptor()\n"
        )
    if import_style == "symbol":
        declaration = f"from {provider} import {factory} as make_field\n"
        expression = "make_field()"
    else:
        declaration = f"import {provider} as fields\n"
        expression = f"fields.{factory}()"
    source = declaration + "".join(
        f"class Handler{index}:\n    field = {expression}\n" for index in range(8)
    )
    filename = tmp_path / "handlers.py"
    filename.write_text(source)
    context = {"filename": str(filename), "source": source, "project_root": tmp_path}
    tree = ast.parse(source)
    findings = GodFileRule(
        max_lines=10, max_definitions=5, max_top_level_definitions=5
    ).visit_node(tree, context)
    assert bool(findings) is local


def test_project_local_field_factory_keeps_god_class_attribute_warning(tmp_path):
    (tmp_path / "pydantic").mkdir()
    (tmp_path / "pydantic" / "__init__.py").write_text(
        "def Field(): return install_runtime_descriptor()\n"
    )
    source = "from pydantic import Field\n" + _record().replace(
        "class Record:\n", "class Record:\n    field_0 = Field()\n"
    )
    filename = tmp_path / "record.py"
    filename.write_text(source)
    context = {"filename": str(filename), "source": source, "project_root": tmp_path}
    rule = GodClassRule()
    findings = [row for node in ast.walk(ast.parse(source))
                for row in rule.visit_node(node, context) or ()]
    assert len(findings) == 1 and findings[0]["value"] == 18
