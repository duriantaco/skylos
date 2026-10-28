"""Property factory declarations keep descriptor kind without invented uses."""

from __future__ import annotations

import json

import pytest

from skylos.analyzer import Skylos
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.listing import listed_result


FACTORY = """def make_setting(name='value'):
    def get_value(self):
        return self.values[name]
    def set_value(self, value):
        self.values[name] = value
    return property(get_value, set_value)
"""


def scan(root, source, extra=None):
    for name, text in {"app.py": source, **(extra or {})}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")
    analyzer = Skylos()
    result = json.loads(
        analyzer.analyze(
            str(root),
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return analyzer, result


def unused(result):
    return {row["full_name"] for row in result.get("unused_variables", [])}


@pytest.fixture(autouse=True)
def serial_static_analysis(monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")


@pytest.mark.parametrize(
    ("prefix", "expression", "extra"),
    [
        ("", "property(lambda self: 1)", {}),
        (
            "from builtins import property as descriptor\n",
            "descriptor(lambda self: 1)",
            {},
        ),
        ("import builtins as runtime\n", "runtime.property(lambda self: 1)", {}),
        ("descriptor = property\n", "descriptor(lambda self: 1)", {}),
        (FACTORY, "make_setting('header')", {}),
        (
            "from provider import make_setting as build\n",
            "build('header')",
            {"provider.py": FACTORY},
        ),
        (
            "import provider as helpers\n",
            "helpers.make_setting('header')",
            {"provider.py": FACTORY},
        ),
    ],
)
def test_source_proven_property_declaration_is_not_an_unused_plain_variable(
    tmp_path, prefix, expression, extra
):
    analyzer, result = scan(
        tmp_path,
        prefix
        + "class Model:\n"
        + f"    setting: object = {expression}\n"
        + "    unused_field = 7\n"
        + "\nprint(Model())\n",
        extra,
    )
    assert "app.Model.setting" not in unused(result)
    assert "app.Model.unused_field" in unused(result)
    assert "app.Model.unused_field" in unused(listed_result(result))
    definition = analyzer.defs["app.Model.setting"]
    assert definition.is_descriptor is True
    assert definition.references == 0
    assert not definition.called_by
    assert definition.skip_reason == "source-proven property descriptor declaration"


@pytest.mark.parametrize(
    ("prefix", "expression", "suffix", "extra"),
    [
        ("def property(*args):\n    return 7\n", "property(None)", "", {}),
        ("from foreign import property\n", "property(None)", "", {}),
        (
            "from foreign import *\n",
            "property(None)",
            "",
            {"foreign.py": "def property(*args): return 7\n"},
        ),
        ("def make_setting():\n    return 7\n", "make_setting()", "", {}),
        (FACTORY + "make_setting = lambda name: 7\n", "make_setting('x')", "", {}),
        (FACTORY + "property = lambda *args: 7\n", "make_setting('x')", "", {}),
        (
            "def make_setting(property):\n    return property(None)\n",
            "make_setting(lambda x: 7)",
            "",
            {},
        ),
        (
            "async def make_setting():\n    return property(None)\n",
            "make_setting()",
            "",
            {},
        ),
        (
            "def make_setting():\n    yield 1\n    return property(None)\n",
            "make_setting()",
            "",
            {},
        ),
        (
            "def make_setting(flag):\n    if flag:\n        return property(None)\n    return 7\n",
            "make_setting(True)",
            "",
            {},
        ),
        (
            "from provider import make_setting\n",
            "make_setting()",
            "",
            {"provider.py": "def make_setting():\n    return 7\n"},
        ),
        (
            "import provider\nprovider.make_setting = lambda: 7\n",
            "provider.make_setting()",
            "",
            {"provider.py": FACTORY},
        ),
        (FACTORY, "make_setting('x')", "Model.setting = 7\n", {}),
        (FACTORY, "make_setting('x')", "del Model.setting\nModel.setting = 7\n", {}),
        (FACTORY, "make_setting('x')", "Alias = Model\nAlias.setting = 7\n", {}),
        (
            "import builtins as runtime\nruntime.property = lambda *args: 7\n",
            "runtime.property(None)",
            "",
            {},
        ),
        (
            "from unittest.mock import patch\n"
            + FACTORY
            + "patch('builtins.property', lambda *args: 7).start()\n",
            "make_setting()",
            "",
            {},
        ),
        (
            "import builtins as runtime\nsetattr(runtime, 'property', lambda *args: 7)\n",
            "runtime.property(None)",
            "",
            {},
        ),
        (
            "from unittest.mock import patch\nfrom builtins import property as descriptor\npatch('app.descriptor', lambda *args: 7).start()\n",
            "descriptor(None)",
            "",
            {},
        ),
        (
            "from unittest.mock import patch\nfrom provider import make_setting as build\npatch('app.build', lambda: 7).start()\n",
            "build()",
            "",
            {"provider.py": FACTORY},
        ),
        (
            "import builtins\n__builtins__ = dict(vars(builtins), property=lambda *args: 7)\n"
            + FACTORY,
            "make_setting()",
            "",
            {},
        ),
        (
            FACTORY
            + "def replacement(): return 7\nmake_setting.__code__ = replacement.__code__\n",
            "make_setting()",
            "",
            {},
        ),
        (
            FACTORY + "make_setting.__globals__['property'] = lambda *args: 7\n",
            "make_setting()",
            "",
            {},
        ),
        (
            "def replace():\n    global property\n    property = lambda *args: 7\ndef make_setting():\n    replace()\n    return property(None)\n",
            "make_setting()",
            "",
            {},
        ),
    ],
)
def test_unproven_or_replaced_property_keeps_the_plain_variable_candidate(
    tmp_path, prefix, expression, suffix, extra
):
    analyzer, result = scan(
        tmp_path,
        prefix
        + "class Model:\n"
        + f"    setting = {expression}\n"
        + suffix
        + "print(Model())\n",
        extra,
    )
    assert "app.Model.setting" in unused(result)
    assert analyzer.defs["app.Model.setting"].is_descriptor is False


def test_wrong_receiver_store_does_not_rescue_an_ordinary_class_variable(tmp_path):
    analyzer, result = scan(
        tmp_path,
        "class Model:\n    setting = 7\n"
        "class Other:\n    pass\n"
        "other = Other()\nother.setting = 9\nprint(Model())\n",
    )
    assert "app.Model.setting" in unused(result)
    assert analyzer.defs["app.Model.setting"].is_descriptor is False


def test_property_declaration_does_not_keep_an_unused_owner_class_alive(tmp_path):
    _, result = scan(
        tmp_path,
        FACTORY + "class Dormant:\n    setting = make_setting()\n",
    )
    assert "app.Dormant" in {
        row["full_name"] for row in result.get("unused_classes", [])
    }


def test_unrelated_same_name_assignment_does_not_get_descriptor_kind(tmp_path):
    analyzer, _ = scan(
        tmp_path,
        FACTORY
        + "class Model:\n    setting = make_setting()\n"
        + "class Other:\n    setting = 7\n"
        + "print(Model(), Other())\n",
    )
    assert analyzer.defs["app.Model.setting"].is_descriptor is True
    assert analyzer.defs["app.Other.setting"].is_descriptor is False


@pytest.mark.parametrize(
    "base",
    [
        "class Meta(type):\n    def __new__(mcls, name, bases, namespace):\n        namespace['setting'] = 7\n        return super().__new__(mcls, name, bases, namespace)\nclass Base(metaclass=Meta):\n    pass\n",
        "class Base:\n    def __init_subclass__(cls):\n        cls.setting = 7\n",
    ],
)
def test_source_owned_base_class_hooks_do_not_prove_final_descriptor_kind(
    tmp_path, base
):
    analyzer, _ = scan(
        tmp_path,
        FACTORY
        + base
        + "class Model(Base):\n    setting = make_setting()\nprint(Model())\n",
    )
    # Existing metaclass/hook policy can already retain this binding; this
    # control checks kind and does not invent a stronger raw finding contract.
    assert analyzer.defs["app.Model.setting"].is_descriptor is False


def test_descriptor_kind_does_not_rescue_module_values_or_private_helpers(tmp_path):
    _, result = scan(
        tmp_path,
        FACTORY + "setting = make_setting()\ndef retired_helper(): return 7\n",
    )
    assert "app.setting" in unused(result)
    assert "app.retired_helper" in {
        row["full_name"] for row in result.get("unused_functions", [])
    }


@pytest.mark.parametrize("namespace", ["globals", "locals", "vars", "globals_alias"])
def test_factory_namespace_exposure_keeps_constructor_binding_unproven(
    tmp_path, namespace
):
    lookup = (
        "namespace = globals\n    namespace = namespace()"
        if namespace == "globals_alias"
        else f"namespace = {namespace}()"
    )
    analyzer, result = scan(
        tmp_path,
        f"def make_setting():\n    {lookup}\n    namespace['property'] = lambda *args: 7\n    return property(None)\n"
        "class Model:\n    setting = make_setting()\nprint(Model())\n",
    )
    assert "app.Model.setting" in unused(result)
    assert analyzer.defs["app.Model.setting"].is_descriptor is False


def test_namespace_in_a_deferred_getter_does_not_run_during_property_construction(
    tmp_path,
):
    analyzer, result = scan(
        tmp_path,
        "def make_setting(name):\n    name = name.lower()\n    def getter(self):\n        return globals().get(name)\n    return property(getter)\n"
        "class Model:\n    setting = make_setting('header')\nprint(Model())\n",
    )
    assert "app.Model.setting" not in unused(result)
    assert analyzer.defs["app.Model.setting"].is_descriptor is True


@pytest.mark.parametrize("shape", ["factory", "called_helper", "direct"])
def test_visible_function_local_builtin_mutation_does_not_prove_property_kind(
    tmp_path, shape
):
    replacement = "import builtins as runtime\n    runtime.property = lambda *args: 7\n"
    if shape == "factory":
        source = (
            "def make_setting():\n    " + replacement + "    return property(None)\n"
        )
        expression = "make_setting()"
    elif shape == "called_helper":
        source = (
            "def replace():\n    "
            + replacement
            + "def make_setting():\n    replace()\n    return property(None)\n"
        )
        expression = "make_setting()"
    else:
        source = "def replace():\n    " + replacement + "replace()\n"
        expression = "property(None)"
    analyzer, result = scan(
        tmp_path, source + f"class Model:\n    setting = {expression}\nprint(Model())\n"
    )
    assert "app.Model.setting" in unused(result)
    assert analyzer.defs["app.Model.setting"].is_descriptor is False
