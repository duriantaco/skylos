"""Only framework dispatch evidence may exempt otherwise dead callers."""

import json

import pytest

from skylos.analyzer import Skylos


def _scan(root, source, confidence):
    (root / "app.py").write_text(source, encoding="utf-8")
    analyzer = Skylos()
    result = json.loads(analyzer.analyze(str(root), thr=confidence, grep_verify=False))
    assert not result.get("analysis_errors")
    definitions = {definition.name: definition for definition in analyzer.defs.values()}
    unused = {item["full_name"] for item in result.get("unused_functions", [])}
    return unused, definitions


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("method", ["__init__", "__repr__", "__call__", "__enter__"])
def test_dead_magic_method_does_not_protect_its_helper(tmp_path, confidence, method):
    unused, definitions = _scan(
        tmp_path,
        "def orphan_helper(): return 1\n"
        f"class Abandoned:\n    def {method}(self): return orphan_helper()\n",
        confidence,
    )
    assert "app.orphan_helper" in unused
    assert definitions[f"app.Abandoned.{method}"].confidence == 0


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("pragma", ["# noqa", "# skylos: ignore"])
def test_ignored_unused_method_does_not_protect_its_helper(
    tmp_path, confidence, pragma
):
    unused, _ = _scan(
        tmp_path,
        "def orphan_helper(): return 1\n"
        "class Active:\n"
        f"    def unused_method(self): {pragma}\n        return orphan_helper()\n"
        "    def ping(self): return 2\nActive().ping()\n",
        confidence,
    )
    assert "app.orphan_helper" in unused


@pytest.mark.parametrize("confidence", [0, 80])
def test_called_constructor_keeps_its_helper(tmp_path, confidence):
    unused, _ = _scan(
        tmp_path,
        "def prepare_value(): return 1\n"
        "class Active:\n    def __init__(self): self.value = prepare_value()\n"
        "active = Active()\n",
        confidence,
    )
    assert "app.prepare_value" not in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize(
    ("provider", "base", "method", "arguments"),
    [
        ("rest_framework.serializers", "Serializer", "validate_phone", "value"),
        (
            "rest_framework.permissions",
            "BasePermission",
            "has_permission",
            "request, view",
        ),
    ],
)
def test_proven_drf_hook_preserves_helper_with_explicit_dispatch_evidence(
    tmp_path, confidence, provider, base, method, arguments
):
    unused, definitions = _scan(
        tmp_path,
        f"from {provider} import {base}\n"
        + (
            "from rest_framework.serializers import CharField\n"
            if base == "Serializer"
            else ""
        )
        + "def hook_helper(): return True\n"
        + f"class Endpoint({base}):\n"
        + ("    phone = CharField()\n" if base == "Serializer" else "")
        + f"    def {method}(self, {arguments}): return hook_helper()\n",
        confidence,
    )
    assert "app.hook_helper" not in unused
    assert definitions[f"app.Endpoint.{method}"].suppression_code == "drf_hook"


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize(
    "replacement", ["class Serializer: pass\n", "Serializer = object\n"]
)
def test_replaced_drf_provider_does_not_protect_helper(
    tmp_path, confidence, replacement
):
    unused, definitions = _scan(
        tmp_path,
        "from rest_framework.serializers import Serializer\n"
        + replacement
        + "def orphan_helper(): return 1\n"
        "class Abandoned(Serializer):\n"
        "    def validate_phone(self, value): return orphan_helper()\n",
        confidence,
    )
    assert "app.orphan_helper" in unused
    assert definitions["app.Abandoned.validate_phone"].suppression_code != "drf_hook"


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize(
    ("method", "declaration"),
    [
        ("get_never", ""),
        ("validate_never", ""),
        ("validate_phone", "    phone = 1\n"),
        ("validate_phone", "    other = CharField()\n"),
    ],
)
def test_unregistered_serializer_prefix_does_not_protect_private_helper(
    tmp_path, confidence, method, declaration
):
    unused, definitions = _scan(
        tmp_path,
        "from rest_framework.serializers import Serializer, CharField\n"
        "def _private_helper(value): return str(value)\n"
        "class Endpoint(Serializer):\n"
        + declaration
        + f"    def {method}(self, value): return _private_helper(value)\n"
        "RESULT = Endpoint(instance=object()).data\n",
        confidence,
    )
    assert "app._private_helper" in unused
    assert definitions[f"app.Endpoint.{method}"].suppression_code != "drf_hook"


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("inherited", [False, True])
def test_declared_aliased_serializer_validation_field_preserves_helper(
    tmp_path, confidence, inherited
):
    declaration = "class Endpoint(S):\n    phone = PhoneField()\n"
    if inherited:
        declaration = (
            "class Parent(S):\n    phone = PhoneField()\nclass Endpoint(Parent):\n"
        )
    unused, definitions = _scan(
        tmp_path,
        "from rest_framework.serializers import Serializer as S, CharField as PhoneField\n"
        "def _private_helper(value): return str(value)\n"
        + declaration
        + "    def validate_phone(self, value): return _private_helper(value)\n"
        "RESULT = Endpoint(data={'phone': '123'}).is_valid()\n",
        confidence,
    )
    assert "app._private_helper" not in unused
    assert definitions["app.Endpoint.validate_phone"].suppression_code == "drf_hook"


@pytest.mark.parametrize("confidence", [0, 80])
def test_registered_serializer_method_field_preserves_getter_helper(
    tmp_path, confidence
):
    unused, _ = _scan(
        tmp_path,
        "from rest_framework.serializers import Serializer, SerializerMethodField\n"
        "def _private_helper(value): return str(value)\n"
        "class Endpoint(Serializer):\n"
        "    total = SerializerMethodField()\n"
        "    def get_total(self, value): return _private_helper(value)\n"
        "RESULT = Endpoint(instance=object()).data\n",
        confidence,
    )
    assert "app._private_helper" not in unused


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("scope", ["module", "class"])
def test_rebound_serializer_field_factory_does_not_protect_private_helper(
    tmp_path, confidence, scope
):
    module_binding = "CharField = object\n" if scope == "module" else ""
    class_binding = "    CharField = object\n" if scope == "class" else ""
    unused, definitions = _scan(
        tmp_path,
        "from rest_framework.serializers import Serializer, CharField\n"
        + module_binding
        + "def _private_helper(value): return str(value)\n"
        "class Endpoint(Serializer):\n" + class_binding + "    phone = CharField()\n"
        "    def validate_phone(self, value): return _private_helper(value)\n"
        "RESULT = Endpoint(instance=object()).data\n",
        confidence,
    )
    assert "app._private_helper" in unused
    assert definitions["app.Endpoint.validate_phone"].suppression_code != "drf_hook"


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize(
    "replacement",
    [
        "    del phone\n",
        "    phone = None\n",
        "    if choose():\n        phone = None\n",
    ],
)
def test_removed_or_uncertain_serializer_field_does_not_prove_validation_dispatch(
    tmp_path, confidence, replacement
):
    unused, definitions = _scan(
        tmp_path,
        "from rest_framework.serializers import Serializer, CharField\n"
        "def _private_helper(value): return str(value)\n"
        "class Endpoint(Serializer):\n"
        "    phone = CharField()\n"
        + replacement
        + "    def validate_phone(self, value): return _private_helper(value)\n"
        "RESULT = Endpoint(instance=object()).data\n",
        confidence,
    )
    assert definitions["app.Endpoint.validate_phone"].suppression_code != "drf_hook"
    # A conditional field replacement remains uncertain; it does not provide
    # the new strong framework-dispatch proof merely from the method spelling.
    if "if choose" not in replacement:
        assert "app._private_helper" in unused
