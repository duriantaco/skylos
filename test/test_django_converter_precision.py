"""Django converter proofs stay bound to the actual registration and class."""

import pytest

from test.web_framework_fixtures import _scan, _unused


CONVERTER = """
class Converter:
    regex = "[a-z]+"

    def to_python(self, value):
        return normalize(value)

    def to_url(self, value):
        return value

    def stale_helper(self):
        return 1


def normalize(value):
    return value.lower()


def unrelated_dead():
    return 2


converter = Converter()
"""


def _assert_no_converter_proof(result, name):
    entries = [
        entry
        for entry in result["dead_code_evidence"]["symbols"]
        if entry["qualified_name"] == name
    ]
    assert len(entries) == 1
    evidence = entries[0]["evidence"]
    assert not any(item.get("kind") == "framework_root" for item in evidence)
    assert not any("converter" in item.get("reason", "").lower() for item in evidence)


def _assert_converter_method(result, name):
    evidence = result["definitions"][name].get("dead_code_evidence", [])
    assert any(item.get("kind") == "framework_root" for item in evidence)
    assert name not in _unused(result)


def _assert_dead_neighbor(result, module="converters"):
    assert module + ".unrelated_dead" in _unused(result)


@pytest.mark.parametrize(
    "provider,registration",
    [
        ("from django.urls import register_converter", "register_converter"),
        ("from django.urls import register_converter as register", "register"),
        ("import django.urls as routes", "routes.register_converter"),
        ("from django import urls as routes", "routes.register_converter"),
        ("import django as framework", "framework.urls.register_converter"),
        ("import django.urls", "django.urls.register_converter"),
    ],
)
def test_real_converter_registration_keeps_exact_protocol_and_callees(
    tmp_path, provider, registration
):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": provider
            + "\nfrom converters import Converter as Registered\n"
            + registration
            + "(Registered, 'custom')\nurlpatterns = []\n",
        },
    )
    unused = _unused(result)
    _assert_converter_method(result, "converters.Converter.to_python")
    _assert_converter_method(result, "converters.Converter.to_url")
    assert "converters.normalize" not in unused
    _assert_no_converter_proof(result, "converters.Converter.stale_helper")
    _assert_dead_neighbor(result)
    assert "converters.Converter.regex" not in _unused(result, "unused_variables")


@pytest.mark.parametrize(
    "provider,registration",
    [
        ("from django.urls import register_converter", "register_converter"),
        ("from django.urls import register_converter as register", "register"),
        ("import django.urls as routes", "routes.register_converter"),
        ("from django import urls as routes", "routes.register_converter"),
        ("import django as framework", "framework.urls.register_converter"),
        ("import django.urls", "django.urls.register_converter"),
    ],
)
@pytest.mark.parametrize(
    "argument",
    ["CONVERTER_NAME", "'cus' + 'tom'", "type_name=CONVERTER_NAME"],
    ids=["bound-name", "computed-name", "keyword-name"],
)
def test_converter_name_expression_preserves_registered_protocol(
    tmp_path, provider, registration, argument
):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": provider + "\nfrom django.urls import path\n"
            "from django.http import HttpResponse\n"
            "from converters import Converter\n"
            "CONVERTER_NAME = 'custom'\n"
            + registration
            + "(Converter, "
            + argument
            + ")\n"
            "def view(request, value):\n    return HttpResponse(value)\n"
            "urlpatterns = [path('<custom:value>/', view)]\n",
        },
    )
    _assert_converter_method(result, "converters.Converter.to_python")
    _assert_converter_method(result, "converters.Converter.to_url")
    assert "converters.Converter.regex" not in _unused(result, "unused_variables")
    assert "converters.normalize" not in _unused(result)
    _assert_no_converter_proof(result, "converters.Converter.stale_helper")
    _assert_dead_neighbor(result)


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("called", [False, True])
def test_wrapper_execution_controls_converter_findings_at_default_confidence(
    tmp_path, called, grep_verify
):
    import json

    from skylos.analyzer import analyze

    (tmp_path / "converters.py").write_text(CONVERTER, encoding="utf-8")
    source = (
        "from django.urls import register_converter\n"
        "from converters import Converter\n"
        "def configure():\n    register_converter(Converter, 'custom')\n"
    )
    if called:
        source += "configure()\n"
    (tmp_path / "urls.py").write_text(source, encoding="utf-8")

    result = json.loads(analyze(str(tmp_path), conf=80, grep_verify=grep_verify))
    assert not result.get("analysis_errors")
    unused = _unused(result)
    assert ("urls.configure" in unused) is not called
    assert ("converters.Converter.to_python" in unused) is not called
    assert ("converters.Converter.to_url" in unused) is not called
    if called:
        _assert_converter_method(result, "converters.Converter.to_python")
        assert "converters.Converter.regex" not in _unused(result, "unused_variables")
    else:
        _assert_no_converter_proof(result, "converters.Converter.to_python")
        _assert_no_converter_proof(result, "converters.Converter.regex")
    _assert_dead_neighbor(result)


@pytest.mark.parametrize("grep_verify", [False, True])
def test_bound_registration_name_keeps_regex_at_default_confidence(
    tmp_path, grep_verify
):
    import json

    from skylos.analyzer import analyze

    (tmp_path / "converters.py").write_text(CONVERTER, encoding="utf-8")
    (tmp_path / "urls.py").write_text(
        "from django.urls import register_converter, path\n"
        "from django.http import HttpResponse\n"
        "from converters import Converter\n"
        "CONVERTER_NAME = 'custom'\n"
        "register_converter(Converter, CONVERTER_NAME)\n"
        "def view(request, value):\n    return HttpResponse(value)\n"
        "urlpatterns = [path('<custom:value>/', view)]\n",
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), conf=80, grep_verify=grep_verify))
    assert not result.get("analysis_errors")
    assert "converters.Converter.regex" not in _unused(result, "unused_variables")
    _assert_converter_method(result, "converters.Converter.to_python")
    _assert_converter_method(result, "converters.Converter.to_url")
    _assert_no_converter_proof(result, "converters.Converter.stale_helper")
    _assert_dead_neighbor(result)


def test_nonliteral_name_does_not_add_evidence_for_a_suffix_only_provider(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "codec.py": "def register_converter(cls, name):\n    return None\n",
            "urls.py": "from codec import register_converter\n"
            "from converters import Converter\n"
            "CONVERTER_NAME = 'custom'\n"
            "register_converter(Converter, CONVERTER_NAME)\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_no_converter_proof(result, "converters.Converter.regex")
    assert "converters.Converter.regex" in _unused(result, "unused_variables")
    _assert_dead_neighbor(result)


@pytest.mark.parametrize(
    "provider,registration",
    [
        (
            "from django.urls import register_converter\n"
            "def noop(cls, name):\n    return None\n"
            "register_converter = noop",
            "register_converter(Registered, 'custom')",
        ),
        (
            "import django.urls as routes\n"
            "class Registry:\n"
            "    def register_converter(self, cls, name):\n        return None\n"
            "routes = Registry()",
            "routes.register_converter(Registered, 'custom')",
        ),
        (
            "import django.urls\n"
            "class Registry:\n"
            "    def register_converter(self, cls, name):\n        return None\n"
            "django.urls = Registry()",
            "django.urls.register_converter(Registered, 'custom')",
        ),
    ],
)
def test_replaced_converter_provider_does_not_hide_protocol(
    tmp_path, provider, registration
):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": provider
            + "\nfrom converters import Converter as Registered\n"
            + registration
            + "\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_no_converter_proof(result, "converters.Converter.to_url")
    _assert_no_converter_proof(result, "converters.Converter.stale_helper")
    _assert_dead_neighbor(result)
    _assert_no_converter_proof(result, "converters.Converter.regex")


def test_converter_registration_does_not_rescue_same_named_class(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "unrelated.py": CONVERTER,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\nregister_converter(Converter, 'custom')\n",
        },
    )
    unused = _unused(result)
    _assert_converter_method(result, "converters.Converter.to_python")
    assert "unrelated.Converter.to_python" in unused
    assert "unrelated.Converter.to_url" in unused
    _assert_no_converter_proof(result, "unrelated.Converter.regex")


@pytest.mark.parametrize("called", [False, True])
def test_only_called_registration_wrapper_proves_converter(tmp_path, called):
    source = "from django.urls import register_converter\n"
    source += "from converters import Converter\n"
    source += "def configure():\n    register_converter(Converter, 'custom')\n"
    if called:
        source += "configure()\n"
    result = _scan(tmp_path, {"converters.py": CONVERTER, "urls.py": source})
    unused = _unused(result)
    if called:
        _assert_converter_method(result, "converters.Converter.to_python")
        _assert_converter_method(result, "converters.Converter.to_url")
        assert "converters.normalize" not in unused
        assert "urls.configure" not in unused
    else:
        assert "converters.Converter.to_python" in unused
        assert "converters.Converter.to_url" in unused
        assert "urls.configure" in unused
    _assert_no_converter_proof(result, "converters.Converter.stale_helper")
    _assert_dead_neighbor(result)


def test_local_django_provider_is_not_a_framework_registration(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "django/__init__.py": "",
            "django/urls.py": "def register_converter(cls, name):\n    return None\n",
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\nregister_converter(Converter, 'custom')\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_no_converter_proof(result, "converters.Converter.to_url")

    _assert_dead_neighbor(result)


def test_replaced_converter_class_binding_does_not_rescue_original(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\n"
            "class Replacement:\n    pass\n"
            "Converter = Replacement\nregister_converter(Converter, 'custom')\n",
        },
    )
    assert "converters.Converter.to_python" in _unused(result)
    assert "converters.Converter.to_url" in _unused(result)


@pytest.mark.parametrize(
    "setup, registration",
    [
        (
            "import django.urls\nregister = django.urls.register_converter",
            "register(Registered, 'custom')",
        ),
        (
            "from django.urls import register_converter\n"
            "def configure(converter):\n"
            "    register_converter(converter, 'custom')",
            "configure(Registered)",
        ),
    ],
)
def test_real_registration_aliases_and_called_arguments(tmp_path, setup, registration):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": setup
            + "\nfrom converters import Converter as Registered\n"
            + registration
            + "\n",
        },
    )
    _assert_converter_method(result, "converters.Converter.to_python")
    assert "converters.normalize" not in _unused(result)
    _assert_no_converter_proof(result, "converters.Converter.stale_helper")
    _assert_dead_neighbor(result)


def test_package_submodule_converter_and_imported_registration_wrapper(tmp_path):
    result = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/converters.py": CONVERTER,
            "shop/boot.py": "from django.urls import register_converter\n"
            "from . import converters\n"
            "def configure():\n"
            "    register_converter(converters.Converter, 'custom')\n",
            "urls.py": "from shop.boot import configure\nconfigure()\n",
        },
    )
    _assert_converter_method(result, "shop.converters.Converter.to_python")
    assert "shop.converters.normalize" not in _unused(result)
    _assert_no_converter_proof(result, "shop.converters.Converter.stale_helper")
    _assert_dead_neighbor(result, "shop.converters")


def test_called_wrapper_uses_provider_binding_at_call_time(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\n"
            "def configure():\n"
            "    register_converter(Converter, 'custom')\n"
            "def noop(cls, name):\n    return None\n"
            "register_converter = noop\nconfigure()\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_no_converter_proof(result, "converters.Converter.to_url")

    _assert_dead_neighbor(result)


def test_parameter_shadowed_registration_provider_is_not_a_root(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\n"
            "def configure(register_converter):\n"
            "    register_converter(Converter, 'custom')\n"
            "def noop(cls, name):\n    return None\n"
            "configure(noop)\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_no_converter_proof(result, "converters.Converter.to_url")

    _assert_dead_neighbor(result)


def test_registered_child_uses_inherited_protocol_members(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER + "\nclass Child(Converter):\n    pass\n",
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Child\nregister_converter(Child, 'custom')\n",
        },
    )
    _assert_converter_method(result, "converters.Converter.to_python")
    _assert_converter_method(result, "converters.Converter.to_url")
    assert "converters.normalize" not in _unused(result)
    assert "converters.Converter.regex" not in _unused(result, "unused_variables")
    _assert_no_converter_proof(result, "converters.Converter.stale_helper")
    _assert_dead_neighbor(result)


def test_converter_c3_lookup_does_not_root_overridden_parent_hook(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER + "\nclass Mixin:\n"
            "    def to_python(self, value):\n        return replacement(value)\n"
            "class Child(Mixin, Converter):\n    pass\n"
            "def replacement(value):\n    return value\n",
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Child\nregister_converter(Child, 'custom')\n",
        },
    )
    _assert_converter_method(result, "converters.Mixin.to_python")
    _assert_converter_method(result, "converters.Converter.to_url")
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    assert "converters.replacement" not in _unused(result)
    _assert_dead_neighbor(result)


def test_converter_diamond_uses_c3_instead_of_first_parent_depth_first(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER + "\nclass Left(Converter):\n    pass\n"
            "class Right(Converter):\n"
            "    def to_python(self, value):\n        return replacement(value)\n"
            "class Child(Left, Right):\n    pass\n"
            "def replacement(value):\n    return value\n",
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Child\nregister_converter(Child, 'custom')\n",
        },
    )
    _assert_converter_method(result, "converters.Right.to_python")
    _assert_converter_method(result, "converters.Converter.to_url")
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    assert "converters.replacement" not in _unused(result)
    _assert_dead_neighbor(result)


def test_actual_django_converter_base_supplies_inherited_protocol(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": "from django.urls.converters import StringConverter as Base\n"
            "class Child(Base):\n"
            "    def to_python(self, value):\n        return normalize(value)\n"
            "    def stale_helper(self):\n        return 1\n"
            "def normalize(value):\n    return value.lower()\n"
            "def unrelated_dead():\n    return 2\n",
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Child\nregister_converter(Child, 'custom')\n",
        },
    )
    _assert_converter_method(result, "converters.Child.to_python")
    _assert_no_converter_proof(result, "converters.Child.stale_helper")
    assert "converters.normalize" not in _unused(result)
    _assert_dead_neighbor(result)


def test_local_lookalike_converter_base_does_not_supply_protocol(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": "class StringConverter:\n    pass\n"
            "class Child(StringConverter):\n"
            "    def to_python(self, value):\n        return value\n"
            "def unrelated_dead():\n    return 2\n",
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Child\nregister_converter(Child, 'custom')\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Child.to_python")
    _assert_dead_neighbor(result)


@pytest.mark.parametrize("django_import", [False, True])
def test_converter_proof_empty_scope_does_not_parse_or_build_an_index(
    tmp_path, monkeypatch, django_import
):
    from types import SimpleNamespace

    from skylos.deadcode import django_converter_liveness as converters

    def unexpected_work(*args, **kwargs):
        pytest.fail("An ineligible converter scope must not parse or build an index")

    monkeypatch.setattr(converters, "parse_python_files", unexpected_work)
    monkeypatch.setattr(converters, "_DefinitionIndex", unexpected_work)
    definitions = {}
    files = [tmp_path / "ordinary.py"]
    if django_import:
        definitions["django"] = SimpleNamespace(type="import", name="django")
        files = [tmp_path / "widget.js"]
    assert (
        converters.find_django_converter_classes(definitions, files, tmp_path)
        == frozenset()
    )


def test_unknown_wrapper_decorator_does_not_prove_original_body_runs(tmp_path):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\n"
            "def erase(callback):\n"
            "    def replacement():\n        return None\n"
            "    return replacement\n"
            "@erase\n"
            "def configure():\n"
            "    register_converter(Converter, 'custom')\n"
            "configure()\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_no_converter_proof(result, "converters.Converter.regex")
    _assert_dead_neighbor(result)


def test_unknown_class_decorator_does_not_prove_original_converter(tmp_path):
    replacement = (
        "class Replacement:\n"
        "    regex = '[a-z]+'\n"
        "    def to_python(self, value):\n        return value\n"
        "    def to_url(self, value):\n        return value\n"
        "def erase(cls):\n    return Replacement\n"
    )
    source = replacement + CONVERTER.replace(
        "class Converter:", "@erase\nclass Converter:"
    )
    result = _scan(
        tmp_path,
        {
            "converters.py": source,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\nregister_converter(Converter, 'custom')\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_no_converter_proof(result, "converters.Converter.regex")
    _assert_dead_neighbor(result)


def test_unknown_method_decorator_does_not_prove_original_protocol_body(tmp_path):
    replacement = (
        "def erase(callback):\n"
        "    def replacement(self, value):\n        return value\n"
        "    return replacement\n"
    )
    source = replacement + CONVERTER.replace(
        "    def to_python(self, value):", "    @erase\n    def to_python(self, value):"
    )
    result = _scan(
        tmp_path,
        {
            "converters.py": source,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\nregister_converter(Converter, 'custom')\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_dead_neighbor(result)


@pytest.mark.parametrize(
    "prefix,decorator,signature",
    [
        ("", "staticmethod", "value"),
        ("", "classmethod", "cls, value"),
        ("from builtins import staticmethod as method\n", "method", "value"),
        ("import builtins as native\n", "native.classmethod", "cls, value"),
    ],
)
def test_source_bound_builtin_method_decorators_preserve_converter_protocol(
    tmp_path, prefix, decorator, signature
):
    source = prefix + CONVERTER.replace(
        "    def to_python(self, value):",
        "    @" + decorator + "\n    def to_python(" + signature + "):",
    )
    result = _scan(
        tmp_path,
        {
            "converters.py": source,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\nregister_converter(Converter, 'custom')\n",
        },
    )
    _assert_converter_method(result, "converters.Converter.to_python")
    assert "converters.normalize" not in _unused(result)
    _assert_dead_neighbor(result)


@pytest.mark.parametrize(
    "wrapper",
    [
        "async def configure():\n    register_converter(Converter, 'custom')\n",
        "def configure():\n    register_converter(Converter, 'custom')\n    yield None\n",
        "def configure():\n    if True:\n        return\n    register_converter(Converter, 'custom')\n",
    ],
    ids=["unawaited-async", "uniterated-generator", "terminal-literal-branch"],
)
def test_unexecuted_wrapper_body_does_not_supply_converter_proof(tmp_path, wrapper):
    result = _scan(
        tmp_path,
        {
            "converters.py": CONVERTER,
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\n" + wrapper + "configure()\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_no_converter_proof(result, "converters.Converter.regex")
    _assert_dead_neighbor(result)


def test_inherited_metaclass_cannot_transform_a_proven_converter_body(tmp_path):
    prefix = (
        "def passthrough(self, value):\n    return value\n"
        "class Rewrite(type):\n"
        "    def __new__(meta, name, bases, namespace):\n"
        "        namespace['to_python'] = passthrough\n"
        "        return super().__new__(meta, name, bases, namespace)\n"
        "class Base(metaclass=Rewrite):\n    pass\n"
    )
    result = _scan(
        tmp_path,
        {
            "converters.py": prefix
            + CONVERTER.replace("class Converter:", "class Converter(Base):"),
            "urls.py": "from django.urls import register_converter\n"
            "from converters import Converter\nregister_converter(Converter, 'custom')\n",
        },
    )
    _assert_no_converter_proof(result, "converters.Converter.to_python")
    _assert_dead_neighbor(result)
