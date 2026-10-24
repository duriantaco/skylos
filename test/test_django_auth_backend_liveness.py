"""Configured Django backend hooks are static roots; fixtures never execute."""

import pytest

from test.web_framework_fixtures import _scan, _unused


_HOOKS = (
    "authenticate",
    "aauthenticate",
    "get_user",
    "aget_user",
    "get_user_permissions",
    "aget_user_permissions",
    "get_group_permissions",
    "aget_group_permissions",
    "get_all_permissions",
    "aget_all_permissions",
    "has_perm",
    "ahas_perm",
    "has_module_perms",
    "ahas_module_perms",
    "with_perm",
)


def _sources(backends, settings=None):
    if settings is None:
        settings = 'AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n'
    return {
        "shop/__init__.py": "",
        "shop/settings.py": (
            "INSTALLED_APPS = ['shop']\n"
            "SECRET_KEY = 'fixture'\n"
            "ROOT_URLCONF = 'shop.urls'\n" + settings
        ),
        "shop/urls.py": "from django.urls import path\nurlpatterns = []\n",
        "shop/backends.py": backends,
    }


def _auth_roots(result):
    return {
        item["name"]
        for item in result["analysis_summary"]["dead_code_liveness"]["rescued"]
        if item["reason"] == "django_web_auth_backend"
    }


def test_configured_backend_keeps_only_documented_sync_and_async_hooks(tmp_path):
    methods = []
    for hook in _HOOKS:
        prefix = ""
        if hook.startswith("a") and hook != "authenticate":
            prefix = "async "
        methods.append(
            f"    {prefix}def {hook}(self, *args, **kwargs):\n        return None\n"
        )
    backends = (
        "class Configured:\n"
        + "".join(methods)
        + "    def unused_helper(self):\n        return 1\n"
        + "class StaleAuthBackend:\n"
        + "    def get_user(self, user_id):\n        return None\n"
    )

    result = _scan(tmp_path, _sources(backends))

    roots = _auth_roots(result)
    assert roots == {"shop.backends.Configured." + hook for hook in _HOOKS}
    assert "shop.backends.Configured.unused_helper" in _unused(result)
    assert "shop.backends.StaleAuthBackend" in _unused(result, "unused_classes")
    assert "shop.backends.StaleAuthBackend.get_user" not in roots


@pytest.mark.parametrize(
    "setting",
    [
        'AUTHENTICATION_BACKENDS = ("shop.backends.Configured",)\n',
        'AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS.append("shop.backends.Configured")\n',
        'AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS.extend(["shop.backends.Configured"])\n',
        'AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS.insert(0, "shop.backends.Configured")\n',
        'AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS += ["shop.backends.Configured"]\n',
        'AUTHENTICATION_BACKENDS = []\nif enabled:\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\n',
        'AUTHENTICATION_BACKENDS = []\nif enabled:\n    AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n',
        'def configure():\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nAUTHENTICATION_BACKENDS = []\nconfigure()\n',
        'def configure():\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nAUTHENTICATION_BACKENDS = []\nactivate = configure\nactivate()\n',
    ],
)
def test_actual_backend_sequence_entries_supply_hook_roots(tmp_path, setting):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n",
            setting,
        ),
    )
    assert "shop.backends.Configured.get_user" in _auth_roots(result)


@pytest.mark.parametrize(
    "setting",
    [
        'UNRELATED = ["shop.backends.Configured"]\n',
        'REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": ["shop.backends.Configured"]}\n',
        'AUTHENTICATION_BACKENDS = {"description": "shop.backends.Configured"}\n',
        'AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS.extend("shop.backends.Configured")\n',
        'AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS.append(["shop.backends.Configured"])\n',
        'AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS[0]["description"] = "shop.backends.Configured"\n',
        'AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\nAUTHENTICATION_BACKENDS = []\n',
        'AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nAUTHENTICATION_BACKENDS = []\n',
        'AUTHENTICATION_BACKENDS = []\ndef never_called():\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\n',
        'AUTHENTICATION_BACKENDS = []\ndef configure(AUTHENTICATION_BACKENDS):\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nconfigure([])\n',
        'AUTHENTICATION_BACKENDS = []\ndef configure():\n    AUTHENTICATION_BACKENDS = []\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nconfigure()\n',
        'AUTHENTICATION_BACKENDS = []\nif False:\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\n',
        'AUTHENTICATION_BACKENDS = []\nif False:\n    AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n',
        'AUTHENTICATION_BACKENDS = []\ndef configure():\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nconfigure = replacement\nconfigure()\n',
        'AUTHENTICATION_BACKENDS = []\nasync def configure():\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nconfigure()\n',
        'AUTHENTICATION_BACKENDS = []\ndef configure():\n    def never_called():\n        AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nconfigure()\n',
        'AUTHENTICATION_BACKENDS = []\ndef configure():\n    if True:\n        return\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nconfigure()\n',
        'AUTHENTICATION_BACKENDS = []\ndef configure():\n    if enabled:\n        return\n    else:\n        return\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\nconfigure()\n',
        'AUTHENTICATION_BACKENDS = []\ndef configure():\n    AUTHENTICATION_BACKENDS.append("shop.backends.Configured")\n    yield None\nconfigure()\n',
    ],
)
def test_other_strings_and_unregistered_mutations_do_not_root_hooks(tmp_path, setting):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n",
            setting,
        ),
    )
    assert "shop.backends.Configured.get_user" not in _auth_roots(result)
    assert "shop.backends.Configured.get_user" in _unused(
        result
    ) or "shop.backends.Configured" in _unused(result, "unused_classes")


@pytest.mark.parametrize(
    "binding",
    [
        "Configured = replacement\n",
        "del Configured\n",
        "if enabled:\n    Configured = replacement\n",
        "Configured.get_user = replacement\n",
        "if enabled:\n    Configured.get_user = replacement\n",
        "def replace():\n    Configured.get_user = replacement\nreplace()\n",
    ],
)
def test_replaced_configured_classes_or_methods_do_not_root_stale_implementations(
    tmp_path, binding
):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n"
            + binding
        ),
    )
    assert "shop.backends.Configured.get_user" not in _auth_roots(result)


def test_backend_import_and_assignment_aliases_keep_the_actual_class_method(tmp_path):
    sources = _sources(
        "from shop.implementation import Actual as Imported\nConfigured = Imported\n"
    )
    sources["shop/implementation.py"] = (
        "class Actual:\n    def get_user(self, user_id):\n        return None\n"
        "    def stale_helper(self):\n        return None\n"
    )
    result = _scan(tmp_path, sources)
    assert _auth_roots(result) == {"shop.implementation.Actual.get_user"}
    assert "shop.implementation.Actual" not in _unused(result, "unused_classes")
    assert "shop.implementation.Actual.stale_helper" in _unused(result)


def test_backend_mro_selects_the_first_inherited_implementation(tmp_path):
    result = _scan(
        tmp_path,
        _sources(
            "class Ancestor:\n    def get_user(self, user_id):\n        return None\n"
            "class Left(Ancestor):\n    pass\n"
            "class Right(Ancestor):\n    def get_user(self, user_id):\n        return None\n"
            "class Configured(Left, Right):\n    pass\n"
        ),
    )
    assert _auth_roots(result) == {"shop.backends.Right.get_user"}
    assert "shop.backends.Ancestor.get_user" in _unused(result)


def test_imported_backend_base_keeps_classmethod_and_hook_dependencies(tmp_path):
    sources = _sources(
        "from shop.base import Backend as Parent\nclass Configured(Parent):\n    pass\n"
    )
    sources["shop/base.py"] = (
        "class Backend(object):\n"
        "    def get_user(self, user_id):\n        return lookup(user_id)\n"
        "    @classmethod\n    def with_perm(cls, perm):\n        return []\n"
        "    def unused_helper(self):\n        return None\n"
        "def lookup(user_id):\n    return None\n"
    )
    result = _scan(tmp_path, sources)
    assert _auth_roots(result) == {
        "shop.base.Backend.get_user",
        "shop.base.Backend.with_perm",
    }
    assert "shop.base.lookup" not in _unused(result)
    assert "shop.base.Backend.unused_helper" in _unused(result)


@pytest.mark.parametrize(
    "override", ["get_user = None", "def get_user(self, user_id):\n        return None"]
)
def test_backend_member_override_does_not_root_shadowed_base_method(tmp_path, override):
    result = _scan(
        tmp_path,
        _sources(
            "class Parent:\n    def get_user(self, user_id):\n        return None\n"
            "class Configured(Parent):\n    " + override + "\n"
        ),
    )
    assert "shop.backends.Parent.get_user" not in _auth_roots(result)
    assert "shop.backends.Parent.get_user" in _unused(result)


def test_unknown_earlier_base_does_not_prove_a_later_local_hook_is_selected(tmp_path):
    result = _scan(
        tmp_path,
        _sources(
            "from external import Provider\n"
            "class Later:\n    def get_user(self, user_id):\n        return None\n"
            "class Configured(Provider, Later):\n    pass\n"
        ),
    )
    assert "shop.backends.Later.get_user" not in _auth_roots(result)


def test_shadowed_django_provider_cannot_establish_backend_hook_roots(tmp_path):
    sources = _sources(
        "class Configured:\n    def get_user(self, user_id):\n        return None\n"
    )
    sources["django/__init__.py"] = ""
    sources["django/urls.py"] = "def path(*args):\n    return None\n"
    result = _scan(tmp_path, sources)
    assert not _auth_roots(result)
    assert "shop.backends.Configured" in _unused(result, "unused_classes")


def test_settings_cannot_root_a_backend_class_replaced_through_its_module(tmp_path):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n",
            "from shop import backends\n"
            "backends.Configured = replacement\n"
            'AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n',
        ),
    )
    assert "shop.backends.Configured.get_user" not in _auth_roots(result)


def test_unloaded_module_replacement_does_not_change_backend_binding(tmp_path):
    sources = _sources(
        "class Configured:\n    def get_user(self, user_id):\n        return None\n"
    )
    sources["unused.py"] = (
        "from shop import backends\nbackends.Configured = replacement\n"
    )
    result = _scan(tmp_path, sources)
    assert "shop.backends.Configured.get_user" in _auth_roots(result)


@pytest.mark.parametrize(
    "class_header",
    ["@redirect\nclass Configured:", "class Configured(metaclass=Redirect):"],
)
def test_transformed_backend_class_does_not_root_stale_methods(tmp_path, class_header):
    result = _scan(
        tmp_path,
        _sources(
            "class Actual:\n    def get_user(self, user_id):\n        return None\n"
            "def redirect(cls):\n    return Actual\n"
            "class Redirect(type):\n"
            "    def __new__(mcls, name, bases, namespace):\n        return Actual\n"
            + class_header
            + "\n"
            "    def get_user(self, user_id):\n        return retired_lookup(user_id)\n"
            "def retired_lookup(user_id):\n    return None\n"
        ),
    )
    assert "shop.backends.Configured.get_user" not in _auth_roots(result)
    assert "shop.backends.retired_lookup" in _unused(result)


@pytest.mark.parametrize("annotation", ["get_user: object", "get_user: object = None"])
def test_backend_annotation_only_masks_inherited_hook_when_it_assigns_value(
    tmp_path, annotation
):
    result = _scan(
        tmp_path,
        _sources(
            "class ActualBase:\n    def get_user(self, user_id):\n        return None\n"
            "class Configured(ActualBase):\n    " + annotation + "\n"
        ),
    )
    if annotation == "get_user: object":
        assert "shop.backends.ActualBase.get_user" in _auth_roots(result)
    else:
        assert "shop.backends.ActualBase.get_user" not in _auth_roots(result)


@pytest.mark.parametrize(
    "prefix, decorator",
    [
        ("def discard(fn):\n    return lambda self, user_id: None\n", "discard"),
        ("classmethod = lambda fn: None\n", "classmethod"),
        ("staticmethod = lambda fn: None\n", "staticmethod"),
        ("", "classmethod"),
        ("", "staticmethod"),
    ],
)
def test_backend_method_decorator_requires_the_actual_builtin(
    tmp_path, prefix, decorator
):
    result = _scan(
        tmp_path,
        _sources(
            prefix + "class Configured:\n" + "    @" + decorator + "\n"
            "    def get_user(self, user_id):\n        return retired_lookup(user_id)\n"
            "def retired_lookup(user_id):\n    return None\n"
        ),
    )
    if prefix:
        assert "shop.backends.Configured.get_user" not in _auth_roots(result)
        assert "shop.backends.retired_lookup" in _unused(result)
    else:
        assert "shop.backends.Configured.get_user" in _auth_roots(result)


@pytest.mark.parametrize("decorator", ["classmethod", "staticmethod"])
def test_backend_method_builtin_decorator_cannot_be_shadowed_in_class(
    tmp_path, decorator
):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    " + decorator + " = lambda fn: None\n"
            "    @" + decorator + "\n"
            "    def get_user(self, user_id):\n        return None\n"
        ),
    )
    assert "shop.backends.Configured.get_user" not in _auth_roots(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "AUTHENTICATION_BACKENDS.clear()",
        'AUTHENTICATION_BACKENDS.remove("shop.backends.Configured")',
        "AUTHENTICATION_BACKENDS.pop()",
        "del AUTHENTICATION_BACKENDS[0]",
        'AUTHENTICATION_BACKENDS[0] = "shop.backends.Other"',
        "AUTHENTICATION_BACKENDS *= 0",
        "AUTHENTICATION_BACKENDS.unknown_mutation()",
        "unknown_mutation(AUTHENTICATION_BACKENDS)",
    ],
)
def test_destructive_or_unknown_backend_list_mutation_does_not_keep_removed_hook(
    tmp_path, mutation
):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n",
            'AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n'
            + mutation
            + "\n",
        ),
    )
    assert "shop.backends.Configured.get_user" not in _auth_roots(result)


@pytest.mark.parametrize("separator", ["\n", "; "])
def test_later_backend_list_assignment_restores_proof_after_destruction(
    tmp_path, separator
):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n",
            "AUTHENTICATION_BACKENDS = []\nAUTHENTICATION_BACKENDS.clear()"
            + separator
            + 'AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n',
        ),
    )
    assert "shop.backends.Configured.get_user" in _auth_roots(result)


@pytest.mark.parametrize(
    "setup, mutation",
    [
        ("", 'setattr(backends.Configured, "get_user", None)'),
        ("", 'delattr(backends.Configured, "get_user")'),
        (
            "from builtins import setattr as change\n",
            'change(backends.Configured, "get_user", None)',
        ),
        (
            "import builtins as operations\n",
            'operations.setattr(backends.Configured, "get_user", None)',
        ),
    ],
)
def test_real_reflective_backend_method_replacement_does_not_root_old_hook(
    tmp_path, setup, mutation
):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n",
            "from shop import backends\n" + setup + mutation + "\n"
            'AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n',
        ),
    )
    assert "shop.backends.Configured.get_user" not in _auth_roots(result)


def test_shadowed_setattr_does_not_replace_real_backend_method(tmp_path):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n",
            "from shop import backends\n"
            "def setattr(*args):\n    return None\n"
            'setattr(backends.Configured, "get_user", None)\n'
            'AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n',
        ),
    )
    assert "shop.backends.Configured.get_user" in _auth_roots(result)


def test_unreachable_helper_destruction_keeps_the_configured_backend(tmp_path):
    result = _scan(
        tmp_path,
        _sources(
            "class Configured:\n    def get_user(self, user_id):\n        return None\n",
            'AUTHENTICATION_BACKENDS = ["shop.backends.Configured"]\n'
            "def configure():\n    if True:\n        return\n"
            "    AUTHENTICATION_BACKENDS.clear()\nconfigure()\n",
        ),
    )
    assert "shop.backends.Configured.get_user" in _auth_roots(result)
