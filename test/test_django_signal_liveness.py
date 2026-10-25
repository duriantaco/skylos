"""Signal fixtures are parsed statically; Django and fixture code never run."""

import ast

import pytest

from skylos.visitors.framework_aware import FrameworkAwareVisitor
from test.web_framework_fixtures import _scan, _unused


_BODY = (
    "def on_save(sender, instance, **kwargs):\n"
    "    return helper()\n"
    "def helper():\n"
    "    return 1\n"
    "def stale_helper():\n"
    "    return 2\n"
)
_IMPORTS = (
    "from django.dispatch import receiver\n"
    "from django.db.models.signals import post_save\n"
)


def _sources(signal_source, *, ready="from . import signals", installed=True):
    apps = "[]"
    if installed:
        apps = "['shop.apps.ShopConfig']"
    return {
        "project/__init__.py": "",
        "project/settings.py": (
            f"INSTALLED_APPS = {apps}\n"
            "SECRET_KEY = 'fixture'\n"
            "ROOT_URLCONF = 'project.urls'\n"
        ),
        "project/urls.py": "from django.urls import path\nurlpatterns = []\n",
        "shop/__init__.py": "",
        "shop/apps.py": (
            "from django.apps import AppConfig\n"
            "class ShopConfig(AppConfig):\n"
            "    name = 'shop'\n"
            "    def ready(self):\n"
            + "".join("        " + line + "\n" for line in ready.splitlines())
        ),
        "shop/signals.py": signal_source,
    }


def _signal_targets(result, reason):
    return {
        item["name"]
        for item in result["analysis_summary"]["dead_code_liveness"]["rescued"]
        if item["reason"] == reason
    }


def _assert_registered(result, *, loaded):
    strong = _signal_targets(result, "django_web_signal_receiver")
    uncertain = _signal_targets(result, "django_signal_registration_unknown_loading")
    callback = "shop.signals.on_save"
    definition = result["definitions"][callback]
    evidence = definition["dead_code_evidence"]
    if loaded:
        assert callback in strong
        assert callback not in uncertain
        assert any(item["kind"] == "framework_root" for item in evidence)
    else:
        assert callback not in strong
        assert callback in uncertain
        assert definition["dead_code_classification"] == "uncertain"
        assert not any(item["kind"] == "framework_root" for item in evidence)
    assert callback not in _unused(result)
    assert "shop.signals.helper" not in _unused(result)
    assert "shop.signals.stale_helper" in _unused(result)
    assert "shop.signals.on_save.instance" not in _unused(result, "unused_parameters")


@pytest.mark.parametrize(
    ("imports", "decorator"),
    [
        (_IMPORTS, "receiver(post_save)"),
        (
            "from django.dispatch import receiver as listen\n"
            "from django.db.models.signals import post_save as saved\n",
            "listen(saved)",
        ),
        (
            "import django.dispatch as dispatch\n"
            "from django.db.models.signals import post_save\n",
            "dispatch.receiver(post_save)",
        ),
        (
            "import django.dispatch\nimport django.db.models.signals\n",
            "django.dispatch.receiver(django.db.models.signals.post_save)",
        ),
        (_IMPORTS + "listen = receiver\nsaved = post_save\n", "listen(saved)"),
        (_IMPORTS, "receiver([post_save])"),
        (_IMPORTS, "receiver(signal=post_save)"),
    ],
)
def test_loaded_real_receiver_bindings_keep_callback_and_its_helper(
    tmp_path, imports, decorator
):
    result = _scan(tmp_path, _sources(imports + "@" + decorator + "\n" + _BODY))
    _assert_registered(result, loaded=True)


@pytest.mark.parametrize(
    "ready",
    ["pass", "if False:\n    from . import signals", "return\nfrom . import signals"],
)
def test_missing_signal_module_loading_is_uncertainty(tmp_path, ready):
    result = _scan(
        tmp_path,
        _sources(_IMPORTS + "@receiver(post_save)\n" + _BODY, ready=ready),
    )
    _assert_registered(result, loaded=False)


def test_uninstalled_app_ready_does_not_prove_signal_loading(tmp_path):
    result = _scan(
        tmp_path,
        _sources(_IMPORTS + "@receiver(post_save)\n" + _BODY, installed=False),
    )
    _assert_registered(result, loaded=False)


@pytest.mark.parametrize(
    "prefix",
    [
        "from django.db.models.signals import post_save\n"
        "def receiver(signal):\n"
        "    def decorate(callback):\n        return callback\n"
        "    return decorate\n",
        _IMPORTS + "def noop(signal):\n"
        "    def decorate(callback):\n        return callback\n"
        "    return decorate\nreceiver = noop\n",
        _IMPORTS + "receiver = lambda signal: (lambda callback: callback)\n",
        "from django.db.models.signals import post_save\n"
        "def receiver(signal):\n    'No registration occurs.'\n"
        "    def decorate(callback):\n        'Return the input.'\n        return callback\n"
        "    return decorate\n",
    ],
)
def test_noop_receiver_spelling_does_not_keep_unused_functions(tmp_path, prefix):
    result = _scan(tmp_path, _sources(prefix + "@receiver(post_save)\n" + _BODY))
    assert {
        "shop.signals.on_save",
        "shop.signals.helper",
        "shop.signals.stale_helper",
    } <= _unused(result)
    assert "shop.signals.on_save" not in _signal_targets(
        result, "django_web_signal_receiver"
    )
    assert "shop.signals.on_save" not in _signal_targets(
        result, "django_signal_registration_unknown_loading"
    )
    assert "shop.signals.on_save.instance" in _unused(result, "unused_parameters")


def test_receiver_spelling_does_not_supply_framework_root_before_project_proof():
    visitor = FrameworkAwareVisitor()
    visitor.visit(ast.parse(_IMPORTS + "@receiver(post_save)\n" + _BODY))
    assert 4 not in visitor.framework_decorated_lines


@pytest.mark.parametrize("called", [True, False])
def test_connect_inside_registration_wrapper_requires_invocation(tmp_path, called):
    source = (
        "from django.db.models.signals import post_save\n"
        + _BODY
        + "def install():\n    post_save.connect(on_save)\n"
    )
    if called:
        source += "install()\n"
    result = _scan(tmp_path, _sources(source))
    if called:
        _assert_registered(result, loaded=True)
    else:
        assert "shop.signals.on_save" not in _signal_targets(
            result, "django_web_signal_receiver"
        )
        assert "shop.signals.on_save" in _unused(result)
        assert "shop.signals.helper" in _unused(result)


@pytest.mark.parametrize(
    "prefix",
    [
        "from django.dispatch import Signal, receiver\nsaved = Signal()\n",
        "from django.dispatch import Signal, receiver\nSignal = Signal()\nsaved = Signal\n",
        "from django.dispatch import Signal as Event, receiver\nsaved = Event()\n",
        "from django.dispatch import Signal, receiver\nclass DomainSignal(Signal):\n    pass\nsaved = DomainSignal()\n",
    ],
)
def test_custom_signal_instances_preserve_genuine_callbacks(tmp_path, prefix):
    result = _scan(tmp_path, _sources(prefix + "@receiver(saved)\n" + _BODY))
    _assert_registered(result, loaded=True)


@pytest.mark.parametrize(
    "prefix",
    [
        "from django.dispatch import receiver\nfrom third_party.signals import saved\n",
        "from django.dispatch import Signal, receiver\n"
        "class DomainSignal(Signal):\n    def connect(self, callback):\n        return connector(callback)\nsaved = DomainSignal()\n",
    ],
)
def test_unsupported_signal_provider_retains_callback_as_uncertain(tmp_path, prefix):
    result = _scan(tmp_path, _sources(prefix + "@receiver(saved)\n" + _BODY))
    assert "shop.signals.on_save" not in _unused(result)
    assert "shop.signals.helper" not in _unused(result)
    assert "shop.signals.on_save" not in _signal_targets(
        result, "django_web_signal_receiver"
    )
    assert (
        result["definitions"]["shop.signals.on_save"]["dead_code_classification"]
        == "uncertain"
    )


def test_unknown_external_receiver_keeps_previous_uncertainty_without_django(tmp_path):
    result = _scan(
        tmp_path,
        {"callbacks.py": "from external import receiver\n@receiver(event)\n" + _BODY},
    )
    assert "callbacks.on_save" not in _unused(result)
    assert "callbacks.helper" not in _unused(result)
    definition = result["definitions"]["callbacks.on_save"]
    assert definition["dead_code_classification"] == "uncertain"
    assert not any(
        item["kind"] == "framework_root" for item in definition["dead_code_evidence"]
    )


def test_source_imported_identity_receiver_is_not_a_registration(tmp_path):
    sources = _sources(
        "from .helpers import receiver\n"
        "from django.db.models.signals import post_save\n"
        "@receiver(post_save)\n" + _BODY
    )
    sources["shop/helpers.py"] = (
        "def receiver(signal):\n"
        "    def decorate(callback):\n        return callback\n"
        "    return decorate\n"
    )
    result = _scan(tmp_path, sources)
    assert {"shop.signals.on_save", "shop.signals.helper"} <= _unused(result)


def test_source_reexport_of_real_receiver_keeps_provider_identity(tmp_path):
    sources = _sources(
        "from .helpers import receive\n"
        "from django.db.models.signals import post_save\n"
        "@receive(post_save)\n" + _BODY
    )
    sources["shop/helpers.py"] = "from django.dispatch import receiver as receive\n"
    result = _scan(tmp_path, sources)
    _assert_registered(result, loaded=True)


@pytest.mark.parametrize(
    "mutation",
    [
        "ShopConfig = object\n",
        "ShopConfig.ready = lambda self: None\n",
        "setattr(ShopConfig, 'ready', lambda self: None)\n",
        "del ShopConfig.ready\n",
    ],
)
def test_replaced_appconfig_or_ready_does_not_prove_signal_loading(tmp_path, mutation):
    sources = _sources(_IMPORTS + "@receiver(post_save)\n" + _BODY)
    sources["shop/apps.py"] += mutation
    result = _scan(tmp_path, sources)
    _assert_registered(result, loaded=False)


@pytest.mark.parametrize("registration", ["decorated", "direct"])
def test_django_awaits_async_receivers(tmp_path, registration):
    body = _BODY.replace("def on_save", "async def on_save", 1)
    source = _IMPORTS
    if registration == "decorated":
        source += "@receiver(post_save)\n" + body
    else:
        source += body + "post_save.connect(on_save)\n"
    result = _scan(tmp_path, _sources(source))
    _assert_registered(result, loaded=True)


@pytest.mark.parametrize(
    "statement",
    [
        "(post_save.connect(on_save) for value in [1])\n",
        "[post_save.connect(on_save) for value in []]\n",
        "False and post_save.connect(on_save)\n",
        "True or post_save.connect(on_save)\n",
        "post_save.connect(on_save) if False else None\n",
        "None if True else post_save.connect(on_save)\n",
        "def install():\n    return\n    post_save.connect(on_save)\ninstall()\n",
        "async def install():\n    post_save.connect(on_save)\ninstall()\n",
        "def install():\n    post_save.connect(on_save)\n    yield None\ninstall()\n",
    ],
)
def test_inactive_expression_or_suspended_wrapper_does_not_prove_registration(
    tmp_path, statement
):
    result = _scan(tmp_path, _sources(_IMPORTS + _BODY + statement))
    assert "shop.signals.on_save" not in _signal_targets(
        result, "django_web_signal_receiver"
    )


@pytest.mark.parametrize(
    "prefix",
    [
        _IMPORTS + "saved = post_save\n",
        "from django.dispatch import Signal\nsaved = Signal()\n",
    ],
)
def test_uncalled_alias_signal_wrapper_has_no_name_only_framework_root(
    tmp_path, prefix
):
    source = prefix + _BODY + "def install():\n    saved.connect(on_save)\n"
    result = _scan(tmp_path, _sources(source))
    assert "shop.signals.on_save" in _unused(result)
    definition = result["definitions"]["shop.signals.on_save"]
    assert not any(
        item["kind"] == "framework_root" for item in definition["dead_code_evidence"]
    )


@pytest.mark.parametrize(
    "prefix",
    [
        _IMPORTS + "post_save.connect = lambda callback: None\n",
        _IMPORTS + "setattr(post_save, 'connect', lambda callback: None)\n",
        "from django.dispatch import Signal\npost_save = Signal()\n"
        "post_save.connect = lambda callback: None\n",
        "from django.dispatch import Signal\npost_save = Signal()\n"
        "setattr(post_save, 'connect', lambda callback: None)\n",
    ],
)
def test_replaced_connect_method_cannot_claim_genuine_registration(tmp_path, prefix):
    result = _scan(tmp_path, _sources(prefix + _BODY + "post_save.connect(on_save)\n"))
    assert "shop.signals.on_save" not in _signal_targets(
        result, "django_web_signal_receiver"
    )


@pytest.mark.parametrize("later_import", ["", "import os\n"])
def test_captured_real_receiver_survives_later_provider_replacement(
    tmp_path, later_import
):
    source = (
        _IMPORTS + "import django.dispatch as dispatch\n"
        "captured = receiver\n"
        "dispatch.receiver = replacement\n"
        + later_import
        + "@captured(post_save)\n"
        + _BODY
    )
    result = _scan(tmp_path, _sources(source))
    _assert_registered(result, loaded=True)


@pytest.mark.parametrize(
    ("configured", "apps_source", "loaded"),
    [
        (
            "shop.apps.ShopConfig",
            "class ShopConfig(AppConfig):\n    name = 'shop'\n    def ready(self):\n        pass\n"
            "class OtherConfig(AppConfig):\n    name = 'shop'\n    def ready(self):\n        from . import signals\n",
            False,
        ),
        (
            "shop",
            "class ShopConfig(AppConfig):\n    name = 'shop'\n    default = False\n"
            "    def ready(self):\n        from . import signals\n",
            False,
        ),
        (
            "shop",
            "class ShopConfig(AppConfig):\n    name = 'shop'\n"
            "    def ready(self):\n        from . import signals\n",
            True,
        ),
        (
            "shop",
            "class ShopConfig(AppConfig):\n    name = 'shop'\n    def ready(self):\n        from . import signals\n"
            "class OtherConfig(AppConfig):\n    name = 'shop'\n    def ready(self):\n        pass\n",
            False,
        ),
        (
            "shop",
            "class ShopConfig(AppConfig):\n    name = 'shop'\n    default = True\n"
            "    def ready(self):\n        from . import signals\n"
            "class OtherConfig(AppConfig):\n    name = 'shop'\n    def ready(self):\n        pass\n",
            True,
        ),
        (
            "shop.apps.Captured",
            "class ShopConfig(AppConfig):\n    name = 'shop'\n    def ready(self):\n        from . import signals\n"
            "Captured = ShopConfig\nShopConfig = object\n",
            True,
        ),
        (
            "shop.apps.ShopConfig",
            "class BaseConfig(AppConfig):\n    name = 'shop'\n    def ready(self):\n        from . import signals\n"
            "class ShopConfig(BaseConfig):\n    pass\n",
            True,
        ),
    ],
)
def test_signal_loading_uses_effective_selected_appconfig(
    tmp_path, configured, apps_source, loaded
):
    sources = _sources(_IMPORTS + "@receiver(post_save)\n" + _BODY)
    sources["project/settings.py"] = (
        f"INSTALLED_APPS = [{configured!r}]\nSECRET_KEY = 'fixture'\nROOT_URLCONF = 'project.urls'\n"
    )
    sources["shop/apps.py"] = "from django.apps import AppConfig\n" + apps_source
    result = _scan(tmp_path, sources)
    _assert_registered(result, loaded=loaded)


@pytest.mark.parametrize(
    "decorator",
    [
        "receiver(post_save, signal=post_save)",
        "receiver(post_save, invalid=True)",
        "receiver(post_save, **options)",
    ],
)
def test_malformed_or_opaque_receiver_arguments_cannot_supply_execution_root(
    tmp_path, decorator
):
    result = _scan(tmp_path, _sources(_IMPORTS + "@" + decorator + "\n" + _BODY))
    assert "shop.signals.on_save" not in _signal_targets(
        result, "django_web_signal_receiver"
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "import django.dispatch as dispatch\nsaved = dispatch.Signal()\n",
        "from django.dispatch import Signal\nFactory = Signal\nsaved = Factory()\n",
        "from django.dispatch import Signal\nclass DomainSignal(Signal):\n    pass\nsaved = DomainSignal()\n",
    ],
)
def test_uncalled_custom_constructor_alias_has_no_framework_root(tmp_path, prefix):
    result = _scan(
        tmp_path,
        _sources(prefix + _BODY + "def install():\n    saved.connect(on_save)\n"),
    )
    assert "shop.signals.on_save" not in _signal_targets(
        result, "django_web_signal_receiver"
    )
    definition = result["definitions"]["shop.signals.on_save"]
    assert not any(
        item["kind"] == "framework_root" for item in definition["dead_code_evidence"]
    )


@pytest.mark.parametrize("provider", [None, "django.forms"])
def test_projects_without_signal_candidates_do_not_construct_signal_registry(
    monkeypatch, tmp_path, provider
):
    from skylos.deadcode import django_signal_liveness as signals
    from skylos.visitors.base import Definition

    definitions = {}
    if provider is not None:
        definitions[provider] = Definition(provider, "import", tmp_path / "app.py", 1)

    def unexpected_registry(*args, **kwargs):
        pytest.fail("signal registry should not be built without a candidate")

    def unexpected_parse_consumption():
        pytest.fail("fast path should not consume parsed files")
        yield

    monkeypatch.setattr(signals, "_SignalRegistry", unexpected_registry)
    assert (
        signals.find_django_signal_targets(
            definitions, unexpected_parse_consumption(), tmp_path
        )
        == []
    )


def test_repeated_registration_wrapper_graph_is_memoized(monkeypatch, tmp_path):
    from skylos.deadcode import django_signal_liveness as signals

    calls = []
    original = signals._SignalScanner.invoke

    def record_invoke(scanner, function, *args, **kwargs):
        calls.append(function[1].name)
        return original(scanner, function, *args, **kwargs)

    monkeypatch.setattr(signals._SignalScanner, "invoke", record_invoke)
    source = _IMPORTS + _BODY + "def level0():\n    post_save.connect(on_save)\n"
    for level in range(1, 17):
        source += (
            f"def level{level}():\n    level{level - 1}()\n    level{level - 1}()\n"
        )
    source += "level16()\n"
    result = _scan(tmp_path, _sources(source))
    _assert_registered(result, loaded=True)
    assert len(calls) <= 36


@pytest.mark.parametrize("external", [True, False])
def test_bare_receiver_decorator_preserves_unknown_provider_but_not_identity(
    tmp_path, external
):
    prefix = "from external import receiver\n"
    if not external:
        prefix = "def receiver(callback):\n    'Keep the input.'\n    return callback\n"
    result = _scan(tmp_path, {"callbacks.py": prefix + "@receiver\n" + _BODY})
    if external:
        assert "callbacks.on_save" not in _unused(result)
        assert "callbacks.helper" not in _unused(result)
        assert (
            result["definitions"]["callbacks.on_save"]["dead_code_classification"]
            == "uncertain"
        )
    else:
        assert {"callbacks.on_save", "callbacks.helper"} <= _unused(result)


def test_signal_memo_observes_called_modules_global_binding_changes(tmp_path):
    sources = _sources(
        "from . import callbacks\n"
        "def wrapper():\n    callbacks.install()\n"
        "wrapper()\ncallbacks.select()\nwrapper()\n"
    )
    sources["shop/callbacks.py"] = (
        "from django.db.models.signals import post_save\n"
        "def first(sender, **kwargs):\n    return first_helper()\n"
        "def first_helper():\n    return 1\n"
        "def second(sender, **kwargs):\n    return second_helper()\n"
        "def second_helper():\n    return 2\n"
        "callback = first\n"
        "def install():\n    post_save.connect(callback)\n"
        "def select():\n    global callback\n    callback = second\n"
    )
    result = _scan(tmp_path, sources)
    assert {"shop.callbacks.first", "shop.callbacks.second"} <= _signal_targets(
        result, "django_web_signal_receiver"
    )


def test_signal_proof_is_not_cut_off_by_many_unrelated_called_functions(tmp_path):
    from skylos.deadcode.django_signal_liveness import find_django_signal_targets
    from skylos.deadcode.python_ast import ParsedPythonFile
    from skylos.visitors.base import Definition

    source = "from django.db.models.signals import post_save\n"
    for index in range(1026):
        source += f"def unrelated{index}():\n    pass\nunrelated{index}()\n"
    source += "def callback(sender, instance, **kwargs):\n    pass\ndef install():\n    post_save.connect(callback)\ninstall()\n"
    tree = ast.parse(source)
    path = tmp_path / "app.py"
    definitions = {
        "signal_import": Definition(
            "django.db.models.signals.post_save", "import", path, 1
        )
    }
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef):
            definitions[statement.name] = Definition(
                "app." + statement.name, "function", path, statement.lineno, statement
            )
    callback = definitions["callback"]
    parameter = Definition("app.callback.instance", "parameter", path, callback.line)
    definitions[parameter.name] = parameter
    targets = find_django_signal_targets(
        definitions, [ParsedPythonFile(path, tree)], tmp_path
    )
    assert (callback, "django_signal_registration_unknown_loading") in targets
    assert parameter.references > 0


@pytest.mark.parametrize("real", [True, False])
def test_staticmethod_receiver_preserves_real_contract_only(tmp_path, real):
    prefix = _IMPORTS
    if not real:
        prefix += "def receiver(signal):\n    def decorate(callback):\n        return callback\n    return decorate\n"
    source = prefix + (
        "class Handlers:\n    @staticmethod\n    @receiver(post_save)\n"
        "    def on_save(sender, instance, **kwargs):\n        return helper()\n"
        "def helper():\n    return 1\nHandlers()\n"
    )
    result = _scan(tmp_path, _sources(source))
    if real:
        assert "shop.signals.helper" not in _unused(result)
        assert "shop.signals.Handlers.on_save.instance" not in _unused(
            result, "unused_parameters"
        )
    else:
        assert "shop.signals.helper" in _unused(result)
        assert "shop.signals.Handlers.on_save.instance" in _unused(
            result, "unused_parameters"
        )


def test_actual_signal_can_connect_source_bound_instance_method(tmp_path):
    source = _IMPORTS + (
        "class Handlers:\n"
        "    def on_save(self, sender, instance, **kwargs):\n        return helper()\n"
        "def helper():\n    return 1\n"
        "handler = Handlers()\npost_save.connect(handler.on_save)\n"
    )
    result = _scan(tmp_path, _sources(source))
    assert "shop.signals.Handlers.on_save" in _signal_targets(
        result, "django_web_signal_receiver"
    )
    assert "shop.signals.helper" not in _unused(result)
    assert "shop.signals.Handlers.on_save.instance" not in _unused(
        result, "unused_parameters"
    )


def test_appconfig_ready_can_connect_its_bound_method(tmp_path):
    sources = _sources("def helper():\n    return 1\n")
    sources["shop/apps.py"] = (
        "from django.apps import AppConfig\nfrom django.db.models.signals import post_save\n"
        "from .signals import helper\n"
        "class ShopConfig(AppConfig):\n    name = 'shop'\n"
        "    def ready(self):\n        post_save.connect(self.on_save)\n"
        "    def on_save(self, sender, instance, **kwargs):\n        return helper()\n"
    )
    result = _scan(tmp_path, sources)
    assert "shop.apps.ShopConfig.on_save" in _signal_targets(
        result, "django_web_signal_receiver"
    )
    assert "shop.signals.helper" not in _unused(result)
    assert "shop.apps.ShopConfig.on_save.instance" not in _unused(
        result, "unused_parameters"
    )


@pytest.mark.parametrize("condition", ["True", "False", "enabled"])
def test_conditional_static_receiver_keeps_only_possible_callback_contract(
    tmp_path, condition
):
    source = _IMPORTS + (
        "class Handlers:\n"
        f"    if {condition}:\n"
        "        @staticmethod\n        @receiver(post_save)\n"
        "        def on_save(sender, instance, **kwargs):\n            return helper()\n"
        "def helper():\n    return 1\nHandlers()\n"
    )
    result = _scan(tmp_path, _sources(source))
    if condition == "False":
        assert "shop.signals.helper" in _unused(result)
    else:
        assert "shop.signals.helper" not in _unused(result)
        assert "shop.signals.Handlers.on_save.instance" not in _unused(
            result, "unused_parameters"
        )


@pytest.mark.parametrize("replacement", ["", "    on_save = None\n"])
def test_source_owned_method_resolves_before_unknown_external_ancestry(
    tmp_path, replacement
):
    source = _IMPORTS + (
        "from external import Base\n"
        "class Handlers(Base):\n"
        "    def on_save(self, sender, instance, **kwargs):\n        return helper()\n"
        + replacement
        + "def helper():\n    return 1\n"
        "handler = Handlers()\npost_save.connect(handler.on_save)\n"
    )
    result = _scan(tmp_path, _sources(source))
    if not replacement:
        assert "shop.signals.helper" not in _unused(result)
        assert "shop.signals.Handlers.on_save.instance" not in _unused(
            result, "unused_parameters"
        )
    else:
        assert "shop.signals.Handlers.on_save" not in _signal_targets(
            result, "django_web_signal_receiver"
        )


def test_unresolved_class_base_does_not_abort_signal_liveness(tmp_path):
    """A Call/expr base stores None in the MRO; that must not crash the pass.

    Large apps hit this shape; an uncaught error previously discarded every
    dead-code liveness rescue after framework entrypoints (signals, registries).
    """
    source = _IMPORTS + (
        "def base_factory():\n    return object\n"
        "class OddSignal(base_factory()):\n    pass\n"
        "odd = OddSignal()\n"
        "@receiver(post_save)\n" + _BODY
    )
    result = _scan(tmp_path, _sources(source))
    _assert_registered(result, loaded=True)
