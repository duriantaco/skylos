"""Framework fixtures are parsed by Skylos, never imported or executed."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze


def _scan(tmp_path, sources):
    for name, source in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write(textwrap.dedent(source).lstrip())
    return json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))


def _names(result, bucket):
    return {item["full_name"] for item in result.get(bucket, [])}


@pytest.mark.parametrize(
    "registration",
    [
        "from django.db import migrations as ops\noperation = ops.RunPython(forwards)",
        "from django.db.migrations import RunPython as Operation\n"
        "operation = Operation(code=forwards)",
        "import django.db.migrations\nimport django.db.models\n"
        "operation = django.db.migrations.RunPython(forwards)",
    ],
)
def test_runpython_rescues_only_framework_argument_slots(tmp_path, registration):
    result = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/migrations/__init__.py": "",
            "shop/migrations/0001_data.py": (
                "def forwards(apps, schema_editor, extra=None): pass\n"
                "def unrelated(apps, schema_editor): pass\n" + registration
            ),
        },
    )
    unused = _names(result, "unused_parameters")
    assert not any(name.endswith(".forwards.apps") for name in unused)
    assert not any(name.endswith(".forwards.schema_editor") for name in unused)
    assert any(name.endswith(".forwards.extra") for name in unused)
    assert any(name.endswith(".unrelated.apps") for name in unused)
    assert any(name.endswith(".unrelated.schema_editor") for name in unused)


def test_runpython_imported_and_reverse_callbacks(tmp_path):
    result = _scan(
        tmp_path,
        {
            "callbacks.py": "def forwards(apps, editor, extra=None): pass\n",
            "shop/__init__.py": "",
            "shop/migrations/__init__.py": "",
            "shop/migrations/0001_data.py": """
                from django.db import migrations
                from callbacks import forwards as apply_data
                def backwards(*runtime, extra=None): pass
                class Migration(migrations.Migration):
                    operations = [migrations.RunPython(apply_data, backwards)]
            """,
        },
    )
    unused = _names(result, "unused_parameters")
    assert "callbacks.forwards.apps" not in unused
    assert "callbacks.forwards.editor" not in unused
    assert "callbacks.forwards.extra" in unused
    assert not any(name.endswith(".backwards.runtime") for name in unused)
    assert any(name.endswith(".backwards.extra") for name in unused)


@pytest.mark.parametrize(
    "registration",
    [
        "class RunPython: pass\noperation = RunPython(forwards)",
        "from django.db import migrations\nimport local_ops as migrations\n"
        "operation = migrations.RunPython(forwards)",
        "from django.db import migrations\n"
        "def helper(migrations): return migrations.RunPython(forwards)",
        "from django.db import migrations\nclass Holder:\n"
        "    migrations = object()\n    operation = migrations.RunPython(forwards)",
        "from django.db import migrations\nforwards = replacement\n"
        "operation = migrations.RunPython(forwards)",
    ],
)
def test_runpython_lookalikes_and_shadowing_do_not_rescue(tmp_path, registration):
    result = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/migrations/__init__.py": "",
            "shop/migrations/0001_data.py": (
                "def forwards(apps, schema_editor): pass\n" + registration
            ),
        },
    )
    unused = _names(result, "unused_parameters")
    assert any(name.endswith(".forwards.apps") for name in unused)
    assert any(name.endswith(".forwards.schema_editor") for name in unused)


@pytest.mark.parametrize(
    "configuration",
    [
        'app = Factory("shop", task_routes=("routers.route_task",))',
        'app = Factory("shop")\napp.conf.task_routes = ("routers.route_task",)',
        'app = Factory("shop")\napp.conf.update(task_routes=("routers.route_task",))',
        'app = Factory("shop")\napp.conf.update({"task_routes": ("routers.route_task",)})',
        'from routers import route_task as router\napp = Factory("shop")\n'
        "app.conf.task_routes = (router,)",
    ],
)
def test_actual_celery_router_and_signature_are_live(tmp_path, configuration):
    result = _scan(
        tmp_path,
        {
            "routers.py": """
                def route_task(name, args, kwargs, options, task=None, extra=None, **kw):
                    return None
                def unrelated(name, args, kwargs, options, task=None): return None
            """,
            "app.py": "from celery import Celery as Factory\n" + configuration,
        },
    )
    assert "routers.route_task" not in _names(result, "unused_functions")
    unused = _names(result, "unused_parameters")
    for argument in ("name", "args", "kwargs", "options", "task", "kw"):
        assert f"routers.route_task.{argument}" not in unused
    assert "routers.route_task.extra" in unused
    assert "routers.unrelated.args" in unused


@pytest.mark.parametrize(
    "configuration",
    [
        "class Celery:\n    def __init__(self):\n"
        '        self.task_routes = ("routers.route_task",)\napp = Celery()',
        'task_routes = ("routers.route_task",)',
        "from celery import Celery\nCelery = factory\n"
        'app = Celery("shop", task_routes=("routers.route_task",))',
        'from celery import Celery\napp = Celery("shop")\napp = object()\n'
        'app.conf.task_routes = ("routers.route_task",)',
        'from celery import Celery\napp = Celery("shop")\n'
        'app.conf.task_routes = ("routers.route_task",)\napp.conf.task_routes = {}',
        'from celery import Celery\napp = Celery("shop")\n'
        'app.conf.task_routes = ("routers.route_task",)\napp.conf.update(settings)',
        'from celery import Celery\napp = Celery("shop")\n'
        'app.conf.task_routes = {"routers.route_task": {"queue": "labels"}}',
    ],
)
def test_celery_fake_private_and_stale_configuration_does_not_rescue(
    tmp_path, configuration
):
    result = _scan(
        tmp_path,
        {
            "routers.py": "def route_task(name, args, kwargs, options): return None\n",
            "app.py": configuration,
        },
    )
    assert "routers.route_task" in _names(result, "unused_functions")
    assert "routers.route_task.args" in _names(result, "unused_parameters")


def test_appconfig_ready_signal_import_only(tmp_path):
    result = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/signals.py": "",
            "shop/helpers.py": "",
            "shop/apps.py": """
                from django.apps import AppConfig as BaseConfig
                class ShopConfig(BaseConfig):
                    def ready(self):
                        from . import helpers, signals as hooks
                    def unrelated(self):
                        from . import signals as unrelated_signals
            """,
        },
    )
    imports = result.get("unused_imports", [])
    assert not any(
        item["line"] == 4 and item["simple_name"] == "signals" for item in imports
    )
    assert any(item["simple_name"] == "helpers" for item in imports)


@pytest.mark.parametrize(
    "prefix", ["class AppConfig: pass", "from local_apps import AppConfig"]
)
def test_fake_appconfig_ready_import_stays_unused(tmp_path, prefix):
    result = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/signals.py": "",
            "shop/apps.py": prefix + "\nclass ShopConfig(AppConfig):\n"
            "    def ready(self):\n        from . import signals\n",
        },
    )
    assert "shop.signals" in _names(result, "unused_imports")


@pytest.mark.parametrize(
    "replacement", ["def ready(self): pass", "ready = replacement"]
)
def test_overwritten_ready_method_does_not_rescue_stale_import(tmp_path, replacement):
    result = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/signals.py": "",
            "shop/apps.py": "from django.apps import AppConfig\n"
            "class ShopConfig(AppConfig):\n"
            "    def ready(self):\n        from . import signals\n"
            f"    {replacement}\n",
        },
    )
    assert "shop.signals" in _names(result, "unused_imports")


@pytest.mark.parametrize(
    "exit_statement", ["return", "raise RuntimeError('not ready')"]
)
def test_ready_literal_branch_exit_prevents_signal_import(tmp_path, exit_statement):
    result = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/signals.py": "",
            "shop/apps.py": "from django.apps import AppConfig\n"
            "class ShopConfig(AppConfig):\n"
            "    def ready(self):\n"
            "        if True:\n"
            "            if False:\n"
            "                pass\n"
            "            else:\n"
            f"                {exit_statement}\n"
            "        from . import signals\n",
        },
    )
    assert "shop.signals" in _names(result, "unused_imports")


def test_ready_false_exit_branch_keeps_signal_import_live(tmp_path):
    result = _scan(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/signals.py": "",
            "shop/apps.py": "from django.apps import AppConfig\n"
            "class ShopConfig(AppConfig):\n"
            "    def ready(self):\n"
            "        if False:\n"
            "            return\n"
            "        from . import signals\n",
        },
    )
    assert "shop.signals" not in _names(result, "unused_imports")


def test_class_local_app_shadow_does_not_erase_module_configuration(tmp_path):
    result = _scan(
        tmp_path,
        {
            "routers.py": "def route_task(name, args, kwargs, options): return None\n",
            "app.py": 'from celery import Celery\napp = Celery("shop")\n'
            'app.conf.task_routes = ("routers.route_task",)\n'
            "class Other:\n    app = object()\n",
        },
    )
    assert "routers.route_task.args" not in _names(result, "unused_parameters")


@pytest.mark.parametrize(
    "replacement",
    [
        'app.conf["task_routes"] = {}',
        "app.conf = object()\napp.conf.task_routes = ('routers.route_task',)",
        "app.conf[key] = value",
    ],
)
def test_replaced_celery_configuration_does_not_rescue_router(tmp_path, replacement):
    result = _scan(
        tmp_path,
        {
            "routers.py": "def route_task(name, args, kwargs, options): return None\n",
            "app.py": 'from celery import Celery\napp = Celery("shop")\n'
            'app.conf.task_routes = ("routers.route_task",)\n' + replacement,
        },
    )
    assert "routers.route_task.args" in _names(result, "unused_parameters")


@pytest.mark.parametrize("framework", ["django", "celery"])
def test_local_framework_package_is_not_trusted(tmp_path, framework):
    sources = {
        f"{framework}/__init__.py": "",
        "routers.py": "def route_task(name, args, kwargs, options): return None\n",
        "app.py": 'from celery import Celery\napp = Celery("shop", task_routes=("routers.route_task",))',
        "shop/__init__.py": "",
        "shop/migrations/__init__.py": "",
        "shop/migrations/0001_data.py": "from django.db import migrations\n"
        "def forwards(apps, editor): pass\noperation = migrations.RunPython(forwards)",
    }
    result = _scan(tmp_path, sources)
    unused = _names(result, "unused_parameters")
    if framework == "django":
        assert any(name.endswith(".forwards.apps") for name in unused)
    else:
        assert "routers.route_task.args" in unused
