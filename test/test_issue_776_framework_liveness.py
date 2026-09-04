import json
import textwrap

from skylos.analyzer import analyze


def _write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _finding_names(result, bucket):
    return {item["full_name"] for item in result.get(bucket, [])}


def test_django_runpython_rescues_only_runtime_supplied_parameters(tmp_path):
    _write(tmp_path / "shop" / "__init__.py", "")
    _write(tmp_path / "shop" / "migrations" / "__init__.py", "")
    _write(
        tmp_path / "shop" / "migrations" / "0001_initial.py",
        """
        from django.db import migrations as migration_ops

        def forwards(apps, schema_editor, extra):
            pass

        def backwards(*runtime_args, extra_kw=None):
            pass

        def unrelated(apps, schema_editor):
            pass

        class Migration(migration_ops.Migration):
            operations = [
                migration_ops.RunPython(
                    code=forwards,
                    reverse_code=backwards,
                ),
            ]
        """,
    )
    _write(
        tmp_path / "shop" / "migrations" / "0002_fake.py",
        """
        class RunPython:
            def __init__(self, callback):
                self.callback = callback

        def fake_callback(apps, schema_editor):
            pass

        operation = RunPython(fake_callback)
        """,
    )
    _write(
        tmp_path / "shop" / "migrations" / "0003_shadowed.py",
        """
        from django.db import migrations

        def nested_callback(apps, schema_editor):
            pass

        def helper(migrations):
            migrations.RunPython(nested_callback)

        helper(None)
        """,
    )
    _write(
        tmp_path / "shop" / "migrations" / "0004_rebound.py",
        """
        from django.db import migrations
        import local_operations as migrations

        def rebound_callback(apps, schema_editor):
            pass

        operation = migrations.RunPython(rebound_callback)
        """,
    )
    _write(
        tmp_path / "shop" / "migrations" / "0005_class_shadow.py",
        """
        from django.db import migrations

        class FakeOperations:
            @staticmethod
            def RunPython(callback):
                return callback

        def class_callback(apps, schema_editor):
            pass

        class Holder:
            migrations = FakeOperations()
            operation = migrations.RunPython(class_callback)
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = _finding_names(result, "unused_parameters")

    assert not any(name.endswith(".forwards.apps") for name in unused)
    assert not any(name.endswith(".forwards.schema_editor") for name in unused)
    assert any(name.endswith(".forwards.extra") for name in unused)
    assert not any(name.endswith(".backwards.runtime_args") for name in unused)
    assert any(name.endswith(".backwards.extra_kw") for name in unused)
    assert any(name.endswith(".unrelated.apps") for name in unused)
    assert any(name.endswith(".unrelated.schema_editor") for name in unused)
    assert any(name.endswith(".fake_callback.apps") for name in unused)
    assert any(name.endswith(".fake_callback.schema_editor") for name in unused)
    assert any(name.endswith(".nested_callback.apps") for name in unused)
    assert any(name.endswith(".nested_callback.schema_editor") for name in unused)
    assert any(name.endswith(".rebound_callback.apps") for name in unused)
    assert any(name.endswith(".rebound_callback.schema_editor") for name in unused)
    assert any(name.endswith(".class_callback.apps") for name in unused)
    assert any(name.endswith(".class_callback.schema_editor") for name in unused)


def test_django_runpython_supports_direct_import_alias(tmp_path):
    _write(tmp_path / "shop" / "__init__.py", "")
    _write(tmp_path / "shop" / "migrations" / "__init__.py", "")
    _write(
        tmp_path / "shop" / "migrations" / "0001_data.py",
        """
        from django.db.migrations import RunPython as DataOperation

        def forwards(apps, schema_editor):
            pass

        operation = DataOperation(forwards)
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = _finding_names(result, "unused_parameters")

    assert not any(name.endswith(".forwards.apps") for name in unused)
    assert not any(name.endswith(".forwards.schema_editor") for name in unused)


def test_django_runpython_rescues_imported_callback_parameters(tmp_path):
    _write(
        tmp_path / "callbacks.py",
        """
        def imported_forwards(apps, schema_editor, extra):
            pass
        """,
    )
    _write(tmp_path / "shop" / "__init__.py", "")
    _write(tmp_path / "shop" / "migrations" / "__init__.py", "")
    _write(
        tmp_path / "shop" / "migrations" / "0001_data.py",
        """
        from callbacks import imported_forwards as forwards
        from django.db import migrations

        operation = migrations.RunPython(forwards)
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = _finding_names(result, "unused_parameters")

    assert "callbacks.imported_forwards.apps" not in unused
    assert "callbacks.imported_forwards.schema_editor" not in unused
    assert "callbacks.imported_forwards.extra" in unused


def test_repeated_compatible_framework_imports_remain_trusted(tmp_path):
    _write(tmp_path / "shop" / "__init__.py", "")
    _write(tmp_path / "shop" / "migrations" / "__init__.py", "")
    _write(
        tmp_path / "shop" / "migrations" / "0001_data.py",
        """
        import django.db.migrations
        import django.db.models
        from django.db.migrations import RunPython
        from django.db.migrations import RunPython

        def module_callback(apps, schema_editor):
            pass

        def direct_callback(apps, schema_editor):
            pass

        operations = [
            django.db.migrations.RunPython(module_callback),
            RunPython(direct_callback),
        ]
        """,
    )
    _write(tmp_path / "shop" / "signals.py", "")
    _write(
        tmp_path / "shop" / "apps.py",
        """
        import django.apps
        import django.conf

        class ShopConfig(django.apps.AppConfig):
            def ready(self):
                from . import signals
        """,
    )
    _write(
        tmp_path / "celery_app.py",
        """
        import celery
        import celery.schedules

        def route_task(name, args, kwargs, options):
            pass

        app = celery.Celery("shop")
        app.conf.task_routes = (route_task,)
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_parameters = _finding_names(result, "unused_parameters")
    unused_functions = _finding_names(result, "unused_functions")
    unused_imports = _finding_names(result, "unused_imports")

    for callback in ("module_callback", "direct_callback"):
        assert not any(
            name.endswith(f".{callback}.apps") for name in unused_parameters
        )
        assert not any(
            name.endswith(f".{callback}.schema_editor")
            for name in unused_parameters
        )
    assert "shop.signals" not in unused_imports
    assert "celery_app.route_task" not in unused_functions
    assert not any(
        name.startswith("celery_app.route_task.") for name in unused_parameters
    )


def test_appconfig_ready_rescues_only_direct_signal_module_import(tmp_path):
    _write(tmp_path / "shop" / "__init__.py", "")
    _write(tmp_path / "shop" / "signals.py", "")
    _write(tmp_path / "shop" / "helpers.py", "")
    _write(
        tmp_path / "shop" / "apps.py",
        """
        from django.apps import AppConfig as DjangoAppConfig

        class ShopConfig(DjangoAppConfig):
            name = "shop"

            def ready(self):
                from . import helpers, signals as hooks
        """,
    )
    _write(tmp_path / "otherpkg" / "__init__.py", "")
    _write(tmp_path / "otherpkg" / "signals.py", "")
    _write(
        tmp_path / "other.py",
        """
        from django.apps import AppConfig

        class OtherConfig(AppConfig):
            def startup(self):
                from otherpkg import signals
        """,
    )
    _write(tmp_path / "nestedpkg" / "__init__.py", "")
    _write(tmp_path / "nestedpkg" / "signals.py", "")
    _write(
        tmp_path / "nested.py",
        """
        from django.apps import AppConfig

        class NestedConfig(AppConfig):
            def ready(self):
                def later():
                    from nestedpkg import signals
                return later
        """,
    )
    _write(tmp_path / "reboundpkg" / "__init__.py", "")
    _write(tmp_path / "reboundpkg" / "signals.py", "")
    _write(
        tmp_path / "rebound.py",
        """
        from django.apps import AppConfig
        from local_framework import AppConfig

        class ReboundConfig(AppConfig):
            def ready(self):
                from reboundpkg import signals
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = _finding_names(result, "unused_imports")

    assert "shop.signals" not in unused
    assert "shop.helpers" in unused
    assert "otherpkg.signals" in unused
    assert "nestedpkg.signals" in unused
    assert "reboundpkg.signals" in unused
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert any(
        item["name"] == "shop.signals"
        and item["reason"] == "django_appconfig_signal_import"
        for item in rescues
    )


def test_local_appconfig_name_does_not_rescue_signal_import(tmp_path):
    _write(tmp_path / "signals.py", "")
    _write(
        tmp_path / "app.py",
        """
        class AppConfig:
            pass

        class LocalConfig(AppConfig):
            def ready(self):
                import signals
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

    assert "signals" in _finding_names(result, "unused_imports")


def test_celery_task_routes_rescue_callable_and_its_contract_parameters(tmp_path):
    _write(tmp_path / "routers" / "__init__.py", "")
    _write(
        tmp_path / "routers" / "checkout.py",
        """
        def dotted(
            name,
            args,
            kwargs,
            options,
            extra=None,
            task=None,
            *,
            debug=None,
            **kw,
        ):
            pass
        """,
    )
    _write(
        tmp_path / "settings.py",
        """
        def direct(name, args, kwargs, options, task=None, **kw):
            return name, options

        task_routes = (direct,)

        class Celery:
            def __init__(self):
                self.task_routes = ("routers.checkout:dotted",)

        app = Celery()
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_functions = _finding_names(result, "unused_functions")
    unused_parameters = _finding_names(result, "unused_parameters")

    assert "settings.direct" not in unused_functions
    assert "routers.checkout.dotted" not in unused_functions
    assert not any(name.startswith("settings.direct.") for name in unused_parameters)
    assert "routers.checkout.dotted.extra" in unused_parameters
    assert "routers.checkout.dotted.debug" in unused_parameters
    assert not any(
        name.startswith("routers.checkout.dotted.")
        and not name.endswith((".extra", ".debug"))
        for name in unused_parameters
    )
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert any(
        item["name"] == "routers.checkout.dotted"
        and item["reason"] == "celery_task_router"
        for item in rescues
    )


def test_celery_task_mapping_and_unrelated_setting_do_not_rescue_functions(tmp_path):
    _write(tmp_path / "routers" / "__init__.py", "")
    _write(
        tmp_path / "routers" / "ignored.py",
        """
        def mapped(name, args, kwargs, options):
            pass

        def unrelated(name, args, kwargs, options):
            pass

        def attribute_router(name, args, kwargs, options):
            pass

        def keyword_router(name, args, kwargs, options):
            pass

        def dictionary_router(name, args, kwargs, options):
            pass

        def ordered_mapping_name(name, args, kwargs, options):
            pass

        def uninstantiated(name, args, kwargs, options):
            pass
        """,
    )
    _write(
        tmp_path / "settings.py",
        """
        task_routes = {
            "routers.ignored.mapped": {"queue": "priority"},
        }
        routes = ("routers.ignored.unrelated",)

        class Config:
            def __init__(self):
                self.task_routes = ("routers.ignored.attribute_router",)

        configure(task_routes=("routers.ignored.keyword_router",))
        config = {"task_routes": ("routers.ignored.dictionary_router",)}
        task_routes = ([
            ("routers.ignored.ordered_mapping_name", {"queue": "priority"}),
        ],)

        class Celery:
            def __init__(self):
                self.task_routes = ("routers.ignored.uninstantiated",)
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_functions = _finding_names(result, "unused_functions")
    unused_parameters = _finding_names(result, "unused_parameters")

    assert "routers.ignored.mapped" in unused_functions
    assert "routers.ignored.unrelated" in unused_functions
    assert "routers.ignored.attribute_router" in unused_functions
    assert "routers.ignored.keyword_router" in unused_functions
    assert "routers.ignored.dictionary_router" in unused_functions
    assert "routers.ignored.uninstantiated" in unused_functions
    assert "routers.ignored.ordered_mapping_name.name" in unused_parameters


def test_proven_celery_app_configuration_rescues_router_paths(tmp_path):
    _write(tmp_path / "routers" / "__init__.py", "")
    _write(
        tmp_path / "routers" / "configured.py",
        """
        def assigned(name, args, kwargs, options, task=None, **kw):
            pass

        def updated(name, args, kwargs, options, task=None, **kw):
            pass

        def dictionary(name, args, kwargs, options, task=None, **kw):
            pass
        """,
    )
    _write(
        tmp_path / "celery_app.py",
        """
        from celery import Celery as WorkerApp

        assigned_app = WorkerApp("assigned")
        assigned_app.conf.task_routes = ("routers.configured.assigned",)

        updated_app = WorkerApp("updated")
        updated_app.conf.update(task_routes=("routers.configured.updated",))

        dictionary_app = WorkerApp("dictionary")
        dictionary_app.conf.update({
            "task_routes": ("routers.configured.dictionary",),
        })
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_functions = _finding_names(result, "unused_functions")

    assert "routers.configured.assigned" not in unused_functions
    assert "routers.configured.updated" not in unused_functions
    assert "routers.configured.dictionary" not in unused_functions


def test_module_setting_rescues_imported_celery_router_parameters(tmp_path):
    _write(tmp_path / "routers" / "__init__.py", "")
    _write(
        tmp_path / "routers" / "imported.py",
        """
        def imported_route(name, args, kwargs, options, extra=None):
            pass
        """,
    )
    _write(
        tmp_path / "settings.py",
        """
        from routers.imported import imported_route as route

        task_routes = (route,)
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = _finding_names(result, "unused_parameters")

    assert not any(
        name.startswith("routers.imported.imported_route.")
        and not name.endswith(".extra")
        for name in unused
    )
    assert "routers.imported.imported_route.extra" in unused


def test_rebound_imported_router_does_not_rescue_original_parameters(tmp_path):
    _write(tmp_path / "routers" / "__init__.py", "")
    _write(
        tmp_path / "routers" / "imported.py",
        """
        def imported_route(name, args, kwargs, options):
            pass
        """,
    )
    _write(
        tmp_path / "settings.py",
        """
        from routers.imported import imported_route as route

        route = object()
        task_routes = (route,)
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = _finding_names(result, "unused_parameters")

    assert {
        "routers.imported.imported_route.name",
        "routers.imported.imported_route.args",
        "routers.imported.imported_route.kwargs",
        "routers.imported.imported_route.options",
    }.issubset(unused)


def test_relative_celery_import_does_not_prove_framework_configuration(tmp_path):
    _write(tmp_path / "local_app" / "__init__.py", "")
    _write(
        tmp_path / "local_app" / "celery.py",
        """
        class Celery:
            pass
        """,
    )
    _write(
        tmp_path / "local_app" / "config.py",
        """
        from .celery import Celery

        def local_router(name, args, kwargs, options):
            pass

        app = Celery()
        app.conf.update(task_routes=("local_app.config.local_router",))
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

    assert "local_app.config.local_router" in _finding_names(
        result, "unused_functions"
    )


def test_overwritten_celery_settings_do_not_rescue_stale_routers(tmp_path):
    _write(tmp_path / "routers" / "__init__.py", "")
    _write(
        tmp_path / "routers" / "stale.py",
        """
        def module_router(name, args, kwargs, options):
            pass

        def app_router(name, args, kwargs, options):
            pass

        def constructor_router(name, args, kwargs, options):
            pass

        def updated_router(name, args, kwargs, options):
            pass

        def subclass_router(name, args, kwargs, options):
            pass

        def discarded_router(name, args, kwargs, options):
            pass
        """,
    )
    _write(
        tmp_path / "celery_app.py",
        """
        from celery import Celery

        task_routes = ("routers.stale.module_router",)
        task_routes = ()

        app = Celery(
            "shop",
            task_routes=("routers.stale.constructor_router",),
        )
        app.conf.task_routes = ("routers.stale.app_router",)
        app.conf.task_routes = ()
        app.conf.update(task_routes=("routers.stale.updated_router",))
        app.conf.update(task_routes=())

        class CustomCelery(Celery):
            def __init__(self):
                self.task_routes = ("routers.stale.subclass_router",)

        Celery(
            "discarded",
            task_routes=("routers.stale.discarded_router",),
        )
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_functions = _finding_names(result, "unused_functions")

    assert "routers.stale.module_router" in unused_functions
    assert "routers.stale.app_router" in unused_functions
    assert "routers.stale.constructor_router" in unused_functions
    assert "routers.stale.updated_router" in unused_functions
    assert "routers.stale.subclass_router" in unused_functions
    assert "routers.stale.discarded_router" in unused_functions


def test_empty_package_admin_is_treated_as_a_framework_stub(tmp_path):
    _write(tmp_path / "django_marker.py", "from django.apps import AppConfig\n")
    _write(tmp_path / "shop" / "__init__.py", "")
    _write(
        tmp_path / "shop" / "admin.py",
        '"""Django discovers this module even before registrations are added."""',
    )
    _write(tmp_path / "tools" / "admin.py", "# Not a package module yet.\n")

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_files = {item["file"] for item in result.get("unused_files", [])}

    assert str(tmp_path / "shop" / "admin.py") not in unused_files
    assert str(tmp_path / "tools" / "admin.py") in unused_files


def test_empty_admin_in_non_django_package_is_still_reported(tmp_path):
    _write(tmp_path / "utilities" / "__init__.py", "")
    _write(tmp_path / "utilities" / "admin.py", "# Empty helper placeholder.\n")

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_files = {item["file"] for item in result.get("unused_files", [])}

    assert str(tmp_path / "utilities" / "admin.py") in unused_files


def test_relative_local_django_module_does_not_hide_empty_admin(tmp_path):
    _write(tmp_path / "utilities" / "__init__.py", "")
    _write(tmp_path / "utilities" / "django.py", "helper = object()\n")
    _write(
        tmp_path / "utilities" / "consumer.py",
        """
        from .django import helper

        value = helper
        """,
    )
    _write(tmp_path / "utilities" / "admin.py", "# Empty helper placeholder.\n")

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_files = {item["file"] for item in result.get("unused_files", [])}

    assert str(tmp_path / "utilities" / "admin.py") in unused_files


def test_local_framework_named_packages_do_not_prove_runtime_hooks(tmp_path):
    _write(tmp_path / "django" / "__init__.py", "")
    _write(tmp_path / "django" / "db" / "__init__.py", "")
    _write(
        tmp_path / "django" / "db" / "migrations.py",
        """
        class RunPython:
            pass
        """,
    )
    _write(
        tmp_path / "django" / "apps.py",
        """
        class AppConfig:
            pass
        """,
    )
    _write(tmp_path / "celery" / "__init__.py", "class Celery: pass\n")
    _write(tmp_path / "shop" / "__init__.py", "")
    _write(tmp_path / "shop" / "migrations" / "__init__.py", "")
    _write(
        tmp_path / "shop" / "migrations" / "0001_fake.py",
        """
        from django.db import migrations

        def forwards(apps, schema_editor):
            pass

        operation = migrations.RunPython(forwards)
        """,
    )
    _write(tmp_path / "shop" / "signals.py", "")
    _write(
        tmp_path / "shop" / "apps.py",
        """
        from django.apps import AppConfig

        class ShopConfig(AppConfig):
            def ready(self):
                from . import signals
        """,
    )
    _write(tmp_path / "shop" / "admin.py", "# Local framework lookalike.\n")
    _write(
        tmp_path / "routes.py",
        """
        def router(name, args, kwargs, options):
            pass
        """,
    )
    _write(
        tmp_path / "celery_config.py",
        """
        from celery import Celery

        app = Celery()
        app.conf.task_routes = ("routes.router",)
        """,
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused_parameters = _finding_names(result, "unused_parameters")
    unused_imports = _finding_names(result, "unused_imports")
    unused_functions = _finding_names(result, "unused_functions")
    unused_files = {item["file"] for item in result.get("unused_files", [])}

    assert "shop.migrations.0001_fake.forwards.apps" in unused_parameters
    assert "shop.migrations.0001_fake.forwards.schema_editor" in unused_parameters
    assert "shop.signals" in unused_imports
    assert "routes.router" in unused_functions
    assert str(tmp_path / "shop" / "admin.py") in unused_files
