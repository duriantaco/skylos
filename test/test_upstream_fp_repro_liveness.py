"""Literal production-shaped Django dead-code FP reproducers (post-#1056 gaps).

Fixtures miniaturize real app wiring. Scan at confidence 80. Do not put
private product or org names in this file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze


def _write_tree(root: Path, sources: dict[str, str]) -> None:
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source if source else "\n", encoding="utf-8")


def _scan(root: Path, sources: dict[str, str], *, conf: int = 80):
    _write_tree(root, sources)
    result = json.loads(analyze(str(root), conf=conf, grep_verify=False))
    assert not result.get("analysis_errors")
    return result


def _unused_names(result, *buckets):
    names = set()
    for bucket in buckets or (
        "unused_functions",
        "unused_classes",
        "unused_methods",
        "unused_variables",
        "unused_imports",
    ):
        for item in result.get(bucket, []):
            names.add(item.get("name") or item.get("full_name") or "")
            full = item.get("full_name") or ""
            if full:
                names.add(full)
                names.add(full.rsplit(".", 1)[-1])
    return names


def _assert_quiet(result, *symbols):
    unused = _unused_names(result)
    missing = [symbol for symbol in symbols if symbol in unused]
    assert not missing, f"still unused at conf=80: {missing}\nall={sorted(unused)}"


def _assert_reported(result, *symbols):
    unused = _unused_names(result)
    absent = [symbol for symbol in symbols if symbol not in unused]
    assert not absent, f"expected still unused: {absent}\nall={sorted(unused)}"


# --- P1.1: AppConfig.ready imports signals from a nested subpackage ------------
# Shape: INSTALLED_APPS = ["pkg.apps.PkgConfig"], name="pkg", ready does
# ``from pkg.feature import signals`` (not ``from . import signals``).

_NESTED_SIGNALS = {
    "project/__init__.py": "",
    "project/settings.py": """\
INSTALLED_APPS = ["pkg.apps.PkgConfig"]
SECRET_KEY = "x"
ROOT_URLCONF = "project.urls"
""",
    "project/urls.py": "urlpatterns = []\n",
    "pkg/__init__.py": "",
    "pkg/apps.py": """\
from django.apps import AppConfig


class PkgConfig(AppConfig):
    name = "pkg"

    def ready(self):
        from pkg.feature import signals  # noqa: F401
""",
    "pkg/feature/__init__.py": "",
    "pkg/feature/models.py": """\
from django.db import models


class Record(models.Model):
    name = models.CharField(max_length=32)
""",
    "pkg/feature/signals.py": """\
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from pkg.feature.models import Record


def _touch_side_effect(record):
    return record.name


@receiver(post_save, sender=Record, dispatch_uid="pkg.feature.record_created")
def on_record_created(sender, instance, created, **kwargs):
    if created:
        _touch_side_effect(instance)


@receiver(post_delete, sender=Record, dispatch_uid="pkg.feature.record_deleted")
def on_record_deleted(sender, instance, **kwargs):
    _touch_side_effect(instance)
""",
}


def test_p1_nested_appconfig_ready_signals_are_live(tmp_path):
    result = _scan(tmp_path, _NESTED_SIGNALS)
    _assert_quiet(
        result,
        "on_record_created",
        "on_record_deleted",
        "_touch_side_effect",
    )


# --- P1.2: Celery result_backend="module:Class" via app.conf.update -----------

_CELERY_RESULT_BACKEND = {
    "worker/__init__.py": "",
    "worker/celery_app.py": """\
from celery import Celery

app = Celery("worker")
app.conf.update(
    result_backend="worker.backends:ClusterResultBackend",
    task_serializer="json",
)
""",
    "worker/backends.py": """\
class ClusterResultBackend:
    \"\"\"Loaded only via Celery result_backend string (colon path).\"\"\"

    def get(self, key):
        return None
""",
}


def test_p1_celery_result_backend_colon_path_is_live(tmp_path):
    result = _scan(tmp_path, _CELERY_RESULT_BACKEND)
    _assert_quiet(result, "ClusterResultBackend")


# --- P1.3: TEST_RUNNER only in a secondary settings module --------------------

_TEST_RUNNER_SECONDARY = {
    "project/__init__.py": "",
    "project/settings.py": """\
INSTALLED_APPS = ["project"]
SECRET_KEY = "x"
ROOT_URLCONF = "project.urls"
# TEST_RUNNER = "project.runners.LegacyNoDbRunner"
""",
    "project/urls.py": "urlpatterns = []\n",
    "project/settings_tests_discover.py": """\
from project.settings import *  # noqa: F401,F403

TEST_RUNNER = "project.runners.NoMigrateDiscoverRunner"
""",
    "project/runners.py": """\
from django.test.runner import DiscoverRunner


class NoMigrateDiscoverRunner(DiscoverRunner):
    def setup_databases(self, **kwargs):
        return None


class LegacyNoDbRunner(DiscoverRunner):
    def setup_databases(self, **kwargs):
        pass
""",
}


def test_p1_test_runner_in_secondary_settings_is_live(tmp_path):
    result = _scan(tmp_path, _TEST_RUNNER_SECONDARY)
    _assert_quiet(result, "NoMigrateDiscoverRunner")
    # Comment-only primary assignment is not AST evidence — may still report.
    # LegacyNoDbRunner is intentionally unreferenced in live settings.


# --- P2.2: management command module helpers called only from handle ----------

_COMMAND_HELPERS = {
    "shop/__init__.py": "",
    "shop/management/__init__.py": "",
    "shop/management/commands/__init__.py": "",
    "shop/management/commands/hello.py": """\
from django.core.management.base import BaseCommand


def _format_name(name):
    return name.strip().title()


def _unused_export_job():
    return "dead"


class Command(BaseCommand):
    def handle(self, *args, **options):
        self.stdout.write(_format_name(options.get("name", "")))
""",
}


def test_p2_management_command_helpers_from_handle_are_live(tmp_path):
    result = _scan(tmp_path, _COMMAND_HELPERS)
    _assert_quiet(result, "_format_name", "Command")
    _assert_reported(result, "_unused_export_job")


# --- P2.3: multi-method provider; call site uses base type only --------------

_PROVIDER_MULTI = {
    "college/__init__.py": "",
    "college/provider.py": """\
class BaseProviderClient:
    def schedule_dates(self, season: int):
        raise NotImplementedError

    def scoreboard(self, day: str):
        raise NotImplementedError

    def division_teams(self, season: int):
        raise NotImplementedError


class StatsClient(BaseProviderClient):
    def schedule_dates(self, season: int):
        return self._graphql("dates", season)

    def scoreboard(self, day: str):
        return self._graphql("board", day)

    def division_teams(self, season: int):
        return self._graphql("teams", season)

    def _graphql(self, kind: str, key):
        return {"kind": kind, "key": key}


def fetch_day(client: BaseProviderClient, day: str):
    return client.scoreboard(day)


RESULT = fetch_day(StatsClient(), "2026-10-23")
""",
}


def test_p2_multi_method_provider_contract_methods_are_live(tmp_path):
    result = _scan(tmp_path, _PROVIDER_MULTI)
    _assert_quiet(
        result,
        "StatsClient.schedule_dates",
        "StatsClient.scoreboard",
        "StatsClient.division_teams",
        "_graphql",
    )


# --- P2.4: registry dict bare names + getattr(module, name) ------------------

_REGISTRY_GETATTR = {
    # Handlers live in a separate top-level package so a ``getattr`` mention
    # in the factory does not dyn-mark the whole handler package.
    "rpc/__init__.py": "",
    "rpc/registry.py": """\
HANDLERS = {
    "games": {
        "create_method": "create_game",
        "options_method": "get_game_form_schema",
        "destroy_method": "delete_game_safely",
    }
}
""",
    "rpc/factory.py": """\
from handlers import form_schemas, mutations
from rpc import registry


def dispatch(kind, request):
    relation = registry.HANDLERS[kind]
    create_name = relation.get("create_method")
    options_name = relation.get("options_method")
    destroy_name = relation.get("destroy_method")
    if create_name:
        getattr(mutations, create_name)(request)
    if options_name and hasattr(form_schemas, options_name):
        getattr(form_schemas, options_name)(request)
    if destroy_name:
        getattr(mutations, destroy_name)(request)


dispatch("games", object())
""",
    "handlers/__init__.py": "",
    "handlers/form_schemas.py": """\
def get_game_form_schema(request, **kwargs):
    return {"fields": []}


def unused_schema():
    return {}
""",
    "handlers/mutations.py": """\
def create_game(request, **kwargs):
    return {"id": 1}


def delete_game_safely(request, **kwargs):
    return {"ok": True}


def unused_mutation():
    return None
""",
}


def test_p2_registry_getattr_handlers_are_live(tmp_path):
    result = _scan(tmp_path, _REGISTRY_GETATTR)
    _assert_quiet(
        result,
        "get_game_form_schema",
        "create_game",
        "delete_game_safely",
    )
    # Opaque ``getattr(module, name)`` retains sibling helpers as uncertain
    # (unresolved_receiver), not as validated unused — do not require them
    # in unused_* buckets.


# --- P2.5: custom form Field class attached to a live Form -------------------

_FORM_FIELD_CLASS = {
    "project/__init__.py": "",
    "project/settings.py": """\
INSTALLED_APPS = ["shop"]
SECRET_KEY = "x"
ROOT_URLCONF = "project.urls"
""",
    "project/urls.py": """\
from django.urls import path
from shop.views import FacilityView

urlpatterns = [path("facility/", FacilityView.as_view())]
""",
    "shop/__init__.py": "",
    "shop/fields.py": """\
from django import forms


class FacilityChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return getattr(obj, "name", str(obj))

    def clean(self, value):
        return super().clean(value)
""",
    "shop/forms.py": """\
from django import forms
from shop.fields import FacilityChoiceField


class FacilityForm(forms.Form):
    facility = FacilityChoiceField(queryset=None)
""",
    "shop/views.py": """\
from django.views.generic import FormView
from shop.forms import FacilityForm


class FacilityView(FormView):
    form_class = FacilityForm
    template_name = "facility.html"
""",
}


def test_p2_form_field_class_on_live_form_is_live(tmp_path):
    result = _scan(tmp_path, _FORM_FIELD_CLASS)
    _assert_quiet(result, "FacilityChoiceField", "label_from_instance")


# --- P3.1: same-module helper called from nested serializers -----------------
# View is routed; serializers are only used from the view. Helper has no
# module-level RESULT= root — only nested method callers (production shape).

_SAME_MODULE_HELPER = {
    "project/__init__.py": "",
    "project/settings.py": """\
INSTALLED_APPS = ["checkout"]
SECRET_KEY = "x"
ROOT_URLCONF = "project.urls"
""",
    "project/urls.py": """\
from django.urls import path
from checkout.views import OrderView

urlpatterns = [path("order/", OrderView.as_view())]
""",
    "checkout/__init__.py": "",
    "checkout/views.py": """\
from django.views import View


def _validate_phone(value):
    return bool(value) and str(value).isdigit()


class CheckoutSerializer:
    def validate_phone(self, value):
        return _validate_phone(value)


class GuestSerializer:
    def validate_phone(self, value):
        return _validate_phone(value)


class OrderView(View):
    def post(self, request):
        phone = request.POST.get("phone")
        return CheckoutSerializer().validate_phone(phone)
""",
}


def test_p3_same_module_helper_called_from_nested_methods_is_live(tmp_path):
    result = _scan(tmp_path, _SAME_MODULE_HELPER)
    _assert_quiet(result, "_validate_phone", "OrderView")
