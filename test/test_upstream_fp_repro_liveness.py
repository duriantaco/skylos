"""Literal production-shaped Django dead-code FP reproducers (post-#1056 gaps).

Fixtures miniaturize real app wiring. Scan at confidence 80. Do not put
private product or org names in this file.
"""

from __future__ import annotations

import json
from pathlib import Path

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
    # Comment-only primary assignment is not AST evidence — must stay reported
    # (consumer NoDbTestRunner canary is the same shape).
    _assert_reported(result, "LegacyNoDbRunner")


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


# --- P2.3: duck-typed provider methods (no base declaration) -----------------
# Production: BaseProviderClient does not declare schedule_dates; sibling
# clients define it; pipeline calls client.schedule_dates after a factory.
# Putting schedule_dates on the base greenwashes via parent_override.

_PROVIDER_MULTI = {
    "college/__init__.py": "",
    "college/provider.py": """\
class BaseProviderClient:
    def scoreboard(self, day: str):
        raise NotImplementedError


class NcaaClient(BaseProviderClient):
    def schedule_dates(self, season: int):
        return self._graphql("dates", season)

    def scoreboard(self, day: str):
        return self._graphql("board", day)

    def _graphql(self, kind: str, key):
        return {"kind": kind, "key": key}


class NjcaaClient(BaseProviderClient):
    def schedule_dates(self, season: int):
        return self._graphql("dates", season)

    def scoreboard(self, day: str):
        return self._graphql("board", day)

    def _graphql(self, kind: str, key):
        return {"kind": kind, "key": key}


def get_provider_client(slug: str):
    if slug == "ncaa":
        return NcaaClient()
    return NjcaaClient()
""",
    "college/pipeline.py": """\
from college.provider import get_provider_client


def import_month(slug: str, season: int):
    client = get_provider_client(slug)
    dates = client.schedule_dates(season)
    return dates


RESULT = import_month("ncaa", 2026)
""",
    "hw/__init__.py": "",
    "hw/na.py": """\
class NotApplicableProvider:
    @staticmethod
    def initialize_field_hardware(field):
        return {"status": "error"}
""",
    "hw/tplink.py": """\
class TPLinkProvider:
    def initialize_field_hardware(self, field):
        return {"status": "ok", "kind": "tplink"}
""",
    "hw/unifi.py": """\
class UnifiProvider:
    def initialize_field_hardware(self, field):
        return {"status": "ok", "kind": "unifi"}
""",
    "hw/providers.py": """\
from hw.na import NotApplicableProvider
from hw.tplink import TPLinkProvider
from hw.unifi import UnifiProvider


def get_network_hardware_provider(key):
    if key == "na":
        return NotApplicableProvider()
    if key == "tplink":
        return TPLinkProvider()
    return UnifiProvider()


def initialize_field_hardware(field):
    return get_network_hardware_provider(field.kind).initialize_field_hardware(field)


class _Field:
    kind = "tplink"


RESULT = initialize_field_hardware(_Field())
""",
}


def test_p2_multi_method_provider_contract_methods_are_live(tmp_path):
    result = _scan(tmp_path, _PROVIDER_MULTI)
    _assert_quiet(
        result,
        "NcaaClient.schedule_dates",
        "NjcaaClient.schedule_dates",
        "initialize_field_hardware",
        "NotApplicableProvider.initialize_field_hardware",
        "TPLinkProvider.initialize_field_hardware",
        "UnifiProvider.initialize_field_hardware",
    )


# --- P2.4: list/tuple registry + factory class_dict + nested getattr ---------
# Production shape: REGISTERED_MODELS = [(Model, {related_models: {...}})] and
# a factory that stores method names on class_dict / closes over config.get
# names inside nested ViewSet methods. Flat HANDLERS+dispatch is not enough.

_REGISTRY_GETATTR = {
    "rpc/__init__.py": "",
    "rpc/registry.py": """\
REGISTERED_MODELS = [
    (
        object,
        {
            "queryset_method": "get_user_teams",
            "related_models": {
                "games": {
                    "queryset_method": "get_team_schedule",
                    "create_method": "create_game",
                    "update_method": "update_game",
                    "destroy_method": "delete_game_safely",
                    "options_method": "get_game_form_schema",
                },
                "practices": {
                    "queryset_method": "get_team_practices",
                    "create_method": "create_practice",
                },
                "roster": {
                    "queryset_method": "get_team_roster",
                },
            },
        },
    )
]
""",
    "rpc/factory.py": """\
from handlers import form_schemas, mutations, queries
from rpc.registry import REGISTERED_MODELS


def create_viewset_class(config):
    class Meta:
        # Nested class body: must not abort autoreload / liveness scanning.
        fields = ("id",)

    queryset_method_name = config.get("queryset_method")
    custom_create_method = config.get("create_method")
    custom_update_method = config.get("update_method")
    custom_destroy_method = config.get("destroy_method")
    options_method_name = config.get("options_method")

    def get_queryset(self):
        if hasattr(self, "_queryset_method_name") and self._queryset_method_name:
            if hasattr(queries, self._queryset_method_name):
                query_func = getattr(queries, self._queryset_method_name)
                return query_func(self.request)
        return []

    def create(self, request):
        if custom_create_method and hasattr(mutations, custom_create_method):
            return getattr(mutations, custom_create_method)(request)
        return None

    def update(self, request):
        if custom_update_method and hasattr(mutations, custom_update_method):
            return getattr(mutations, custom_update_method)(request)
        return None

    def destroy(self, request):
        if custom_destroy_method and hasattr(mutations, custom_destroy_method):
            return getattr(mutations, custom_destroy_method)(request)
        return None

    def options(self, request):
        if options_method_name and hasattr(form_schemas, options_method_name):
            return getattr(form_schemas, options_method_name)(request)
        return {}

    class_dict = {
        "_queryset_method_name": queryset_method_name,
        "get_queryset": get_queryset,
        "create": create,
        "update": update,
        "destroy": destroy,
        "options": options,
    }
    return type("DynamicViewSet", (object,), class_dict)


def build_related(relation_config):
    queryset_method_name = relation_config.get("queryset_method")
    create_method_name = relation_config.get("create_method")

    def related_action(self, request):
        if create_method_name and hasattr(mutations, create_method_name):
            getattr(mutations, create_method_name)(request)
        if queryset_method_name and hasattr(queries, queryset_method_name):
            return getattr(queries, queryset_method_name)(request)
        return []

    return related_action


for _model, config in REGISTERED_MODELS:
    View = create_viewset_class(config)
    view = View()
    view.request = object()
    view.get_queryset()
    for relation in (config.get("related_models") or {}).values():
        Related = create_viewset_class(relation)
        related = Related()
        related.request = object()
        related.get_queryset()
        related.create(object())
        related.update(object())
        related.destroy(object())
        related.options(object())
        action = build_related(relation)
        action(None, object())
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


def update_game(request, **kwargs):
    return {"id": 1}


def delete_game_safely(request, **kwargs):
    return {"ok": True}


def create_practice(request, **kwargs):
    return {"id": 2}


def unused_mutation():
    return None
""",
    "handlers/queries.py": """\
def get_user_teams(request):
    return []


def get_team_schedule(request):
    return []


def get_team_practices(request):
    return []


def get_team_roster(request):
    return []


def unused_query():
    return []
""",
}


def test_p2_registry_getattr_handlers_are_live(tmp_path):
    result = _scan(tmp_path, _REGISTRY_GETATTR)
    _assert_quiet(
        result,
        "get_game_form_schema",
        "create_game",
        "update_game",
        "delete_game_safely",
        "create_practice",
        "get_user_teams",
        "get_team_schedule",
        "get_team_practices",
        "get_team_roster",
    )


# Keep the original unexecuted factory as a negative proof control. Merely
# declaring a lookup in a factory, or iterating an empty input, registers nothing.
_UNEXECUTED_REGISTRY_FACTORY = """from handlers import form_schemas, mutations, queries


def create_viewset_class(config):
    class Meta:
        # Nested class body: must not abort autoreload / liveness scanning.
        fields = ("id",)

    queryset_method_name = config.get("queryset_method")
    custom_create_method = config.get("create_method")
    custom_update_method = config.get("update_method")
    custom_destroy_method = config.get("destroy_method")
    options_method_name = config.get("options_method")

    def get_queryset(self):
        if hasattr(self, "_queryset_method_name") and self._queryset_method_name:
            if hasattr(queries, self._queryset_method_name):
                query_func = getattr(queries, self._queryset_method_name)
                return query_func(self.request)
        return []

    def create(self, request):
        if custom_create_method and hasattr(mutations, custom_create_method):
            return getattr(mutations, custom_create_method)(request)
        return None

    def update(self, request):
        if custom_update_method and hasattr(mutations, custom_update_method):
            return getattr(mutations, custom_update_method)(request)
        return None

    def destroy(self, request):
        if custom_destroy_method and hasattr(mutations, custom_destroy_method):
            return getattr(mutations, custom_destroy_method)(request)
        return None

    def options(self, request):
        if options_method_name and hasattr(form_schemas, options_method_name):
            return getattr(form_schemas, options_method_name)(request)
        return {}

    class_dict = {
        "_queryset_method_name": queryset_method_name,
        "get_queryset": get_queryset,
        "create": create,
        "update": update,
        "destroy": destroy,
        "options": options,
    }
    return type("DynamicViewSet", (object,), class_dict)


def build_related(relation_config):
    queryset_method_name = relation_config.get("queryset_method")
    create_method_name = relation_config.get("create_method")

    def related_action(self, request):
        if create_method_name and hasattr(mutations, create_method_name):
            getattr(mutations, create_method_name)(request)
        if queryset_method_name and hasattr(queries, queryset_method_name):
            return getattr(queries, queryset_method_name)(request)
        return []

    return related_action


for _model, config in []:
    create_viewset_class(config)
    for relation in (config.get("related_models") or {}).values():
        build_related(relation)
"""


def test_unexecuted_registry_factory_does_not_supply_lookup_evidence(tmp_path):
    sources = dict(_REGISTRY_GETATTR)
    sources["rpc/factory.py"] = _UNEXECUTED_REGISTRY_FACTORY
    result = _scan(tmp_path, sources)
    rescues = result["analysis_summary"]["dead_code_liveness"]["rescued"]
    assert not any(item["reason"] == "nested_dict_getattr_registry" for item in rescues)


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
# Nested Serializer.validate_* → module helper. No direct View call of the
# helper or validate_phone (that greenwashed an earlier fixture).

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
from rest_framework import serializers


def _validate_phone(value):
    return bool(value) and str(value).isdigit()


class QuoteCustomerSerializer(serializers.Serializer):
    phone = serializers.CharField()

    def validate_phone(self, value):
        return _validate_phone(value)


class AccountRequestSerializer(serializers.Serializer):
    phone = serializers.CharField()

    def validate_phone(self, value):
        return _validate_phone(value)


class OrderView(View):
    def post(self, request):
        ser = QuoteCustomerSerializer(data=request.POST)
        ser.is_valid(raise_exception=True)
        return ser.validated_data
""",
    "checkout/permissions.py": """\
from rest_framework.permissions import BasePermission


def _get_api_key_from_request(request):
    return request.META.get("HTTP_AUTHORIZATION")


class APIKeyScopePermission(BasePermission):
    def has_permission(self, request, view):
        return bool(_get_api_key_from_request(request))
""",
}


def test_p3_same_module_helper_called_from_nested_methods_is_live(tmp_path):
    result = _scan(tmp_path, _SAME_MODULE_HELPER)
    _assert_quiet(
        result,
        "_validate_phone",
        "_get_api_key_from_request",
        "OrderView",
    )
