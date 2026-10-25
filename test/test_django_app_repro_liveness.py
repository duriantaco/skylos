"""Literal Django-app repros from daveisfera/skylos-repro (issue #1056).

Fixtures mirror messy production layouts, not textbook Django. Scan at
confidence 80 — the same threshold as the repro runner.
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


# --- 04: local register_converter wrapper via django_urls stub -----------------

_CONVERTER = {
    "04_django_url_converter.py": '''\
"""Django path converter protocol — regex is read by register_converter."""

from enum import Enum


class PerformanceDataType(str, Enum):
    GAME = "mg"
    EVENT = "te"


class PerformanceDataKey:
    def __init__(self, type_: PerformanceDataType, id_: int) -> None:
        self.type = type_
        self.id = id_

    def __str__(self):
        return f"{self.type.value}_{self.id}"


class PerformanceDataKeyDjango:
    # register_converter dispatches to regex/to_python/to_url reflectively.
    regex = "({})_[0-9]+".format("|".join(x.value for x in PerformanceDataType))

    @staticmethod
    def to_python(value: str) -> PerformanceDataKey:
        type_, id_ = value.split("_")
        return PerformanceDataKey(PerformanceDataType(type_), int(id_))

    @staticmethod
    def to_url(value: PerformanceDataKey) -> str:
        return str(value)


def register_converter():
    # Stand-in for django.urls.register_converter(PerformanceDataKeyDjango, "perfkey")
    from django_urls import register_converter as django_register_converter

    django_register_converter(PerformanceDataKeyDjango, "perfkey")
''',
    "django_urls.py": '''\
"""Minimal stand-in for django.urls.register_converter introspection."""


def register_converter(converter, name: str) -> None:
    _ = name
    _ = converter.regex
    converter.to_python("mg_1")
    converter.to_url(converter.to_python("mg_1"))
''',
}


def test_repro_04_uncalled_register_converter_wrapper_is_unused(tmp_path):
    result = _scan(tmp_path, _CONVERTER)
    _assert_reported(result, "04_django_url_converter.register_converter")


def test_repro_04_called_register_converter_wrapper_is_live(tmp_path):
    sources = dict(_CONVERTER)
    sources["04_django_url_converter.py"] += "\nregister_converter()\n"
    result = _scan(tmp_path, sources)
    _assert_quiet(result, "register_converter")


# --- 07: {% static %} loaded ES export -----------------------------------------

_TEMPLATE_STATIC_JS = {
    "static/widget.js": 'export function greet() {\n  return "ok";\n}\n',
    "templates/page.html": """\
{% load static %}
<!doctype html>
<html>
  <body>
    <script src="{% static 'widget.js' %}"></script>
  </body>
</html>
""",
}


def test_repro_07_unconsumed_static_script_export_is_unused(tmp_path):
    result = _scan(tmp_path, _TEMPLATE_STATIC_JS)
    _assert_reported(result, "greet")
    assert not result.get("unused_files")


# --- 11: autoreload.run_with_reloader helper ------------------------------------

_MGMT_COMMAND = {
    "mgmt_command/__init__.py": "",
    "mgmt_command/management/__init__.py": "",
    "mgmt_command/management/commands/__init__.py": "",
    "mgmt_command/management/commands/hello.py": '''\
"""Management command helper passed to Django autoreload (not called directly)."""

from django.core.management.base import BaseCommand
from django.utils import autoreload


def _restart_worker(name, queue):
    # Live: passed to autoreload.run_with_reloader (not called directly).
    print(f"restart {name} on {queue}")


class Command(BaseCommand):
    help = "Restart a worker on code changes"

    def add_arguments(self, parser):
        parser.add_argument("-Q", "--queue", required=True)
        parser.add_argument("-n", "--name", required=True)

    def handle(self, *args, **options):
        autoreload.run_with_reloader(
            _restart_worker, options["name"], options["queue"]
        )
''',
}


def test_repro_11_reloader_helper_is_live(tmp_path):
    result = _scan(tmp_path, _MGMT_COMMAND)
    _assert_quiet(result, "_restart_worker")


# --- 12: duck-typed AUTHENTICATION_BACKENDS ------------------------------------

_AUTH_BACKEND = {
    "auth_backend/__init__.py": "",
    "auth_backend/urls.py": "urlpatterns = []\n",
    "auth_backend/backends.py": '''\
"""Duck-typed auth backend — mirrors MobileTokenBackend (no ModelBackend/BaseBackend)."""


class MobileTokenBackend:
    """Wired only via AUTHENTICATION_BACKENDS; Django calls authenticate/get_user."""

    def authenticate(self, request, user_id=None, token=None):
        if not user_id or not token:
            return None
        return self.get_user(user_id)

    def get_user(self, user_id):
        return {"id": user_id}
''',
    "auth_backend/settings.py": '''\
"""Settings wiring a duck-typed auth backend by dotted path."""

INSTALLED_APPS = ["auth_backend"]
SECRET_KEY = "x"
ROOT_URLCONF = "auth_backend.urls"

AUTHENTICATION_BACKENDS = (
    "auth_backend.backends.MobileTokenBackend",
)
''',
}


def test_repro_12_auth_backend_hooks_are_live(tmp_path):
    result = _scan(tmp_path, _AUTH_BACKEND)
    _assert_quiet(
        result,
        "MobileTokenBackend.authenticate",
        "MobileTokenBackend.get_user",
        "authenticate",
        "get_user",
    )


# --- 13: plain middleware + STORAGES MediaStorage.save -------------------------

_SETTINGS_WIRED = {
    "settings_wired/__init__.py": "",
    "settings_wired/urls.py": "urlpatterns = []\n",
    "settings_wired/middleware.py": '''\
"""Plain middleware + in-file helper — mirrors pitchaware.route.RouteMiddleware."""


def _matched_route(request) -> str | None:
    path = getattr(request, "path_info", None) or getattr(request, "path", "")
    if not path:
        return None
    return path.rstrip("/") or "/"


class RouteMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if route := _matched_route(request):
            request.META = getattr(request, "META", {})
            request.META["app.route"] = route
        return response
''',
    "settings_wired/storage.py": '''\
"""Storage backend referenced only via STORAGES BACKEND string."""


class MediaStorage:
    def save(self, name, content, max_length=None):
        return name
''',
    "settings_wired/settings.py": '''\
"""Recognizable settings with plain middleware (no MiddlewareMixin) and STORAGES."""

INSTALLED_APPS = ["settings_wired"]
SECRET_KEY = "x"
ROOT_URLCONF = "settings_wired.urls"

MIDDLEWARE = [
    "settings_wired.middleware.RouteMiddleware",
]

STORAGES = {
    "default": {
        "BACKEND": "settings_wired.storage.MediaStorage",
    },
}
''',
}


def test_repro_13_middleware_and_storage_save_are_live(tmp_path):
    result = _scan(tmp_path, _SETTINGS_WIRED)
    _assert_quiet(
        result,
        "RouteMiddleware",
        "_matched_route",
        "MediaStorage",
        "MediaStorage.save",
    )


# --- 14: unittest.TestCase in package tests.py ---------------------------------

_TEST_MODULE = {
    "test_module/__init__.py": "",
    "test_module/tests.py": '''\
"""Test module — unittest discovers TestCase subclasses by convention."""

import unittest


def _expected_label() -> str:
    return "ready"


class DemoAPITests(unittest.TestCase):
    def test_label(self):
        self.assertEqual(_expected_label(), "ready")


class UnusedHelperTests:
    """Not a TestCase — may still be unused noise; keep out of discovery contract."""

    def check(self):
        return False
''',
}


def test_repro_14_unittest_testcase_is_live_helper_is_not(tmp_path):
    result = _scan(tmp_path, _TEST_MODULE)
    _assert_quiet(result, "DemoAPITests")
    _assert_reported(result, "UnusedHelperTests")


# --- 15: template-only model methods -------------------------------------------

_MODEL_TEMPLATE = {
    "model_template/__init__.py": "",
    "model_template/urls.py": "urlpatterns = []\n",
    "model_template/models.py": '''\
"""Model method used from a Django template only — no Python call sites / no CBV bridge."""

from django.db import models


class Record(models.Model):
    name = models.CharField(max_length=64)

    def get_display_name(self) -> str:
        return self.name.upper()

    def next_steps_message(self) -> str:
        # Another template-risk helper with no Python callers.
        return f"Review {self.name}"

    class Meta:
        app_label = "model_template"
''',
    "model_template/settings.py": '''\
"""Settings so TEMPLATES DIRS are in play for template member scanning."""

from pathlib import Path

INSTALLED_APPS = ["model_template"]
SECRET_KEY = "x"
ROOT_URLCONF = "model_template.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [str(Path(__file__).resolve().parent / "templates")],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": []},
    }
]
''',
    "model_template/templates/record.html": """\
{# Template-only uses — mirrors model-method-template-risk from unused-review. #}
<p>{{ record.get_display_name }}</p>
<p>{{ record.next_steps_message }}</p>
""",
}


def test_repro_15_template_only_model_methods_are_live(tmp_path):
    result = _scan(tmp_path, _MODEL_TEMPLATE)
    _assert_quiet(
        result,
        "get_display_name",
        "next_steps_message",
        "Record.get_display_name",
        "Record.next_steps_message",
    )


# --- 16: duck-typed provider contract method -----------------------------------

_PROVIDER_IFACE = {
    "provider_iface/__init__.py": "",
    "provider_iface/provider.py": '''\
"""Provider interface — duck-typed calls on base type.

schedule_dates is part of the live provider contract but never named at the
call site below.
"""


class Provider:
    def schedule_dates(self, season: int):
        raise NotImplementedError

    def scoreboard(self, day: str):
        raise NotImplementedError


class ConcreteProvider(Provider):
    def schedule_dates(self, season: int):
        return [f"{season}-01-01"]

    def scoreboard(self, day: str):
        return {"day": day, "games": []}


def fetch_day(provider: Provider, day: str):
    return provider.scoreboard(day)


# Entry keeps ConcreteProvider / scoreboard live; schedule_dates stays contract-only.
RESULT = fetch_day(ConcreteProvider(), "2026-10-23")
''',
}


def test_repro_16_provider_contract_method_is_live(tmp_path):
    result = _scan(tmp_path, _PROVIDER_IFACE)
    # Concrete implementer method must stay live; abstract base may still look unused.
    unused = _unused_names(result)
    assert "ConcreteProvider.schedule_dates" not in unused
    assert "provider_iface.provider.ConcreteProvider.schedule_dates" not in unused


# --- 18: satellite LOGGING "()" factories --------------------------------------

_LOGGING_INFRA = {
    "logging_infra/__init__.py": "",
    "logging_infra/urls.py": "urlpatterns = []\n",
    "logging_infra/settings.py": '''\
"""Main settings module — pulls LOGGING in from a satellite settings module."""

INSTALLED_APPS = ["logging_infra"]
SECRET_KEY = "x"
ROOT_URLCONF = "logging_infra.urls"

# These imports place the settings in this module's namespace for Django.
from logging_infra.settings_logging import LOGGING  # noqa: F401
''',
    "logging_infra/settings_logging.py": '''\
"""Satellite logging settings — LOGGING lives here, imported into settings.py.

Mirrors pitchaware/settings_logging.py: dotted \"()\" paths are not in the
module that itself defines INSTALLED_APPS.
"""

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "pa_extra": {
            "()": "logging_infra.json_formatter.ExtraAdder",
        },
    },
    "formatters": {
        "pa_json": {
            "()": "logging_infra.json_formatter.JSONFormatter",
        },
    },
    "handlers": {
        "pa_json": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "filters": ["pa_extra"],
            "formatter": "pa_json",
        },
    },
    "loggers": {
        "": {
            "level": "INFO",
            "handlers": ["pa_json"],
        },
    },
}
''',
    "logging_infra/json_formatter.py": '''\
"""Logging formatter — only named from settings_logging LOGGING["()"] strings."""

import json
import logging


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "level": record.levelname,
                "msg": record.getMessage(),
                "name": record.name,
            }
        )


class ExtraAdder:
    """Filter constructed via LOGGING filters \"()\" path."""

    def filter(self, record: logging.LogRecord) -> bool:
        return True
''',
}


def test_repro_18_satellite_logging_factories_are_live(tmp_path):
    result = _scan(tmp_path, _LOGGING_INFRA)
    _assert_quiet(result, "JSONFormatter", "ExtraAdder", "ExtraAdder.filter", "filter")


# --- 19: importlib processor registry ------------------------------------------

_PROCESSOR_PLUGIN = {
    "processor_plugin/__init__.py": "",
    "processor_plugin/plugins/__init__.py": "",
    "processor_plugin/loader.py": '''\
"""Convention loader: processor path chosen by name string only.

No module-level RESULT= that proves IntegrateSessions live — the class is only
reachable when a runtime name selects the dotted path.
"""

from importlib import import_module

# Registry of logical name → module path (class name is conventional).
PROCESSORS = {
    "integrate_sessions": "processor_plugin.plugins.integrate",
}


def load_processor(name: str):
    module_path = PROCESSORS[name]
    module = import_module(module_path)
    return getattr(module, "IntegrateSessions")


def run_named(name: str, session):
    cls = load_processor(name)
    return cls(session).process()
''',
    "processor_plugin/plugins/integrate.py": '''\
"""Bare processor class — product convention load, no static importers of the class."""


class IntegrateSessions:
    def __init__(self, session, debug=False, **kwargs):
        self.session = session
        self.debug = debug

    def process(self):
        return {"session": self.session, "integrated": True}
''',
}


def test_repro_19_importlib_processor_is_live(tmp_path):
    result = _scan(tmp_path, _PROCESSOR_PLUGIN)
    _assert_quiet(result, "IntegrateSessions")


# --- 20: ModelChoiceField.label_from_instance ----------------------------------

_DJANGO_FORM_FIELD = {
    "django_form_field/__init__.py": "",
    "django_form_field/fields.py": '''\
"""Custom ModelChoiceField — mirrors modernstat.msfacility.fields.FacilityChoiceField."""

from django import forms


class FacilityChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return getattr(obj, "scoreboard_name", str(obj))
''',
    "django_form_field/forms.py": '''\
"""Form that declares the custom field."""

from django import forms

from django_form_field.fields import FacilityChoiceField


class JoinFacilityForm(forms.Form):
    facility = FacilityChoiceField(queryset=None, required=True)
''',
}


def test_repro_20_label_from_instance_is_live(tmp_path):
    result = _scan(tmp_path, _DJANGO_FORM_FIELD)
    _assert_quiet(
        result,
        "label_from_instance",
        "FacilityChoiceField.label_from_instance",
    )
