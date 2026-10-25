"""Named settings imports expose selected bindings in their effective roles."""

import json

import pytest

from skylos.analyzer import analyze
from test.web_framework_fixtures import _scan, _unused


PROTOCOLS = """
class Backend:
    def get_user(self, user_id): return user_id
class Storage:
    def save(self, name, content): return name
class Factory:
    def filter(self, record): return True
class Unrelated:
    pass
def context_processor(request): return {}
"""
SATELLITE = """
TIMEOUT = 5
AUTHENTICATION_BACKENDS = ['app.protocols.Backend']
STORAGES = {'default': {'BACKEND': 'app.protocols.Storage'}}
LOGGING = {'version': 1, 'filters': {'extra': {'()': 'app.protocols.Factory'}}}
EXTRA_PATH = 'app.protocols.Unrelated'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates',
              'OPTIONS': {'context_processors': ['app.protocols.context_processor']}}]
"""


def _sources(imports, satellite=SATELLITE, extra=None):
    sources = {
        "app/__init__.py": "",
        "app/settings.py": "INSTALLED_APPS = ['app']\nSECRET_KEY = 'x'\n" + imports,
        "app/satellite.py": satellite,
        "app/protocols.py": PROTOCOLS,
    }
    sources.update(extra or {})
    return sources


def _roots(result, qualified_name):
    return [
        item
        for symbol in result["dead_code_evidence"]["symbols"]
        if symbol["qualified_name"] == qualified_name
        for item in symbol["evidence"]
        if item.get("kind") == "framework_root"
    ]


def _assert_unselected(result, *classes):
    assert not result.get("analysis_errors")
    for name in classes:
        assert "app.protocols." + name in _unused(result, "unused_classes")
    for name in ["Backend.get_user", "Storage.save", "Factory.filter"]:
        assert not _roots(result, "app.protocols." + name)


def test_importing_scalar_setting_does_not_activate_its_satellite(tmp_path):
    result = _scan(tmp_path, _sources("from app.satellite import TIMEOUT\n"))
    _assert_unselected(result, "Backend", "Storage", "Factory", "Unrelated")
    assert "app.protocols.context_processor" in _unused(result)


def test_reverse_named_reader_does_not_become_active_settings(tmp_path):
    result = _scan(
        tmp_path,
        _sources(
            "TIMEOUT = 5\n",
            extra={
                "app/settings_reader.py": "from app.settings import TIMEOUT\n"
                + SATELLITE,
            },
        ),
    )
    _assert_unselected(result, "Backend", "Storage", "Factory", "Unrelated")


@pytest.mark.parametrize(
    "setting,target,reason",
    [
        ("LOGGING", "Factory.filter", "django_web_logging_factory"),
        ("AUTHENTICATION_BACKENDS", "Backend.get_user", "django_web_auth_backend"),
        ("STORAGES", "Storage.save", "django_web_storage_backend"),
        ("TEMPLATES", "context_processor", "django_web_setting_reference"),
    ],
)
def test_only_named_setting_is_selected(tmp_path, setting, target, reason):
    result = _scan(tmp_path, _sources("from app.satellite import " + setting + "\n"))
    assert any(
        item["reason"] == reason and item["name"] == "app.protocols." + target
        for item in result["analysis_summary"]["dead_code_liveness"]["rescued"]
    )
    assert not _roots(result, "app.protocols.Unrelated")
    for name, role in [
        ("Backend.get_user", "AUTHENTICATION_BACKENDS"),
        ("Storage.save", "STORAGES"),
        ("Factory.filter", "LOGGING"),
    ]:
        if role != setting:
            assert not _roots(result, "app.protocols." + name)


@pytest.mark.parametrize(
    "role,target",
    [
        ("LOGGING", "Factory.filter"),
        ("AUTHENTICATION_BACKENDS", "Backend.get_user"),
        ("STORAGES", "Storage.save"),
    ],
)
def test_named_settings_aliases_and_reexports_keep_the_effective_role(
    tmp_path, role, target
):
    satellite = SATELLITE.replace(role + " =", "VALUE =")
    result = _scan(
        tmp_path,
        _sources(
            "from app.bridge import SELECTED as " + role + "\n",
            satellite=satellite,
            extra={"app/bridge.py": "from app.satellite import VALUE as SELECTED\n"},
        ),
    )
    assert _roots(result, "app.protocols." + target)
    assert not _roots(result, "app.protocols.Unrelated")


@pytest.mark.parametrize("replacement", ["LOGGING = {}\n", "del LOGGING\n"])
def test_overwritten_named_import_does_not_activate_its_old_value(
    tmp_path, replacement
):
    result = _scan(
        tmp_path, _sources("from app.satellite import LOGGING\n" + replacement)
    )
    _assert_unselected(result, "Backend", "Storage", "Factory", "Unrelated")


def test_final_named_import_replaces_old_local_setting(tmp_path):
    result = _scan(
        tmp_path,
        _sources(
            "LOGGING = {'filters': {'old': {'()': 'app.protocols.Unrelated'}}}\n"
            "from app.satellite import LOGGING\n"
        ),
    )
    assert _roots(result, "app.protocols.Factory.filter")
    assert not _roots(result, "app.protocols.Unrelated")


def test_literal_dead_named_import_has_no_setting_effect(tmp_path):
    result = _scan(
        tmp_path, _sources("if False:\n    from app.satellite import LOGGING\n")
    )
    _assert_unselected(result, "Backend", "Storage", "Factory", "Unrelated")


def test_possible_named_import_preserves_selected_setting(tmp_path):
    result = _scan(
        tmp_path, _sources("if enabled:\n    from app.satellite import LOGGING\n")
    )
    assert _roots(result, "app.protocols.Factory.filter")
    assert not _roots(result, "app.protocols.Storage.save")


@pytest.mark.parametrize("setting", ["AUTHENTICATION_BACKENDS", "STORAGES", "LOGGING"])
def test_imported_value_is_interpreted_in_its_settings_role(tmp_path, setting):
    result = _scan(
        tmp_path, _sources("from app.satellite import " + setting + " as UNUSED\n")
    )
    for name in ["Backend.get_user", "Storage.save", "Factory.filter"]:
        assert not _roots(result, "app.protocols." + name)


def test_imported_template_directories_retain_the_source_path_context(tmp_path):
    result = _scan(
        tmp_path,
        _sources(
            'from app.satellite import TEMPLATES\nROOT_URLCONF = "app.urls"\n',
            satellite="from pathlib import Path\n"
            'TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", '
            '"DIRS": [Path(__file__).parent / "pages"]}]\n',
            extra={
                "app/models.py": "from django.db import models\n"
                "class Record(models.Model):\n"
                '    def label(self): return "live"\n'
                '    def retired(self): return "dead"\n',
                "app/views.py": "from django.views.generic import DetailView\n"
                "from .models import Record\n"
                "class Page(DetailView):\n"
                '    model = Record\n    template_name = "record.html"\n',
                "app/urls.py": "from django.urls import path\n"
                "from .views import Page\n"
                'urlpatterns = [path("", Page.as_view())]\n',
                "app/pages/record.html": "{{ object.label }}",
            },
        ),
    )
    assert _roots(result, "app.models.Record.label")
    assert not _roots(result, "app.models.Record.retired")


@pytest.mark.parametrize(
    "setting,target", [("LOGGING", "Factory.filter"), ("STORAGES", "Storage.save")]
)
@pytest.mark.parametrize("scope", ["argument", "local", "global", "read-global"])
def test_called_setting_mutation_helper_uses_the_module_binding(
    tmp_path, setting, target, scope
):
    configured = "{'filters': {'extra': {'()': 'app.protocols.Factory'}}}"
    if setting == "STORAGES":
        configured = "{'default': {'BACKEND': 'app.protocols.Storage'}}"
    parameters = ""
    prefix = ""
    argument = ""
    if scope == "argument":
        parameters = setting
        argument = "{}"
    elif scope == "local":
        prefix = "    " + setting + " = {}\n"
    elif scope == "global":
        prefix = "    global " + setting + "\n"
    source = setting + " = {}\n"
    source += "def configure(" + parameters + "):\n" + prefix
    source += "    " + setting + ".update(" + configured + ")\n"
    source += "configure(" + argument + ")\n"
    result = _scan(tmp_path, _sources(source, satellite=""))
    assert bool(_roots(result, "app.protocols." + target)) == (
        scope in {"global", "read-global"}
    )


@pytest.mark.parametrize("grep_verify", [False, True])
def test_selected_import_precision_at_default_confidence(tmp_path, grep_verify):
    for name, source in _sources("from app.satellite import TIMEOUT\n").items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    result = json.loads(analyze(str(tmp_path), conf=80, grep_verify=grep_verify))
    _assert_unselected(result, "Backend", "Storage", "Factory", "Unrelated")
