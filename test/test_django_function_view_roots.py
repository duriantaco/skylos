"""Only active, intact Django function URL callbacks provide execution roots."""

import json

import pytest

from skylos.analyzer import analyze
from test.test_provider_source_dispatch import PROVIDERS


SOURCES = {
    "manage.py": 'import os\nfrom django.core.management import execute_from_command_line\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")\nexecute_from_command_line([])\n',
    "settings.py": 'ROOT_URLCONF="urls"\nINSTALLED_APPS=[]\n',
    "urls.py": 'from django.urls import path\nfrom views import view\nurlpatterns = [path("items/", view)]\n',
    "views.py": "from pipeline import dispatch\ndef view(request):\n    return dispatch()\n",
    "providers.py": PROVIDERS,
    "pipeline.py": "from providers import get_client\nclass Pipeline:\n    def __init__(self, client):\n        self.client = client\n    def update(self):\n        return self.client.schedule_dates(2026)\ndef dispatch():\n    return Pipeline(get_client('ncaa')).update()\n",
}


def _scan(root, changes, confidence):
    for relative, source in {**SOURCES, **changes}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    result = json.loads(
        analyze(str(root), conf=confidence, grep_verify=False, grep_cache=False)
    )
    assert not result.get("analysis_errors")
    unused = {row["full_name"] for row in result["unused_functions"]}
    symbols = {
        row["qualified_name"]: row for row in result["dead_code_evidence"]["symbols"]
    }
    return unused, symbols


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize(
    "kind", ["path", "re_path", "include", "readonly_metadata", "keyword_arguments"]
)
def test_active_native_function_callback_consumes_exact_provider(
    tmp_path, kind, confidence
):
    changes = {}
    if kind == "re_path":
        changes["urls.py"] = (
            SOURCES["urls.py"]
            .replace("import path", "import re_path")
            .replace('path("items/"', 're_path("^items/$"')
        )
    elif kind == "include":
        changes["urls.py"] = (
            'from django.urls import path, include\nurlpatterns = [path("", include("app.urls"))]\n'
        )
        changes["app/__init__.py"] = ""
        changes["app/urls.py"] = SOURCES["urls.py"]
    elif kind == "readonly_metadata":
        changes["views.py"] = SOURCES["views.py"] + "label = view.__name__\n"
    elif kind == "keyword_arguments":
        changes["urls.py"] = SOURCES["urls.py"].replace(
            'path("items/", view)',
            'path(route="items/", view=view, kwargs={}, name="items")',
        )
    unused, symbols = _scan(tmp_path, changes, confidence)
    assert "providers.NcaaClient.schedule_dates" not in unused
    assert symbols["providers.NcaaClient.schedule_dates"]["classification"] == "alive"
    assert "framework_root" in {
        row["kind"] for row in symbols["views.view"]["evidence"]
    }
    assert "providers.UnrelatedClient.schedule_dates" in unused


NEGATIVES = {
    "unrouted": {"urls.py": "urlpatterns=[]\n"},
    "unselected": {
        "settings.py": 'ROOT_URLCONF="unused_urls"\nINSTALLED_APPS=[]\n',
        "unused_urls.py": "urlpatterns=[]\n",
    },
    "replaced_patterns": {"urls.py": SOURCES["urls.py"] + "urlpatterns=[]\n"},
    "unused_table": {
        "urls.py": SOURCES["urls.py"].replace("urlpatterns =", "unused =")
        + "urlpatterns=[]\n"
    },
    "clear_patterns": {"urls.py": SOURCES["urls.py"] + "urlpatterns.clear()\n"},
    "opaque_patterns": {"urls.py": SOURCES["urls.py"] + "opaque(urlpatterns)\n"},
    "replace_callback": {
        "urls.py": SOURCES["urls.py"]
        + "urlpatterns[0].callback = lambda request: None\n"
    },
    "replace_code": {
        "views.py": SOURCES["views.py"]
        + "def replacement(request):\n    return None\nview.__code__ = replacement.__code__\n"
    },
    "replace_code_alias": {
        "views.py": SOURCES["views.py"]
        + "def replacement(request):\n    return None\nselected = view\nselected.__code__ = replacement.__code__\n"
    },
    "opaque_view": {"views.py": SOURCES["views.py"] + "opaque(view)\n"},
    "module_failure": {
        "views.py": SOURCES["views.py"] + 'raise RuntimeError("not ready")\n'
    },
    "unknown_decorator": {
        "views.py": SOURCES["views.py"].replace("def view", "@unknown\ndef view")
    },
    "async_view": {
        "views.py": SOURCES["views.py"].replace("def view", "async def view")
    },
    "generator_view": {
        "views.py": SOURCES["views.py"].replace("return dispatch()", "yield dispatch()")
    },
}


@pytest.mark.parametrize("confidence", [0, 80])
@pytest.mark.parametrize("kind", NEGATIVES)
def test_unproved_function_callbacks_do_not_create_provider_roots(
    tmp_path, kind, confidence
):
    unused, symbols = _scan(tmp_path, NEGATIVES[kind], confidence)
    assert "providers.NcaaClient.schedule_dates" in unused
    assert (
        symbols["providers.NcaaClient.schedule_dates"]["classification"]
        == "likely_dead"
    )
    assert "framework_root" not in {
        row["kind"] for row in symbols["views.view"]["evidence"]
    }


@pytest.mark.parametrize(
    "call",
    [
        'path("items/", view, route="other/")',
        'path("items/", view, view=view)',
        'path("items/", view, unexpected=True)',
        'path("items/", view, None, None, None)',
        'path("items/", view, kwargs="wrong")',
        'path("items/", view, kwargs=[])',
        'path("items/", view, kwargs={}, name="one", **{"name":"two"})',
        'path("", include("app.urls", arg="app.urls"))',
        'path("", include("app.urls", unexpected=True))',
        'path("", include("app.urls", None, None))',
        'path("", include("app.urls", namespace="missing_app_name"))',
    ],
)
def test_invalid_native_registration_cannot_root_callback_body(tmp_path, call):
    changes = {
        "urls.py": "from django.urls import path, include\nfrom views import view\nurlpatterns=["
        + call
        + "]\n",
        "app/__init__.py": "",
        "app/urls.py": SOURCES["urls.py"],
    }
    unused, symbols = _scan(tmp_path, changes, 80)
    assert "providers.NcaaClient.schedule_dates" in unused
    assert (
        symbols["providers.NcaaClient.schedule_dates"]["classification"]
        == "likely_dead"
    )


@pytest.mark.parametrize("selector", ["default", "literal_kwargs"])
def test_unmodeled_view_binding_does_not_consume_an_unselected_provider(
    tmp_path, selector
):
    view = "from pipeline import dispatch\ndef view(request, slug='ncaa'):\n    return dispatch(slug)\n"
    urls = SOURCES["urls.py"]
    if selector == "literal_kwargs":
        view = view.replace("slug='ncaa'", "slug")
        urls = urls.replace(
            'path("items/", view)', 'path("items/", view, {"slug":"ncaa"})'
        )
    pipeline = (
        SOURCES["pipeline.py"]
        .replace("def dispatch():", "def dispatch(slug):")
        .replace("get_client('ncaa')", "get_client(slug)")
    )
    unused, _ = _scan(
        tmp_path, {"views.py": view, "urls.py": urls, "pipeline.py": pipeline}, 80
    )
    assert "providers.NjcaaClient.schedule_dates" in unused
