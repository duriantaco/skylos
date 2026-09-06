import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze


def _sources(root: Path, sources: dict[str, str]):
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write(source)


@pytest.mark.parametrize(
    ("extra_sources", "package", "reported"),
    [
        pytest.param(
            {"settings.py": "from django.apps import AppConfig\n"},
            True,
            False,
            id="django-package-admin-stub",
        ),
        pytest.param({}, True, True, id="non-django-package"),
        pytest.param(
            {"settings.py": "from django.apps import AppConfig\n"},
            False,
            True,
            id="standalone-admin-file",
        ),
        pytest.param(
            {
                "shop/django.py": "value = 1\n",
                "shop/config.py": "from .django import value\n",
            },
            True,
            True,
            id="relative-local-django-is-not-the-framework",
        ),
        pytest.param(
            {
                "django.py": "value = 1\n",
                "settings.py": "from django.apps import AppConfig\n",
            },
            True,
            True,
            id="top-level-django-shadow",
        ),
        pytest.param(
            {
                "src/django/__init__.py": "",
                "settings.py": "from django.apps import AppConfig\n",
            },
            True,
            True,
            id="source-root-django-shadow",
        ),
    ],
)
def test_admin_stub_requires_django_package_context(
    tmp_path, extra_sources, package, reported
):
    sources = {
        **extra_sources,
        "shop/admin.py": "# Register your models here.\n",
        "shop/placeholder.py": "# An ordinary empty file.\n",
    }
    if package:
        sources["shop/__init__.py"] = ""
    _sources(tmp_path, sources)

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    empty_files = {
        finding["file"]
        for finding in result.get("unused_files", [])
        if finding.get("rule_id") == "SKY-E002"
    }

    assert (str(tmp_path / "shop/admin.py") in empty_files) is reported
    assert str(tmp_path / "shop/placeholder.py") in empty_files


def test_admin_filename_does_not_rescue_unused_functions(tmp_path):
    _sources(
        tmp_path,
        {
            "settings.py": "from django.apps import AppConfig\n",
            "shop/__init__.py": "",
            "shop/admin.py": "def unused_helper():\n    return 1\n",
        },
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

    assert any(
        finding["name"] == "unused_helper"
        for finding in result.get("unused_functions", [])
    )
