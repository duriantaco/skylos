"""Framework class attributes read by base ``self.Attr`` / settings hooks.

When Celery / Django / django-storages are not installed in the scanner
environment, class-body hooks such as ``ResultConsumer`` must still stay
live. A deliberate unread ``orphan`` in the same class must stay reported.
"""

from __future__ import annotations

import json
from pathlib import Path

from skylos.analysis.external_bases import default_search_dirs
from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")


def _scan(root: Path, files: dict[str, str], *, conf: int = 80):
    _write(root, files)
    return json.loads(
        analyze(str(root), conf=conf, grep_verify=False, grep_cache=False)
    )


def _names(result, bucket: str) -> set[str]:
    names = set()
    for item in result.get(bucket) or []:
        names.add(item.get("name") or "")
        full = item.get("full_name") or ""
        if full:
            names.add(full)
            names.add(full.rsplit(".", 1)[-1])
    return names


def test_stub_base_reads_hook_keeps_attr_and_reports_orphan(tmp_path):
    result = _scan(
        tmp_path,
        {
            "base.py": """\
class FrameworkishBase:
    def __init__(self):
        self.hook = self.Hook()
""",
            "impl.py": "class Impl:\n    pass\n",
            "plugin.py": """\
from base import FrameworkishBase
from impl import Impl


class Plugin(FrameworkishBase):
    Hook = Impl
    orphan = 1


RESULT = Plugin()
""",
        },
    )
    unused = _names(result, "unused_variables")
    assert "Hook" not in unused
    assert "Plugin.Hook" not in unused
    assert "orphan" in unused


def test_unrelated_celery_name_keeps_result_consumer_reported(tmp_path):
    """An unavailable lookalike package does not establish a Celery hook."""
    result = _scan(
        tmp_path,
        {
            "backend.py": """\
from notinstalled_celery.backends.redis import RedisBackend


class _ClusterResultConsumer:
    def _reconnect_pubsub(self):
        return None


class RedisClusterBackend(RedisBackend):
    ResultConsumer = _ClusterResultConsumer
    orphan = 1


ENTRY = RedisClusterBackend
""",
        },
    )
    unused = _names(result, "unused_variables")
    assert "ResultConsumer" in unused
    assert "backend.RedisClusterBackend.ResultConsumer" in unused
    assert "orphan" in unused


def test_unrelated_django_name_keeps_filter_attributes_reported(tmp_path):
    result = _scan(
        tmp_path,
        {
            "filters.py": """\
from notinstalled_django.contrib.admin import SimpleListFilter


class StatusFilter(SimpleListFilter):
    title = "status"
    parameter_name = "status"
    orphan = 1

    def lookups(self, request, model_admin):
        return ()

    def queryset(self, request, queryset):
        return queryset
""",
        },
    )
    unused = _names(result, "unused_variables")
    assert "parameter_name" in unused
    assert "title" in unused
    assert "orphan" in unused


def test_unrelated_storages_name_keeps_bucket_name_reported(tmp_path):
    result = _scan(
        tmp_path,
        {
            "storage.py": """\
from notinstalled_storages.backends.s3boto3 import S3Boto3Storage


class CVStorage(S3Boto3Storage):
    bucket_name = "cv-bucket"
    orphan = 1
""",
        },
    )
    unused = _names(result, "unused_variables")
    assert "bucket_name" in unused
    assert "orphan" in unused


def test_project_venv_site_packages_are_external_search_dirs(tmp_path):
    root = tmp_path / "proj"
    site = root / ".venv" / "lib" / "python3.11" / "site-packages"
    _write(
        site,
        {
            "fakelib/__init__.py": "",
            "fakelib/core.py": (
                "class BaseRenderer:\n"
                "    NAME = 'base'\n\n"
                "    def render_token(self, token):\n"
                "        return token\n"
            ),
        },
    )
    _write(
        root,
        {
            "pyproject.toml": "[project]\nname = 'proj'\n",
            "app.py": (
                "from fakelib.core import BaseRenderer\n\n\n"
                "class DocsRenderer(BaseRenderer):\n"
                "    NAME = 'docs'\n"
                "    orphan = 1\n\n"
                "    def render_token(self, token):\n"
                "        return token\n\n\n"
                "RENDERER = DocsRenderer()\n"
            ),
        },
    )

    dirs = default_search_dirs([root])
    assert site.resolve() in dirs

    reported = {
        item["full_name"]
        for key in ("unused_functions", "unused_variables", "unused_classes")
        for item in (
            json.loads(
                analyze(str(root), conf=60, grep_verify=False, grep_cache=False)
            ).get(key)
            or []
        )
    }
    assert "app.DocsRenderer.NAME" not in reported
    assert "app.DocsRenderer.orphan" in reported


def test_vendored_site_packages_inside_scan_still_excluded(tmp_path):
    root = tmp_path / "proj"
    site = root / "vendored" / "site-packages"
    site.mkdir(parents=True)
    assert site.resolve() not in default_search_dirs([root])
