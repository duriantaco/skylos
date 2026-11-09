"""Fallback hooks require the actual framework provider, including aliases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analysis import external_bases
from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


@pytest.fixture(autouse=True)
def unavailable_dependencies(monkeypatch):
    """Exercise the fallback even if the test interpreter has a framework."""
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setattr(external_bases, "default_search_dirs", lambda roots=(): [])


def _scan(root: Path, source: str, extra_files: dict[str, str] | None = None):
    files = {"app.py": source}
    files.update(extra_files or {})
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")
    result = json.loads(
        analyze(str(root), conf=80, grep_verify=False, grep_cache=False)
    )
    return {item["full_name"] for item in result.get("unused_variables", [])}


@pytest.mark.parametrize(
    ("provider", "attributes"),
    [
        ("celery.backends.redis.RedisBackend", ("ResultConsumer",)),
        ("django.contrib.admin.SimpleListFilter", ("parameter_name", "title")),
        ("django.contrib.admin.filters.SimpleListFilter", ("parameter_name", "title")),
        ("storages.backends.s3.S3Storage", ("bucket_name", "location")),
        ("storages.backends.s3boto3.S3Boto3Storage", ("bucket_name", "location")),
    ],
)
def test_missing_framework_provider_keeps_only_documented_attributes_live(
    tmp_path, provider, attributes
):
    module, _, name = provider.rpartition(".")
    assignments = "".join(f"    {attr} = 'configured'\n" for attr in attributes)
    reported = _scan(
        tmp_path,
        f"from {module} import {name}\n\n"
        f"class Backend({name}):\n"
        f"{assignments}"
        "    orphan = 1\n\n"
        "ENTRY = Backend()\n",
    )
    for attr in attributes:
        assert f"app.Backend.{attr}" not in reported
    assert "app.Backend.orphan" in reported


@pytest.mark.parametrize(
    ("imports", "base"),
    [
        (
            "from celery.backends.redis import RedisBackend as FrameworkBase",
            "FrameworkBase",
        ),
        ("import celery.backends.redis as backend", "backend.RedisBackend"),
        ("from celery.backends import redis as backend", "backend.RedisBackend"),
        ("import celery.backends.redis", "celery.backends.redis.RedisBackend"),
    ],
)
def test_celery_provider_aliases_keep_the_hook_live(tmp_path, imports, base):
    reported = _scan(
        tmp_path,
        f"{imports}\n\n"
        f"class Backend({base}):\n"
        "    ResultConsumer = object\n"
        "    orphan = 1\n\n"
        "ENTRY = Backend()\n",
    )
    assert "app.Backend.ResultConsumer" not in reported
    assert "app.Backend.orphan" in reported


def test_framework_provider_through_project_intermediary_keeps_the_hook_live(tmp_path):
    reported = _scan(
        tmp_path,
        "from project_base import ProjectBackend as Intermediate\n\n"
        "class Backend(Intermediate):\n"
        "    ResultConsumer = object\n"
        "    orphan = 1\n\n"
        "ENTRY = Backend()\n",
        {
            "project_base.py": (
                "from celery.backends.redis import RedisBackend as FrameworkBase\n\n"
                "class ProjectBackend(FrameworkBase):\n"
                "    pass\n"
            )
        },
    )
    assert "app.Backend.ResultConsumer" not in reported
    assert "app.Backend.orphan" in reported


@pytest.mark.parametrize(
    ("name", "attribute"),
    [
        ("RedisBackend", "ResultConsumer"),
        ("SimpleListFilter", "parameter_name"),
        ("BaseStorage", "bucket_name"),
        ("S3Storage", "bucket_name"),
        ("S3Boto3Storage", "bucket_name"),
    ],
)
def test_local_lookalike_base_does_not_hide_dead_attributes(tmp_path, name, attribute):
    reported = _scan(
        tmp_path,
        f"class {name}:\n"
        "    pass\n\n"
        f"class Backend({name}):\n"
        f"    {attribute} = 'unused'\n"
        "    orphan = 1\n\n"
        "ENTRY = Backend()\n",
    )
    assert f"app.Backend.{attribute}" in reported
    assert "app.Backend.orphan" in reported


@pytest.mark.parametrize(
    "binding",
    [
        "class RedisBackend:\n    pass\n",
        "class LocalBase:\n    pass\n\nRedisBackend = LocalBase\n",
    ],
)
def test_shadowed_framework_import_does_not_hide_dead_attributes(tmp_path, binding):
    reported = _scan(
        tmp_path,
        "from celery.backends.redis import RedisBackend\n\n"
        f"{binding}\n"
        "class Backend(RedisBackend):\n"
        "    ResultConsumer = object\n"
        "    orphan = 1\n\n"
        "ENTRY = Backend()\n",
    )
    assert "app.Backend.ResultConsumer" in reported
    assert "app.Backend.orphan" in reported


def test_project_module_named_like_the_framework_does_not_gain_hooks(tmp_path):
    reported = _scan(
        tmp_path,
        "from celery.backends.redis import RedisBackend\n\n"
        "class Backend(RedisBackend):\n"
        "    ResultConsumer = object\n"
        "    orphan = 1\n\n"
        "ENTRY = Backend()\n",
        {
            "celery/__init__.py": "",
            "celery/backends/__init__.py": "",
            "celery/backends/redis.py": "class RedisBackend:\n    pass\n",
        },
    )
    assert "app.Backend.ResultConsumer" in reported
    assert "app.Backend.orphan" in reported


def test_generic_storages_base_does_not_consume_s3_settings(tmp_path, monkeypatch):
    site = tmp_path / "dependencies" / "site-packages"
    (site / "storages").mkdir(parents=True)
    assert write_text_no_symlink(site / "storages/__init__.py", "", encoding="utf-8")
    assert write_text_no_symlink(
        site / "storages/base.py",
        "class BaseStorage:\n"
        "    def __init__(self):\n"
        "        for name, value in self.get_default_settings().items():\n"
        "            if not hasattr(self, name):\n"
        "                setattr(self, name, value)\n\n"
        "    def get_default_settings(self):\n"
        "        return {}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(external_bases, "default_search_dirs", lambda roots=(): [site])
    reported = _scan(
        tmp_path / "project",
        "from storages.base import BaseStorage\n\n"
        "class Backend(BaseStorage):\n"
        "    bucket_name = 'unused'\n"
        "    orphan = 1\n\n"
        "ENTRY = Backend()\n",
    )
    assert "app.Backend.bucket_name" in reported
    assert "app.Backend.orphan" in reported
