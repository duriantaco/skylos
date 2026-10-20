"""Overrides of external base classes and documented framework hooks.

External bases are read from source (stdlib, or a site-packages directory on
``sys.path`` outside the scan root), never imported. Every case keeps a
genuinely dead member next to the override and requires it to stay
reported."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from skylos.analysis.external_bases import ExternalClassIndex, default_search_dirs
from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")


def _project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "proj"
    _write(root, {"pyproject.toml": "[project]\nname = 'proj'\n", **files})
    return root


def _reported(root: Path) -> set[str]:
    result = json.loads(analyze(str(root), conf=60, grep_cache=False))
    return {
        item["full_name"]
        for key in ("unused_functions", "unused_variables", "unused_classes")
        for item in result.get(key) or []
    }


def test_stdlib_overrides_through_project_bases(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/base.py": (
                "import ast\n"
                "import asyncio\n\n\n"
                "class BaseVisitor(ast.NodeVisitor):\n"
                "    pass\n\n\n"
                "class BaseProtocol(asyncio.Protocol):\n"
                "    pass\n\n\n"
                "class HttpProtocol(BaseProtocol):\n"
                "    pass\n"
            ),
            "app/impl.py": (
                "import ast\n"
                "import ctypes\n"
                "from app.base import BaseVisitor, HttpProtocol\n\n\n"
                "class Visitor(BaseVisitor):\n"
                "    def generic_visit(self, node):\n"
                "        return None\n\n"
                "    def stale_visitor_helper(self):\n"
                "        return 1\n\n\n"
                "class WebSocketProtocol(HttpProtocol):\n"
                "    def eof_received(self):\n"
                "        return None\n\n"
                "    def stale_protocol_helper(self):\n"
                "        return 1\n\n\n"
                "class CursorInfo(ctypes.Structure):\n"
                "    _fields_ = [('size', ctypes.c_int)]\n"
                "    stale_layout_note = 1\n\n\n"
                "def main():\n"
                "    Visitor().visit(ast.parse('x'))\n"
                "    return WebSocketProtocol(), CursorInfo()\n"
            ),
        },
    )
    reported = _reported(root)

    assert "app.impl.Visitor.generic_visit" not in reported
    assert "app.impl.WebSocketProtocol.eof_received" not in reported
    assert "app.impl.CursorInfo._fields_" not in reported
    assert "app.impl.Visitor.stale_visitor_helper" in reported
    assert "app.impl.WebSocketProtocol.stale_protocol_helper" in reported
    assert "app.impl.CursorInfo.stale_layout_note" in reported


_FAKELIB = {
    "fakelib/__init__.py": "from .renderers import HTMLRenderer\n",
    "fakelib/core.py": (
        "class BaseRenderer:\n"
        "    NAME = 'base'\n\n"
        "    def render_token(self, token):\n"
        "        return getattr(self, token['type'])(token)\n"
    ),
    "fakelib/renderers.py": (
        "from . import core\n"
        "from .compat import with_metaclass\n\n\n"
        "class Meta(type):\n"
        "    pass\n\n\n"
        "class HTMLRenderer(with_metaclass(Meta, core.BaseRenderer)):\n"
        "    def block_code(self, code):\n"
        "        return code\n"
    ),
    "fakelib/compat.py": (
        "def with_metaclass(meta, *bases):\n    return meta('tmp', bases, {})\n"
    ),
}

_RENDERER_APP = {
    "docs/__init__.py": "",
    "docs/markdown.py": (
        "import fakelib\n\n\n"
        "class DocsRenderer(fakelib.HTMLRenderer):\n"
        "    NAME = 'docs'\n"
        "    stale_renderer_flag = True\n\n"
        "    def block_code(self, code):\n"
        "        return code\n\n"
        "    def render_token(self, token):\n"
        "        return token\n\n"
        "    def stale_renderer_helper(self):\n"
        "        return 1\n\n\n"
        "RENDERER = DocsRenderer()\n"
    ),
}


def test_third_party_overrides_read_from_site_packages(tmp_path, monkeypatch):
    site = tmp_path / "env" / "site-packages"
    _write(site, _FAKELIB)
    monkeypatch.syspath_prepend(str(site))
    root = _project(tmp_path, _RENDERER_APP)

    reported = _reported(root)

    assert "docs.markdown.DocsRenderer.block_code" not in reported
    assert "docs.markdown.DocsRenderer.render_token" not in reported
    assert "docs.markdown.DocsRenderer.NAME" not in reported
    assert "docs.markdown.DocsRenderer.stale_renderer_helper" in reported
    assert "docs.markdown.DocsRenderer.stale_renderer_flag" in reported
    # Read from source, never imported.
    assert "fakelib" not in sys.modules


def test_unresolvable_external_base_keeps_reporting(tmp_path):
    root = _project(tmp_path, _RENDERER_APP)

    reported = _reported(root)

    assert "docs.markdown.DocsRenderer.block_code" in reported
    assert "docs.markdown.DocsRenderer.stale_renderer_helper" in reported


def test_site_packages_inside_the_scan_root_is_not_external(tmp_path, monkeypatch):
    root = _project(tmp_path, _RENDERER_APP)
    site = root / "vendored" / "site-packages"
    _write(site, _FAKELIB)
    monkeypatch.syspath_prepend(str(site))

    assert site.resolve() not in default_search_dirs([root])
    index = ExternalClassIndex(default_search_dirs([root]))
    assert index.defining_class("fakelib.HTMLRenderer", "block_code") is None


def test_index_follows_reexports_aliases_and_stops_on_cycles(tmp_path):
    site = tmp_path / "site-packages"
    _write(
        site,
        {
            **_FAKELIB,
            "cyclic/__init__.py": "from .a import Loop\n",
            "cyclic/a.py": "from .b import Loop\n",
            "cyclic/b.py": "from .a import Loop\n",
            "aliased.py": (
                "from fakelib.core import BaseRenderer as _Base\nRenderer = _Base\n"
            ),
        },
    )
    index = ExternalClassIndex([site])

    assert index.defining_class("fakelib.HTMLRenderer", "block_code") == (
        "fakelib.renderers.HTMLRenderer"
    )
    assert index.defining_class("fakelib.HTMLRenderer", "render_token") == (
        "fakelib.core.BaseRenderer"
    )
    assert index.defining_class("aliased.Renderer", "NAME") == (
        "fakelib.core.BaseRenderer"
    )
    assert index.defining_class("fakelib.HTMLRenderer", "missing") is None
    assert index.mro_members("cyclic.Loop") is None
    assert index.mro_members("not_installed.Thing") is None
    assert "fakelib" not in sys.modules and "aliased" not in sys.modules


def test_traitlets_handlers_and_dynamic_defaults(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/base.py": (
                "from traitlets.config import LoggingConfigurable\n\n\n"
                "class Configurable(LoggingConfigurable):\n"
                "    pass\n"
            ),
            "app/manager.py": (
                "import traitlets\n"
                "from traitlets import Unicode, default, validate\n"
                "from app.base import Configurable\n\n\n"
                "class Manager(Configurable):\n"
                "    root_dir = Unicode()\n\n"
                "    @default('root_dir')\n"
                "    def _default_root_dir(self):\n"
                "        return '/'\n\n"
                "    @validate('root_dir')\n"
                "    def _validate_root_dir(self, proposal):\n"
                "        return proposal['value']\n\n"
                "    @traitlets.observe('root_dir')\n"
                "    def _on_root_dir(self, change):\n"
                "        return None\n\n"
                "    def _root_dir_default(self):\n"
                "        return '/'\n\n"
                "    def _undeclared_default(self):\n"
                "        return None\n\n"
                "    def stale_manager_helper(self):\n"
                "        return 1\n\n\n"
                "MANAGER = Manager()\n"
            ),
            "app/local.py": (
                "def default(name):\n"
                "    return lambda fn: fn\n\n\n"
                "class Plain:\n"
                "    @default('x')\n"
                "    def _local_default_x(self):\n"
                "        return 1\n\n\n"
                "PLAIN = Plain()\n"
            ),
        },
    )
    reported = _reported(root)

    for hook in (
        "_default_root_dir",
        "_validate_root_dir",
        "_on_root_dir",
        "_root_dir_default",
    ):
        assert f"app.manager.Manager.{hook}" not in reported
    assert "app.manager.Manager._undeclared_default" in reported
    assert "app.manager.Manager.stale_manager_helper" in reported
    assert "app.local.Plain._local_default_x" in reported


def test_drf_field_hooks_through_project_serializers(tmp_path):
    root = _project(
        tmp_path,
        {
            "api/__init__.py": "",
            "api/base.py": (
                "from rest_framework import serializers\n\n\n"
                "class OwnedObjectSerializer(serializers.ModelSerializer):\n"
                "    pass\n"
            ),
            "api/tags.py": (
                "from api.base import OwnedObjectSerializer\n"
                "from rest_framework import serializers\n\n\n"
                "class TagSerializer(OwnedObjectSerializer):\n"
                "    def validate_color(self, value):\n"
                "        return value\n\n"
                "    def stale_tag_helper(self):\n"
                "        return 1\n\n\n"
                "class AmountField(serializers.Field):\n"
                "    default_error_messages = {'invalid': 'bad'}\n"
                "    stale_amount_table = {}\n\n\n"
                "class NotASerializer:\n"
                "    def validate_color(self, value):\n"
                "        return value\n\n\n"
                "USED = (TagSerializer, AmountField, NotASerializer)\n"
            ),
            "api/views.py": (
                "from rest_framework.authtoken.views import ObtainAuthToken\n"
                "from rest_framework.viewsets import ModelViewSet\n\n\n"
                "class TokenView(ObtainAuthToken):\n"
                "    throttle_scope = 'login'\n\n\n"
                "class BundleViewSet(ModelViewSet):\n"
                "    http_method_names = ['get', 'post']\n\n\n"
                "USED = (TokenView, BundleViewSet)\n"
            ),
        },
    )
    reported = _reported(root)

    assert "api.tags.TagSerializer.validate_color" not in reported
    assert "api.tags.AmountField.default_error_messages" not in reported
    assert "api.views.TokenView.throttle_scope" not in reported
    assert "api.views.BundleViewSet.http_method_names" not in reported
    assert "api.tags.TagSerializer.stale_tag_helper" in reported
    assert "api.tags.AmountField.stale_amount_table" in reported
    assert "api.tags.NotASerializer.validate_color" in reported


def test_django_admin_options_on_third_party_model_admins(tmp_path):
    root = _project(
        tmp_path,
        {
            "mail/__init__.py": "",
            "mail/admin.py": (
                "from django.contrib import admin\n"
                "from guardian.admin import GuardedModelAdmin\n\n\n"
                "class BaseAdmin(GuardedModelAdmin):\n"
                "    pass\n\n\n"
                "class MailRuleAdmin(BaseAdmin):\n"
                "    radio_fields = {'action': admin.VERTICAL}\n"
                "    sortable_by = []\n"
                "    date_hierarchy = 'created'\n"
                "    stale_admin_note = 'x'\n\n\n"
                "admin.site.register(object, MailRuleAdmin)\n"
            ),
        },
    )
    reported = _reported(root)

    for option in ("radio_fields", "sortable_by", "date_hierarchy"):
        assert f"mail.admin.MailRuleAdmin.{option}" not in reported
    assert "mail.admin.MailRuleAdmin.stale_admin_note" in reported


@pytest.mark.parametrize("name", ["get", "keys"])
def test_builtin_base_members_count_as_overrides(tmp_path, name):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/store.py": (
                "class Store(dict):\n"
                f"    def {name}(self, *args):\n"
                "        return None\n\n"
                "    def stale_store_helper(self):\n"
                "        return 1\n\n\n"
                "STORE = Store()\n"
            ),
        },
    )
    reported = _reported(root)

    assert f"app.store.Store.{name}" not in reported
    assert "app.store.Store.stale_store_helper" in reported
