"""Django and Wagtail names read by documented convention (round-2 T0-C).

Every case keeps a genuinely dead symbol next to the convention and requires
it to stay reported."""

from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text, encoding="utf-8")


def _reported(root: Path) -> set[str]:
    # Confidence 50 also lists unused parameters (hidden at the default 60),
    # so the signature rules are checked where parameters are visible.
    result = json.loads(analyze(str(root), conf=50, grep_cache=False))
    return {
        item["full_name"]
        for key in (
            "unused_functions",
            "unused_variables",
            "unused_parameters",
            "unused_classes",
        )
        for item in result.get(key) or []
    }


_WAGTAIL_APP = {
    "home/__init__.py": "",
    "home/models.py": (
        "from django.db import models\n"
        "from modelcluster.fields import ParentalKey\n"
        "from wagtail.models import Page, Orderable, Task\n"
        "from wagtail.fields import RichTextField\n"
        "from wagtail.admin.panels import FieldPanel\n"
        "from wagtail.contrib.settings.models import BaseSiteSetting, register_setting\n\n\n"
        "class HomePage(Page):\n"
        "    lead_text = RichTextField(blank=True)\n"
        "    hero = models.ForeignKey('wagtailimages.Image', null=True,"
        " on_delete=models.SET_NULL)\n"
        "    content_panels = Page.content_panels + [FieldPanel('lead_text')]\n"
        "    subpage_types = ['home.HomePage']\n"
        "    max_count = 1\n\n"
        "    def get_preview_template(self, request, mode_name):\n"
        "        return 'home.html'\n\n"
        "    def paginate(self, request, *args):\n"
        "        return request\n\n"
        "    class Meta:\n"
        "        verbose_name = 'home'\n\n\n"
        "class Slot(Orderable):\n"
        "    page = ParentalKey('home.HomePage', related_name='slots')\n\n\n"
        "class ReviewTask(Task):\n"
        "    task_state_class = None\n\n"
        "    def user_can_access_editor(self, obj, user):\n"
        "        return False\n\n\n"
        "@register_setting(icon='site')\n"
        "class SiteSettings(BaseSiteSetting):\n"
        "    footer = models.CharField(max_length=10)\n\n\n"
        "class NotAModel:\n"
        "    pass\n\n\n"
        "def stale_helper():\n"
        "    return 1\n"
    ),
    "home/blocks.py": (
        "from wagtail.blocks import CharBlock, ListBlock, StreamBlock, StructBlock\n\n\n"
        "class QuoteBlock(StructBlock):\n"
        "    text = CharBlock()\n\n"
        "    class Meta:\n"
        "        icon = 'openquote'\n"
        "        label_format = 'Quote: {text}'\n\n\n"
        "class BodyBlock(StreamBlock):\n"
        "    items = ListBlock(CharBlock())\n"
    ),
    "home/views.py": (
        "from wagtail.snippets.views.snippets import SnippetViewSet\n\n\n"
        "class PersonViewSet(SnippetViewSet):\n"
        "    list_display = ('name',)\n"
        "    sort_order_field = 'sort_order'\n"
        "    unrelated_option = 1\n"
    ),
}


def test_wagtail_page_fields_attributes_blocks_and_registries_are_live(tmp_path):
    _write(tmp_path, _WAGTAIL_APP)

    reported = _reported(tmp_path)

    for live in (
        "home.models.HomePage.lead_text",
        "home.models.HomePage.hero",
        "home.models.HomePage.content_panels",
        "home.models.HomePage.subpage_types",
        "home.models.HomePage.max_count",
        "home.models.HomePage.get_preview_template.mode_name",
        "home.models.HomePage.get_preview_template.request",
        "home.models.Meta.verbose_name",
        "home.models.Slot",
        "home.models.Slot.page",
        "home.models.ReviewTask",
        "home.models.ReviewTask.task_state_class",
        "home.models.ReviewTask.user_can_access_editor.obj",
        "home.models.SiteSettings",
        "home.blocks.Meta.label_format",
        "home.blocks.BodyBlock.items",
        "home.views.PersonViewSet.list_display",
        "home.views.PersonViewSet.sort_order_field",
    ):
        assert live not in reported, live
    # Dead controls: an undocumented attribute, an unused vararg of an own
    # method, a non-model class and an orphan function stay reported.
    assert "home.views.PersonViewSet.unrelated_option" in reported
    assert "home.models.HomePage.paginate.args" in reported
    assert "home.models.NotAModel" in reported
    assert "home.models.stale_helper" in reported


def test_django_signatures_and_format_files(tmp_path):
    _write(
        tmp_path,
        {
            "site/__init__.py": "",
            "site/locale/fr/formats.py": "DATE_FORMAT = 'j F Y'\n",
            "site/checks.py": (
                "from django.core.checks import register, Tags\n\n\n"
                "@register(Tags.security)\n"
                "def check_x(app_configs, **kwargs):\n"
                "    return []\n"
            ),
            "site/views.py": (
                "from django.views import View\n"
                "from django.contrib import admin\n"
                "from django import forms\n\n\n"
                "class Thing(View):\n"
                "    def get(self, request, *args, **kwargs):\n"
                "        return None\n\n"
                "    def helper(self, unused_arg):\n"
                "        return None\n\n\n"
                "class ThingAdmin(admin.ModelAdmin):\n"
                "    def get_list_select_related(self, request):\n"
                "        return ()\n\n\n"
                "class PickerWidget(forms.Widget):\n"
                "    def value_from_datadict(self, data, files, name):\n"
                "        return data.get(name)\n\n\n"
                "def use():\n"
                "    return Thing, ThingAdmin, PickerWidget\n\n\n"
                "use()\n"
            ),
            "site/helpers.py": "LOCAL_CONSTANT = 3\n",
            "site/context_processors.py": (
                "from django.conf import settings\n\n\n"
                "def site_name(request):\n"
                "    return {'site_name': settings.SITE_NAME}\n"
            ),
            "site/signals.py": (
                "from django.db.models.signals import post_save\n\n\n"
                "def on_save(sender, instance, **kwargs):\n"
                "    return instance\n\n\n"
                "post_save.connect(on_save)\n"
            ),
            "site/fields.py": (
                "from django.db import models\n\n\n"
                "class Upper(models.CharField):\n"
                "    def from_db_value(self, value, expression, connection):\n"
                "        return value\n\n\n"
                "def call_checks(app_configs, **kwargs):\n"
                "    return []\n\n\n"
                "def _private(value, unused_flag):\n"
                "    return value\n\n\n"
                "_private(1, 2)\n"
            ),
        },
    )

    reported = _reported(tmp_path)

    for live in (
        "site.locale.fr.formats.DATE_FORMAT",
        "site.checks.check_x.app_configs",
        "site.checks.check_x.kwargs",
        "site.views.Thing.get.request",
        "site.views.Thing.get.args",
        "site.views.ThingAdmin.get_list_select_related.request",
        "site.views.PickerWidget.value_from_datadict.files",
        "site.context_processors.site_name.request",
        "site.signals.on_save.sender",
        "site.signals.on_save.kwargs",
        "site.fields.Upper.from_db_value.expression",
        "site.fields.Upper.from_db_value.connection",
        "site.fields.call_checks.app_configs",
        "site.fields.call_checks.kwargs",
    ):
        assert not any(name.endswith(live.split(".", 1)[1]) for name in reported), live
    assert any(name.endswith("Thing.helper.unused_arg") for name in reported)
    assert any(name.endswith("helpers.LOCAL_CONSTANT") for name in reported)
    assert any(name.endswith("fields._private.unused_flag") for name in reported)
