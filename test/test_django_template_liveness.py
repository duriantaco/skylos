"""End-to-end framework evidence checks; fixture modules are never executed."""

import textwrap

import pytest

from test.web_framework_fixtures import _django_sources, _scan, _unused


def test_routed_detail_template_resolves_specific_model_and_helpers(tmp_path):
    result = _scan(tmp_path, _django_sources())
    unused = _unused(result)
    assert "shop.models.Product.tax" not in unused
    assert "shop.models.format_tax" not in unused
    assert "shop.models.Product.old_tax" in unused
    assert "shop.models.Other.tax" in unused
    assert "shop.views.old_page" in unused
    assert "project.config.old_helper" in unused
    variables = _unused(result, "unused_variables")
    assert "project.config.DEBUG" not in variables
    assert "shop.views.ProductPage.model" not in variables
    assert "project.config.helper_value" in variables


@pytest.mark.parametrize(
    "markup",
    [
        "object.tax",
        "{# {{ object.tax }} #}",
        "{% comment %}{{ object.tax }}{% endcomment %}",
        "{{ 'object.tax' }}",
        "{% if 'object.tax' %}literal{% endif %}",
        "{{ unrelated.object.tax }}",
    ],
)
def test_template_literals_and_comments_do_not_rescue_model_method(tmp_path, markup):
    sources = _django_sources()
    sources["shop/templates/shop/product_detail.html"] = markup
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


@pytest.mark.parametrize(
    "markup",
    [
        "{% with object=unrelated %}{{ object.tax }}{% endwith %}",
        "{% with unrelated as object %}{{ object.tax }}{% endwith %}",
        "{% for object in others %}{{ object.tax }}{% endfor %}",
        "{% for object, other in others %}{{ object.tax }}{% endfor %}",
        "{% with product=unrelated %}{{ product.tax }}{% endwith %}",
        "{% firstof unrelated as object %}{{ object.tax }}",
        "{% with object=unrelated %}{% include 'shop/base.html' %}{% endwith %}",
    ],
)
def test_shadowed_template_aliases_do_not_rescue_model_method(tmp_path, markup):
    sources = _django_sources()
    sources["shop/templates/shop/product_detail.html"] = markup
    sources["shop/templates/shop/base.html"] = "{{ object.tax }}"
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


@pytest.mark.parametrize(
    "markup",
    [
        "{% with object=unrelated %}{{ object.old_tax }}{% endwith %}{{ object.tax }}",
        "{% for object in others %}{{ object.old_tax }}{% endfor %}{{ object.tax }}",
        "{% for object in others %}x{% empty %}{{ object.tax }}{% endfor %}",
        "{% with object=object.tax %}{{ object }}{% endwith %}",
    ],
)
def test_template_alias_scope_restores_the_original_context(tmp_path, markup):
    sources = _django_sources()
    sources["shop/templates/shop/product_detail.html"] = markup
    result = _scan(tmp_path, sources)
    assert "shop.models.Product.tax" not in _unused(result)
    assert "shop.models.Product.old_tax" in _unused(result)


@pytest.mark.parametrize(
    "override",
    [
        "def get_object(self): return replacement",
        "def get_queryset(self): return replacement",
        "def get_context_data(self, **kwargs): return {'object': replacement}",
        "def get_context_object_name(self, obj): return 'other'",
        "def get_template_names(self): return ['other.html']",
        "queryset = replacement",
        "extra_context = {'object': replacement, 'product': replacement}",
        "extra_context = unknown_context",
    ],
)
def test_context_overrides_make_model_template_inference_uncertain(tmp_path, override):
    sources = _django_sources()
    sources["shop/views.py"] = textwrap.dedent(sources["shop/views.py"]).replace(
        "    model = Product", "    model = Product\n    " + override
    )
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


def test_extra_context_only_masks_the_alias_it_overwrites(tmp_path):
    sources = _django_sources()
    sources["shop/views.py"] = textwrap.dedent(sources["shop/views.py"]).replace(
        "    model = Product",
        "    model = Product\n    extra_context = {'object': replacement}",
    )
    sources["shop/templates/shop/product_detail.html"] = (
        "{{ object.old_tax }} {{ product.tax }}"
    )
    result = _scan(tmp_path, sources)
    assert "shop.models.Product.tax" not in _unused(result)
    assert "shop.models.Product.old_tax" in _unused(result)


@pytest.mark.parametrize(
    "option,markup",
    [
        ("template_name = chosen_template", "{{ object.tax }}"),
        ("template_name_suffix = chosen_suffix", "{{ object.tax }}"),
        ("context_object_name = chosen_name", "{{ product.tax }}"),
    ],
)
def test_dynamic_template_options_do_not_invent_default_references(
    tmp_path, option, markup
):
    sources = _django_sources()
    sources["shop/views.py"] = textwrap.dedent(sources["shop/views.py"]).replace(
        "    model = Product", "    model = Product\n    " + option
    )
    sources["shop/templates/shop/product_detail.html"] = markup
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


def test_as_view_overrides_do_not_guess_the_template_model(tmp_path):
    sources = _django_sources()
    sources["shop/urls.py"] = sources["shop/urls.py"].replace(
        "ProductPage.as_view()", "ProductPage.as_view(model=Other)"
    )
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


@pytest.mark.parametrize(
    "registration",
    [
        "unused_patterns = [path('p/', ProductPage.as_view())]",
        "urlpatterns = []",
    ],
)
def test_unrouted_view_template_does_not_consume_model_method(tmp_path, registration):
    sources = _django_sources()
    sources["shop/urls.py"] = (
        "from django.urls import path\nfrom .views import ProductPage\n" + registration
    )
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


def test_unused_template_and_custom_context_name(tmp_path):
    sources = _django_sources()
    sources["shop/views.py"] = """
        from django.views.generic import DetailView
        from shop.models import Product
        class ProductPage(DetailView):
            model = Product
            context_object_name = "item"
    """
    sources["shop/templates/shop/product_detail.html"] = (
        "{{ item.tax }} {{ product.old_tax }}"
    )
    sources["shop/templates/shop/unused.html"] = "{{ object.old_tax }}"
    result = _scan(tmp_path, sources)
    assert "shop.models.Product.tax" not in _unused(result)
    assert "shop.models.Product.old_tax" in _unused(result)


def test_class_body_shadowing_does_not_guess_a_template_model(tmp_path):
    sources = _django_sources()
    sources["shop/views.py"] = """
        from django.views.generic import DetailView
        from shop.models import Product
        class ProductPage(DetailView):
            Product = replacement
            model = Product
    """
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


def test_template_inheritance_keeps_context_and_excludes_ambiguous_names(tmp_path):
    sources = _django_sources()
    sources["shop/templates/shop/product_detail.html"] = (
        "{% extends 'shop/base.html' %}"
    )
    sources["shop/templates/shop/base.html"] = "{{ object.tax }}"
    assert "shop.models.Product.tax" not in _unused(_scan(tmp_path, sources))


def test_overridden_parent_template_blocks_do_not_rescue_methods(tmp_path):
    sources = _django_sources()
    sources["shop/templates/shop/product_detail.html"] = (
        "{% extends 'shop/base.html' %}{% block content %}other{% endblock %}"
    )
    sources["shop/templates/shop/base.html"] = (
        "{% block content %}{{ object.tax }}{% endblock %}"
    )
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


def test_ambiguous_templates_are_not_guessed(tmp_path):
    sources = _django_sources()
    sources["project/config.py"] = sources["project/config.py"].replace(
        '"APP_DIRS": True,',
        f'"APP_DIRS": True, "DIRS": [{str(tmp_path / "templates")!r}],',
    )
    sources["templates/shop/product_detail.html"] = "{{ object.tax }}"
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


@pytest.mark.parametrize("directory", ["retired/templates", "templates"])
def test_unconfigured_template_directories_are_not_used(tmp_path, directory):
    sources = _django_sources()
    sources.pop("shop/templates/shop/product_detail.html")
    sources["retired/__init__.py"] = ""
    sources[directory + "/shop/product_detail.html"] = "{{ object.tax }}"
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


@pytest.mark.parametrize(
    "configuration",
    [
        "TEMPLATES = []",
        "TEMPLATES = [{'BACKEND': 'django.template.backends.jinja2.Jinja2', 'APP_DIRS': True}]",
        "TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': False}]",
        "TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': True, 'DIRS': unknown_dirs}]",
        "TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': True, 'OPTIONS': {'loaders': custom_loaders}}]",
    ],
)
def test_templates_need_a_resolved_django_loader_configuration(tmp_path, configuration):
    sources = _django_sources()
    sources["project/config.py"] = (
        textwrap.dedent(sources["project/config.py"]) + "\n" + configuration + "\n"
    )
    assert "shop.models.Product.tax" in _unused(_scan(tmp_path, sources))


def test_configured_pathlib_template_directory_is_resolved_without_execution(tmp_path):
    sources = _django_sources()
    sources.pop("shop/templates/shop/product_detail.html")
    sources["project/config.py"] = (
        textwrap.dedent(sources["project/config.py"])
        + """
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR / 'project_templates'],
}]
"""
    )
    sources["project_templates/shop/product_detail.html"] = "{{ object.tax }}"
    assert "shop.models.Product.tax" not in _unused(_scan(tmp_path, sources))


@pytest.mark.parametrize("exclude", ["templates", "shop/templates", "**/templates/**"])
def test_excluded_templates_do_not_rescue_model_methods(tmp_path, exclude):
    result = _scan(tmp_path, _django_sources(), exclude_folders=[exclude])
    assert "shop.models.Product.tax" in _unused(result)
