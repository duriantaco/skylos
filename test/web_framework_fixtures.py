"""Trusted source fixtures shared by static web-framework regression tests."""

import json
import textwrap

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink


def _scan(root, sources, **kwargs):
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, textwrap.dedent(source).lstrip())
    result = json.loads(analyze(str(root), conf=0, grep_verify=False, **kwargs))
    assert not result.get("analysis_errors")
    return result


def _unused(result, bucket="unused_functions"):
    return {item["full_name"] for item in result.get(bucket, [])}


def _django_sources():
    return {
        "manage.py": """
            import os
            from django.core.management import execute_from_command_line
            if __name__ == "__main__":
                os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.config")
                execute_from_command_line([])
        """,
        "project/__init__.py": "",
        "project/config.py": """
            DEBUG = True
            INSTALLED_APPS = ["django.contrib.admin", "shop.apps.ShopConfig"]
            ROOT_URLCONF = "project.urls"
            TEMPLATES = [{
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "APP_DIRS": True,
            }]
            helper_value = "unused"
            def old_helper(): return "unused"
        """,
        "project/urls.py": """
            from django.urls import include, path
            urlpatterns = [path("", include("shop.urls"))]
        """,
        "shop/__init__.py": "",
        "shop/apps.py": """
            from django.apps import AppConfig
            class ShopConfig(AppConfig):
                name = "shop"
        """,
        "shop/models.py": """
            from django.db import models
            class Product(models.Model):
                def tax(self): return format_tax(2)
                def old_tax(self): return 1
            class Other(models.Model):
                def tax(self): return 3
            def format_tax(value): return str(value)
        """,
        "shop/views.py": """
            from django.views.generic import DetailView
            from shop.models import Product
            class ProductPage(DetailView):
                model = Product
            def old_page(request): return "unused"
        """,
        "shop/urls.py": """
            from django.urls import path
            from .views import ProductPage
            urlpatterns = [path("p/<int:pk>/", ProductPage.as_view())]
        """,
        "shop/templates/shop/product_detail.html": "{{ object.tax }}",
    }
