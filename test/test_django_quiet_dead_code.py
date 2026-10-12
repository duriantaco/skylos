"""Django-aware dead code on a pontoon-shaped project (mozilla/pontoon, 4.47.2).

Settings read by name, choices members, DRF ``get_<field>`` methods,
migrations, settings-string classes and framework attributes are live; real
dead code next to them must still be reported. Fixtures are never executed.
"""

from test.web_framework_fixtures import _scan, _unused


def _names(result, *buckets):
    names = set()
    for bucket in buckets:
        names |= _unused(result, bucket)
    return names


def _all_unused(result):
    return _names(
        result,
        "unused_functions",
        "unused_classes",
        "unused_variables",
    )


PONTOON_SHAPED = {
    "manage.py": """
        import os
        import sys
        def main():
            os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.settings")
            from django.core.management import execute_from_command_line
            execute_from_command_line(sys.argv)
        if __name__ == "__main__":
            main()
    """,
    "project/__init__.py": "",
    "project/wsgi.py": """
        import os
        from django.core.wsgi import get_wsgi_application
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.settings")
        application = get_wsgi_application()
    """,
    "project/settings/__init__.py": """
        import sys
        from .base import *  # noqa
        try:
            from .local import *  # noqa
        except ImportError:
            pass
        if DEV and "pytest" not in sys.modules:  # noqa
            from .dev import *  # noqa
    """,
    "project/settings/base.py": """
        DEV = False
        SECRET_KEY = "x"
        EMAIL_CONSENT_TITLE = "Stay informed"
        INSTALLED_APPS = ("django.contrib.admin", "shop")
        MIDDLEWARE = (
            "django.middleware.common.CommonMiddleware",
            "shop.middleware.ConsentMiddleware",
        )
        ROOT_URLCONF = "project.urls"
        STORAGES = {"staticfiles": {"BACKEND": "shop.storage.PipelineStorage"}}
        REST_FRAMEWORK = {
            "DEFAULT_PAGINATION_CLASS": "shop.pagination.DynamicPagination",
        }
        TEMPLATES = [{
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "OPTIONS": {"context_processors": ["shop.context.globals"]},
        }]
        if DEV:
            SESSION_COOKIE_SECURE = False
    """,
    "project/settings/dev.py": """
        from . import base
        INSTALLED_APPS = base.INSTALLED_APPS + ("debug_toolbar",)
        DEBUG_TOOLBAR_CONFIG = {"SHOW_TOOLBAR_CALLBACK": lambda request: True}
    """,
    "project/urls.py": """
        from django.urls import path
        urlpatterns = []
    """,
    "shop/__init__.py": "",
    "shop/middleware.py": """
        class ConsentMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response
            def __call__(self, request):
                return self.get_response(request)
        class AbandonedMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response
    """,
    "shop/storage.py": """
        from django.contrib.staticfiles.storage import ManifestStaticFilesStorage
        class PipelineStorage(ManifestStaticFilesStorage):
            pass
    """,
    "shop/context.py": """
        def globals(request):
            return {}
        def stale_context(request):
            return {}
    """,
    "shop/pagination.py": """
        from rest_framework.pagination import PageNumberPagination
        class DynamicPagination(PageNumberPagination):
            page_size_query_param = "page_size"
            max_page_size = 1000
    """,
    "shop/models.py": """
        from django.db import models
        class Priority(models.IntegerChoices):
            LOW = 1, "Low"
            HIGH = 3, "High"
        class Product(models.Model):
            class Themes(models.TextChoices):
                DARK = "dark", "Dark"
                LIGHT = "light", "Light"
            theme = models.CharField(choices=Themes.choices, max_length=20)
            def has_changed(self):
                return False
    """,
    "shop/serializers.py": """
        from rest_framework import serializers
        from shop.models import Product
        class DynamicFieldsSerializer(serializers.ModelSerializer):
            pass
        class ProductSerializer(DynamicFieldsSerializer):
            script_name = serializers.SerializerMethodField()
            contact = serializers.SerializerMethodField(method_name="compute_contact")
            def get_script_name(self, obj) -> str:
                return "Latn"
            def compute_contact(self, obj):
                return None
            def stale_helper(self):
                return 1
            class Meta:
                model = Product
                fields = ["script_name", "contact"]
    """,
    "shop/exceptions.py": """
        from rest_framework.exceptions import APIException
        class UploadConflict(APIException):
            status_code = 409
            default_detail = "Retry the request."
    """,
    "shop/forms.py": """
        from django import forms
        from shop.models import Product
        class ProductForm(forms.ModelForm):
            class Meta:
                model = Product
                fields = "__all__"
                help_texts = {"theme": "Pick one"}
                widgets = {}
    """,
    "shop/celeryapp.py": """
        from celery.signals import setup_logging
        @setup_logging.connect
        def configure_logging(*args, **kwargs):
            return None
    """,
    "shop/utils.py": """
        OLD_LIMIT = 5
        def unused_helper():
            return 1
    """,
    "shop/views.py": """
        from shop.exceptions import UploadConflict
        from shop.models import Priority, Product
        from shop.serializers import ProductSerializer
        def product_json(request):
            if request.method != "GET":
                raise UploadConflict()
            return ProductSerializer(Product(), context={"p": Priority}).data
    """,
    "shop/migrations/__init__.py": "",
    "shop/migrations/0001_initial.py": """
        from django.db import migrations
        class Migration(migrations.Migration):
            initial = True
            dependencies = []
            operations = []
    """,
}


def test_django_framework_names_are_live_and_real_dead_code_remains(tmp_path):
    result = _scan(tmp_path, PONTOON_SHAPED)
    unused = _all_unused(result)

    live = {
        # settings read by name via django.conf.settings, through
        # ``from .base import *`` and conditional blocks
        "project.settings.base.EMAIL_CONSENT_TITLE",
        "project.settings.base.SECRET_KEY",
        "project.settings.base.ROOT_URLCONF",
        "project.settings.base.SESSION_COOKIE_SECURE",
        "project.settings.dev.DEBUG_TOOLBAR_CONFIG",
        # classes/functions Django imports from settings strings
        "shop.middleware.ConsentMiddleware",
        "shop.storage.PipelineStorage",
        "shop.pagination.DynamicPagination",
        "shop.context.globals",
        # choices members
        "shop.models.Priority.LOW",
        "shop.models.Priority.HIGH",
        "shop.models.Product.Themes.DARK",
        # DRF SerializerMethodField methods, also through a local base class
        "shop.serializers.ProductSerializer.get_script_name",
        "shop.serializers.ProductSerializer.compute_contact",
        # framework attributes
        "shop.pagination.DynamicPagination.page_size_query_param",
        "shop.pagination.DynamicPagination.max_page_size",
        "shop.exceptions.UploadConflict.default_detail",
        "shop.forms.ProductForm.Meta.help_texts",
        # signal receiver
        "shop.celeryapp.configure_logging",
        # migrations
        "shop.migrations.0001_initial.Migration",
        "shop.migrations.0001_initial.Migration.dependencies",
        "shop.migrations.0001_initial.Migration.operations",
    }
    assert not (live & unused), sorted(live & unused)

    still_dead = {
        "shop.middleware.AbandonedMiddleware",
        "shop.context.stale_context",
        "shop.serializers.ProductSerializer.stale_helper",
        "shop.models.Product.has_changed",
        "shop.utils.unused_helper",
        "shop.utils.OLD_LIMIT",
    }
    assert still_dead <= unused, sorted(still_dead - unused)


def test_settings_module_found_without_a_launcher(tmp_path):
    # DJANGO_SETTINGS_MODULE set outside the code (env, pytest.ini).
    sources = {
        "conf/__init__.py": "",
        "conf/settings.py": """
            INSTALLED_APPS = ["django.contrib.auth"]
            ROOT_URLCONF = "conf.urls"
            CUSTOM_FLAG = True
        """,
        "conf/settings_production.py": """
            from conf.settings import *  # noqa
            PRODUCTION_ONLY = True
        """,
        "conf/urls.py": """
            from django.urls import path
            urlpatterns = []
        """,
        "conf/constants.py": """
            STALE_CONSTANT = 1
        """,
    }
    unused = _all_unused(_scan(tmp_path, sources))
    assert "conf.settings.CUSTOM_FLAG" not in unused
    assert "conf.settings_production.PRODUCTION_ONLY" not in unused
    assert "conf.constants.STALE_CONSTANT" in unused


def test_migration_class_needs_the_migration_base(tmp_path):
    sources = {
        "app/__init__.py": "",
        "app/models.py": "from django.db import models\n",
        "app/migrations/__init__.py": "",
        "app/migrations/0002_data.py": """
            from django.db import migrations
            class Migration(migrations.Migration):
                dependencies = [("app", "0001_initial")]
                operations = []
        """,
        "app/tools.py": """
            class Migration:
                pass
        """,
    }
    unused = _names(_scan(tmp_path, sources), "unused_classes")
    assert "app.migrations.0002_data.Migration" not in unused
    # A plain class that happens to be named Migration is not exempt.
    assert "app.tools.Migration" in unused


def test_serializer_method_field_only_covers_declared_fields(tmp_path):
    sources = {
        "api/__init__.py": "",
        "api/serializers.py": """
            from rest_framework import serializers
            class Base(serializers.Serializer):
                pass
            class Mixin:
                def get_total(self, obj):
                    return 1
            class Report(Mixin, Base):
                total = serializers.SerializerMethodField()
            class Plain:
                def get_orphan(self, obj):
                    return 2
        """,
        "api/views.py": """
            from api.serializers import Plain, Report
            def show(request):
                return Report(request).data, Plain()
        """,
    }
    unused = _names(_scan(tmp_path, sources), "unused_functions")
    assert "api.serializers.Mixin.get_total" not in unused
    assert "api.serializers.Plain.get_orphan" in unused
