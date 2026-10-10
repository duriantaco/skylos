"""End-to-end framework evidence checks; fixture modules are never executed."""

import textwrap

import pytest

from test.web_framework_fixtures import _django_sources, _scan, _unused


def test_registered_blueprint_callback_and_helper_are_live(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": """
            from flask import Blueprint as Routes, Flask as Application
            routes = Routes("shop", __name__)
            @routes.before_app_request
            def load_user(): return lookup_user()
            def lookup_user(): return "user"
            def abandoned_helper(): return "unused"
            application = Application(__name__)
            application.register_blueprint(routes)
        """,
        },
    )
    unused = _unused(result)
    assert "web.load_user" not in unused
    assert "web.lookup_user" not in unused
    assert "web.abandoned_helper" in unused
    evidence = result["definitions"]["web.load_user"]["dead_code_evidence"]
    assert any(item["kind"] == "framework_root" for item in evidence)


def test_blueprint_import_and_called_app_factory(tmp_path):
    result = _scan(
        tmp_path,
        {
            "routes.py": """
            import flask as framework
            bp = framework.Blueprint("shop", __name__)
            @bp.before_app_request
            def prepare(): return "ready"
        """,
            "app.py": """
            from flask import Flask
            from routes import bp
            def create_app():
                app = Flask(__name__)
                app.register_blueprint(bp)
                @app.context_processor
                def context(): return {"name": helper()}
                return app
            def helper(): return "shop"
            application = create_app()
        """,
        },
    )
    unused = _unused(result)
    assert "routes.prepare" not in unused
    assert "app.create_app.context" not in unused
    assert "app.helper" not in unused


@pytest.mark.parametrize(
    "setup",
    [
        "from local_framework import Blueprint\nbp = Blueprint()",
        "from flask import Blueprint\nBlueprint = replacement\nbp = Blueprint()",
        "from flask import Blueprint\nbp = Blueprint('shop', __name__)\nbp = replacement",
        "from flask import Blueprint\nbp = Blueprint('shop', __name__)",
    ],
)
def test_flask_lookalikes_and_unregistered_blueprints_remain_unused(tmp_path, setup):
    result = _scan(
        tmp_path,
        {
            "web.py": setup
            + "\n@bp.before_app_request\ndef prepare(): return helper()\n"
            "def helper(): return 1\n",
            "local_framework.py": "class Blueprint: pass\n",
        },
    )
    assert "web.prepare" in _unused(result)
    assert "web.helper" in _unused(result)


@pytest.mark.parametrize("parameters", ["Blueprint", "*Blueprint", "**Blueprint"])
def test_factory_arguments_shadow_framework_imports(tmp_path, parameters):
    result = _scan(
        tmp_path,
        {
            "web.py": f"from flask import Blueprint, Flask\n"
            f"def factory({parameters}):\n"
            "    bp = Blueprint('shop', __name__)\n"
            "    @bp.before_app_request\n"
            "    def prepare(): return 1\n"
            "    app = Flask(__name__)\n"
            "    app.register_blueprint(bp)\n"
            "    return app\n"
            "application = factory(replacement)\n",
        },
    )
    evidence = result["definitions"]["web.factory.prepare"]["dead_code_evidence"]
    # Ordinary dynamic-callback uncertainty may retain this function. The web
    # contract must not promote the shadowed constructor into a proven root.
    assert not any(item["kind"] == "framework_root" for item in evidence)


def test_unused_factory_does_not_register_callbacks(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": """
            from flask import Blueprint, Flask
            bp = Blueprint("shop", __name__)
            @bp.before_app_request
            def prepare(): return 1
            def unused_factory(): return private_factory()
            def private_factory():
                app = Flask(__name__)
                app.register_blueprint(bp)
                return app
        """,
        },
    )
    assert "web.prepare" in _unused(result)
    assert "web.private_factory" in _unused(result)


def test_blueprint_callback_cannot_register_itself_into_liveness(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": """
                from flask import Blueprint, Flask
                bp = Blueprint("shop", __name__)
                app = Flask(__name__)
                @bp.before_app_request
                def prepare():
                    app.register_blueprint(bp)
                    return helper()
                def helper(): return 1
            """,
        },
    )
    assert "web.prepare" in _unused(result)
    assert "web.helper" in _unused(result)


@pytest.mark.parametrize(
    "launch",
    [
        "from django.core.wsgi import get_wsgi_application as factory\napplication = factory()",
        "from django.core.asgi import get_asgi_application as factory\napplication = factory()",
        "from django.core.wsgi import get_wsgi_application as application\napplication = application()",
        "import django\ndjango.setup()",
    ],
)
def test_explicit_django_settings_module_and_application(tmp_path, launch):
    result = _scan(
        tmp_path,
        {
            "config.py": "DEBUG = True\nunused_value = 1\ndef helper(): return 1\n",
            "wsgi.py": "import os as environment\n"
            "environment.environ['DJANGO_SETTINGS_MODULE'] = 'config'\n" + launch,
        },
    )
    unused = _unused(result, "unused_variables")
    assert "config.DEBUG" not in unused
    assert "wsgi.application" not in unused
    assert "config.unused_value" in unused
    assert "config.helper" in _unused(result)


@pytest.mark.parametrize(
    "launch",
    [
        "application = factory()",
        "from local_framework import get_wsgi_application\napplication = get_wsgi_application()",
        "from django.core.wsgi import get_wsgi_application\n"
        "get_wsgi_application = factory\napplication = get_wsgi_application()",
        "import django\ndjango = replacement\ndjango.setup()\napplication = factory()",
    ],
)
def test_settings_and_wsgi_names_do_not_establish_framework_provenance(
    tmp_path, launch
):
    result = _scan(
        tmp_path,
        {
            "settings.py": "DEBUG = True\n",
            "wsgi.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')\n"
            + launch,
            "local_framework.py": "def get_wsgi_application(): return 1\n",
        },
    )
    assert "settings.DEBUG" in _unused(result, "unused_variables")
    assert "wsgi.application" in _unused(result, "unused_variables")


def test_settings_file_lookalike_and_shadowed_django_module(tmp_path):
    result = _scan(
        tmp_path,
        {
            "settings.py": "DEBUG = True\n",
            "django.py": "def setup(): pass\n",
            "app.py": "import os, django\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')\ndjango.setup()\n",
        },
    )
    assert "settings.DEBUG" in _unused(result, "unused_variables")


def test_django_admin_named_callbacks_only(tmp_path):
    sources = _django_sources()
    sources["shop/admin.py"] = """
        from django.contrib import admin
        from .models import Product
        @admin.register(Product)
        class ProductAdmin(admin.ModelAdmin):
            list_display = ("tax_display",)
            @admin.display(description="Tax")
            def tax_display(self, obj): return format_price(2)
            @admin.display(description="Old")
            def old_display(self, obj): return 3
        class Unregistered(admin.ModelAdmin):
            list_display = ("tax_display",)
            def tax_display(self, obj): return 4
        def format_price(value): return str(value)
    """
    result = _scan(tmp_path, sources)
    unused = _unused(result)
    assert "shop.admin.ProductAdmin.tax_display" not in unused
    assert "shop.admin.format_price" not in unused
    assert "shop.admin.ProductAdmin.old_display" in unused
    assert "shop.admin.Unregistered.tax_display" in unused


def test_overwritten_admin_option_does_not_consume_stale_method(tmp_path):
    sources = _django_sources()
    sources["shop/admin.py"] = """
        from django.contrib import admin
        from .models import Product
        @admin.register(Product)
        class ProductAdmin(admin.ModelAdmin):
            list_display = ("tax_display",)
            list_display = ()
            def tax_display(self, obj): return 2
    """
    assert "shop.admin.ProductAdmin.tax_display" in _unused(_scan(tmp_path, sources))


@pytest.mark.parametrize(
    "admin_app,explicit_import,live",
    [
        (None, "", False),
        ("django.contrib.admin.apps.SimpleAdminConfig", "", False),
        ("django.contrib.admin", "", True),
        ("django.contrib.admin.apps.AdminConfig", "", True),
        (None, "import shop.admin\n", True),
        (None, "from shop import admin\n", True),
    ],
)
def test_admin_callbacks_need_autodiscovery_or_an_entry_module_import(
    tmp_path, admin_app, explicit_import, live
):
    sources = _django_sources()
    apps = ["shop.apps.ShopConfig"] + ([admin_app] if admin_app else [])
    sources["project/config.py"] = sources["project/config.py"].replace(
        '["django.contrib.admin", "shop.apps.ShopConfig"]', repr(apps)
    )
    sources["project/urls.py"] = explicit_import + textwrap.dedent(
        sources["project/urls.py"]
    )
    sources["shop/admin.py"] = """
        from django.contrib import admin
        from .models import Product
        @admin.register(Product)
        class ProductAdmin(admin.ModelAdmin):
            list_display = ("tax_display",)
            def tax_display(self, obj): return 2
    """
    result = _scan(tmp_path, sources)
    assert ("shop.admin.ProductAdmin.tax_display" not in _unused(result)) is live
