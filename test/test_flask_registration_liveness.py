import json

import pytest

from skylos.analyzer import analyze
from test.web_framework_fixtures import _scan, _unused


@pytest.mark.parametrize("attach", [True, False])
def test_nested_flask_blueprints_follow_application_registration(tmp_path, attach):
    registration = "application.register_blueprint(parent)" if attach else ""
    result = _scan(
        tmp_path,
        {
            "web.py": f"""
                from flask import Flask, Blueprint
                from routes import child
                application = Flask(__name__)
                parent = Blueprint("parent", __name__)
                parent.register_blueprint(child)
                {registration}
            """,
            "routes.py": """
                from flask import Blueprint as Routes
                child = Routes("child", __name__)
                @child.before_app_request
                def prepare_page():
                    return read_preferences()
                @child.get("/page")
                def show_page():
                    return render_page()
                def read_preferences():
                    return "preferences"
                def render_page():
                    return "page"
                def retired_page():
                    return "retired"
            """,
        },
    )
    callbacks = {"routes.prepare_page", "routes.show_page"}
    used_through_callbacks = callbacks | {
        "routes.read_preferences",
        "routes.render_page",
    }
    unused = _unused(result)
    assert "routes.retired_page" in unused
    for callback in callbacks:
        evidence = result["definitions"][callback]["dead_code_evidence"]
        assert any(item["kind"] == "framework_root" for item in evidence) is attach
    if attach:
        assert not unused & used_through_callbacks
    else:
        assert used_through_callbacks <= unused


def test_flask_value_preprocessor_and_template_test_preserve_signatures(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": """
                from flask import Flask
                app = Flask(__name__)
                @app.url_value_preprocessor
                def record_locale(endpoint, values):
                    return 0
                @app.template_test("cheap")
                def cheaper_than_limit(amount):
                    return under_limit(amount)
                def under_limit(amount):
                    return amount < 100
                def retired_filter():
                    return 0
            """,
        },
    )
    unused = _unused(result)
    assert "web.retired_filter" in unused
    assert not unused & {
        "web.record_locale",
        "web.cheaper_than_limit",
        "web.under_limit",
    }
    assert not _unused(result, "unused_parameters") & {
        "web.record_locale.endpoint",
        "web.record_locale.values",
    }


def test_flask_recreated_blueprint_keeps_distinct_route_owners(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": """
                from flask.app import Flask
                from flask.blueprints import Blueprint
                app = Flask(__name__)
                catalog = Blueprint("first", __name__)
                @catalog.route("/first")
                def old_catalog():
                    return "old"
                catalog = mounted_catalog = Blueprint("second", __name__)
                @catalog.route("/<sku>")
                def active_catalog(*, sku):
                    return "active"
                app.register_blueprint(blueprint=mounted_catalog)
            """,
        },
    )
    assert "web.old_catalog" in _unused(result)
    assert "web.active_catalog" not in _unused(result)
    assert "web.active_catalog.sku" not in _unused(result, "unused_parameters")


@pytest.mark.parametrize("mounted", ["first", "second", None])
def test_flask_stacked_routes_accept_either_registered_blueprint(tmp_path, mounted):
    registration = f"app.register_blueprint({mounted})" if mounted else ""
    result = _scan(
        tmp_path,
        {
            "web.py": f"""
                from flask import Blueprint, Flask
                app = Flask(__name__)
                first = Blueprint("first", __name__)
                second = Blueprint("second", __name__)
                @first.get("/one")
                @second.get("/two")
                def shared_page():
                    return page_title()
                def page_title():
                    return "Home"
                {registration}
            """,
        },
    )
    names = {"web.shared_page", "web.page_title"}
    assert _unused(result) & names == (set() if mounted else names)


def test_flask_module_helper_can_supply_a_blueprint_after_app_creation(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": """
                from flask import Blueprint, Flask
                app = Flask(__name__)
                current = Blueprint("current", __name__)
                retired = Blueprint("retired", __name__)
                @current.get("/")
                def homepage():
                    return site_name()
                def site_name():
                    return "Home"
                @retired.get("/old")
                def old_page():
                    return "Old"
                def current_routes():
                    return current
                app.register_blueprint(current_routes())
            """,
        },
    )
    unused = _unused(result)
    assert not unused & {"web.homepage", "web.site_name"}
    assert "web.old_page" in unused


def test_flask_conditional_registration_keeps_only_possible_blueprints(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": """
                from flask import Blueprint, Flask
                from os import getenv
                app = Flask(__name__)
                first = Blueprint("first", __name__)
                second = Blueprint("second", __name__)
                retired = Blueprint("retired", __name__)
                @first.get("/one")
                def primary_view(): return 1
                @second.get("/two")
                def secondary_view(): return 2
                @retired.get("/old")
                def old_view(): return 3
                app.register_blueprint(first if getenv("MODE") else second)
            """,
        },
    )
    unused = _unused(result)
    assert not unused & {"web.primary_view", "web.secondary_view"}
    assert "web.old_view" in unused


@pytest.mark.parametrize(
    "application",
    [
        "",
        "app = Flask(__name__)\nif enable_catalog:\n    app.register_blueprint(catalog)",
        "app = Flask(__name__)\nconfigure_blueprint(catalog)",
        "app = Flask(__name__)\naddons = [catalog]\nconfigure_blueprints(addons)",
    ],
)
def test_flask_unknown_attachment_keeps_route(tmp_path, application):
    source = """from flask import Blueprint, Flask
catalog = Blueprint("catalog", __name__)
@catalog.get("/")
def show_catalog():
    return "catalog"
"""
    result = _scan(tmp_path, {"web.py": source + application + "\n"})
    assert "web.show_catalog" not in _unused(result)


def test_flask_detach_requires_an_application_source_scope(tmp_path):
    sources = {
        "web.py": """
            from flask import Flask
            from routes import catalog
            app = Flask(__name__)
        """,
        "routes.py": """
            from flask import Blueprint
            catalog = Blueprint("catalog", __name__)
            @catalog.get("/")
            def show_catalog():
                return "catalog"
        """,
        "extension.py": """
            from flask import Blueprint
            extension = Blueprint("extension", __name__)
            @extension.get("/")
            def show_extension():
                return "extension"
        """,
    }
    whole_project = _scan(tmp_path, sources)
    assert "routes.show_catalog" in _unused(whole_project)
    assert "extension.show_extension" not in _unused(whole_project)
    single_file = json.loads(
        analyze(str(tmp_path / "routes.py"), conf=0, grep_verify=False)
    )
    assert "routes.show_catalog" not in _unused(single_file)


def test_flask_called_factory_scopes_nested_and_detached_routes(tmp_path):
    _scan(
        tmp_path,
        {
            "service/__init__.py": "",
            "service/legacy.py": """
                from flask import Blueprint, Flask
                from .legacy_views import child, idle
                parent = Blueprint("parent", __name__)
                def assemble_legacy():
                    web = Flask(__name__)
                    parent.register_blueprint(child)
                    web.register_blueprint(parent)
                    return web
                hosted = assemble_legacy()
            """,
            "service/legacy_views.py": """
                from flask import Blueprint
                child = Blueprint("child", __name__)
                idle = Blueprint("idle", __name__)
                @child.get("/status")
                def show_status():
                    return current_status()
                def current_status():
                    return "ready"
                @idle.get("/archive")
                def show_archive():
                    return archive_status()
                def archive_status():
                    return "archived"
            """,
        },
    )
    result = json.loads(analyze(str(tmp_path)))
    unused = _unused(result)
    assert {
        "service.legacy_views.show_archive",
        "service.legacy_views.archive_status",
    } <= unused
    assert not unused & {
        "service.legacy_views.show_status",
        "service.legacy_views.current_status",
    }


def test_flask_imported_setup_helper_keeps_possible_blueprint(tmp_path):
    result = _scan(
        tmp_path,
        {
            "web.py": """
                from flask import Flask
                from setup_routes import register_routes
                def create_app():
                    app = Flask(__name__)
                    register_routes(app)
                    return app
            """,
            "setup_routes.py": """
                from views import catalog
                def register_routes(app):
                    app.register_blueprint(catalog)
            """,
            "views.py": """
                from flask import Blueprint
                catalog = Blueprint("catalog", __name__)
                @catalog.get("/")
                def show_catalog():
                    return get_current_items()
                def get_current_items():
                    return []
            """,
        },
    )
    assert not _unused(result) & {"views.show_catalog", "views.get_current_items"}
