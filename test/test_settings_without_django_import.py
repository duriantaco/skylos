"""Settings-shaped modules must activate without importing django."""

from test.web_framework_fixtures import _scan, _unused


def test_middleware_string_live_without_django_import(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app/__init__.py": "\n",
            "app/urls.py": "urlpatterns = []\n",
            "app/middleware.py": """
                class RouteMiddleware:
                    def __init__(self, get_response):
                        self.get_response = get_response
                    def __call__(self, request):
                        return self.get_response(request)
            """,
            "app/settings.py": """
                INSTALLED_APPS = ["app"]
                SECRET_KEY = "x"
                ROOT_URLCONF = "app.urls"
                MIDDLEWARE = ["app.middleware.RouteMiddleware"]
            """,
        },
    )
    unused = _unused(result, "unused_classes")
    assert "app.middleware.RouteMiddleware" not in unused
    rescued = {
        item["reason"]
        for item in result["analysis_summary"]["dead_code_liveness"]["rescued"]
    }
    assert "django_web_setting_reference" in rescued


def test_satellite_logging_factories_without_django_import(tmp_path):
    result = _scan(
        tmp_path,
        {
            "app/__init__.py": "\n",
            "app/urls.py": "urlpatterns = []\n",
            "app/settings.py": """
                INSTALLED_APPS = ["app"]
                SECRET_KEY = "x"
                ROOT_URLCONF = "app.urls"
                from app.settings_logging import LOGGING  # noqa: F401
            """,
            "app/settings_logging.py": """
                LOGGING = {
                    "formatters": {
                        "json": {"()": "app.formatters.JSONFormatter"},
                    },
                    "filters": {
                        "extra": {"()": "app.formatters.ExtraAdder"},
                    },
                }
            """,
            "app/formatters.py": """
                import logging
                class JSONFormatter(logging.Formatter):
                    def format(self, record):
                        return record.getMessage()
                class ExtraAdder:
                    def filter(self, record):
                        return True
            """,
        },
    )
    unused = _unused(result, "unused_classes")
    assert "app.formatters.JSONFormatter" not in unused
    assert "app.formatters.ExtraAdder" not in unused
